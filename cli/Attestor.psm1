#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
Attestor developer CLI for PowerShell.

This module is a thin, safety-preserving layer over the verified Python core
(attestor_cli.py). It adds developer experience -- configuration, logging,
secret hygiene, clean help and error handling -- and delegates every actual
analysis to the core, which is invoked in Python isolated mode (-I -B -X utf8)
exactly as the shipped launcher does. It adds no analysis of its own and removes
no check: scope validation, link refusal, the fail-closed exit codes, and the
no-execution / no-network contract all remain the core's responsibility and are
untouched here.
#>

$script:Root = Split-Path -Parent $PSScriptRoot
$script:CoreCli = Join-Path $script:Root 'attestor_cli.py'
$script:ConfigDir = if ($env:ATTESTOR_HOME) { $env:ATTESTOR_HOME } else { Join-Path $HOME '.attestor' }
$script:ConfigPath = Join-Path $script:ConfigDir 'config.json'
$script:LogDir = Join-Path $script:ConfigDir 'logs'

# Exit codes mirror the Python core so scripts can branch on them uniformly.
$script:Exit = @{ Clean = 0; Findings = 1; Invalid = 2; Incomplete = 3; Operational = 4 }

$script:DefaultConfig = [ordered]@{
    schema             = 'attestor.cli-config/1'
    python             = ''          # empty = auto-detect (py -3, then python)
    default_jobs       = 4
    default_format     = 'text'
    deep               = $false
    log_level          = 'info'      # debug | info | warn | error | off
    log_retention_days = 14
}

# Names whose values must never reach a log or the console. The core never wants
# secrets as arguments, but if one is passed anyway it is redacted before any
# log line is written.
$script:SecretPattern = '(?i)(key|token|secret|password|passwd|credential|authorization|api[_-]?key)'


function Get-AttestorPython {
    [CmdletBinding()]
    param([string] $Configured)
    if ($Configured) {
        $resolved = Get-Command $Configured -CommandType Application -ErrorAction SilentlyContinue
        if ($resolved) { return @($resolved.Source, @('-I', '-B', '-X', 'utf8')) }
        throw "Configured Python '$Configured' was not found on PATH."
    }
    $py = Get-Command 'py.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($py) { return @($py.Source, @('-3', '-I', '-B', '-X', 'utf8')) }
    $python = Get-Command 'python.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($python) { return @($python.Source, @('-I', '-B', '-X', 'utf8')) }
    $python3 = Get-Command 'python3' -CommandType Application -ErrorAction SilentlyContinue
    if ($python3) { return @($python3.Source, @('-I', '-B', '-X', 'utf8')) }
    throw 'Python 3 was not found. Install it and re-run, or set "python" in the config.'
}


function Get-AttestorConfig {
    <#
    .SYNOPSIS
    Return the effective Attestor CLI configuration (defaults merged with the
    on-disk file). A missing or malformed file falls back to defaults rather
    than failing. Secrets are never stored here.
    #>
    [CmdletBinding()]
    param()
    $config = [ordered]@{}
    foreach ($key in $script:DefaultConfig.Keys) { $config[$key] = $script:DefaultConfig[$key] }
    if (Test-Path -LiteralPath $script:ConfigPath) {
        try {
            $onDisk = Get-Content -LiteralPath $script:ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            foreach ($prop in $onDisk.PSObject.Properties) {
                if ($config.Contains($prop.Name)) { $config[$prop.Name] = $prop.Value }
            }
        } catch {
            Write-Warning "Config at $script:ConfigPath is unreadable; using defaults. ($($_.Exception.Message))"
        }
    }
    [pscustomobject]$config
}


function Set-AttestorConfig {
    <#
    .SYNOPSIS
    Set one configuration value and persist it.
    .EXAMPLE
    Set-AttestorConfig -Name default_jobs -Value 8
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('python', 'default_jobs', 'default_format', 'deep', 'log_level', 'log_retention_days')]
        [string] $Name,
        [Parameter(Mandatory)] $Value
    )
    if ($Name -match $script:SecretPattern) {
        throw 'Refusing to store a secret-like value in the config file. Use an environment variable instead.'
    }
    if (-not (Test-Path -LiteralPath $script:ConfigDir)) {
        New-Item -ItemType Directory -Path $script:ConfigDir -Force | Out-Null
    }
    $current = Get-AttestorConfig
    $map = [ordered]@{}
    foreach ($p in $current.PSObject.Properties) { $map[$p.Name] = $p.Value }
    $map[$Name] = $Value
    if ($PSCmdlet.ShouldProcess($script:ConfigPath, "set $Name = $Value")) {
        ($map | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $script:ConfigPath -Encoding utf8
        Write-Verbose "Wrote $Name to $script:ConfigPath"
    }
}


function Write-AttestorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('debug', 'info', 'warn', 'error')][string] $Level,
        [Parameter(Mandatory)][string] $Message,
        [string] $ConfiguredLevel = 'info'
    )
    $order = @{ debug = 0; info = 1; warn = 2; error = 3; off = 99 }
    if ($ConfiguredLevel -eq 'off' -or $order[$Level] -lt $order[$ConfiguredLevel]) { return }
    if (-not (Test-Path -LiteralPath $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }
    $file = Join-Path $script:LogDir ('attestor-{0:yyyyMMdd}.log' -f (Get-Date))
    $line = '{0:o} [{1}] {2}' -f (Get-Date), $Level.ToUpper(), $Message
    Add-Content -LiteralPath $file -Value $line -Encoding utf8
}


function Protect-AttestorArgs {
    # Redact any value that follows a secret-like flag, for log lines only.
    # A flag counts as secret when a secret word appears anywhere in its name,
    # so --token, --api-key, --auth-token and --some-secret are all caught, in
    # both the "--flag value" and "--flag=value" spellings.
    param([string[]] $Arguments)
    $words = 'key|token|secret|passwd|password|credential|authorization'
    $eqForm = "^(?i)--?[\w.-]*($words)[\w.-]*="
    $flagForm = "^(?i)--?[\w.-]*($words)[\w.-]*$"
    $out = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $current = $Arguments[$i]
        if ($current -match $eqForm) {
            $out.Add(($current -replace '=.*$', '=***redacted***'))
        } elseif ($current -match $flagForm -and ($i + 1) -lt $Arguments.Count -and $Arguments[$i + 1] -notmatch '^-') {
            $out.Add($current); $out.Add('***redacted***'); $i++
        } else {
            $out.Add($current)
        }
    }
    ($out -join ' ')
}


function Remove-AttestorOldLog {
    param([int] $RetentionDays = 14)
    if ($RetentionDays -le 0 -or -not (Test-Path -LiteralPath $script:LogDir)) { return }
    $cutoff = (Get-Date).AddDays(-1 * $RetentionDays)
    Get-ChildItem -LiteralPath $script:LogDir -Filter 'attestor-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}


function Invoke-Attestor {
    <#
    .SYNOPSIS
    Run the Attestor code-security analyzer.
    .DESCRIPTION
    Developer-facing wrapper over the verified Attestor core. It resolves
    configuration and logging, then hands the command through unchanged to the
    Python core in isolated mode. Every safety control -- scope validation, link
    refusal, no target execution, no network on the analysis path, fail-closed
    exit codes -- belongs to the core and is preserved here.

    Exit codes: 0 clean, 1 findings, 2 invalid usage, 3 incomplete/gated,
    4 operational failure.
    .EXAMPLE
    Invoke-Attestor scan .\src --format json
    .EXAMPLE
    attestor assure .\repo
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Arguments = @()
    )

    # The exit code is surfaced through $LASTEXITCODE (as any native tool does),
    # never returned to the pipeline -- returning it would print a stray integer
    # after every scan and corrupt piped/redirected output.
    if (-not (Test-Path -LiteralPath $script:CoreCli -PathType Leaf)) {
        [Console]::Error.WriteLine('attestor: verified core (attestor_cli.py) is unavailable')
        $global:LASTEXITCODE = $script:Exit.Operational
        return
    }

    $config = Get-AttestorConfig
    Remove-AttestorOldLog -RetentionDays ([int]$config.log_retention_days)

    if ($Arguments.Count -eq 0 -or $Arguments[0] -in @('-h', '--help', 'help')) {
        Show-AttestorHelp
        $global:LASTEXITCODE = $script:Exit.Clean
        return
    }

    try {
        $python, $flags = Get-AttestorPython -Configured $config.python
    } catch {
        [Console]::Error.WriteLine("attestor: $($_.Exception.Message)")
        $global:LASTEXITCODE = $script:Exit.Operational
        return
    }

    $redacted = Protect-AttestorArgs -Arguments $Arguments
    Write-AttestorLog -Level 'info' -ConfiguredLevel $config.log_level -Message "run: $redacted"

    $allArgs = @($flags) + @($script:CoreCli) + $Arguments
    & $python @allArgs
    $code = $LASTEXITCODE

    $verdict = switch ($code) {
        0 { 'clean' } 1 { 'findings' } 2 { 'invalid' } 3 { 'incomplete' } default { 'operational-failure' }
    }
    $level = if ($code -ge 2) { 'warn' } else { 'info' }
    Write-AttestorLog -Level $level -ConfiguredLevel $config.log_level -Message "exit $code ($verdict)"
    $global:LASTEXITCODE = $code
}


function Show-AttestorHelp {
    $helpText = @"
Attestor -- offline, verifiable code security analysis.

USAGE
  attestor <command> [arguments]

CORE COMMANDS
  scan <paths>       Static security scan (offline; no target execution).
  assure <dir>       Experimental read-only repository assurance report.
  lang ...           AttestorLang / OWVM.
  control ...        Owner Control (permission-gated).
  verify             Audit this release tree without writing it.
  status             Show available and gated commands.

MODULE COMMANDS (this PowerShell layer)
  Get-AttestorConfig             Show effective configuration.
  Set-AttestorConfig -Name ...   Persist one setting.
  Test-Attestor                  Environment / health check (doctor).
  Install-Attestor               One-time setup and profile wiring.

COMMON OPTIONS (passed to scan)
  --format text|json|sarif|markdown|html   Output format.
  --jobs N                                  Parallel workers (1-32).
  --deep                                    Higher-recall analysis.

EXIT CODES
  0 clean   1 findings   2 invalid usage   3 incomplete/gated   4 operational

EXAMPLES
  attestor scan .\src --format sarif > report.sarif
  attestor assure .\repo
  attestor status

Secrets are never taken as command arguments and never logged. The optional
model-backed features read provider keys from environment variables only.
Run 'attestor <command> --help' for the core's own detailed help.
"@
    Write-Host $helpText
}


function Test-Attestor {
    <#
    .SYNOPSIS
    Health check: Python, the core, config, and log directory.
    #>
    [CmdletBinding()]
    param()
    $config = Get-AttestorConfig
    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        $python, $flags = Get-AttestorPython -Configured $config.python
        $ver = & $python @($flags + @('--version')) 2>&1 | Select-Object -First 1
        $rows.Add([pscustomobject]@{ Check = 'python'; OK = $true; Detail = "$python ($ver)" })
    } catch {
        $rows.Add([pscustomobject]@{ Check = 'python'; OK = $false; Detail = $_.Exception.Message })
    }
    $rows.Add([pscustomobject]@{ Check = 'core cli'; OK = (Test-Path -LiteralPath $script:CoreCli); Detail = $script:CoreCli })
    $rows.Add([pscustomobject]@{ Check = 'config'; OK = (Test-Path -LiteralPath $script:ConfigPath); Detail = $script:ConfigPath })
    $rows.Add([pscustomobject]@{ Check = 'log dir'; OK = $true; Detail = $script:LogDir })
    $rows
}


function Install-Attestor {
    <#
    .SYNOPSIS
    One-time setup: verify prerequisites, write a default config, and either
    print or append the line that loads this module in every session.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([switch] $AddToProfile)

    if (-not (Test-Path -LiteralPath $script:ConfigDir)) {
        New-Item -ItemType Directory -Path $script:ConfigDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) {
        ($script:DefaultConfig | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $script:ConfigPath -Encoding utf8
        Write-Host "Wrote default config to $script:ConfigPath"
    } else {
        Write-Host "Config already present at $script:ConfigPath"
    }

    try {
        $python, $flags = Get-AttestorPython
        Write-Host "Python OK: $python"
    } catch {
        Write-Warning $_.Exception.Message
    }

    $modulePath = Join-Path $PSScriptRoot 'Attestor.psm1'
    $line = "Import-Module '$modulePath'"
    if ($AddToProfile) {
        if ($PSCmdlet.ShouldProcess($PROFILE, 'append Import-Module line')) {
            if (-not (Test-Path -LiteralPath $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force | Out-Null }
            if (-not (Select-String -LiteralPath $PROFILE -SimpleMatch $modulePath -Quiet)) {
                Add-Content -LiteralPath $PROFILE -Value $line -Encoding utf8
                Write-Host "Added Attestor to your profile: $PROFILE"
            } else {
                Write-Host 'Attestor already in your profile.'
            }
        }
    } else {
        Write-Host ''
        Write-Host 'To load Attestor in every session, add this to your profile:'
        Write-Host "  $line"
        Write-Host '(or re-run Install-Attestor -AddToProfile)'
    }
}


Set-Alias -Name attestor -Value Invoke-Attestor
Export-ModuleMember -Function Invoke-Attestor, Get-AttestorConfig, Set-AttestorConfig, Test-Attestor, Install-Attestor, Show-AttestorHelp -Alias attestor
