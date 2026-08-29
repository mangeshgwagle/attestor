$ErrorActionPreference = "Stop"

$attestorCli = Join-Path -Path $PSScriptRoot -ChildPath "attestor_cli.py"
if (-not (Test-Path -LiteralPath $attestorCli -PathType Leaf)) {
    [Console]::Error.WriteLine("attestor: unified CLI entry point is unavailable")
    exit 4
}
$pythonLauncher = Get-Command -Name "py.exe" -CommandType Application -ErrorAction SilentlyContinue
if ($null -ne $pythonLauncher) {
    & $pythonLauncher.Source -3 -I -B -X utf8 $attestorCli @args
} else {
    $pythonLauncher = Get-Command -Name "python.exe" -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $pythonLauncher) {
        [Console]::Error.WriteLine("attestor: Python 3 is unavailable")
        exit 4
    }
    & $pythonLauncher.Source -I -B -X utf8 $attestorCli @args
}
exit $LASTEXITCODE
