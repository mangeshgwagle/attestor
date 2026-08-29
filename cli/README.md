# Attestor CLI for PowerShell

A developer-friendly PowerShell front end for the Attestor offline
code-security analyzer. It is a thin layer over the verified Python core
(`attestor_cli.py`): it adds configuration, logging, secret hygiene, clean
help, and clear error handling, and delegates every analysis to the core in
Python isolated mode. It changes no analysis and removes no safety control —
scope validation, symlink refusal, the no-execution / no-network contract, and
the fail-closed exit codes all remain the core's job.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Python 3.11+ on `PATH` (the `py` launcher is used if present, else `python`)

No third-party PowerShell modules and no Python packages are required for the
default scan path — the core imports only the standard library.

## Install

From this `cli/` directory:

```powershell
Import-Module .\Attestor.psd1
Install-Attestor            # writes default config; prints the profile line
```

To load it automatically in every session:

```powershell
Install-Attestor -AddToProfile
```

That appends an `Import-Module` line to your `$PROFILE`. Open a new session and
`attestor` is available.

## Verify the setup

```powershell
Test-Attestor              # doctor: checks Python, the core, config, logs
```

Every row should report `OK = True` except `config`, which becomes present the
first time you run `Install-Attestor` or `Set-AttestorConfig`.

## Use

```powershell
attestor --help                              # command overview
attestor status                              # what is available vs gated
attestor scan .\src                          # scan a tree (text output)
attestor scan .\src --format sarif > out.sarif
attestor scan .\src --format json --jobs 8 --deep
attestor assure .\repo                       # read-only assurance report
attestor verify                              # audit the release tree
```

`attestor` is an alias for `Invoke-Attestor`; both work.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | clean — no findings |
| 1 | findings present |
| 2 | invalid usage or input |
| 3 | incomplete or intentionally gated |
| 4 | operational failure |

Read the result in scripts with `$LASTEXITCODE` (the wrapper never prints a
stray status value into the output stream):

```powershell
attestor scan .\src --format json > report.json
if ($LASTEXITCODE -eq 1) { Write-Host 'Findings — see report.json' }
```

## Configuration

Settings live in `$HOME\.attestor\config.json` (override the directory with the
`ATTESTOR_HOME` environment variable).

```powershell
Get-AttestorConfig                              # show effective settings
Set-AttestorConfig -Name default_jobs -Value 8
Set-AttestorConfig -Name log_level -Value debug
Set-AttestorConfig -Name python -Value 'C:\Python312\python.exe'
```

| Key | Default | Meaning |
|-----|---------|---------|
| `python` | `''` (auto) | Interpreter to use; empty auto-detects `py -3` then `python`. |
| `default_jobs` | `4` | Suggested parallel workers. |
| `default_format` | `text` | Suggested output format. |
| `deep` | `false` | Suggested higher-recall mode. |
| `log_level` | `info` | `debug` / `info` / `warn` / `error` / `off`. |
| `log_retention_days` | `14` | Age after which old logs are pruned. |

## Logging

Structured logs are written to `$HOME\.attestor\logs\attestor-YYYYMMDD.log`,
one line per run and per exit, filtered by `log_level`. Logs older than
`log_retention_days` are pruned automatically.

## Secrets

- The default scan path takes and needs **no secrets**.
- Secret-like values are **never taken as command arguments** and **never
  logged**: any argument whose flag name contains `key`, `token`, `secret`,
  `password`, `credential`, or `authorization` is redacted before a log line is
  written (both `--flag value` and `--flag=value` forms).
- `Set-AttestorConfig` **refuses** to store a secret-like value in the config
  file.
- The optional model-backed features read provider keys from **environment
  variables only** — never from the config file or the command line.
