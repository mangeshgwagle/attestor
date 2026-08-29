@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  py -3 -I -B -X utf8 integrations\attestorlang\cli.py %*
) else (
  python -I -B -X utf8 integrations\attestorlang\cli.py %*
)
exit /b %errorlevel%
