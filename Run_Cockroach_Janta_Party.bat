@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  py -3 -I -B -X utf8 detector\superattestor.py --attestor414 --variant cockroach-janta-party %*
) else (
  python -I -B -X utf8 detector\superattestor.py --attestor414 --variant cockroach-janta-party %*
)
exit /b %errorlevel%
