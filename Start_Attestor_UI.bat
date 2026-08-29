@echo off
setlocal
cd /d "%~dp0detector"
echo Starting Attestor 4.2 distribution ^(4.1.4 analysis/report protocol^)...
echo.
echo Open this in your browser:
echo   http://127.0.0.1:8787
echo.
where python >nul 2>nul
if errorlevel 1 (
  py -3 -I -B -X utf8 attestor_ui.py --host 127.0.0.1 --port 8787
) else (
  python -I -B -X utf8 attestor_ui.py --host 127.0.0.1 --port 8787
)
pause
