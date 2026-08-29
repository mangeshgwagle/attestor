@echo off
rem ---------------------------------------------------------------
rem build.cmd -- rebuild triage_kernel.dll from pure x86-64 source
rem Requires: NASM on PATH (or set NASM), any MSVC link.exe.
rem Every byte of computation lives in triage_kernel_x86_64.asm;
rem this script only assembles and packages it into a loadable DLL.
rem ---------------------------------------------------------------
setlocal
set HERE=%~dp0
if "%NASM%"=="" set NASM=nasm

set LINKEXE=%LINK%
if "%LINKEXE%"=="" (
  for /r "C:\Program Files (x86)\Microsoft Visual Studio" %%i in (link.exe) do (
    echo %%i | findstr /C:"x64" >nul && set LINKEXE=%%i
  )
)
if not exist "%LINKEXE%" (
  echo link.exe not found; install VS C++ tools or set LINK= ^
  & exit /b 1
)

"%NASM%" -f win64 "%HERE%triage_kernel_x86_64.asm" -o "%HERE%triage_kernel.obj" || exit /b 1
"%LINKEXE%" /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 ^
  /OUT:"%HERE%triage_kernel.dll" ^
  /EXPORT:triage_score_q16 /EXPORT:triage_grade ^
  "%HERE%triage_kernel.obj" || exit /b 1
echo Built %HERE%triage_kernel.dll
endlocal
