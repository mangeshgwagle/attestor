@echo off
rem Attestor, small and on the desktop. Double-click me.
rem
rem pythonw rather than python: the companion is a window, and a console
rem flashing up behind it every launch is not the impression we are going for.
rem %~dp0 keeps this working no matter where the distribution is copied.
start "Attestor" pythonw "%~dp0integrations\attestor_desk\attestor_desk.py"
