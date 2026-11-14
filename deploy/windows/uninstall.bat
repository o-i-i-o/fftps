@echo off
rem FFTPS 卸载入口：双击运行，自动提权执行 uninstall.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" %*
pause
