@echo off
rem FFTPS 安装入口：双击运行，自动提权执行 install.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
