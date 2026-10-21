@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

:: ========================================
:: FFTPS 安装脚本（适配自 wftpd-windows/安装.cmd）
:: 功能：请求管理员权限、创建目录、复制文件、创建快捷方式、
::       注册并启动 Windows 服务（开机自启）
:: ========================================

:: 检查是否以管理员权限运行
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ========================================
    echo   请求管理员权限...
    echo ========================================
    echo.

    :: 使用 PowerShell 请求提升权限
    powershell -Command "Start-Process cmd -ArgumentList '/c', '%~dpnx0' -Verb RunAs"
    exit /b
)

echo ========================================
echo   FFTPS 安装程序
echo ========================================
echo.

:: 获取脚本所在目录（脚本可与 fftpd.exe / ftp-gui.exe 同目录，
:: 也可位于 scripts/windows/，此时从 dist 产物或上级目录定位）
set SCRIPT_DIR=%~dp0
set BIN_DIR=%SCRIPT_DIR%
if not exist "%BIN_DIR%fftpd.exe" if exist "%SCRIPT_DIR%..\..\dist\x86_64-pc-windows-gnu\fftpd.exe" (
    set BIN_DIR=%SCRIPT_DIR%..\..\dist\x86_64-pc-windows-gnu\
)

:: 定义目标路径
set INSTALL_DIR=C:\Program Files\fftps\
set FFTPG_EXE=ftp-gui.exe
set FFTPD_EXE=fftpd.exe
set SERVICE_NAME=fftpd
set DESKTOP_SHORTCUT=%USERPROFILE%\Desktop\FFTPS.lnk

:: 检查源文件是否存在
echo [1/6] 检查安装文件...
if not exist "%BIN_DIR%%FFTPG_EXE%" (
    echo  错误：找不到 %FFTPG_EXE%
    echo   路径：%BIN_DIR%%FFTPG_EXE%
    pause
    exit /b 1
)
if not exist "%BIN_DIR%%FFTPD_EXE%" (
    echo  错误：找不到 %FFTPD_EXE%
    echo   路径：%BIN_DIR%%FFTPD_EXE%
    pause
    exit /b 1
)
echo  安装文件检查通过
echo.

:: 创建安装目录
echo [2/6] 创建安装目录...
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    if errorlevel 1 (
        echo  错误：无法创建目录 %INSTALL_DIR%
        pause
        exit /b 1
    )
    echo  已创建目录：%INSTALL_DIR%
) else (
    echo  目录已存在：%INSTALL_DIR%
)
echo.

:: 复制程序文件
echo [3/6] 复制程序文件...
echo   正在复制 %FFTPG_EXE%...
copy /Y "%BIN_DIR%%FFTPG_EXE%" "%INSTALL_DIR%%FFTPG_EXE%"
if errorlevel 1 (
    echo  错误：无法复制 %FFTPG_EXE%
    pause
    exit /b 1
)
echo  已复制：%FFTPG_EXE%

echo   正在复制 %FFTPD_EXE%...
copy /Y "%BIN_DIR%%FFTPD_EXE%" "%INSTALL_DIR%%FFTPD_EXE%"
if errorlevel 1 (
    echo  错误：无法复制 %FFTPD_EXE%
    pause
    exit /b 1
)
echo  已复制：%FFTPD_EXE%
echo.

:: 创建桌面快捷方式
echo [4/6] 创建桌面快捷方式...
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%DESKTOP_SHORTCUT%'); $Shortcut.TargetPath = '%INSTALL_DIR%\%FFTPG_EXE%'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.IconLocation = '%INSTALL_DIR%\%FFTPG_EXE%,0'; $Shortcut.Description = 'FFTPS FTP/SFTP Server Manager'; $Shortcut.Save()"
if errorlevel 1 (
    echo   警告：无法创建桌面快捷方式
    echo   可以手动创建快捷方式指向：%INSTALL_DIR%%FFTPG_EXE%
) else (
    echo  已创建桌面快捷方式：%DESKTOP_SHORTCUT%
)
echo.

:: 注册并启动 Windows 服务（开机自启）
echo [5/6] 注册 %SERVICE_NAME% Windows 服务（start= auto 开机自启）...
sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo   服务已存在，先停止并删除旧服务...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

sc create %SERVICE_NAME% binPath= "\"%INSTALL_DIR%%FFTPD_EXE%\" --service" DisplayName= "fftps FTP/SFTP Server" start= auto
if errorlevel 1 (
    echo  错误：注册服务失败
    echo   可手动注册：sc create %SERVICE_NAME% binPath= "\"%INSTALL_DIR%%FFTPD_EXE%\" --service" start= auto
    pause
    exit /b 1
)
echo  服务已注册：%SERVICE_NAME%

echo [6/6] 启动服务...
sc start %SERVICE_NAME% >nul 2>&1
if errorlevel 1 (
    echo   警告：服务启动失败，可在服务管理器（services.msc）中手动启动
) else (
    echo  服务已启动
)
echo.

:: 启动图形管理程序
start "" "%INSTALL_DIR%\%FFTPG_EXE%"
if errorlevel 1 (
    echo   警告：无法自动启动管理程序
    echo   可以手动运行：%INSTALL_DIR%%FFTPG_EXE%
) else (
    echo   管理程序已启动
)
echo.

:: 完成
echo ========================================
echo   安装完成！
echo ========================================
echo.
echo 安装位置：%INSTALL_DIR%
echo Windows 服务：%SERVICE_NAME%（开机自启）
echo 桌面快捷方式：%DESKTOP_SHORTCUT%
echo.
echo 服务管理：
echo   sc start %SERVICE_NAME%     sc stop %SERVICE_NAME%
echo   sc delete %SERVICE_NAME%
echo 或在 ftp-gui「服务」页操作。
echo.
exit
