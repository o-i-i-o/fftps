@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

:: ========================================
:: FFTPS 卸载脚本（适配自 wftpd-windows/卸载.cmd）
:: 功能：请求管理员权限、停止服务、删除 Windows 服务、
::       关闭管理程序、删除快捷方式、删除文件
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
echo   FFTPS 卸载程序
echo ========================================
echo.

:: 定义路径
set INSTALL_DIR=C:\Program Files\fftps
set FFTPG_EXE=ftp-gui.exe
set FFTPD_EXE=fftpd.exe
set SERVICE_NAME=fftpd
set DESKTOP_SHORTCUT=%USERPROFILE%\Desktop\FFTPS.lnk

:: 步骤 1: 检查安装
echo [1/6] 检查安装状态...
if not exist "%INSTALL_DIR%" (
    echo   路径不存在：%INSTALL_DIR%
    pause
    exit /b 1
)
echo  检测到 FFTPS 安装
echo.

:: 步骤 2: 停止 fftpd 服务
echo [2/6] 停止 %SERVICE_NAME% 服务...
sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    sc query %SERVICE_NAME% | find "RUNNING" >nul 2>&1
    if %errorLevel% equ 0 (
        echo   正在停止服务 %SERVICE_NAME%...
        sc stop %SERVICE_NAME% >nul 2>&1
        if errorlevel 1 (
            echo  警告：停止服务失败，尝试强制停止
            taskkill /F /IM %FFTPD_EXE% >nul 2>&1
        )

        :: 等待服务完全停止
        timeout /t 2 /nobreak >nul

        :: 验证服务已停止
        sc query %SERVICE_NAME% | find "STOPPED" >nul 2>&1
        if %errorLevel% equ 0 (
            echo  服务已停止
        ) else (
            echo  警告：服务可能仍在运行
        )
    ) else (
        echo  服务未运行，无需停止
    )
) else (
    echo  服务未安装，无需停止
)
echo.

:: 步骤 3: 删除 fftpd 服务
echo [3/6] 删除 %SERVICE_NAME% 服务...
sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo   正在删除服务 %SERVICE_NAME%...
    sc delete %SERVICE_NAME% >nul 2>&1
    if errorlevel 1 (
        echo  警告：删除服务失败
        pause
    ) else (
        echo  服务已删除
    )
) else (
    echo  服务不存在，无需删除
)
echo.

:: 步骤 4: 停止 ftp-gui 管理程序
echo [4/6] 停止 %FFTPG_EXE% 管理程序...
tasklist | find "%FFTPG_EXE%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   正在关闭 %FFTPG_EXE% 管理程序...
    taskkill /F /IM %FFTPG_EXE% >nul 2>&1
    if errorlevel 1 (
        echo  警告：无法关闭 %FFTPG_EXE% 管理程序
    ) else (
        echo  管理程序已关闭
    )
) else (
    echo  管理程序未运行，无需停止
)
echo.

:: 步骤 5: 删除桌面快捷方式
echo [5/6] 删除桌面快捷方式...
if exist "%DESKTOP_SHORTCUT%" (
    del /Q "%DESKTOP_SHORTCUT%" >nul 2>&1
    if errorlevel 1 (
        echo  警告：无法删除快捷方式
    ) else (
        echo  快捷方式已删除
    )
) else (
    echo  快捷方式不存在，无需删除
)
echo.

:: 步骤 6: 删除安装目录
echo [6/6] 删除安装目录...
if exist "%INSTALL_DIR%" (
    echo   正在删除 %INSTALL_DIR%...

    :: 先尝试删除 exe（可能被占用）
    if exist "%INSTALL_DIR%\%FFTPG_EXE%" (
        del /Q "%INSTALL_DIR%\%FFTPG_EXE%" >nul 2>&1
    )

    if exist "%INSTALL_DIR%\%FFTPD_EXE%" (
        del /Q "%INSTALL_DIR%\%FFTPD_EXE%" >nul 2>&1
    )

    rmdir /S /Q "%INSTALL_DIR%"
    if errorlevel 1 (
        echo  警告：无法完全删除 %INSTALL_DIR%
        echo   可能有文件被占用，请手动删除此目录
    ) else (
        echo  安装目录已删除
    )
) else (
    echo  安装目录不存在，无需删除
)
echo.

:: 结果
echo ========================================
echo   卸载完成！
echo ========================================
echo.
echo  FFTPS 已从系统中移除
echo.
echo 已删除项目:
echo   - fftpd Windows 服务
echo   - 程序文件
echo   - 桌面快捷方式
echo   - 安装目录：%INSTALL_DIR%
echo.
echo 注意：用户配置与状态位于 %ProgramData%\fftps\
echo      如需完全清除，请手动删除该目录。
echo.
exit
