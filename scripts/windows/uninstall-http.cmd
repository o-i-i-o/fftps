@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

:: ========================================
:: FFTPS (fftp-http 变体) 卸载脚本
:: 功能：请求管理员权限、停止并删除 fftp-http 与 fftpd 两个 Windows 服务、
::       关闭前台残留进程、删除安装目录
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
echo   FFTPS 卸载程序（fftp-http Web 管理版）
echo ========================================
echo.

:: 定义路径
set INSTALL_DIR=C:\Program Files\fftps
set FFTPD_EXE=fftpd.exe
set FFTPHTTP_EXE=fftp-http.exe
set BACKEND_SERVICE=fftpd
set WEB_SERVICE=fftp-http

:: 步骤 1: 检查安装
echo [1/5] 检查安装状态...
if not exist "%INSTALL_DIR%" (
    echo   路径不存在：%INSTALL_DIR%
    echo   若服务仍存在，将继续尝试清理。
) else (
    echo  检测到 FFTPS 安装
)
echo.

:: 步骤 2: 停止并删除 fftp-http 服务（先停前端，避免 depend 顺序问题）
echo [2/5] 停止并删除 %WEB_SERVICE% 服务...
sc query %WEB_SERVICE% >nul 2>&1
if %errorLevel% equ 0 (
    sc query %WEB_SERVICE% | find "RUNNING" >nul 2>&1
    if %errorLevel% equ 0 (
        echo   正在停止服务 %WEB_SERVICE%...
        sc stop %WEB_SERVICE% >nul 2>&1
        if errorlevel 1 (
            echo  警告：停止服务失败，尝试强制停止
            taskkill /F /IM %FFTPHTTP_EXE% >nul 2>&1
        )
        timeout /t 2 /nobreak >nul
    ) else (
        echo  服务未运行
    )
    echo   正在删除服务 %WEB_SERVICE%...
    sc delete %WEB_SERVICE% >nul 2>&1
    if errorlevel 1 (
        echo  警告：删除服务失败
        pause
    ) else (
        echo  服务已删除
    )
) else (
    echo  服务未安装，无需删除
)

:: 关闭前台手动运行的 fftp-http 实例
tasklist | find "%FFTPHTTP_EXE%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   关闭前台运行的 %FFTPHTTP_EXE%...
    taskkill /F /IM %FFTPHTTP_EXE% >nul 2>&1
)
echo.

:: 步骤 3: 停止并删除 fftpd 后端服务
echo [3/5] 停止并删除 %BACKEND_SERVICE% 服务...
sc query %BACKEND_SERVICE% >nul 2>&1
if %errorLevel% equ 0 (
    sc query %BACKEND_SERVICE% | find "RUNNING" >nul 2>&1
    if %errorLevel% equ 0 (
        echo   正在停止服务 %BACKEND_SERVICE%...
        sc stop %BACKEND_SERVICE% >nul 2>&1
        if errorlevel 1 (
            echo  警告：停止服务失败，尝试强制停止
            taskkill /F /IM %FFTPD_EXE% >nul 2>&1
        )
        timeout /t 2 /nobreak >nul
    ) else (
        echo  服务未运行
    )
    echo   正在删除服务 %BACKEND_SERVICE%...
    sc delete %BACKEND_SERVICE% >nul 2>&1
    if errorlevel 1 (
        echo  警告：删除服务失败
        pause
    ) else (
        echo  服务已删除
    )
) else (
    echo  服务未安装，无需删除
)

:: 关闭前台手动运行的 fftpd 实例
tasklist | find "%FFTPD_EXE%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   关闭前台运行的 %FFTPD_EXE%...
    taskkill /F /IM %FFTPD_EXE% >nul 2>&1
)
echo.

:: 步骤 4: 删除安装目录
echo [4/5] 删除安装目录...
if exist "%INSTALL_DIR%" (
    echo   正在删除 %INSTALL_DIR%...

    :: 先尝试删除 exe（可能被占用）
    if exist "%INSTALL_DIR%\%FFTPD_EXE%" (
        del /Q "%INSTALL_DIR%\%FFTPD_EXE%" >nul 2>&1
    )
    if exist "%INSTALL_DIR%\%FFTPHTTP_EXE%" (
        del /Q "%INSTALL_DIR%\%FFTPHTTP_EXE%" >nul 2>&1
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

:: 步骤 5: 结果
echo [5/5] 清理完成
echo.
echo ========================================
echo   卸载完成！
echo ========================================
echo.
echo 已删除项目:
echo   - %WEB_SERVICE% Windows 服务（Web 前端）
echo   - %BACKEND_SERVICE% Windows 服务（后端）
echo   - 程序文件与配置
echo   - 安装目录：%INSTALL_DIR%
echo.
echo 注意：用户配置与状态位于 %ProgramData%\fftpd\
echo      如需完全清除，请手动删除该目录。
echo.
exit
