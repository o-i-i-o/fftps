@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

:: ========================================
:: FFTPS (fftp-http 变体) 安装脚本
:: 功能：请求管理员权限、创建目录、复制文件、
::       注册并启动 fftpd（后端）与 fftp-http（Web 前端）两个 Windows 服务
:: 说明：与 fftp-gui 变体的 install.cmd 平级；本变体无图形界面，
::       通过浏览器访问 Web 管理界面（默认 http://127.0.0.1:8080）
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
echo   FFTPS 安装程序（fftp-http Web 管理版）
echo ========================================
echo.

:: 获取脚本所在目录（脚本可与 fftpd.exe / fftp-http.exe 同目录，
:: 也可位于 scripts/windows/，此时从 dist 产物或上级目录定位）
set SCRIPT_DIR=%~dp0
set BIN_DIR=%SCRIPT_DIR%
if not exist "%BIN_DIR%fftpd.exe" if exist "%SCRIPT_DIR%..\..\dist\x86_64-pc-windows-gnu\fftpd.exe" (
    set BIN_DIR=%SCRIPT_DIR%..\..\dist\x86_64-pc-windows-gnu\
)

:: 定义目标路径
set INSTALL_DIR=C:\Program Files\fftps\
set FFTPD_EXE=fftpd.exe
set FFTPHTTP_EXE=fftp-http.exe
set BACKEND_SERVICE=fftpd
set WEB_SERVICE=fftp-http

:: 检查源文件是否存在
echo [1/7] 检查安装文件...
if not exist "%BIN_DIR%%FFTPD_EXE%" (
    echo  错误：找不到 %FFTPD_EXE%
    echo   路径：%BIN_DIR%%FFTPD_EXE%
    pause
    exit /b 1
)
if not exist "%BIN_DIR%%FFTPHTTP_EXE%" (
    echo  错误：找不到 %FFTPHTTP_EXE%
    echo   路径：%BIN_DIR%%FFTPHTTP_EXE%
    pause
    exit /b 1
)
echo  安装文件检查通过
echo.

:: 创建安装目录
echo [2/7] 创建安装目录...
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

:: 复制程序文件与配置模板（已存在的配置不覆盖，保留用户修改）
echo [3/7] 复制程序文件...
echo   正在复制 %FFTPD_EXE%...
copy /Y "%BIN_DIR%%FFTPD_EXE%" "%INSTALL_DIR%%FFTPD_EXE%"
if errorlevel 1 (
    echo  错误：无法复制 %FFTPD_EXE%
    pause
    exit /b 1
)
echo  已复制：%FFTPD_EXE%

echo   正在复制 %FFTPHTTP_EXE%...
copy /Y "%BIN_DIR%%FFTPHTTP_EXE%" "%INSTALL_DIR%%FFTPHTTP_EXE%"
if errorlevel 1 (
    echo  错误：无法复制 %FFTPHTTP_EXE%
    pause
    exit /b 1
)
echo  已复制：%FFTPHTTP_EXE%

if exist "%BIN_DIR%config.toml" if not exist "%INSTALL_DIR%config.toml" (
    copy /Y "%BIN_DIR%config.toml" "%INSTALL_DIR%config.toml" >nul
    echo  已预置后端配置模板：config.toml
)
if exist "%BIN_DIR%fftp-http.toml" if not exist "%INSTALL_DIR%fftp-http.toml" (
    copy /Y "%BIN_DIR%fftp-http.toml" "%INSTALL_DIR%fftp-http.toml" >nul
    echo  已预置 Web 前端配置模板：fftp-http.toml
)
echo.

:: 注册 fftpd 后端服务（开机自启）
echo [4/7] 注册 %BACKEND_SERVICE% Windows 服务（start= auto 开机自启）...
sc query %BACKEND_SERVICE% >nul 2>&1
if %errorLevel% equ 0 (
    echo   服务已存在，先停止并删除旧服务...
    sc stop %BACKEND_SERVICE% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %BACKEND_SERVICE% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

sc create %BACKEND_SERVICE% binPath= "\"%INSTALL_DIR%%FFTPD_EXE%\" --service" DisplayName= "fftps FTP/SFTP Server" start= auto
if errorlevel 1 (
    echo  错误：注册 %BACKEND_SERVICE% 服务失败
    echo   可手动注册：sc create %BACKEND_SERVICE% binPath= "\"%INSTALL_DIR%%FFTPD_EXE%\" --service" start= auto
    pause
    exit /b 1
)
echo  服务已注册：%BACKEND_SERVICE%

echo [5/7] 启动 %BACKEND_SERVICE% 服务...
sc start %BACKEND_SERVICE% >nul 2>&1
if errorlevel 1 (
    echo   警告：%BACKEND_SERVICE% 启动失败，可在服务管理器（services.msc）中手动启动
) else (
    echo  服务已启动
)
echo.

:: 注册 fftp-http Web 前端服务（depend= fftpd 保证后端先启动）
echo [6/7] 注册 %WEB_SERVICE% Windows 服务（start= auto，依赖 %BACKEND_SERVICE%）...
sc query %WEB_SERVICE% >nul 2>&1
if %errorLevel% equ 0 (
    echo   服务已存在，先停止并删除旧服务...
    sc stop %WEB_SERVICE% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %WEB_SERVICE% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

sc create %WEB_SERVICE% binPath= "\"%INSTALL_DIR%%FFTPHTTP_EXE%\" --service" DisplayName= "fftps Web Management Frontend" start= auto depend= %BACKEND_SERVICE%
if errorlevel 1 (
    echo  错误：注册 %WEB_SERVICE% 服务失败
    echo   可手动注册：sc create %WEB_SERVICE% binPath= "\"%INSTALL_DIR%%FFTPHTTP_EXE%\" --service" start= auto depend= %BACKEND_SERVICE%
    pause
    exit /b 1
)
echo  服务已注册：%WEB_SERVICE%

echo [7/7] 启动 %WEB_SERVICE% 服务...
sc start %WEB_SERVICE% >nul 2>&1
if errorlevel 1 (
    echo   警告：%WEB_SERVICE% 启动失败
    echo   最常见原因：fftp-http.toml 中尚未配置管理员账户（启动校验拒绝）。
    echo   配置步骤：
    echo     1. 生成口令哈希："%INSTALL_DIR%%FFTPHTTP_EXE%" hash 你的口令
    echo     2. 编辑 %INSTALL_DIR%fftp-http.toml，取消 [[admin_users]] 段注释并填入哈希
    echo     3. 重新启动服务：sc start %WEB_SERVICE%
) else (
    echo  服务已启动
)
echo.

:: 完成
echo ========================================
echo   安装完成！
echo ========================================
echo.
echo 安装位置：%INSTALL_DIR%
echo Windows 服务：%BACKEND_SERVICE%（后端，开机自启） + %WEB_SERVICE%（Web 前端，开机自启）
echo 配置文件：%INSTALL_DIR%config.toml（后端）
echo           %INSTALL_DIR%fftp-http.toml（Web 前端，管理员哈希见上文步骤）
echo 用户与状态数据：%ProgramData%\fftpd\
echo.
echo Web 管理界面：默认 http://127.0.0.1:8080（监听地址与端口见 fftp-http.toml [listen] 段）
echo 服务管理：
echo   sc start %BACKEND_SERVICE%     sc stop %BACKEND_SERVICE%
echo   sc start %WEB_SERVICE%         sc stop %WEB_SERVICE%
echo   sc delete %BACKEND_SERVICE%    sc delete %WEB_SERVICE%
echo 或在服务管理器（services.msc）中操作。
echo.
exit
