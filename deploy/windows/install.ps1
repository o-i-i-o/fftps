# FFTPS Web 管理版 Windows 安装脚本（zip 交付物）
#
# 用法：双击 install.bat，或管理员 PowerShell 执行 ./install.ps1
# 语义与原 NSIS 安装器一致：
#   - %ProgramFiles%\fftps\{fftpd,fftp-http,fftp-http-launcher}.exe
#   - %ProgramData%\fftpd 下初始配置模板（已存在时绝不覆盖），Users 组可写
#   - fftpd 注册为 SCM 自启服务
#   - 桌面/开始菜单快捷方式 → fftp-http-launcher.exe（GUI 子系统，无黑框）
#
# fftp-http 不注册服务：按用户身份按需启动，空闲自动关闭无需管理员权限。

$ErrorActionPreference = 'Stop'

# ---------- 自提权 ----------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args
    exit
}

$InstallDir = Join-Path $env:ProgramFiles 'fftps'
$DataDir = Join-Path $env:ProgramData 'fftpd'
$SrcDir = $PSScriptRoot
$ServiceName = 'fftpd'
$AppName = 'FFTPS Web 管理'
$UninstKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FFTPS'
$Version = '0.1.1'   # build-zip.sh 打包时替换

Write-Host "=== $AppName $Version 安装 ==="
Write-Host "安装目录: $InstallDir"
Write-Host "数据目录: $DataDir"
Write-Host ""

# ---------- 复制二进制 ----------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($bin in 'fftpd.exe', 'fftp-http.exe', 'fftp-http-launcher.exe') {
    Copy-Item -Force (Join-Path $SrcDir $bin) (Join-Path $InstallDir $bin)
    Write-Host "  已安装 $bin"
}

# ---------- 配置模板（仅首次安装时预置） ----------
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'logs') | Out-Null
foreach ($cfg in 'config.toml', 'fftp-http.toml') {
    $dst = Join-Path $DataDir $cfg
    if (-not (Test-Path $dst)) {
        Copy-Item (Join-Path $SrcDir $cfg) $dst
        Write-Host "  已生成配置 $cfg"
    } else {
        Write-Host "  保留现有配置 $cfg"
    }
}
# 允许普通用户维护配置/日志（服务与按需前端均需写入）
icacls $DataDir /grant '*S-1-5-32-545:(OI)(CI)M' /T /C | Out-Null

# ---------- 注册 fftpd 自启服务 ----------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}
# binPath 引号嵌套确保带空格路径正确写入 SCM
& sc.exe create $ServiceName binPath= "`"$InstallDir\fftpd.exe`" --service" DisplayName= 'fftps FTP/SFTP Server' start= auto | Out-Null
& sc.exe start $ServiceName | Out-Null
Write-Host '  fftpd 服务已注册并启动（开机自启）'

# ---------- 卸载脚本随装 ----------
Copy-Item -Force (Join-Path $SrcDir 'uninstall.ps1') (Join-Path $InstallDir 'uninstall.ps1')
Copy-Item -Force (Join-Path $SrcDir 'uninstall.bat') (Join-Path $InstallDir 'uninstall.bat')

# ---------- 快捷方式 ----------
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"))
$lnk.TargetPath = Join-Path $InstallDir 'fftp-http-launcher.exe'
$lnk.IconLocation = Join-Path $InstallDir 'fftp-http.exe,0'
$lnk.Save()
$smRoot = Join-Path $env:ProgramData ([System.IO.Path]::Combine('Microsoft', 'Windows', 'Start Menu', 'Programs'))
$smDir = Join-Path $smRoot 'FFTPS'
New-Item -ItemType Directory -Force -Path $smDir | Out-Null
$lnk2 = $shell.CreateShortcut((Join-Path $smDir "$AppName.lnk"))
$lnk2.TargetPath = Join-Path $InstallDir 'fftp-http-launcher.exe'
$lnk2.IconLocation = Join-Path $InstallDir 'fftp-http.exe,0'
$lnk2.Save()
$lnk3 = $shell.CreateShortcut((Join-Path $smDir '卸载 FFTPS.lnk'))
$lnk3.TargetPath = Join-Path $InstallDir 'uninstall.bat'
$lnk3.Save()
Write-Host '  桌面/开始菜单快捷方式已创建'

# ---------- ARP 注册（设置→应用 可卸载） ----------
New-Item -Path $UninstKey -Force | Out-Null
Set-ItemProperty $UninstKey 'DisplayName' $AppName
Set-ItemProperty $UninstKey 'DisplayVersion' $Version
Set-ItemProperty $UninstKey 'Publisher' 'fftps developers'
Set-ItemProperty $UninstKey 'InstallLocation' $InstallDir
Set-ItemProperty $UninstKey 'UninstallString' "`"$InstallDir\uninstall.bat`""
Set-ItemProperty $UninstKey 'QuietUninstallString' "`"$InstallDir\uninstall.bat`" /S"
Set-ItemProperty $UninstKey 'NoModify' 1 -Type DWord
Set-ItemProperty $UninstKey 'NoRepair' 1 -Type DWord

Write-Host ''
Write-Host '=== 安装完成 ==='
Write-Host "fftpd 已注册为开机自启服务；点击「$AppName」即可启动 Web 服务。"
Write-Host "首次启动会进入本机初始化向导；配置文件位于：$DataDir"
