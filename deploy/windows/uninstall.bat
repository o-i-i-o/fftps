@echo off
rem FFTPS uninstaller entry: batch header + embedded PowerShell (single file).
rem The batch part only launches PowerShell; the script body follows #:PSBEGIN.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$f='%~f0'; $l=[IO.File]::ReadAllLines($f,[Text.Encoding]::UTF8); $i=[Array]::IndexOf($l,'#:PSBEGIN'); if($i -lt 0){throw 'PS marker not found'}; & ([scriptblock]::Create(($l[($i+1)..($l.Length-1)] -join [Environment]::NewLine))) -SourceDir '%~dp0' %*"
set "rc=%ERRORLEVEL%"
if not "%rc%"=="0" echo [FFTPS] Exit code: %rc%
pause
exit /b %rc%
#:PSBEGIN
param([string]$SourceDir)

# FFTPS Web 管理版 Windows 卸载脚本（内嵌于 uninstall.bat）
#
# 用法：双击 uninstall.bat，或通过「设置 → 应用」卸载（由 ARP 注册指向本脚本）。
# 语义：先停用户进程，再停删服务；询问是否保留配置数据。

$ErrorActionPreference = 'Stop'

$Silent = ($args -contains '/S')

# ---------- 自提权 ----------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $bat = Join-Path $SourceDir 'uninstall.bat'
    $launchArgs = @('/c', "`"$bat`"")
    if ($Silent) { $launchArgs += '/S' }
    Start-Process -FilePath $env:ComSpec -ArgumentList $launchArgs -Verb RunAs
    exit
}

$InstallDir = Join-Path $env:ProgramFiles 'fftps'
$DataDir = Join-Path $env:ProgramData 'fftpd'
$ServiceName = 'fftpd'
$AppName = 'FFTPS'
$UninstKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FFTPS'

Write-Host "=== $AppName 卸载 ==="

# ---------- 先停前端用户进程，再停后端服务 ----------
& taskkill /F /IM fftp-http.exe 2> $null | Out-Null
& taskkill /F /IM fftp-http-launcher.exe 2> $null | Out-Null
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}
Write-Host '  fftpd 服务已停止并移除'

# ---------- 数据保留询问 ----------
$keepData = $true
if (-not $Silent) {
    $answer = Read-Host "是否同时删除配置、用户库与日志？`n位置：$DataDir`n选择「否」将保留数据便于重装 [y/N]"
    if ($answer -match '^[Yy]') { $keepData = $false }
}
if (-not $keepData -and (Test-Path $DataDir)) {
    Remove-Item -Recurse -Force $DataDir
    Write-Host '  配置数据已删除'
} else {
    Write-Host "  配置数据保留于 $DataDir"
}

# ---------- 安装目录与快捷方式 ----------
# uninstall.bat 自身被父 cmd 占用，先尽力删除，残留交给独立进程退出后重试清理
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
}
if (Test-Path $InstallDir) {
    $cleanup = 'for /l %i in (1,1,300) do @(ping -n 2 127.0.0.1 >nul & rd /s /q "' + $InstallDir + '" 2>nul & if not exist "' + $InstallDir + '" exit /b)'
    Start-Process -FilePath $env:ComSpec -ArgumentList @('/c', $cleanup) -WindowStyle Hidden
}
$lnkDesktop = Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"
if (Test-Path $lnkDesktop) { Remove-Item -Force $lnkDesktop }
$smDir = Join-Path $env:ProgramData ([System.IO.Path]::Combine('Microsoft', 'Windows', 'Start Menu', 'Programs', 'FFTPS'))
if (Test-Path $smDir) { Remove-Item -Recurse -Force $smDir }
if (Test-Path $UninstKey) { Remove-Item -Path $UninstKey -Recurse -Force }

Write-Host '=== 卸载完成 ==='
if (-not $Silent) { Read-Host '按回车键退出' }
