; FFTPS Web 管理版 Windows 安装器（NSIS 3 / Unicode）
;
; 构建示例（Linux CI）:
;   makensis -DAPP_VERSION=0.1.0 \
;            -DDIST_DIR=dist/x86_64-pc-windows-gnu \
;            -DOUT_DIR=dist \
;            scripts/windows/fftps-http.nsi
;
; 安装内容：
;   - %ProgramFiles%\fftps\{fftpd,fftp-http,fftp-http-launcher}.exe
;   - %ProgramData%\fftpd 下的初始配置模板（已存在时绝不覆盖）
;   - fftpd 自动启动 Windows 服务（SCM，开机自启）
;   - 开始菜单/桌面快捷方式 → fftp-http-launcher.exe（GUI 子系统，无黑框）
;
; fftp-http 自身不注册为服务：由快捷方式按用户身份按需启动，
; 这样空闲自动关闭无需管理员权限，且退出后不会被 SCM 拉起。

Unicode true
SetCompressor /SOLID lzma
SetCompressorDictSize 32

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!ifndef APP_VERSION
  !define APP_VERSION "0.1.0"
!endif
!ifndef DIST_DIR
  !define DIST_DIR "dist/x86_64-pc-windows-gnu"
!endif
!ifndef OUT_DIR
  !define OUT_DIR "dist"
!endif
!ifndef REPO_ROOT
  !define REPO_ROOT "."
!endif

!define APP_NAME "FFTPS Web 管理"
!define APP_PUBLISHER "fftps developers"
!define APP_URL "https://github.com/fftps/fftps"
!define SERVICE_NAME "fftpd"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\FFTPS"

Name "${APP_NAME}"
OutFile "${OUT_DIR}/fftps-http-${APP_VERSION}-windows-x86_64-setup.exe"
InstallDir "$PROGRAMFILES64\fftps"
InstallDirRegKey HKLM "${UNINST_KEY}" "InstallLocation"
RequestExecutionLevel admin
BrandingText "${APP_NAME} ${APP_VERSION}"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_TITLE "${APP_NAME} 安装完成"
!define MUI_FINISHPAGE_TEXT "fftpd 已注册为开机自启服务。$\r$\n$\r$\n点击桌面/开始菜单中的「FFTPS Web 管理」即可启动 Web 服务并在浏览器中打开。首次启动会进入本机初始化向导。$\r$\n$\r$\n配置文件位于：$APPDATA\fftpd"
!define MUI_FINISHPAGE_TEXT_LARGE
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "FFTPS 仅提供 64 位 Windows 版本。"
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

Section "FFTPS" SecMain
  SetShellVarContext all
  SetRegView 64
  SetOutPath "$INSTDIR"
  File "${DIST_DIR}/fftpd.exe"
  File "${DIST_DIR}/fftp-http.exe"
  File "${DIST_DIR}/fftp-http-launcher.exe"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; ---------- 配置模板（仅首次安装时预置） ----------
  CreateDirectory "$APPDATA\fftpd"
  CreateDirectory "$APPDATA\fftpd\logs"
  SetOutPath "$PLUGINSDIR"
  ${IfNot} ${FileExists} "$APPDATA\fftpd\config.toml"
    File /oname=config.toml "${REPO_ROOT}/debian/config_example.toml"
    CopyFiles /SILENT "$PLUGINSDIR\config.toml" "$APPDATA\fftpd\config.toml"
  ${EndIf}
  ${IfNot} ${FileExists} "$APPDATA\fftpd\fftp-http.toml"
    File /oname=fftp-http.toml "${REPO_ROOT}/examples/fftp-http.toml.example"
    CopyFiles /SILENT "$PLUGINSDIR\fftp-http.toml" "$APPDATA\fftpd\fftp-http.toml"
  ${EndIf}
  ; 允许普通用户维护配置/日志（服务与按需前端均需写入）
  nsExec::ExecToLog 'icacls "$APPDATA\fftpd" /grant *S-1-5-32-545:(OI)(CI)M /T /C'

  ; ---------- 注册 fftpd 自动服务 ----------
  nsExec::ExecToStack 'sc.exe query ${SERVICE_NAME}'
  Pop $0
  ${If} $0 == 0
    nsExec::ExecToLog 'sc.exe stop ${SERVICE_NAME}'
    Sleep 1500
    nsExec::ExecToLog 'sc.exe delete ${SERVICE_NAME}'
    Sleep 1500
  ${EndIf}
  ; 内层 \" 由 sc.exe 的 Windows 命令行解析保留，确保带空格的安装路径
  ; 以引号形式写入 SCM（等价于旧 cmd 脚本的 binPath= "\"..\fftpd.exe\" --service"）
  nsExec::ExecToLog 'sc.exe create ${SERVICE_NAME} binPath= "\"$INSTDIR\fftpd.exe\" --service" DisplayName= "fftps FTP/SFTP Server" start= auto'
  nsExec::ExecToLog 'sc.exe start ${SERVICE_NAME}'

  ; ---------- 快捷方式 ----------
  CreateShortcut "$DESKTOP\FFTPS Web 管理.lnk" "$INSTDIR\fftp-http-launcher.exe" "" "$INSTDIR\fftp-http.exe" 0
  CreateDirectory "$SMPROGRAMS\FFTPS"
  CreateShortcut "$SMPROGRAMS\FFTPS\FFTPS Web 管理.lnk" "$INSTDIR\fftp-http-launcher.exe" "" "$INSTDIR\fftp-http.exe" 0
  CreateShortcut "$SMPROGRAMS\FFTPS\卸载 FFTPS.lnk" "$INSTDIR\uninstall.exe"

  ; ---------- 卸载信息 ----------
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" "${APP_URL}"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" 12000
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64

  ; 先停前端用户进程，再停后端服务
  nsExec::ExecToLog 'taskkill /F /IM fftp-http.exe'
  nsExec::ExecToLog 'taskkill /F /IM fftp-http-launcher.exe'
  nsExec::ExecToLog 'sc.exe stop ${SERVICE_NAME}'
  Sleep 1500
  nsExec::ExecToLog 'sc.exe delete ${SERVICE_NAME}'
  Sleep 1500

  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 \
    "是否同时删除配置、用户库与日志？$\r$\n$\r$\n位置：$APPDATA\fftpd$\r$\n选择「否」将保留这些数据，便于以后重新安装。" \
    IDNO keep_data
  RMDir /r "$APPDATA\fftpd"
keep_data:

  Delete "$INSTDIR\fftpd.exe"
  Delete "$INSTDIR\fftp-http.exe"
  Delete "$INSTDIR\fftp-http-launcher.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$DESKTOP\FFTPS Web 管理.lnk"
  Delete "$SMPROGRAMS\FFTPS\FFTPS Web 管理.lnk"
  Delete "$SMPROGRAMS\FFTPS\卸载 FFTPS.lnk"
  RMDir "$SMPROGRAMS\FFTPS"

  DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd
