; FFTPS Windows 安装向导（Inno Setup 6.7）
;
; 由 scripts/build-inno.sh 编译：构建脚本会把本文件、二进制、配置模板与
; LICENSE 复制到临时暂存目录，生成 defines.iss（Version / ArchLabel /
; VersionInfo，arm64 时另加 IsArm64），并为本文件补 UTF-8 BOM 后调用 ISCC。
; 因此不要直接用 Inno IDE 编译部署目录里的本文件。
;
; 安装语义（与 deploy/windows/install.bat、fftps.wxs 对齐）：
;   - %ProgramFiles%\fftps\{fftpd,fftp-http,fftp-http-launcher}.exe
;   - fftpd 注册 SCM 自启服务（binPath 附带 --service 参数）
;   - %ProgramData%\fftpd 下配置模板（仅首次预置，Users 组可写）
;   - 桌面/开始菜单快捷方式 → fftp-http-launcher.exe
;   - 卸载经「设置 → 应用」标准入口；可选删除配置/日志/用户数据

#include "defines.iss"

[Setup]
AppId={{7C4E9A2B-1D5F-4B83-9E6A-3C8F2D5B7A41}
AppName=FFTPS
AppVerName=FFTPS {#Version}
AppVersion={#Version}
AppPublisher=fftps developers
AppPublisherURL=https://github.com/fftps/fftps
AppSupportURL=https://github.com/fftps/fftps
AppUpdatesURL=https://github.com/fftps/fftps
AppCopyright=GPL-3.0
DefaultDirName={autopf}\fftps
DefaultGroupName=FFTPS
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
UsePreviousAppDir=yes
UsePreviousTasks=yes
OutputDir=.
OutputBaseFilename=fftps-{#Version}-windows-{#ArchLabel}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
CloseApplications=no
RestartApplications=no
UninstallDisplayName=FFTPS
UninstallDisplayIcon={app}\fftp-http-launcher.exe
VersionInfoVersion={#VersionInfo}
VersionInfoDescription=FFTPS Setup
VersionInfoCompany=fftps developers
VersionInfoCopyright=GPL-3.0
LicenseFile=LICENSE.txt
MinVersion=10.0

; 每个架构一个安装包：x64 包严格拒绝 ARM64（避免误装 x64 模拟版），
; arm64 包只允许 ARM64。
#ifdef IsArm64
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
#endif

[Languages]
; 简体中文语言文件随仓库 vendored（deploy/windows/languages/ChineseSimplified.isl，
; 取自 Inno Setup 6.7.4 源码 Files/Languages/Unofficial/）。build-inno.sh 会把它
; 暂存到脚本同目录的 languages\ 下，这里以相对路径引用，不依赖本地 Inno 安装
; 是否自带中文语言包（6.7.4 把中文放在 Languages\Unofficial\，路径并不稳定）。
Name: "chinesesimplified"; MessagesFile: "languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "fftpd.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "fftp-http.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "fftp-http-launcher.exe"; DestDir: "{app}"; Flags: ignoreversion
; 配置模板只首次预置；用户改过的文件在升级/重装时保留
Source: "config.toml"; DestDir: "{commonappdata}\fftpd"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "fftp-http.toml"; DestDir: "{commonappdata}\fftpd"; Flags: onlyifdoesntexist uninsneveruninstall

[Dirs]
; Users 组可写：服务（LocalSystem）与按需前端（普通用户）共同维护配置/日志
Name: "{commonappdata}\fftpd"; Permissions: users-modify; Flags: uninsneveruninstall
Name: "{commonappdata}\fftpd\logs"; Permissions: users-modify; Flags: uninsneveruninstall

[Icons]
Name: "{autoprograms}\FFTPS\FFTPS"; Filename: "{app}\fftp-http-launcher.exe"; WorkingDir: "{app}"
Name: "{autoprograms}\FFTPS\{cm:UninstallProgram,FFTPS}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\FFTPS"; Filename: "{app}\fftp-http-launcher.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\fftp-http-launcher.exe"; Description: "{cm:LaunchProgram,FFTPS}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[InstallDelete]
; 清理旧 zip 安装器（install.ps1）留在程序目录的脚本
Type: files; Name: "{app}\install.bat"
Type: files; Name: "{app}\install.ps1"
Type: files; Name: "{app}\uninstall.bat"
Type: files; Name: "{app}\uninstall.ps1"

[Registry]
; 旧 zip 安装器写入的 ARP 入口（Inno 使用自己的 {GUID}_is1 卸载键）
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FFTPS"; Flags: deletekey

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
const
  ServiceName = 'fftpd';

var
  DeleteUserData: Boolean;

function RunHidden(const FileName, Params: String; var ResultCode: Integer): Boolean;
begin
  Result := Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function StopAndDeleteService(): Boolean;
var
  I, ResultCode: Integer;
begin
  ResultCode := 0;
  { net stop 会等待服务真正停止；未安装/未启动时返回非 0，忽略 }
  RunHidden(ExpandConstant('{sys}\net.exe'), 'stop ' + ServiceName + ' /y', ResultCode);
  { 兜底：防止服务进程仍占用 fftpd.exe 导致升级覆盖失败 }
  RunHidden(ExpandConstant('{sys}\taskkill.exe'), '/F /IM fftpd.exe', ResultCode);
  Sleep(1000);

  { sc delete：1072 = 标记删除中，等待重试；1060 = 不存在，视为成功 }
  Result := False;
  for I := 1 to 10 do
  begin
    if RunHidden(ExpandConstant('{sys}\sc.exe'), 'delete ' + ServiceName, ResultCode)
       and ((ResultCode = 0) or (ResultCode = 1060)) then
    begin
      Result := True;
      Exit;
    end;
    Sleep(1000);
  end;
  Log('sc delete fftpd failed, last result code: ' + IntToStr(ResultCode));
end;

function CreateAndStartService(): Boolean;
var
  I, ResultCode: Integer;
  Params: String;
  ExePath: String;
begin
  ResultCode := 0;
  ExePath := ExpandConstant('{app}\fftpd.exe');
  { 等价于 install.bat 的 sc create；binPath 整体加引号并转义内层引号 }
  Params := 'create ' + ServiceName + ' binPath= ' + #34 + '\' + #34 + ExePath + '\' + #34 +
            ' --service' + #34 + ' DisplayName= ' + #34 + 'FFTPS FTP/SFTP Server' + #34 +
            ' start= auto';

  Result := False;
  for I := 1 to 10 do
  begin
    if RunHidden(ExpandConstant('{sys}\sc.exe'), Params, ResultCode) and (ResultCode = 0) then
    begin
      RunHidden(ExpandConstant('{sys}\sc.exe'),
        'description ' + ServiceName + ' ' + #34 + 'FFTPS FTP/SFTP Server (auto start)' + #34,
        ResultCode);
      { 1062 = 已在运行，忽略 }
      RunHidden(ExpandConstant('{sys}\sc.exe'), 'start ' + ServiceName, ResultCode);
      Result := True;
      Exit;
    end;

    { 1073 = 服务已存在：先删掉再重试 }
    if ResultCode = 1073 then
    begin
      RunHidden(ExpandConstant('{sys}\sc.exe'), 'delete ' + ServiceName, ResultCode);
      Sleep(1000);
    end
    else
      Sleep(1000);
  end;
  Log('sc create fftpd failed, last result code: ' + IntToStr(ResultCode));
end;

procedure KillFrontendProcesses();
var
  ResultCode: Integer;
begin
  RunHidden(ExpandConstant('{sys}\taskkill.exe'), '/F /IM fftp-http.exe', ResultCode);
  RunHidden(ExpandConstant('{sys}\taskkill.exe'), '/F /IM fftp-http-launcher.exe', ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;
  KillFrontendProcesses();
  if not StopAndDeleteService() then
    Result := '无法停止/删除旧的 fftpd 服务。请先以管理员身份执行：' + #13#10 +
              'sc stop fftpd' + #13#10 +
              'sc delete fftpd' + #13#10 +
              '然后重新运行安装程序。';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not CreateAndStartService() then
      MsgBox('fftpd 服务注册失败。请以管理员身份手动注册服务，或查看安装日志。',
             mbError, MB_OK);
  end;
end;

function InitializeUninstall(): Boolean;
var
  Answer: Integer;
begin
  Result := True;
  DeleteUserData := False;

  if not UninstallSilent then
  begin
    Answer := MsgBox(
      '是否同时删除配置、用户库与日志？' + #13#10 +
      '位置：' + ExpandConstant('{commonappdata}\fftpd') + #13#10 +
      '选择“否”将保留数据，便于以后重装。',
      mbConfirmation, MB_YESNO);
    DeleteUserData := (Answer = IDYES);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    KillFrontendProcesses();
    StopAndDeleteService();
    if DeleteUserData then
      DelTree(ExpandConstant('{commonappdata}\fftpd'), True, True, True);
  end;
end;
