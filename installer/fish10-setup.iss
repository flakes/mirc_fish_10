#define ReleaseDir "..\Release"
#define OpenSSLVer GetStringFileInfo(ReleaseDir + "\libssl-3.dll", "ProductVersion")
#define BuildTime GetFileDateTimeString(ReleaseDir + "\fish_10.dll", 'yyyy/mm/dd hh:nn:ss', '-', ':')
#define SetupBuildDate GetFileDateTimeString(ReleaseDir + "\fish_10.dll", 'yyyy/mm/dd', '-', ':')
#define SetupBuildDateMachine GetFileDateTimeString(ReleaseDir + "\fish_10.dll", 'yyyy/mm/dd', '.', ':')
#define SetupBuildDateYear GetFileDateTimeString(ReleaseDir + "\fish_10.dll", 'yyyy', '.', ':')

[Setup]
AppId={{cb634ee1-f9f8-4236-b2ae-dc9912d30d72}
AppName=FiSH 10
AppVerName=FiSH 10 ({#SetupBuildDate}) for mIRC 7
AppVersion={#SetupBuildDateMachine}
AppPublisher=flakes
AppCopyright=© flakes 2010-{#SetupBuildDateYear}
VersionInfoVersion={#SetupBuildDateMachine}
MinVersion=6.1sp1
OutputDir={#ReleaseDir}
OutputBaseFilename=mirc_fish_10-setup-{#SetupBuildDate}
DisableWelcomePage=yes
DisableDirPage=yes
DisableProgramGroupPage=yes
AllowCancelDuringInstall=no
; the uninstaller is placed here:
DefaultDirName="{pf}\FiSH 10 Setup"
Uninstallable=not IsPortableInstall()
SolidCompression=yes
LanguageDetectionMethod=none
; save some bytes by using the small image:
WizardImageFile=compiler:WizModernSmallImage.bmp
WizardImageStretch=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#ReleaseDir}\libcrypto-3.dll"; DestDir: "{code:mIRCExeDir}"; Flags: ignoreversion overwritereadonly
Source: "{#ReleaseDir}\libcrypto-legacy.dll"; DestDir: "{code:mIRCExeDir}"; Flags: ignoreversion overwritereadonly
Source: "{#ReleaseDir}\libssl-3.dll"; DestDir: "{code:mIRCExeDir}"; Flags: ignoreversion overwritereadonly
Source: "{#ReleaseDir}\fish_10.dll"; DestDir: "{code:mIRCExeDir}"; Flags: ignoreversion overwritereadonly
Source: "{#ReleaseDir}\fish_inject.dll"; DestDir: "{code:mIRCExeDir}"; Flags: ignoreversion overwritereadonly
Source: "{#ReleaseDir}\README.BLOWINI.txt"; DestDir: "{code:mIRCIniDir}"; Flags: ignoreversion overwritereadonly
Source: "{#ReleaseDir}\blow.ini-EXAMPLE"; DestDir: "{code:mIRCIniDir}"; Flags: ignoreversion overwritereadonly
Source: "{#ReleaseDir}\blow.ini-EXAMPLE"; DestName: "blow.ini"; DestDir: "{code:mIRCIniDir}"; Flags: onlyifdoesntexist uninsneveruninstall
; back up .mrc just in case someone customized it:
Source: "{code:mIRCIniDir}\fish_10.mrc"; DestDir: "{code:mIRCIniDir}"; DestName: "fish_10.mrc.bak"; Flags: external skipifsourcedoesntexist
Source: "{#ReleaseDir}\fish_10.mrc"; DestDir: "{code:mIRCIniDir}"; Flags: ignoreversion overwritereadonly

[InstallDelete]
Type: files; Name: "{code:mIRCExeDir}\libcrypto-1_1.dll"
Type: files; Name: "{code:mIRCExeDir}\libssl-1_1.dll"

[Run]
Filename: "{code:mIRCExeDir}\mirc.exe"; Description: "Launch mIRC now"; Flags: shellexec skipifdoesntexist postinstall skipifsilent

[Code]
var
  mIRCDirPage: TInputDirWizardPage;

function IIf(cond: Boolean; a, b: String): String;
begin
	if cond then
		Result := a
	else
		Result := b;
end;

function DllMsiQueryProductState(const ProductCode: String): Integer; external 'MsiQueryProductStateW@msi.dll stdcall';

function IsMsiInstalled(const ProductCode: String): Boolean;
begin
	Result := (5 = DllMsiQueryProductState(ProductCode));
end;

#include "mirc-business.iss"
#include "compare-version.iss"

// event function
procedure InitializeWizard();
var
	InstalledPath: String;
begin
	mIRCDirPage := CreateInputDirPage(wpWelcome,
	'Select mIRC Install Location',
	'You need to point out your mIRC installation directory to the setup.',
	'Enter your path to mirc.exe here:',
	False,
	'');

	mIRCDirPage.Add('');

	if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\mIRC', 'InstallLocation', InstalledPath) then
	begin
		if not FileExists(InstalledPath + '\mirc.exe') then
			InstalledPath := '';
	end;

	mIRCDirPage.Values[0] := GetPreviousData('mIRCExeDir', InstalledPath);
end;

// scripted constant
function mIRCExeDir(p: String): String;
begin
	Result := GetMIRCExeDir();
end;

// scripted constant
function mIRCIniDir(p: String): String;
begin
	Result := GetMIRCIniDirectory();
end;

// event function
function NextButtonClick(CurPageID: Integer): Boolean;
var
	VersStr: String;
begin
	Result := False;

	if CurPageID = mIRCDirPage.ID then
	begin
		if (GetMIRCExeDir() = '') or (not FileExists(GetMIRCExeDir() + '\mirc.exe')) then
		begin
			MsgBox('mirc.exe could not be found in the given directory!', mbError, MB_OK);
			exit;
		end;

		VersStr := GetMIRCVersion();
		if Length(VersStr) < 2 then
		begin
			MsgBox('mIRC version not recognized - please check mirc.exe!', mbError, MB_OK);
			exit;
		end;

		if (CompareVersion(VersStr, '7.73') < 0) then
		begin
			MsgBox('mIRC version ' + VersStr + ' is not supported, please upgrade to at least version 7.73.', mbError, MB_OK);
			exit;
		end;

		if (GetMIRCIniDirectory() = '') or (not FileExists(GetMIRCIniPath())) then
		begin
			MsgBox('mirc.ini file could not be located!', mbError, MB_OK);
			exit;
		end;

		if HasMIRCNeverBeenStarted() then
		begin
			MsgBox('It looks like mIRC has never been started. Please launch it once, close it again and proceed with this setup.', mbError, MB_OK);
			exit;
		end;
	end;

	Result := True;
end;

// event function
procedure RegisterExtraCloseApplicationsResources;
begin
	RegisterExtraCloseApplicationsResource(False, GetMIRCExeDir() + '\mirc.exe');
end;

// event function
procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
	SetPreviousData(PreviousDataKey, 'mIRCExeDir', GetMIRCExeDir());
end;

// event function
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
	ok, nok: String;
begin
	ok := IIf(GetWindowsVersion() shr 24 >= 6, #$2713, '[+]');
	nok := IIf(GetWindowsVersion() shr 24 >= 6, #$2717, '[!]');

	Result := 'Build time: {#BuildTime}' + NewLine
		+ 'Included OpenSSL version: {#OpenSSLVer}' + NewLine + NewLine
		+ ok + ' mIRC directory: ' + GetMIRCExeDir() + NewLine
		+ ok + ' mIRC settings directory: ' + GetMIRCIniDirectory() + NewLine
		+ ok + ' mIRC portable install: ' + IIf(IsPortableInstall(), 'yes', 'no') + NewLine
		+ ok + ' mIRC version: ' + GetMIRCVersion() + NewLine
		+ IIf(CheckBlowIni(), ok + ' blow.ini sanity check', nok + ' blow.ini sanity check FAILED') + NewLine
		+ NewLine + 'Creating uninstaller: ' + IIf(IsPortableInstall(), 'no', 'yes') + NewLine;
end;

// event function
procedure CurStepChanged(CurStep: TSetupStep);
begin
	if CurStep = ssPostInstall then
	begin
		EnableMIRCScriptFile('fish_10.mrc');
		SwitchOpenSSLModeToDLLs();
	end;
end;

// event function
procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
	Cancel := True;
	Confirm := False;
end;
