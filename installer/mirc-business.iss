[code]

function GetMIRCExeDir(): String;
begin
	Result := mIRCDirPage.Values[0];
end;

function GetMIRCIniDirectory(): String;
begin
	Result := '';

	if FileExists(GetMIRCExeDir() + '\mirc.ini') then
	begin
		if LowerCase(GetIniString('about', 'portable', 'yes', GetMIRCExeDir() + '\mirc.ini')) = 'yes' then
		begin
			Result := GetMIRCExeDir();
			exit;
		end;
	end;

	if FileExists(ExpandConstant('{userappdata}\mIRC\mirc.ini')) then
	begin
		if LowerCase(GetIniString('about', 'portable', 'yes', ExpandConstant('{userappdata}\mIRC\mirc.ini'))) = 'yes' then
		begin
			// doesn't make any sense!
			exit;
		end
		else
		begin
			Result := ExpandConstant('{userappdata}\mIRC');
		end;
	end;
end;

function GetMIRCIniPath(): String;
begin
	Result := GetMIRCIniDirectory() + '\mirc.ini';
end;

function IsPortableInstall(): Boolean;
begin
	Result := (LowerCase(GetIniString('about', 'portable', 'yes', GetMIRCIniPath())) = 'yes');
end;

function HasMIRCNeverBeenStarted(): Boolean;
begin
	Result := IsIniSectionEmpty('rfiles', GetMIRCIniPath());
end;

procedure EnableMIRCScriptFile(filename: String);
var
	ini: String;
	tmp: String;
	i: Integer;
begin
	if HasMIRCNeverBeenStarted() then
		exit;

	ini := GetMIRCIniPath();

	i := 0;

	while i <= 999 do
	begin
		tmp := GetIniString('rfiles', 'n' + IntToStr(i), '', ini);

		if (CompareText(tmp, filename) = 0) then
			break;

		if (tmp = '') or (CompareText(ExtractFileName(tmp), filename) = 0) then
		begin
			// change absolute paths to relative.

			SetIniString('rfiles', 'n' + IntToStr(i), filename, ini);
			break;
		end;

		i := i + 1;
	end;
end;

procedure SwitchOpenSSLModeToDLLs();
var
	ini: String;
begin
	ini := GetMIRCIniPath();

	SetIniString('ssl', 'load', '1', ini);
end;

function GetMIRCVersion(): String;
var
	VersStr: String;
begin
	Result := '';

	if GetVersionNumbersString(GetMIRCExeDir() + '\mirc.exe', VersStr) then
	begin
		if Length(VersStr) > 4 then
			SetLength(VersStr, 4);
		Result := VersStr;
	end;
end;

function CheckBlowIni(): Boolean;
var
	ini: String;
begin
	ini := GetMIRCIniDirectory() + '\blow.ini';

	Result := True;

	if FileExists(ini) then
	begin
		// if blow.ini doesn't exist, a valid version will be installed.

		if (GetIniInt('FiSH', 'process_incoming', 0, 0, 1, ini) <> 1)
			or (GetIniInt('FiSH', 'process_outgoing', 0, 0, 1, ini) <> 1) then
		begin
			Result := False;
		end;

		if Result and (not IsPortableInstall()) and FileExists(GetMIRCExeDir() + '\blow.ini')
			and FileExists(ExpandConstant('{userappdata}\mIRC\blow.ini')) then
		begin
			// two blow.inis can be confusing!
			Result := False;
		end;
	end;
end;
