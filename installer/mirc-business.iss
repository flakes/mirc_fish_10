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

procedure EnableMIRCScriptFile(filename: String);
var
	ini: String;
	tmp: String;
	i: Integer;
begin
	ini := GetMIRCIniPath();

	if IsIniSectionEmpty('rfiles', ini) then
	begin
		SetIniString('rfiles', 'n0', filename, ini);
		exit;
	end;

	i := 0;

	while i <= 999 do
	begin
		tmp := GetIniString('rfiles', 'n' + IntToStr(i), '', ini);

		if LowerCase(tmp) = LowerCase(filename) then
			break;

		if tmp = '' then
		begin
			SetIniString('rfiles', 'n' + IntToStr(i), filename, ini);
			break;
		end;

		i := i + 1;
	end;
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
