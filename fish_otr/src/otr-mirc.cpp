#include "mirc-otr-internal.h"
#include "fish-inject-engine.h"
#include "mircdll.h"
#include "otr-engine.h"


static void ExtractNetworkName(const POTRConnection& otrConnection, const char* a_start)
{
	const char *network = strstr(a_start, " NETWORK=");

	if (network)
	{
		char network_name[100] = { 0 };

		if (sscanf_s(network + 1, "NETWORK=%99s", network_name, 99) == 1)
		{
			otrConnection->SetNetworkName(network_name);
		}
	}
}


/* called from fish_inject.dll */
char* _OnIncomingIRCLine(HANDLE a_socket, const char* a_line, size_t a_len)
{
	if (!a_socket || !a_line || a_len < 1 || (*a_line != ':' && *a_line != '@'))
		return nullptr;

	POTRConnection otrConnection = CMIRCOTR::Instance()->ConnectionManager()->FindBySocket(a_socket);

	if (!otrConnection)
		return nullptr;

	// handle message tags:
	// ( http://ircv3.atheme.org/specification/message-tags-3.2 )
	bool l_hasMsgTag = (*a_line == '@');
	const char *l_afterMsgTag = a_line;

	if (l_hasMsgTag)
	{
		const char *p = strstr(a_line, " :");

		if (!p)
			return nullptr;

		l_afterMsgTag = p + 1;
	}

	if (strstr(l_afterMsgTag, " ") == strstr(l_afterMsgTag, " 005 "))
	{
		ExtractNetworkName(otrConnection, l_afterMsgTag);

		return nullptr;
	}

	if (!otrConnection->InWorkingOrder())
		return nullptr;

	// back up message tag, then process without it:
	std::string l_tag;
	std::string l_line;

	if (l_hasMsgTag)
	{
		l_tag = std::string(a_line, static_cast<size_t>(l_afterMsgTag - a_line));
		l_line = std::string(l_afterMsgTag, a_len - l_tag.size());
	}
	else
	{
		l_line = std::string(a_line, a_len);
	}

	std::string l_cmd, l_contact, l_message;
	std::string::size_type l_cmdPos, l_tmpPos, l_msgPos;

	l_cmdPos = l_line.find(' ');
	if (l_cmdPos != std::string::npos)
	{
		while (l_line[l_cmdPos] == ' ') l_cmdPos++;
		l_tmpPos = l_line.find(' ', l_cmdPos);

		if (l_tmpPos != std::string::npos)
		{
			while (l_line[l_tmpPos + 1] == ' ') l_tmpPos++;
			l_cmd = l_line.substr(l_cmdPos, l_tmpPos - l_cmdPos);

			l_msgPos = l_line.find(" :", l_tmpPos + 1);

			if (l_msgPos != std::string::npos)
			{
				l_msgPos += 2;
				l_message = l_line.substr(l_msgPos);
			}
		}
	}

	if (l_cmd.empty() || l_message.empty())
		return nullptr;

	if (_stricmp(l_cmd.c_str(), "PRIVMSG") && _stricmp(l_cmd.c_str(), "NOTICE"))
		return nullptr;

	/*if (!strncmp(l_message.c_str(), "?OTR", 4))
		return nullptr;*/

	l_contact = l_line.substr(l_tmpPos + 1, l_msgPos - 2 - l_tmpPos - 1);



	return nullptr;
}


/* called from fish_inject.dll */
char* _OnOutgoingIRCLine(HANDLE a_socket, const char* a_line, size_t a_len)
{
	if (!a_socket || !a_line || a_len < 1)
		return nullptr;

	POTRConnection otrConnection = CMIRCOTR::Instance()->ConnectionManager()->FindBySocket(a_socket);

	if (!otrConnection)
		return nullptr;

	if (strncmp(a_line, "FiSH_OTR_USERDATA_SET ", 22) == 0)
	{
		if (int mirc_connection_id = atoi(a_line + 22))
		{
			otrConnection->SetMIRCConnectionID(mirc_connection_id);

			CMIRCOTR::Instance()->ConnectionManager()->SetCid(otrConnection, mirc_connection_id);
		}

		return new char[1]{0};
	}

	// use the first (and only the first) nickname that is sent as account name:
	if (!otrConnection->IsUserAccountNameSet() && strncmp(a_line, "NICK ", 5) == 0)
	{
		char acc_name[100] = { 0 };

		if (sscanf_s(a_line, "NICK %99s", acc_name, 99) == 1) // trim trailing whitespace
		{
			otrConnection->SetAccountUserName(acc_name);
		}

		return nullptr;
	}

	if (!otrConnection->InWorkingOrder())
		return nullptr;

	if (!_strnicmp(a_line, "PRIVMSG ", 8))
		;
	else if (!_strnicmp(a_line, "NOTICE ", 7))
		;
	else
		return nullptr;

	// split line:
	const std::string l_line(a_line, a_len);
	std::string::size_type l_targetPos = l_line.find(' ') + 1,
		l_msgPos = l_line.find(" :", l_targetPos);

	if (l_msgPos == std::string::npos)
		return nullptr; // "should never happen"

	const std::string l_target = l_line.substr(l_targetPos, l_msgPos - l_targetPos);
	std::string l_message = l_line.substr(l_msgPos + 2);

	otrConnection->LibOtrSending(l_target, l_message);

	return nullptr;
}


/* called from fish_inject.dll */
void _FreeString(const char* a_str)
{
	delete[] a_str;
}


/* called from fish_inject.dll */
void _OnSocketClosed(HANDLE a_socket)
{
	CMIRCOTR::Instance()->ConnectionManager()->RemoveConnection(a_socket);
}


/* engine struct for fish_inject.dll */

DECLARE_FISH_INJECT_ENGINE(g_engine_export, _OnIncomingIRCLine, _OnOutgoingIRCLine, _OnSocketClosed, _FreeString, false, "OTR")

CMIRCOTR* CMIRCOTR::ms_instance = nullptr;


/* mIRC interface to keep DLL loaded */

MIRC_EXPORT_SIG(void) LoadDll(LOADINFO* info)
{
	info->mKeep = TRUE; // always keep to avoid possible error messages from showing up again and again.

	CMIRCOTR* global = CMIRCOTR::Create(info->mHwnd, &g_engine_export);

	if (!global->RegisterFishEngine())
	{
		::MessageBoxW(info->mHwnd, L"OTR: failed to register engine w/ inject component!", L"This is likely a bug", MB_ICONERROR | MB_OK);

		global->SetFailedInit();
	}
	else if (!COTREngine::InitLibrary())
	{
		::MessageBoxW(info->mHwnd, L"OTR: initializing libotr failed!", L"This is likely a bug", MB_ICONERROR | MB_OK);

		global->SetFailedInit();
	}

	// ??? /echo -ntc Notify nnnn * OTR: Test
}

MIRC_EXPORT_SIG(int) UnloadDll(int mTimeout)
{
	if (mTimeout != 1) // unload due to timeout is not acceptable.
	{
		CMIRCOTR::Destroy();
	}
	
	return 0;
}


/* call for mIRC to show compililation date */

MIRC_DLL_EXPORT(_callMe)
{
	strcpy_s(data, MIRC_PARAM_DATA_LENGTH, "/echo -a *** FiSH-OTR \xA0*** by flakes *** fish_otr.dll\xA0\xA0\xA0\xA0""compiled " __DATE__ " " __TIME__ " ***");

	return MIRC_RET_DATA_COMMAND;
}


/* call for mIRC to set path for key files */

MIRC_DLL_EXPORT(mIRC_OTR_SetKeyDir)
{
	wchar_t wpath[MIRC_PARAM_DATA_LENGTH + 1] = { 0 };

	::MultiByteToWideChar(CP_UTF8, 0, data, -1, wpath, MIRC_PARAM_DATA_LENGTH);

	if (::PathIsDirectoryW(wpath))
	{
		::PathAddBackslashW(wpath);

		CMIRCOTR::Instance()->SetKeyDir(wpath);

		return MIRC_RET_CONTINUE;
	}

	return MIRC_RET_HALT;
}


/* dummy DllMain */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return TRUE;
}
