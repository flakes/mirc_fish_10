#include "mirc-otr-internal.h"
#include "mircdll.h"
#include "libotr-wrap.h"
#include <string>

MIRC_DLL_EXPORT(mIRC_OTR_Version)
{
	std::string ss = "*** FiSH-OTR *** fish_otr.dll compiled " __DATE__ " " __TIME__ " | libotr ";
	ss.append(w_otrl_version());

	strcpy_s(data, MIRC_PARAM_DATA_LENGTH, ss.c_str());

	return MIRC_RET_DATA_RETURN;
}

MIRC_DLL_EXPORT(mIRC_OTR_GenPrivKey)
{
	int cid = 0;

	//
	// This must be run like so:
	//		$dllcall(%OTR_dll, xxx, mIRC_OTR_GenPrivKey, $cid)
	//
	// Expecting to be in a background thread (started by mIRC itself) here.
	//

	if (sscanf_s(data, "%d", &cid) != 1)
		return MIRC_RET_HALT;

	POTRConnection otrConnection = CMIRCOTR::Instance()->ConnectionManager()->FindByCid(cid);

	if (!otrConnection || !otrConnection->InWorkingOrder())
		return MIRC_RET_HALT; // -TODO- error message

	if (otrConnection->GeneratePrivKeyBlocking())
	{
		// -TODO- success
	}
	else
	{
		// -TODO- error message
	}

	return MIRC_RET_CONTINUE;
}

MIRC_DLL_EXPORT(mIRC_OTR_Init)
{
	int cid = 0;
	char nickname[MAX_NICKNAME_LENGTH + 1] = {0};

	if (sscanf_s(data, "%d %s", &cid, nickname, MAX_NICKNAME_LENGTH) != 2)
		return MIRC_RET_HALT;

	POTRConnection otrConnection = CMIRCOTR::Instance()->ConnectionManager()->FindByCid(cid);

	if (!otrConnection)
		return MIRC_RET_HALT; // -TODO- error message
	
	// -TODO- check if already encrypted, OTRL_MSGSTATE_ENCRYPTED

	sprintf_s(data, MIRC_PARAM_DATA_LENGTH, "/say ?OTRv23?"
		" - $me has requested an Off-the-Record encrypted conversation. However, if you can read this message, you do not have a plugin to support OTR. See https://otr.im for more information.");

	return MIRC_RET_DATA_COMMAND;
}
