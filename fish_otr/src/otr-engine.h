#pragma once

#include <string>
#include <memory>
#include "otr-connection.h"

class COTREngine
{
public:
	//
	// note: un-initializing the library is not supported.
	//
	static bool InitLibrary();

	static const OtrlMessageAppOps* GetOps() { return &ms_opsCallbacks; }

private:
	static bool ms_libraryInitialized;
	static OtrlMessageAppOps ms_opsCallbacks;
};
