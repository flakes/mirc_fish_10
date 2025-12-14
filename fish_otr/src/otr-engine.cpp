#include "mirc-otr-internal.h"
#include "otr-engine.h"

bool COTREngine::InitLibrary()
{
	if (ms_libraryInitialized)
	{
		return true;
	}

	// the version check probably does not make a lot of sense,
	// but apparently some initialization is performed by the call as well.

	if (!gcry_check_version(GCRYPT_VERSION))
	{
		return false;
	}

	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0); // <--
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	// gcrypt 1.6 does no longer use thread callbacks, so there is no need to initialize those.
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	ms_libraryInitialized = (w_otrl_init() == 0);

	return ms_libraryInitialized;
}

bool COTREngine::ms_libraryInitialized = false;
