#include "inject-main.h"
#include "inject-engines.h"
#include "Shlwapi.h"

#pragma comment(lib, "Shlwapi")

static HMODULE LoadLibraryFromSameDirectory(const std::wstring& a_dllName)
{
	HMODULE hLib = NULL;
	wchar_t wszBuf[1000] = { 0 };

	if (::GetModuleHandleW(a_dllName.c_str()))
	{
		hLib = ::GetModuleHandleW(a_dllName.c_str());
	}
	else if (::GetModuleFileNameW(g_hModule, wszBuf, 999) || ::GetModuleFileNameW(NULL, wszBuf, 999))
	{
		std::wstring dll_path;

		::PathRemoveFileSpecW(wszBuf);
		::PathAddBackslashW(wszBuf);

		dll_path.append(wszBuf);
		dll_path.append(a_dllName);

		hLib = ::LoadLibraryW(dll_path.c_str());
	}

	return hLib;
}


bool CInjectEngines::LoadRegister(const std::wstring& a_dllName)
{
	// get default fish_10 engine:
	HMODULE hLib = LoadLibraryFromSameDirectory(a_dllName);
	bool ok = false;

	if (hLib)
	{
		Get_FiSH_Inject_Engine_Function engine_export_function = (Get_FiSH_Inject_Engine_Function)
			::GetProcAddress(hLib, FISH_INJECT_ENGINE_EXPORT_NAME);

		if (engine_export_function)
		{
			const fish_inject_engine_t* pEngine = engine_export_function();

			if (pEngine && pEngine->version == FISH_INJECT_ENGINE_VERSION)
			{
				CSimpleScopedLock lock(m_engineListAccess);

				m_engines.push_back(TEngine(hLib, pEngine));

				ok = true;
			}
		}
	}

	if (!ok)
	{
		::FreeLibrary(hLib);
	}

	return ok;
}


bool CInjectEngines::OnOutgoingLine(SOCKET socket, std::string& a_line) const
{
	// attention, not currently thread safe
	// ( m_engineListAccess would unnecessarily block all sockets )

	bool modified = false;

	for (const auto& engine : m_engines)
	{
		char *engine_result = engine.second->OnOutgoingIRCLine((HANDLE)socket, a_line.c_str(), a_line.size());

		if (engine_result)
		{
			a_line = engine_result; // ~ avoid additional copy to local var

			engine.second->FreeString(engine_result);

			modified = true;
		}
	}

	return modified;
}


bool CInjectEngines::OnIncomingLine(SOCKET socket, std::string& a_line) const
{
	// attention, not currently thread safe
	// ( m_engineListAccess would unnecessarily block all sockets )

	bool modified = false;

	for (const auto& engine : m_engines)
	{
		char *engine_result = engine.second->OnIncomingIRCLine((HANDLE)socket, a_line.c_str(), a_line.size());

		if (engine_result)
		{
			a_line = engine_result; // ~ avoid additional copy to local var

			engine.second->FreeString(engine_result);

			modified = true;
		}
	}

	return modified;
}


void CInjectEngines::OnSocketClosed(SOCKET socket) const
{
	// attention, not currently thread safe
	// ( m_engineListAccess would unnecessarily block all sockets )

	for (const auto& engine : m_engines)
	{
		engine.second->OnSocketClosed((HANDLE)socket);
	}
}


CInjectEngines::~CInjectEngines()
{
	CSimpleScopedLock lock(m_engineListAccess);

	for (const auto& engine : m_engines)
	{
		::FreeLibrary(engine.first);
	}
}
