#include "inject-main.h"
#include "inject-engines.h"
#include "Shlwapi.h"

#pragma comment(lib, "Shlwapi")

static HMODULE LoadLibraryFromSameDirectory(const std::wstring& a_dllName)
{
	HMODULE hLib = nullptr;
	wchar_t wszBuf[1000] = { 0 };

	if (::GetModuleFileNameW(g_hModule, wszBuf, 999) || ::GetModuleFileNameW(nullptr, wszBuf, 999))
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


bool CInjectEngines::Register(HMODULE hLib, const fish_inject_engine_t* pEngine)
{
	Unregister(pEngine); // make sure no engine is loaded twice

	if (pEngine && pEngine->version == FISH_INJECT_ENGINE_VERSION)
	{
		m_engineListAccess.EnterWriter();

		m_engines.push_back(TEngine(hLib, pEngine));

		m_engineListAccess.LeaveWriter();

		return true;
	}

	return false;
}


bool CInjectEngines::Unregister(const fish_inject_engine_t* pEngine)
{
	m_engineListAccess.EnterWriter();

	for (TEngineList::iterator it = m_engines.begin(); it != m_engines.end(); ++it)
	{
		if (it->second == pEngine)
		{
			m_engines.erase(it);

			m_engineListAccess.LeaveWriter();

			return true;
		}
	}

	m_engineListAccess.LeaveWriter();

	return false;
}


bool CInjectEngines::OnOutgoingLine(SOCKET socket, std::string& a_line) const
{
	m_engineListAccess.EnterReader();

	bool modified = false;

	for (const auto& engine : m_engines)
	{
		if (!engine.second->is_postprocessor && modified)
		{
			continue;
		}

		char *engine_result = engine.second->OnOutgoingIRCLine((HANDLE)socket, a_line.c_str(), a_line.size());

		if (engine_result)
		{
			a_line = engine_result; // ~ avoid additional copy to local var

			engine.second->FreeString(engine_result);

			modified = true;
		}
	}

	m_engineListAccess.LeaveReader();

	return modified;
}


bool CInjectEngines::OnIncomingLine(SOCKET socket, std::string& a_line) const
{
	m_engineListAccess.EnterReader();

	bool modified = false;

	for (const auto& engine : m_engines)
	{
		if (!engine.second->is_postprocessor && modified)
		{
			continue;
		}

		char *engine_result = engine.second->OnIncomingIRCLine((HANDLE)socket, a_line.c_str(), a_line.size());

		if (engine_result)
		{
			a_line = engine_result; // ~ avoid additional copy to local var

			engine.second->FreeString(engine_result);

			modified = true;
		}
	}

	m_engineListAccess.LeaveReader();

	return modified;
}


void CInjectEngines::OnSocketClosed(SOCKET socket) const
{
	m_engineListAccess.EnterReader();

	for (const auto& engine : m_engines)
	{
		engine.second->OnSocketClosed((HANDLE)socket);
	}

	m_engineListAccess.LeaveReader();
}


std::string CInjectEngines::GetEngineList() const
{
	std::string result;

	m_engineListAccess.EnterReader();

	for (const auto& engine : m_engines)
	{
		result += "[" + std::string(engine.second->engine_name) + "]";
	}

	m_engineListAccess.LeaveReader();

	return result;
}


CInjectEngines::~CInjectEngines()
{
	m_engineListAccess.EnterWriter();

	for (const auto& engine : m_engines)
	{
		if (engine.first)
		{
			::FreeLibrary(engine.first);
		}
	}

	m_engines.clear();

	m_engineListAccess.LeaveWriter();
}
