#pragma once

#include "targetver.h"
#include "mircsendmessageapi.h"
#include <Windows.h>
#include <Shlwapi.h>
#include <string>
#include <memory>

#define MAX_NICKNAME_LENGTH 64

#include "fish-inject-engine.h"
#include "otr-connection-manager.h"

class CMIRCOTR
{
public:
	static CMIRCOTR* Create(HWND a_hwndMainWindow, const fish_inject_engine_t* a_enginePtr)
	{
		// fuck constructors
		ms_instance = new CMIRCOTR();
		ms_instance->m_hwndMainWindow = a_hwndMainWindow;
		ms_instance->m_fishEngineReg = std::make_shared<CFishEngineRegistration>(a_enginePtr);
		ms_instance->m_connMgr = std::make_shared<COTRConnectionManager>();

		ms_instance->m_sendMessageAPI = std::make_shared<CMIRCSendMessageAPI>(a_hwndMainWindow);
		ms_instance->m_sendMessageAPI->Connect(); // -TODO- check success

		ms_instance->m_sendMessageAPI->SendCommand("/echo HALLO");
		ms_instance->m_sendMessageAPI->SendCommand(L"/echo HALLO WWWW!");

		std::string x;
		ms_instance->m_sendMessageAPI->EvaluateCommand("$version", x);

		std::wstring y;
		ms_instance->m_sendMessageAPI->EvaluateCommand(L"$version $titlebar $url $usermode $sslversion $ssldll $ssllibdll", y);

		return ms_instance;
	}

	static void Destroy()
	{
		delete ms_instance;
		ms_instance = nullptr;
	}

	static CMIRCOTR* Instance()
	{
		return ms_instance;
	}

	void SetFailedInit()
	{
		m_failedInit = true;
	}

	bool RegisterFishEngine()
	{
		return m_fishEngineReg->RegisterUsingDll();
	}

	const POTRConnectionManager& ConnectionManager()
	{
		return m_connMgr;
	}

	void SetKeyDir(const std::wstring& a_path)
	{
		m_keyDirPath = a_path;
	}

	// return value must include a trailing backslash!
	const std::wstring& GetKeyDir() const
	{
		return m_keyDirPath;
	}

private:
	bool m_failedInit;

	HWND m_hwndMainWindow;
	std::shared_ptr<CMIRCSendMessageAPI> m_sendMessageAPI;

	PFishEngineRegistration m_fishEngineReg;
	POTRConnectionManager m_connMgr;
	std::wstring m_keyDirPath;

private:
	static CMIRCOTR* ms_instance;

	CMIRCOTR()
		: m_failedInit(true), m_hwndMainWindow(0)
	{}
};
