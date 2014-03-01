#pragma once

#include <WS2tcpip.h>
#include <Windows.h>
#include <string>
#include <vector>
#include <utility>
#include <memory>

#include "fish-inject-engine.h"
#include "simple-thread-lock.h"

class CInjectEngines
{
public:
	bool LoadRegister(const std::wstring& a_dllName);
	bool Register(HMODULE hLib, const fish_inject_engine_t*);
	bool Unregister(const fish_inject_engine_t*);

	bool OnOutgoingLine(SOCKET socket, std::string& a_line) const;
	bool OnIncomingLine(SOCKET socket, std::string& a_line) const;

	void OnSocketClosed(SOCKET socket) const;

	virtual ~CInjectEngines();

private:
	typedef std::pair<HMODULE, const fish_inject_engine_t*> TEngine;
	typedef std::vector<TEngine> TEngineList;

	mutable CSimpleThreadLock m_engineListAccess;
	TEngineList m_engines;
};

typedef std::shared_ptr<CInjectEngines> PInjectEngines;
