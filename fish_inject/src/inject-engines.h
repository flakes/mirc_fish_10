#pragma once

#include <WS2tcpip.h>
#include <Windows.h>
#include <string>
#include <vector>
#include <utility>
#include <memory>

#include "fish-inject-engine.h"
#include "CMultiReaderSingleWriterLock.h"

class CInjectEngines
{
public:
	bool Register(HMODULE hLib, const fish_inject_engine_t*);
	bool Unregister(const fish_inject_engine_t*);

	bool OnOutgoingLine(SOCKET socket, std::string& a_line) const;
	bool OnIncomingLine(SOCKET socket, std::string& a_line) const;

	void OnSocketClosed(SOCKET socket) const;

	std::string GetEngineList() const;

	virtual ~CInjectEngines();

private:
	typedef std::pair<HMODULE, const fish_inject_engine_t*> TEngine;
	typedef std::vector<TEngine> TEngineList;

	mutable CMultiReaderSingleWriterLock m_engineListAccess;
	TEngineList m_engines;
};

typedef std::shared_ptr<CInjectEngines> PInjectEngines;
