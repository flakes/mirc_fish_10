#pragma once

#include <Windows.h>

extern "C" {

typedef struct {
	size_t version;

	char* (*OnIncomingIRCLine)(HANDLE socket, const char* line, size_t length);
	char* (*OnOutgoingIRCLine)(HANDLE socket, const char* line, size_t length);

	void (*OnSocketClosed)(HANDLE socket);
	void (*FreeString)(const char* string);

} fish_inject_engine_t;

typedef const fish_inject_engine_t* (*Get_FiSH_Inject_Engine_Function)();

}

#define FISH_INJECT_ENGINE_VERSION 1

#define EXPORT_FISH_INJECT_ENGINE(on_incoming, on_outgoing, on_socket_closed, free_string) \
	extern "C" __declspec(dllexport) const fish_inject_engine_t* _FiSH_Inject_Engine() { \
		static const fish_inject_engine_t exp = { \
			FISH_INJECT_ENGINE_VERSION, on_incoming, on_outgoing, on_socket_closed, free_string \
		}; \
		return &exp; \
	}

#define FISH_INJECT_ENGINE_EXPORT_NAME "_FiSH_Inject_Engine"
