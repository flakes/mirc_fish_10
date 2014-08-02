#pragma once

#include <Windows.h>

#ifdef __cplusplus
#include <memory>
#define FISH_INJECT_EXTERN_C extern "C"
#else
#define FISH_INJECT_EXTERN_C
#endif

FISH_INJECT_EXTERN_C {

#define FISH_INJECT_ENGINE_DLLNAME "fish_inject.dll"
#define FISH_INJECT_ENGINE_REGISTER_FUNCTION "RegisterEngine"
#define FISH_INJECT_ENGINE_UNREGISTER_FUNCTION "UnregisterEngine"

typedef struct {
	size_t version;

	char* (*OnIncomingIRCLine)(HANDLE socket, const char* line, size_t length);
	char* (*OnOutgoingIRCLine)(HANDLE socket, const char* line, size_t length);

	void (*OnSocketClosed)(HANDLE socket);
	void (*FreeString)(const char* string);

	bool is_postprocessor;

	const char* engine_name;

} fish_inject_engine_t;

typedef const fish_inject_engine_t* (*Get_FiSH_Inject_Engine_Function)();
typedef int (*Register_FiSH_Inject_Engine_Function)(const fish_inject_engine_t*);
typedef int (*Unregister_FiSH_Inject_Engine_Function)(const fish_inject_engine_t*);

#define FISH_INJECT_ENGINE_VERSION 2

#define DECLARE_FISH_INJECT_ENGINE(var_name, on_incoming, on_outgoing, on_socket_closed, free_string, is_postprocessor, engine_name) \
	static const fish_inject_engine_t var_name = { \
		FISH_INJECT_ENGINE_VERSION, on_incoming, on_outgoing, on_socket_closed, free_string, is_postprocessor, engine_name \
	};

} /* FISH_INJECT_EXTERN_C */

#undef FISH_INJECT_EXTERN_C

#ifdef __cplusplus

//
// Utility class for engine implementors.
//

class CFishEngineRegistration
{
public:
	CFishEngineRegistration(const fish_inject_engine_t* engine)
		: m_engine(engine) { }

	bool RegisterUsingDll()
	{
		return RegUnRegUsingDll<Register_FiSH_Inject_Engine_Function>(FISH_INJECT_ENGINE_REGISTER_FUNCTION);
	}

	bool Unregister()
	{
		return RegUnRegUsingDll<Unregister_FiSH_Inject_Engine_Function>(FISH_INJECT_ENGINE_UNREGISTER_FUNCTION);
	}

	virtual ~CFishEngineRegistration()
	{
		Unregister();
	}

private:
	const fish_inject_engine_t* m_engine;

	template<typename TF> bool RegUnRegUsingDll(const char* EXPORT_NAME)
	{
		HMODULE hInjectDll = ::GetModuleHandleA(FISH_INJECT_ENGINE_DLLNAME);

		if (hInjectDll && m_engine)
		{
			const TF func = (TF)::GetProcAddress(hInjectDll, EXPORT_NAME);
			return (func && func(m_engine) == 0);
		}

		return false;
	}
};

typedef std::shared_ptr<CFishEngineRegistration> PFishEngineRegistration;

#endif /* __cplusplus */
