#pragma once

#include "MinHook.h"
#include <memory>

class CPatch
{
public:
	static bool Initialize()
	{
		return ms_initialized
			|| (ms_initialized = (MH_Initialize() == MH_OK));
	}

	static void Unitialize()
	{
		if (ms_initialized)
		{
			(void)MH_Uninitialize();

			ms_initialized = false;
		}
	}

	template<typename F>
	CPatch(F pTarget, F pDetour, F& ppOriginal)
		: m_target(pTarget), m_created(false), m_enabled(false)
	{
		m_created = (MH_CreateHook(pTarget, pDetour, reinterpret_cast<void**>(&ppOriginal)) == MH_OK);

		if (m_created)
		{
			m_enabled = (MH_EnableHook(pTarget) == MH_OK);
		}
	}

	bool patched() const { return m_created && m_enabled; }

	~CPatch()
	{
		if (m_enabled)
		{
			MH_DisableHook(m_target);
		}

		if (m_created)
		{
			MH_RemoveHook(m_target);
		}
	}
private:
	void *m_target;
	bool m_created;
	bool m_enabled;

	static bool ms_initialized;
};

typedef std::shared_ptr<CPatch> PPatch;
