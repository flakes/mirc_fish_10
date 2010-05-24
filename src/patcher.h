#pragma once

// Source: http://www.codeproject.com/KB/cpp/Intercepting_functions.aspx
// License: http://www.codeproject.com/info/cpol10.aspx

#include "targetver.h"
#include <windows.h>
#pragma warning( push )
#ifdef  __DO_NOT_SHOW_PATCHER_WARNINGS__
	#pragma warning(disable:4311)
#endif

class CPatch
{
private:
	bool m_valid;
	bool m_patched;
	bool m_set_forever;
	long m_old_jmp;
	char* m_PatchInstructionSet;
	char* m_RestorePatchSet;
	int m_size;
	int m_restore_size;
	DWORD m_protect;
	long m_FuncToHook;
	CPatch(){}
	CPatch(CPatch&){}

protected:
	bool okToRewriteTragetInstructionSet(long addr, int& rw_len);
	BOOL HookFunction(long FuncToHook, long  MyHook, long* NewCallAddress, bool patch_now = true);

public:
	template<class TFunction>explicit CPatch(TFunction FuncToHook, TFunction MyHook, TFunction& NewCallAddress, bool patch_now = true, bool set_forever = false)
		: m_valid(false)
		, m_patched(false)
		, m_set_forever(set_forever)
		, m_PatchInstructionSet(0)
		, m_RestorePatchSet(0)
	{
	HookFunction(reinterpret_cast<long>(FuncToHook), reinterpret_cast<long>(MyHook), reinterpret_cast<long*>(&NewCallAddress), patch_now);
	}

	template<class TFunction>explicit CPatch(TFunction FuncToHook, TFunction MyHook, TFunction* NewCallAddress, bool patch_now = true, bool set_forever = false)
		: m_valid(false)
		, m_patched(false)
		, m_set_forever(set_forever)
		, m_PatchInstructionSet(0)
		, m_RestorePatchSet(0)
	{
		HookFunction(reinterpret_cast<long>(FuncToHook), reinterpret_cast<long>(MyHook), reinterpret_cast<long*>(NewCallAddress), patch_now);
	}

	template<class TFunction>explicit CPatch(TFunction& NewCallAddress, TFunction MyHook, bool patch_now = true, bool set_forever = false)
		: m_valid(false)
		, m_patched(false)
		, m_set_forever(set_forever)
		, m_PatchInstructionSet(0)
		, m_RestorePatchSet(0)
	{
		HookFunction(reinterpret_cast<long>(NewCallAddress), reinterpret_cast<long>(MyHook), reinterpret_cast<long*>(&NewCallAddress), patch_now);
	}

	template<class TFunction>explicit CPatch(TFunction* NewCallAddress, TFunction MyHook, bool patch_now = true, bool set_forever = false)
		: m_valid(false)
		, m_patched(false)
		, m_set_forever(set_forever)
		, m_PatchInstructionSet(0)
		, m_RestorePatchSet(0)
	{
		HookFunction(reinterpret_cast<long>(NewCallAddress), reinterpret_cast<long>(MyHook), reinterpret_cast<long*>(NewCallAddress), patch_now);
	}
	~CPatch();

	bool patched() const;
	bool ok() const;
	bool ok(bool _valid);
	void remove_patch(bool forever = false);
	void set_patch();
};

#pragma warning(pop)
