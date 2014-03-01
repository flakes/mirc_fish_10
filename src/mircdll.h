#pragma once

#include <Windows.h>

/* from mIRC help file */
typedef struct {
	DWORD  mVersion;
	HWND   mHwnd;
	BOOL   mKeep;
	BOOL   mUnicode;
} LOADINFO;

#define MIRC_EXPORT_SIG(RET_TYPE) extern "C" RET_TYPE __stdcall

#define MIRC_DLL_EXPORT(NAME) MIRC_EXPORT_SIG(int) NAME(HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
