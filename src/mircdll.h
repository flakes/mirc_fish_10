#pragma once

#include <Windows.h>

/* from mIRC help file */
typedef struct {
	DWORD mVersion;
	HWND  mHwnd;
	BOOL  mKeep;
	BOOL  mUnicode;
	DWORD mBeta;
	DWORD mBytes;
} LOADINFO;

enum {
	MIRC_RET_HALT = 0,
	MIRC_RET_CONTINUE = 1,
	MIRC_RET_DATA_COMMAND = 2,
	MIRC_RET_DATA_RETURN = 3,
};

#define MIRC_PARAM_DATA_LENGTH_LOW 900

#define MIRC_EXPORT_SIG(RET_TYPE) extern "C" RET_TYPE __stdcall

#define MIRC_DLL_EXPORT(NAME) MIRC_EXPORT_SIG(int) NAME(HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
