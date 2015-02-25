//
// Class to communicate with mIRC and evaluate commands and even mIRC script code.
// Check "SendMessage" in the mIRC help file for more details.
//
// @author flakes 2015
// @license Hereby released into Public Domain.
//
#pragma once

#include <Windows.h>
#include <Strsafe.h>
#include <string>

class CMIRCSendMessageAPI
{
public:
	CMIRCSendMessageAPI(HWND hwnd)
		: m_hwnd(hwnd), m_mappingHandle(INVALID_HANDLE_VALUE), m_dataPtr(nullptr), m_mappingNameIndex(0)
	{
	}

	CMIRCSendMessageAPI(const CMIRCSendMessageAPI&) = delete;

	bool Connect()
	{
		wchar_t mappingName[10] = { 0 };
		int index = 0; 

		while (m_mappingHandle == INVALID_HANDLE_VALUE)
		{
			++index; // start at 1 because simple/stupid scripts use "mIRC" (= 0) and we do not want to break them

			if (index > 32)
				break;

			::StringCchPrintfW(mappingName, 10, L"mIRC%d", index);

			::SetLastError(ERROR_SUCCESS);

			m_mappingHandle = ::CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, MAPPING_SIZE, mappingName);

			if (m_mappingHandle && ::GetLastError() == ERROR_ALREADY_EXISTS)
			{
				// already used by someone else, try next one
				m_mappingHandle = INVALID_HANDLE_VALUE;
			}
		}

		if (m_mappingHandle != INVALID_HANDLE_VALUE)
		{
			if (!m_dataPtr)
			{
				m_dataPtr = ::MapViewOfFile(m_mappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
			}

			m_mappingNameIndex = index;
		}

		return (m_mappingHandle && m_dataPtr);
	}

	bool SendCommand(const std::string& cmd, unsigned short eventId = 0) const
	{
		if (!m_dataPtr)
			return false;

		::StringCbCopyA(reinterpret_cast<char*>(m_dataPtr), MAPPING_SIZE, cmd.c_str());

		return MIRCSendMessage(WM_MCOMMAND, 1, eventId);
	}

	bool SendCommand(const std::wstring& cmd, unsigned short eventId = 0) const
	{
		if (!m_dataPtr)
			return false;

		::StringCbCopyW(reinterpret_cast<wchar_t*>(m_dataPtr), MAPPING_SIZE, cmd.c_str());
		
		return MIRCSendMessage(WM_MCOMMAND, 1 | METHOD_UNICODE, eventId);
	}

	bool EvaluateCommand(const std::string& cmd, std::string& result, unsigned short eventId = 0) const
	{
		if (!m_dataPtr)
			return false;

		char* dataPtr = reinterpret_cast<char*>(m_dataPtr);

		::StringCbCopyA(dataPtr, MAPPING_SIZE, cmd.c_str());

		if (MIRCSendMessage(WM_MEVALUATE, 0, eventId)
			&& SUCCEEDED(::StringCbLengthA(dataPtr, MAPPING_SIZE - 1, NULL))
		)
		{
			result = std::string(dataPtr);

			return true;
		}
		
		return false;
	}

	bool EvaluateCommand(const std::wstring& cmd, std::wstring& result, unsigned short eventId = 0) const
	{
		if (!m_dataPtr)
			return false;

		wchar_t* wDataPtr = reinterpret_cast<wchar_t*>(m_dataPtr);

		::StringCbCopyW(wDataPtr, MAPPING_SIZE, cmd.c_str());

		if (MIRCSendMessage(WM_MEVALUATE, METHOD_UNICODE, eventId)
			&& SUCCEEDED(::StringCbLengthW(wDataPtr, MAPPING_SIZE - 1, NULL))
		)
		{
			result = std::wstring(wDataPtr);

			return true;
		}

		return false;
	}

	virtual ~CMIRCSendMessageAPI()
	{
		::UnmapViewOfFile(m_dataPtr); m_dataPtr = nullptr;
		::CloseHandle(m_mappingHandle); m_mappingHandle = INVALID_HANDLE_VALUE;
	}

private:
	const DWORD MAPPING_SIZE = 8192;
	const WORD METHOD_UNICODE = 8;
	const UINT WM_MCOMMAND = WM_USER + 200;
	const UINT WM_MEVALUATE = WM_USER + 201;

	HWND m_hwnd;
	int m_mappingNameIndex;
	HANDLE m_mappingHandle;
	void *m_dataPtr;

	bool MIRCSendMessage(UINT msg, WORD method, WORD eventId) const
	{
		const WORD USEFUL_RETURN_CODES = 16;

		// 0 = success, 1 = failure or'd with 2 = bad mapfile name, 4 = bad mapfile size, 8 = bad eventid, 16 = bad server, 32 = bad script, 64 = disabled in lock dialog.

		return (::SendMessageW(m_hwnd, msg, MAKEWPARAM(method | USEFUL_RETURN_CODES, eventId), m_mappingNameIndex) == 0);
	}
};
