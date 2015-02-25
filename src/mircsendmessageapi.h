#pragma once

#include "mircdll.h"
#include <Windows.h>
#include <stdio.h>
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
		wchar_t m_mappingName[10] = { 0 };
		int index = 0; 

		while (m_mappingHandle == INVALID_HANDLE_VALUE)
		{
			++index; // start at 1 because simple/stupid scripts use "mIRC" (= 0) and we do not want to break them

			if (index > 32)
				break;

			swprintf_s(m_mappingName, 10, L"mIRC%d", index);

			::SetLastError(ERROR_SUCCESS);

			m_mappingHandle = ::CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, MAPPING_SIZE, m_mappingName);

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
		strcpy_s(reinterpret_cast<char*>(m_dataPtr), MAPPING_SIZE, cmd.c_str());

		return MIRCSendMessage(MIRC_WM_MCOMMAND, 1, eventId);
	}

	bool SendCommand(const std::wstring& cmd, unsigned short eventId = 0) const
	{
		wcscpy_s(reinterpret_cast<wchar_t*>(m_dataPtr), MAPPING_SIZE / sizeof(wchar_t), cmd.c_str());
		
		return MIRCSendMessage(MIRC_WM_MCOMMAND, 1 | METHODE_UNICODE, eventId);
	}

	bool EvaluateCommand(const std::string& cmd, std::string& result, unsigned short eventId = 0) const
	{
		char* dataPtr = reinterpret_cast<char*>(m_dataPtr);

		strcpy_s(dataPtr, MAPPING_SIZE, cmd.c_str());

		if (MIRCSendMessage(MIRC_WM_MEVALUATE, 0, eventId)
			&& SUCCEEDED(::StringCchLengthA(dataPtr, MAPPING_SIZE - 1, NULL))
		)
		{
			result = std::string(dataPtr);

			return true;
		}
		
		return false;
	}

	bool EvaluateCommand(const std::wstring& cmd, std::wstring& result, unsigned short eventId = 0) const
	{
		wchar_t* wDataPtr = reinterpret_cast<wchar_t*>(m_dataPtr);

		wcscpy_s(wDataPtr, MAPPING_SIZE / sizeof(wchar_t), cmd.c_str());

		if (MIRCSendMessage(MIRC_WM_MEVALUATE, METHODE_UNICODE, eventId)
			&& SUCCEEDED(::StringCchLengthW(wDataPtr, MAPPING_SIZE - 1, NULL))
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
	const WORD METHODE_UNICODE = 8;

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
