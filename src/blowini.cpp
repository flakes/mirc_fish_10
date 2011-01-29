#include "fish-internal.h"
#include <time.h>

#define INI_SECTION L"FiSH"


CBlowIni::CBlowIni(std::wstring a_iniPath)
{
	SetIniPath(a_iniPath);

	m_iniBlowKey = "blowinikey\0ADDITIONAL SPACE FOR CUSTOM BLOW.INI PASSWORD";
	// well, it's open source now, but hex editing the DLL might still
	// be easier in some cases.
}


void CBlowIni::SetIniPath(std::wstring a_iniPath)
{
	m_iniPath = a_iniPath;
	// allow no_legay setting to be read in GetBool call... *hack*:
	m_noLegacy = false;
	m_noLegacy = GetBool(L"no_legacy", false);
}


bool CBlowIni::IsWritable() const
{
	wchar_t l_buf[20] = {0};
	swprintf_s(l_buf, 19, L"%d", time(NULL));

	return (::WritePrivateProfileStringW(L"Test", L"StartUp", l_buf, m_iniPath.c_str()) != 0);
}


std::wstring CBlowIni::GetStringW(const wchar_t* a_key, const wchar_t* a_default) const
{
	wchar_t l_buf[4096] = {0};

	::GetPrivateProfileStringW(INI_SECTION, a_key, a_default, l_buf, 4095, m_iniPath.c_str());

	return l_buf;
}


std::string CBlowIni::GetString(const wchar_t* a_key, const wchar_t* a_default) const
{
	return UnicodeToCp(CP_UTF8, GetStringW(a_key, a_default));
}


bool CBlowIni::GetBool(const wchar_t* a_key, bool a_default) const
{
	const std::wstring l_val = GetStringW(a_key, (a_default ? L"1" : L"0"));

	return (l_val.empty() ? a_default : (l_val[0] != L'0' && l_val[0] != L'n' && l_val[0] != L'N'));
}


int CBlowIni::GetInt(const wchar_t* a_key, int a_default) const
{
	return ::GetPrivateProfileIntW(INI_SECTION, a_key, a_default, m_iniPath.c_str());
}


bool CBlowIni::SetInt(const wchar_t* a_key, int a_value) const
{
	wchar_t l_buf[20] = {0};
	swprintf_s(l_buf, 19, L"%d", a_value);

	return (::WritePrivateProfileStringW(INI_SECTION, a_key, l_buf, m_iniPath.c_str()) != FALSE);
}


std::string CBlowIni::FixContactName(const std::string& a_name)
{
	std::string l_result;

	l_result.reserve(a_name.size());

	for(size_t p = 0; p < a_name.size(); p++)
	{
		l_result += (a_name[p] == '[' || a_name[p] == ']' ? '~' : a_name[p]);
	}

	return l_result;
}


std::string CBlowIni::GetBlowKey(const std::string& a_name, bool& ar_cbc) const
{
	const std::string l_iniSection = FixContactName(a_name);
	std::string l_blowKey;

	if(m_noLegacy)
	{
		const std::wstring l_iniSectionW = UnicodeFromCp(CP_UTF8, l_iniSection);

		wchar_t l_buf[4096] = {0};
		::GetPrivateProfileStringW(l_iniSectionW.c_str(), L"key", L"", l_buf, 4095, m_iniPath.c_str());

		l_blowKey = UnicodeToCp(CP_UTF8, l_buf);
	}
	else
	{
		const std::string l_ansiFileName = UnicodeToCp(CP_ACP, m_iniPath);
		char l_buf[4096] = {0};

		// use ANSI to maintain backwards compatibility to old blow.ini / fish.dlls.
		::GetPrivateProfileStringA(l_iniSection.c_str(), "key", "", l_buf, 4095, l_ansiFileName.c_str());

		if(*l_buf == 0)
		{
			// fallback for INI filenames with non-ANSI characters:
			const std::wstring l_iniSectionW = UnicodeFromCp(CP_ACP, l_iniSection);

			wchar_t l_buf[4096] = {0};
			::GetPrivateProfileStringW(l_iniSectionW.c_str(), L"key", L"", l_buf, 4095, m_iniPath.c_str());

			l_blowKey = UnicodeToCp(CP_ACP, l_buf);
		}
		else
		{
			l_blowKey = l_buf;
		}
	}

	if(l_blowKey.find("+OK ") == 0)
	{
		// the blowfish_decrypt must not change in a way that makes it stop
		// making a copy of the first argument or this will blow up.
		if(blowfish_decrypt(l_blowKey.substr(4), l_blowKey, m_iniBlowKey) != 0)
		{
			l_blowKey = "";
		}
	}

	ar_cbc = (HasCBCPrefix(l_blowKey, true) || GetSectionBool(a_name, L"cbc", false));

	return l_blowKey;
}


std::string CBlowIni::GetBlowKey(const std::string& a_network, const std::string& a_contact, bool& ar_cbc) const
{
#if 0
	if(a_network.empty())
	{
		return GetBlowKey(a_contact, ar_cbc);
	}
	else
#endif
	{
		std::string l_result = GetBlowKey(a_network + ":" + a_contact, ar_cbc);

		if(!m_noLegacy && l_result.empty())
		{
			// fall back to legacy non-network name-prefixed section:
			l_result = GetBlowKey(a_contact, ar_cbc);
		}

		return l_result;
	}
}


bool CBlowIni::DeleteBlowKey(const std::string& a_name) const
{
	const std::string l_iniSection = FixContactName(a_name);
	bool l_success = true;

	if(m_noLegacy)
	{
		const std::wstring l_iniSectionW = UnicodeFromCp(CP_UTF8, l_iniSection);

		l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), NULL, NULL, m_iniPath.c_str()) != 0);
	}
	else
	{
		const std::string l_ansiFileName = UnicodeToCp(CP_ACP, m_iniPath);

		if(::WritePrivateProfileStringA(l_iniSection.c_str(), NULL, NULL, l_ansiFileName.c_str()) == 0)
		{
			// compatibility fallback, read above...
			const std::wstring l_iniSectionW = UnicodeFromCp(CP_ACP, l_iniSection);

			l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), NULL, NULL, m_iniPath.c_str()) != 0);
		}
	}

	return l_success;
}


bool CBlowIni::DeleteBlowKey(const std::string& a_network, const std::string& a_contact) const
{
	bool l_result = DeleteBlowKey(a_network + ":" + a_contact);

	if(!m_noLegacy)
	{
		l_result = DeleteBlowKey(a_contact) || l_result;
	}

	return l_result;
}


bool CBlowIni::WriteBlowKey(const std::string& a_name, const std::string& a_value) const
{
	const std::string l_iniSection = FixContactName(a_name);
	std::wstring l_iniSectionW;
	std::string l_keyActual(a_value), l_keyValue;
	bool l_cbc = HasCBCPrefix(l_keyActual, true);

	blowfish_encrypt(l_keyActual, l_keyValue, m_iniBlowKey);
	l_keyValue.insert(0, "+OK ");

	bool l_success = true;

	if(m_noLegacy)
	{
		l_iniSectionW = UnicodeFromCp(CP_UTF8, l_iniSection);
		const std::wstring l_keyValueW = UnicodeFromCp(CP_UTF8, l_keyValue);
		l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), L"key", l_keyValueW.c_str(), m_iniPath.c_str()) != 0);
	}
	else
	{
		const std::string l_ansiFileName = UnicodeToCp(CP_ACP, m_iniPath);
		l_iniSectionW = UnicodeFromCp(CP_ACP, l_iniSection);

		if(::WritePrivateProfileStringA(l_iniSection.c_str(), "key", l_keyValue.c_str(), l_ansiFileName.c_str()) == 0)
		{
			const std::wstring l_keyValueW = UnicodeFromCp(CP_ACP, l_keyValue);

			l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), L"key", l_keyValueW.c_str(), m_iniPath.c_str()) != 0);
		}
	}

	if(l_success)
	{
		wchar_t l_timeBuf[30] = {0};
		time_t l_time = time(NULL);
		struct tm l_today;
		_localtime64_s(&l_today, &l_time);
		if(wcsftime(l_timeBuf, 29, L"%d/%m/%Y", &l_today) > 0)
		{
			::WritePrivateProfileStringW(l_iniSectionW.c_str(), L"date", l_timeBuf, m_iniPath.c_str());
		}
	}

	if(l_success && l_cbc)
	{
		::WritePrivateProfileStringW(l_iniSectionW.c_str(), L"cbc", L"1", m_iniPath.c_str());
	}
	else
	{
		// delete cbc entry
		::WritePrivateProfileStringW(l_iniSectionW.c_str(), L"cbc", NULL, m_iniPath.c_str());
	}

	return l_success;
}


bool CBlowIni::WriteBlowKey(const std::string& a_network, const std::string& a_contact, const std::string& a_value) const
{
	bool l_result = WriteBlowKey(a_network + ":" + a_contact, a_value);

	if(!m_noLegacy)
	{
		// (over)write key, legacy style:
		l_result = WriteBlowKey(a_contact, a_value) || l_result;
	}

	return l_result;
}


bool CBlowIni::GetSectionBool(const std::string& a_name, const wchar_t* a_key, bool a_default) const
{
	const std::string l_iniSection = FixContactName(a_name);
	int l_result = -1;

	if(!m_noLegacy)
	{
		const std::string l_ansiFileName = UnicodeToCp(CP_ACP, m_iniPath);
		const std::string l_iniKey = UnicodeToCp(CP_ACP, a_key);
		char l_buf[10] = {0};

		::GetPrivateProfileStringA(l_iniSection.c_str(), l_iniKey.c_str(),
			(a_default ? "1" : "0"), l_buf, 9, l_ansiFileName.c_str());

		l_result = (l_buf[0] != L'0' && l_buf[0] != L'n' && l_buf[0] != L'N' ? 1 : 0);
	}

	if(m_noLegacy || l_result == -1)
	{
		const std::wstring l_iniSectionW = UnicodeFromCp((m_noLegacy ? CP_UTF8 : CP_ACP), l_iniSection);
		wchar_t l_bufW[10] = {0};

		::GetPrivateProfileStringW(l_iniSectionW.c_str(), a_key,
			(a_default ? L"1" : L"0"), l_bufW, 9, m_iniPath.c_str());

		return (!*l_bufW ? a_default : (l_bufW[0] != L'0' && l_bufW[0] != L'n' && l_bufW[0] != L'N'));
	}

	return (l_result != 0);
}


bool CBlowIni::GetSectionBool(const std::string& a_network, const std::string& a_contact, const wchar_t* a_key, bool a_default) const
{
	if(m_noLegacy)
	{
		return GetSectionBool(a_network + ":" + a_contact, a_key, a_default);
	}
	else
	{
		return GetSectionBool(a_network + ":" + a_contact, a_key, GetSectionBool(a_contact, a_key, a_default));
	}
}


bool CBlowIni::SetSectionValue(const std::string& a_name, const wchar_t* a_key, const std::wstring& a_value) const
{
	const std::string l_iniSection = FixContactName(a_name);
	std::wstring l_iniSectionW;

	bool l_success = true;

	if(m_noLegacy)
	{
		l_iniSectionW = UnicodeFromCp(CP_UTF8, l_iniSection);
		l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), a_key, a_value.c_str(), m_iniPath.c_str()) != 0);
	}
	else
	{
		const std::string l_ansiFileName = UnicodeToCp(CP_ACP, m_iniPath),
			l_ansiValue = UnicodeToCp(CP_ACP, a_value),
			l_ansiKey = UnicodeToCp(CP_ACP, a_key);

		l_iniSectionW = UnicodeFromCp(CP_ACP, l_iniSection);

		if(::WritePrivateProfileStringA(l_iniSection.c_str(), l_ansiKey.c_str(), l_ansiValue.c_str(), l_ansiFileName.c_str()) == 0)
		{
			l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), a_key, a_value.c_str(), m_iniPath.c_str()) != 0);
		}
	}

	return l_success;
}


bool CBlowIni::SetSectionBool(const std::string& a_network, const std::string& a_contact, const wchar_t* a_key, bool a_value) const
{
	wchar_t l_buf[3] = {0};
	swprintf_s(l_buf, 2, L"%d", (a_value ? 1 : 0));

	bool l_result = SetSectionValue(a_network + ":" + a_contact, a_key, l_buf);

	if(!m_noLegacy)
	{
		// (over)write, legacy style:
		l_result = SetSectionValue(a_contact, a_key, l_buf) || l_result;
	}

	return l_result;
}
