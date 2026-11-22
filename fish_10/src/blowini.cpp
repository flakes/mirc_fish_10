#include "fish-internal.h"
#include <time.h>

#define INI_SECTION L"FiSH"

static constexpr wchar_t ALIAS_ITEM[] = L"Alias";

static bool IsAliasContact(const std::string& a_contact)
{
	return !a_contact.empty() && a_contact.find_first_of(": \t\r\n") == std::string::npos;
}


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
	swprintf_s(l_buf, 19, L"%lld", time(nullptr));

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


size_t CBlowIni::MaxKeyLength(bool a_cbc) const
{
	// Only ECB supports the legacy OpenSSL key schedule extension up to 72 bytes.
	return (a_cbc || GetBool(L"enforce_max_key_length", true)) ? 56 : 72;
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

	const bool l_obfuscated = l_blowKey.find("+OK ") == 0;
	if(l_obfuscated)
	{
		// the blowfish_decrypt must not change in a way that makes it stop
		// making a copy of the first argument or this will blow up.
		if(blowfish_decrypt(l_blowKey.substr(4), l_blowKey, m_iniBlowKey) != 0)
		{
			l_blowKey = "";
		}
	}

	ar_cbc = GetSectionBool(a_name, L"cbc", false);
	// An obfuscated CBC key with a separate mode flag can itself start with "cbc:".
	if(!ar_cbc || !l_obfuscated)
		ar_cbc = HasCBCPrefix(l_blowKey, true) || ar_cbc;

	return l_blowKey;
}


std::string CBlowIni::FindBlowKey(const std::string& a_network, const std::string& a_contact,
	bool& ar_cbc, std::string& ar_alias) const
{
	const UINT l_codePage = m_noLegacy ? CP_UTF8 : CP_ACP;
	const std::string l_networkSection = a_network + ":" + a_contact;
	ar_cbc = false;
	ar_alias = UnicodeToCp(l_codePage, GetSectionValue(l_networkSection, ALIAS_ITEM));
	if(!ar_alias.empty())
		return {};

	std::string l_result = GetBlowKey(l_networkSection, ar_cbc);
	if(!m_noLegacy && l_result.empty())
	{
		ar_alias = UnicodeToCp(l_codePage, GetSectionValue(a_contact, ALIAS_ITEM));
		if(!ar_alias.empty())
		{
			ar_cbc = false;
			return {};
		}
		l_result = GetBlowKey(a_contact, ar_cbc);
	}

	return l_result;
}


std::string CBlowIni::ResolveBlowKey(const std::string& a_network, const std::string& a_contact,
	bool& ar_cbc, std::string& ar_alias) const
{
	std::string l_key = FindBlowKey(a_network, a_contact, ar_cbc, ar_alias);
	if(ar_alias.empty())
		return l_key;
	if(!IsAliasContact(ar_alias))
		return {};

	// An alias selects the source's key and mode. A second alias ends the lookup.
	std::string l_sourceAlias;
	l_key = FindBlowKey(a_network, ar_alias, ar_cbc, l_sourceAlias);
	if(l_key.empty())
		ar_cbc = false;
	return l_key;
}


std::string CBlowIni::GetBlowKey(const std::string& a_network, const std::string& a_contact, bool& ar_cbc) const
{
	std::string l_alias;
	return ResolveBlowKey(a_network, a_contact, ar_cbc, l_alias);
}


CBlowIni::AliasWriteResult CBlowIni::WriteBlowAlias(const std::string& a_network,
	const std::string& a_target, const std::string& a_source, bool a_trackNick) const
{
	if(!IsAliasContact(a_target) || !IsAliasContact(a_source))
		return AliasWriteResult::Error;

	bool l_cbc;
	std::string l_alias;
	if(ResolveBlowKey(a_network, a_source, l_cbc, l_alias).empty())
		return AliasWriteResult::NoKey;

	// Flatten an existing alias so successive nickname changes stay one hop away.
	const std::string& l_source = l_alias.empty() ? a_source : l_alias;
	const UINT l_codePage = m_noLegacy ? CP_UTF8 : CP_ACP;
	const std::wstring l_targetSection = UnicodeFromCp(l_codePage, FixContactName(a_target));
	const std::wstring l_sourceSection = UnicodeFromCp(l_codePage, FixContactName(l_source));
	if(::CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
		l_targetSection.c_str(), -1, l_sourceSection.c_str(), -1) == CSTR_EQUAL)
		return AliasWriteResult::Ok; // The target already owns the selected key.

	std::wstring l_dhMode;
	if(a_trackNick)
	{
		l_dhMode = GetSectionValue(a_network + ":" + a_source, L"dh1080_cbc");
		if(l_dhMode.empty() && !m_noLegacy)
			l_dhMode = GetSectionValue(a_source, L"dh1080_cbc");
	}

	const std::wstring l_value = UnicodeFromCp(l_codePage, l_source);
	const auto l_write = [&](const std::string& a_section) {
		if(!SetSectionValue(a_section, ALIAS_ITEM, l_value.c_str()))
			return false;
		SetSectionValue(a_section, L"key", nullptr);
		SetSectionValue(a_section, L"cbc", nullptr);
		if(!l_dhMode.empty())
			SetSectionValue(a_section, L"dh1080_cbc", l_dhMode.c_str());
		return true;
	};
	bool l_success = l_write(a_network + ":" + a_target);
	if(!m_noLegacy)
		l_success = l_write(a_target) || l_success;
	return l_success ? AliasWriteResult::Ok : AliasWriteResult::Error;
}


bool CBlowIni::DeleteBlowKey(const std::string& a_name) const
{
	const std::string l_iniSection = FixContactName(a_name);
	bool l_success = true;

	if(m_noLegacy)
	{
		const std::wstring l_iniSectionW = UnicodeFromCp(CP_UTF8, l_iniSection);

		l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), nullptr, nullptr, m_iniPath.c_str()) != 0);
	}
	else
	{
		const std::string l_ansiFileName = UnicodeToCp(CP_ACP, m_iniPath);

		if(::WritePrivateProfileStringA(l_iniSection.c_str(), nullptr, nullptr, l_ansiFileName.c_str()) == 0)
		{
			// compatibility fallback, read above...
			const std::wstring l_iniSectionW = UnicodeFromCp(CP_ACP, l_iniSection);

			l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), nullptr, nullptr, m_iniPath.c_str()) != 0);
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

	if(l_keyActual.empty() || l_keyActual.size() > MaxKeyLength(l_cbc)
		|| l_keyActual.find_first_of("\r\n") != std::string::npos)
	{
		return false;
	}

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
		time_t l_time = time(nullptr);
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
		::WritePrivateProfileStringW(l_iniSectionW.c_str(), L"cbc", nullptr, m_iniPath.c_str());
	}

	if(l_success && !GetSectionValue(a_name, ALIAS_ITEM).empty())
		l_success = SetSectionValue(a_name, ALIAS_ITEM, nullptr);

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


std::wstring CBlowIni::GetSectionValue(const std::string& a_name, const wchar_t* a_key) const
{
	const std::wstring l_section = UnicodeFromCp(m_noLegacy ? CP_UTF8 : CP_ACP, FixContactName(a_name));
	wchar_t l_value[4096] = {0};
	::GetPrivateProfileStringW(l_section.c_str(), a_key, L"", l_value, _countof(l_value), m_iniPath.c_str());
	return l_value;
}


bool CBlowIni::SetSectionValue(const std::string& a_name, const wchar_t* a_key, const wchar_t* a_value) const
{
	const std::string l_iniSection = FixContactName(a_name);
	std::wstring l_iniSectionW;

	bool l_success = true;

	if(m_noLegacy)
	{
		l_iniSectionW = UnicodeFromCp(CP_UTF8, l_iniSection);
		l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), a_key, a_value, m_iniPath.c_str()) != 0);
	}
	else
	{
		const std::string l_ansiFileName = UnicodeToCp(CP_ACP, m_iniPath),
			l_ansiValue = a_value ? UnicodeToCp(CP_ACP, a_value) : std::string(),
			l_ansiKey = UnicodeToCp(CP_ACP, a_key);

		l_iniSectionW = UnicodeFromCp(CP_ACP, l_iniSection);

		if(::WritePrivateProfileStringA(l_iniSection.c_str(), l_ansiKey.c_str(), a_value ? l_ansiValue.c_str() : nullptr, l_ansiFileName.c_str()) == 0)
		{
			l_success = (::WritePrivateProfileStringW(l_iniSectionW.c_str(), a_key, a_value, m_iniPath.c_str()) != 0);
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
