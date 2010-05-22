#include "targetver.h"
#include <windows.h>
#include <string>
#include <memory>
#include <map>

class CBlowIni
{
protected:
	std::wstring m_iniPath;
	std::string m_iniBlowKey;
	bool m_noLegacy;

public:
	CBlowIni(std::wstring a_iniPath = L"");
	void SetIniPath(std::wstring a_iniPath);

	/* general purpose INI tools */
	std::wstring GetStringW(const wchar_t* a_key, const wchar_t* a_default = NULL) const;
	std::string GetString(const wchar_t* a_key, const wchar_t* a_default = NULL) const;
	bool GetBool(const wchar_t* a_key, bool a_default) const;
	int GetInt(const wchar_t* a_key, int a_default = 0) const;

	/* blow.ini-specific methods */
	static std::string FixContactName(const std::string& a_name);
	std::string GetBlowKey(const std::string& a_name, bool& ar_cbc) const;
	bool DeleteBlowKey(const std::string& a_name) const;
	bool WriteBlowKey(const std::string& a_name, const std::string& a_value) const;
	bool GetSectionBool(const std::string& a_name, const wchar_t* a_key, bool a_default) const;
};

/* from util.cpp */
std::string UnicodeToCp(UINT a_codePage, const std::wstring& a_wstr);
std::wstring UnicodeFromCp(UINT a_codePage, const std::string& a_str);
void StrTrimRight(std::string& a_str);
std::string HttpDownloadTextFile(const std::wstring& a_url);
std::string Base64_Encode(const std::string& a_input);
std::string Base64_Decode(const std::string& a_input);
bool HasCBCPrefix(std::string& a_key, bool a_strip = false);
void remove_bad_chars(std::string &str);

/* from blowfish.cpp */
void blowfish_encrypt(const std::string& ain, std::string &out, const std::string &key);
int blowfish_decrypt(const std::string& ain, std::string &out, const std::string &key);

/* from dh1080.cpp */
bool DH1080_Generate(std::string& ar_priv, std::string& ar_pub);
std::string DH1080_Compute(const std::string& a_priv, const std::string& a_pub);

/* from blowfish_cbc.cpp */
int blowfish_decrypt_cbc(const std::string& a_in, std::string &ar_out, const std::string &a_key);
void blowfish_encrypt_cbc(const std::string& a_in, std::string &ar_out, const std::string &a_key);

/* for fish-main.cpp */
#define EXPORT_SIG(RET_TYPE) extern "C" RET_TYPE __stdcall
#define blowfish_encrypt_auto(CBC, A, B, C) if(CBC) blowfish_encrypt_cbc(A, B, C); else blowfish_encrypt(A, B, C)
#define blowfish_decrypt_auto(CBC, A, B, C) ((CBC) ? blowfish_decrypt_cbc(A, B, C) : blowfish_decrypt(A, B, C))
