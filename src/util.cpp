#include "fish-internal.h"
#include <WinInet.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>


std::string UnicodeToCp(UINT a_codePage, const std::wstring& a_wstr)
{
	int l_size = ::WideCharToMultiByte(a_codePage, 0, a_wstr.c_str(), -1, NULL, NULL, NULL, NULL);

	if(l_size)
	{
		char *l_buf = new char[l_size];

		if(l_buf)
		{
			::WideCharToMultiByte(a_codePage, 0, a_wstr.c_str(), -1, l_buf, l_size, NULL, NULL);
			std::string l_result(l_buf);
			delete[] l_buf;
			return l_result;
		}
	}

	return "";
}


std::wstring UnicodeFromCp(UINT a_codePage, const std::string& a_str)
{
	int l_size = ::MultiByteToWideChar(a_codePage, 0, a_str.c_str(), -1, NULL, NULL);

	if(l_size)
	{
		wchar_t *l_buf = new wchar_t[l_size];

		if(l_buf)
		{
			::MultiByteToWideChar(a_codePage, 0, a_str.c_str(), -1, l_buf, l_size);
			std::wstring l_result(l_buf);
			delete[] l_buf;
			return l_result;
		}
	}

	return L"";
}


void StrTrimRight(std::string& a_str)
{
	std::string::size_type l_pos = a_str.find_last_not_of(" \t\r\n");

	if(l_pos != std::string::npos)
	{
		a_str.erase(l_pos + 1);
	}
	else
	{
		a_str.clear();
	}
}


/* source: http://code.google.com/p/infekt/source/browse/trunk/src/lib/util.cpp?r=200
 GPL licensed */

std::string HttpDownloadTextFile(const std::wstring& a_url)
{
	HINTERNET hInet;
	std::string sText;
	BOOL bSuccess = TRUE;

	hInet = ::InternetOpen(L"HttpDownloadTextFile/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	if(hInet)
	{
		HINTERNET hRequest;
		DWORD dwTimeBuffer = 3000;

		::InternetSetOption(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &dwTimeBuffer, sizeof(dwTimeBuffer));

		hRequest = ::InternetOpenUrl(hInet, a_url.c_str(), NULL, 0,
			INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE |
			INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_AUTH, 0);

		::InternetSetOption(hRequest, INTERNET_OPTION_IGNORE_OFFLINE, NULL, 0);

		if(hRequest)
		{
			long long uFileSize = 0;

			if(true)
			{
				TCHAR szSizeBuffer[32];
				DWORD dwLengthSizeBuffer = 32;

				if(::HttpQueryInfo(hRequest, HTTP_QUERY_CONTENT_LENGTH, szSizeBuffer, &dwLengthSizeBuffer, NULL) == TRUE)
				{
					uFileSize = _wcstoi64(szSizeBuffer, NULL, 10);
				}
			}

			if(uFileSize && uFileSize < 100 * 1024)
			{
				char szBuffer[8192] = {0};
				DWORD dwRead;

				while(::InternetReadFile(hRequest, szBuffer, 8191, &dwRead))
				{
					if(!dwRead || dwRead > 8191)
					{
						break;
					}

					if(lstrlenA(szBuffer) == dwRead)
					{
						sText += szBuffer;
					}
					else
					{
						// we got some binary stuff, but we don't want any.
						bSuccess = FALSE;
						break;
					}
				}
			}

			::InternetCloseHandle(hRequest);
		}

		::InternetCloseHandle(hInet);
	}

	return (bSuccess ? sText : "");
}


std::string Base64_Encode(const std::string& a_input)
{
	BIO *l_mem, *l_b64;
	std::string l_result;

	if(a_input.size() == 0) return l_result;

	l_b64 = BIO_new(BIO_f_base64());
	if(!l_b64)
	{
		return l_result;
	}

	BIO_set_flags(l_b64, BIO_FLAGS_BASE64_NO_NL);

	l_mem = BIO_new(BIO_s_mem());
	if(!l_mem)
	{
		BIO_free_all(l_b64);
		return l_result;
	}

	l_b64 = BIO_push(l_b64, l_mem);

	if(BIO_write(l_b64, a_input.c_str(), a_input.size()) == (int)a_input.size())
	{
		BUF_MEM *l_ptr;

		BIO_flush(l_b64);
		BIO_get_mem_ptr(l_b64, &l_ptr);

		l_result.append(l_ptr->data, l_ptr->length);
	}

	BIO_free_all(l_b64);

	return l_result;
}


std::string Base64_Decode(const std::string& a_input)
{
	BIO *l_mem, *l_b64;
	std::string l_result;

	if(a_input.size() == 0) return l_result;
	
	l_b64 = BIO_new(BIO_f_base64());
	if(l_b64)
	{
		char *l_buf = new char[3];
		BIO_set_flags(l_b64, BIO_FLAGS_BASE64_NO_NL);
		
		l_mem = BIO_new_mem_buf((void*)a_input.c_str(), a_input.size());
		if(l_mem)
		{
			int l_bytesRead;
			l_b64 = BIO_push(l_b64, l_mem);
			while((l_bytesRead = BIO_read(l_b64, l_buf, 3)) > 0)
			{
				l_result.append(l_buf, l_bytesRead);
			}
		}

		BIO_free_all(l_b64);
		delete[] l_buf;
	}

	return l_result;
}


void remove_bad_chars(std::string &str)
{
	std::string::size_type i;
	while (i = str.find('\x00', 0), i != std::string::npos) str.erase(i, 1);
	while (i = str.find_first_of("\x0d\x0a"), i != std::string::npos) str.erase(i, 1);
}


bool HasCBCPrefix(std::string& a_key, bool a_strip)
{
	size_t l_prefixLen = 0;

	if(_strnicmp(a_key.c_str(), "cbc:", 4) == 0)
	{
		l_prefixLen = 4;
	}

	if(l_prefixLen > 0 && a_strip)
	{
		a_key.erase(0, l_prefixLen);
	}

	return (l_prefixLen > 0);
}


const string_vector SplitString(const std::string& a_in, const char *a_delimiter, size_t a_limit)
{
	string_vector l_result;
	std::string::size_type l_prevPos = 0, l_pos = a_in.find(a_delimiter);
	size_t l_delimLen = strlen(a_delimiter);

	while(l_pos != std::string::npos)
	{
		if(l_delimLen == 1) { l_pos = a_in.find_first_not_of(a_delimiter, l_pos); l_pos--; }
		l_result.push_back(a_in.substr(l_prevPos, l_pos - l_prevPos));
		l_prevPos = l_pos + l_delimLen;
		if(l_result.size() == a_limit - 1) break;
		l_pos = a_in.find(a_delimiter, l_prevPos);
	}

	if(l_prevPos < a_in.size())
	{
		l_result.push_back(a_in.substr(l_prevPos));
	}

	return l_result;
}


std::string SimpleMIRCParser(const std::string a_str)
{
	std::string l_result;
	std::string::size_type l_pos = a_str.find('$'), l_prevPos = 0;

	while(l_pos != std::string::npos)
	{
		auto l_newPos = std::string::npos;

		l_result += a_str.substr(l_prevPos, l_pos - l_prevPos);

		if(l_pos < a_str.size() - 1)
		{
			if(a_str[l_pos + 1] == '+')
			{
				if(l_result.size() > 0 && l_result[l_result.size() - 1] == ' ') l_result.erase(l_result.size() - 1);
				l_newPos = l_pos + 2;
				if(l_newPos < a_str.size() - 1 && a_str[l_newPos] == ' ') l_newPos++;
			}
			else if(a_str.substr(l_pos + 1, 4) == "chr(")
			{
				auto l_endPos = a_str.find(')', l_pos + 6);

				if(l_endPos != std::string::npos)
				{
					std::string l_buf = a_str.substr(l_pos + 5, l_endPos - l_pos - 5);
					int l_code = atoi(l_buf.c_str());

					if(l_code > 0)
					{
						l_result += (char)l_code;
						l_newPos = l_endPos + 1;
					}
				}
			}
		}

		if(l_newPos == std::string::npos)
		{
			l_result += '$';
			l_newPos = l_pos + 1;
		}

		l_prevPos = l_newPos;
		l_pos = a_str.find('$', l_prevPos);
	}

	if(l_prevPos < a_str.size())
	{
		l_result += a_str.substr(l_prevPos);
	}

	return l_result;
}

