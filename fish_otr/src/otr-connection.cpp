#include "mirc-otr-internal.h"
#include "otr-connection.h"
#include "otr-engine.h"
#include <cctype>

COTRConnection::COTRConnection(HANDLE socket)
	: m_socket(socket), m_otrUserState(nullptr), m_mircConnectionID(0)
{
}

bool COTRConnection::InWorkingOrder() const
{
	if (!m_socket)
		return false;

	if (m_networkName.empty() || m_accountUserName.empty() || m_mircConnectionID == 0)
		return false;

	return true;
}

OtrlUserState& COTRConnection::GetUserState()
{
	if (!m_otrUserState)
	{
		m_otrUserState = w_otrl_userstate_create();

		LoadInstanceTags();
		LoadPrivKey();
		LoadFingerprints();
	}

	return m_otrUserState;
}

std::wstring COTRConnection::GetAccountNameW()
{
	const std::string& accountNameA = GetAccountName();
	std::wstring result;
	result.reserve(accountNameA.size());

	// this is good enough:
	for (char c : accountNameA)
	{
		if (c != '_' && c != '-' && c != '@' && !::isalnum(c)) // whitelist!
		{
			c = '_';
		}

		result.push_back(c);
	}

	return result;
}

void COTRConnection::LoadInstanceTags()
{
	const std::wstring path = CMIRCOTR::Instance()->GetKeyDir() + GetAccountNameW() + L".instag";
	FILE *fp = NULL;

	if (::PathFileExistsW(path.c_str()) && _wfopen_s(&fp, path.c_str(), L"rb") == ERROR_SUCCESS)
	{
		gcry_error_t err = w_otrl_instag_read_FILEp(m_otrUserState, fp);

		// -TODO- do something with err

		fclose(fp);
	}
}

void COTRConnection::LoadPrivKey()
{
	const std::wstring path = CMIRCOTR::Instance()->GetKeyDir() + GetAccountNameW() + L".key";
	FILE *fp = NULL;

	if (::PathFileExistsW(path.c_str()) && _wfopen_s(&fp, path.c_str(), L"rb") == ERROR_SUCCESS)
	{
		gcry_error_t err = w_otrl_privkey_read_FILEp(m_otrUserState, fp);

		// -TODO- do something with err

		fclose(fp);
	}
}

void COTRConnection::LoadFingerprints()
{
	const std::wstring path = CMIRCOTR::Instance()->GetKeyDir() + GetAccountNameW() + L".fp";
	FILE *fp = NULL;

	if (::PathFileExistsW(path.c_str()) && _wfopen_s(&fp, path.c_str(), L"rb") == ERROR_SUCCESS)
	{
		gcry_error_t err = w_otrl_privkey_read_fingerprints_FILEp(m_otrUserState, fp, NULL, NULL);

		// -TODO- do something with err

		fclose(fp);
	}
}


bool COTRConnection::GeneratePrivKeyBlocking()
{
	const std::wstring path = CMIRCOTR::Instance()->GetKeyDir() + GetAccountNameW() + L".key";
	FILE *fp = NULL;
	gcry_error_t err = GPG_ERR_ENFILE;

	if (_wfopen_s(&fp, path.c_str(), L"w+b") == ERROR_SUCCESS)
	{
		err = w_otrl_privkey_generate_FILEp(GetUserState(), fp, GetAccountName().c_str());

		fclose(fp);
	}

	return (err == GPG_ERR_NO_ERROR);
}


bool COTRConnection::LibOtrSending(const std::string& a_recipientName, const std::string& a_message)
{
	ConnContext *ctx = NULL;

	gcry_error_t err = w_otrl_message_sending(GetUserState(), COTREngine::GetOps(), this, GetAccountName().c_str(),
		a_recipientName.c_str(), OTRL_INSTAG_BEST, a_message.c_str(), NULL, NULL, OTRL_FRAGMENT_SEND_ALL,
		&ctx, NULL, NULL);

	return (err == GPG_ERR_NO_ERROR);
}

COTRConnection::~COTRConnection()
{
	if (m_otrUserState)
	{
		w_otrl_userstate_free(m_otrUserState);
	}
}
