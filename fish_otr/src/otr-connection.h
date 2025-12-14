#pragma once

#include <Windows.h>
#include <string>
#include <memory>

#include "libotr-wrap.h"

//
// keeps the OTR-specific data for a single IRC server connection.
//
class COTRConnection
{
public:
	COTRConnection(HANDLE socket);
	virtual ~COTRConnection();

	void SetNetworkName(const std::string& a_name)
	{
		m_networkName = a_name;

		// :TODO: handle changes after OTR handle has been created
	}

	void SetAccountUserName(const std::string& a_name)
	{
		if (IsUserAccountNameSet())
		{
			return;
		}

		m_accountUserName = a_name;
	}

	void SetMIRCConnectionID(int connection_id)
	{
		if (!m_mircConnectionID)
			m_mircConnectionID = connection_id;
	}

	int GetMIRCConnectionID() const
	{
		return m_mircConnectionID;
	}

	HANDLE GetSocket() const
	{
		return m_socket;
	}

	bool InWorkingOrder() const;

	std::string GetAccountName() const
	{
		return m_accountUserName + "@" + m_networkName;
	}

	bool IsUserAccountNameSet() const
	{
		return !m_accountUserName.empty();
	}

	bool GeneratePrivKeyBlocking();
	bool LibOtrSending(const std::string& a_recipientName, const std::string& a_message);

private:
	HANDLE m_socket;
	OtrlUserState m_otrUserState;
	std::string m_networkName;
	std::string m_accountUserName;
	int m_mircConnectionID; // $cid

	OtrlUserState& GetUserState();
	std::wstring GetAccountNameW();
	void LoadInstanceTags();
	void LoadPrivKey();
	void LoadFingerprints();
};

typedef std::shared_ptr<COTRConnection> POTRConnection;

