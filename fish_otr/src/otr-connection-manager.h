#pragma once

#include "otr-connection.h"
#include "CMultiReaderSingleWriterLock.h"
#include <map>

class COTRConnectionManager
{
public:
	POTRConnection FindBySocket(HANDLE a_socket)
	{
		POTRConnection otrConnection;

		m_lock.EnterReader();
		
		const auto& found = m_bySocket.find(a_socket);

		if (found != m_bySocket.end())
		{
			otrConnection = found->second;
			m_lock.LeaveReader();
		}
		else
		{
			m_lock.LeaveReader();
			m_lock.EnterWriter();
			otrConnection = m_bySocket[a_socket] = std::make_shared<COTRConnection>(a_socket);
			m_lock.LeaveWriter();
		}

		return otrConnection;
	}

	POTRConnection FindByCid(int a_mircConnectionId)
	{
		POTRConnection otrConnection;

		m_lock.EnterReader();

		const auto& found = m_byCid.find(a_mircConnectionId);

		if (found != m_byCid.end())
			otrConnection = found->second;

		m_lock.LeaveReader();

		return otrConnection;
	}

	void SetCid(const POTRConnection& a_otrConnection, int a_mircConnectionId)
	{
		a_otrConnection->SetMIRCConnectionID(a_mircConnectionId);

		m_lock.EnterWriter();
		m_byCid[a_mircConnectionId] = a_otrConnection;
		m_lock.LeaveWriter();
	}

	void RemoveConnection(HANDLE a_socket)
	{
		m_lock.EnterWriter();

		const auto& found = m_bySocket.find(a_socket);

		if (found != m_bySocket.end())
		{
			m_byCid.erase(found->second->GetMIRCConnectionID());
			m_bySocket.erase(found);
		}

		m_lock.LeaveWriter();
	}
	
	~COTRConnectionManager()
	{
		m_lock.EnterWriter();
		m_bySocket.clear();
		m_byCid.clear();
		m_lock.LeaveWriter();
	}

private:
	std::map<HANDLE, POTRConnection> m_bySocket;
	std::map<int, POTRConnection> m_byCid;
	CMultiReaderSingleWriterLock m_lock;
};

typedef std::shared_ptr<COTRConnectionManager> POTRConnectionManager;
