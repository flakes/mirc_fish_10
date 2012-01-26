#include "inject-main.h"


CSocketInfo::CSocketInfo(SOCKET s)
{
	m_socket = s;
	m_ssl = m_sslShakingHands = false;
	m_dataExchanged = false;
}

/**
	* @return Modified data placed in m_sendBuffer yes/no
	**/
bool CSocketInfo::OnSending(bool a_ssl, const char* a_data, size_t a_len)
{
	if(!m_dataExchanged)
	{
		if(a_len < 7 || (memcmp(a_data, "CAP LS\n", 7) != 0 && memcmp(a_data, "CAP LS\r\n", 8) != 0))
		{
			// not an IRC client->server socket.
			return false;
		}

		m_dataExchanged = true;
		m_ssl = a_ssl;

		if(m_ssl) m_sslShakingHands = false;
	}

	m_sendingBuffer.append(a_data, a_len);

	std::string l_chunk;
	std::string::size_type l_pos;
	while((l_pos = m_sendingBuffer.find("\n")) != std::string::npos)
	{
		std::string l_line = m_sendingBuffer.substr(0, l_pos + 1);
		m_sendingBuffer.erase(0, l_pos + 1);

		INJECT_DEBUG_MSG(l_line);

		char* l_szNewLine = FiSH_DLL::_OnOutgoingIRCLine(m_socket, l_line.c_str(), l_line.size());

		if(l_szNewLine)
		{
			INJECT_DEBUG_MSG("encrypted:"); INJECT_DEBUG_MSG(l_szNewLine);
			l_chunk += l_szNewLine;
			FiSH_DLL::_FreeString(l_szNewLine);
		}
		else
		{
			l_chunk += l_line;
		}
	}

	m_sendBuffer = l_chunk;

	return true;
}

void CSocketInfo::OnBeforeReceive(bool a_ssl)
{
	if(!m_ssl)
	{
		m_ssl = a_ssl;
	}

	if(m_sslShakingHands && a_ssl)
	{
		m_sslShakingHands = false;
	}
}

void CSocketInfo::OnAfterReceive(const char* a_data, size_t a_len)
{
	m_receivingBuffer.append(a_data, a_len);

	if(!m_dataExchanged) m_dataExchanged = true;

	std::string l_chunk;
	std::string::size_type l_pos;
	while((l_pos = m_receivingBuffer.find("\n")) != std::string::npos)
	{
		std::string l_line = m_receivingBuffer.substr(0, l_pos + 1);
		m_receivingBuffer.erase(0, l_pos + 1);

		INJECT_DEBUG_MSG(l_line);

		char* l_szNewLine = FiSH_DLL::_OnIncomingIRCLine(m_socket, l_line.c_str(), l_line.size());

		if(l_szNewLine)
		{
			INJECT_DEBUG_MSG("decrypted:"); INJECT_DEBUG_MSG(l_szNewLine);
			m_receivedBuffer += l_szNewLine;
			FiSH_DLL::_FreeString(l_szNewLine);
		}
		else
		{
			m_receivedBuffer += l_line;
		}
	}
}

std::string CSocketInfo::GetSendBuffer()
{
	std::string l_tmp = m_sendBuffer;
	m_sendBuffer.clear();
	return l_tmp;
}

bool CSocketInfo::HasReceivedLine() const
{
	return (m_receivedBuffer.find("\n") != std::string::npos);
}

std::string CSocketInfo::ReadFromRecvBuffer(size_t a_max)
{
	INJECT_DEBUG_MSG("");
	std::string l_tmp = m_receivedBuffer.substr(0, a_max);
	m_receivedBuffer.erase(0, a_max);
	return l_tmp;
}
