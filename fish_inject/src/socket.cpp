#include "inject-main.h"
#include "inject-socket.h"


CSocketInfo::CSocketInfo(SOCKET s, const PInjectEngines& engines) :
	m_socket(s),
	m_engines(engines),
	m_state(MSCK_INITIALIZING),
	m_ssl(false), m_sslHandshakeComplete(false), m_usedSTARTTLS(false),
	m_bytesSent(0), m_bytesReceived(0),
	m_linesSent(0), m_linesReceived(0),
	m_linesEncrypted(0), m_linesDecrypted(0)
{
	INJECT_DEBUG_MSG("NEW CONNECTION");
}


void CSocketInfo::OnSSLHandshakeComplete()
{
	INJECT_DEBUG_MSG("");

	m_sslHandshakeComplete = true;

	if (!m_usedSTARTTLS)
	{
		m_state = MSCK_INITIALIZING;
		// reset counters so we can more easily detect stuff in OnSending:
		m_bytesSent = 0;
		m_bytesReceived = 0;
	}
	else
	{
		m_state = MSCK_IRC_IDENTIFIED;
	}
}


static bool IsTLSHandshakePacket(const char* a_data, size_t a_len)
{
	(void)a_len;

	// http://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record
	return (*a_data == 22);
}


/**
 * Please make sure a_data is valid before calling me.
 * @return Modified data placed in m_sendBuffer yes/no
 **/
bool CSocketInfo::OnSending(bool a_ssl, const char* a_data, size_t a_len)
{
	const size_t l_bytesSentBefore = m_bytesSent;

	m_bytesSent += a_len;

	_ASSERT(a_ssl == m_ssl || (m_state == MSCK_TLS_HANDSHAKE && l_bytesSentBefore == 0));

	if(m_state == MSCK_NOT_IRC)
	{
		return false;
	}
	else if(m_state == MSCK_INITIALIZING)
	{
		if(l_bytesSentBefore == 0 && !a_ssl)
		{
			INJECT_DEBUG_MSG("initial (no SSL)");
			INJECT_DEBUG_MSG(std::string(a_data, std::min(size_t(30), a_len)));

			if (IsInitialIRCCommand(a_data, a_len))
			{
				// well, this was easy.
				m_state = MSCK_IRC_IDENTIFIED;
			}
			else if (IsTLSHandshakePacket(a_data, a_len))
			{
				m_ssl = true;

				m_state = MSCK_TLS_HANDSHAKE;
			}
			else if(*a_data == 0x04 && a_len > sizeof(socks4_conn_request_t)) // PROXY: SOCKS4/SOCKS4a
			{
				socks4_conn_request_t l_req;
				memcpy_s(&l_req, sizeof(socks4_conn_request_t), a_data, sizeof(socks4_conn_request_t));

				if(l_req.version == 0x04 && l_req.command == 0x01 && l_req.port > 0 && l_req.ip_addr > 0)
				{
					// seems legit enough...

					m_state = MSCK_SOCKS4_HANDSHAKE;
				}
				else
				{
					INJECT_DEBUG_MSG("bail socks4_conn_request");

					m_state = MSCK_NOT_IRC;
				}
			}
			else if(*a_data == 0x05 && a_len > sizeof(socks5_greeting_t)) // PROXY: SOCKS5
			{
				socks5_greeting_t l_gre;
				memcpy_s(&l_gre, sizeof(socks5_greeting_t), a_data, sizeof(socks5_greeting_t));

				if(l_gre.version == 0x05 && l_gre.num_auth_methods < 5)
				{
					m_state = MSCK_SOCKS5_GREETING;
				}
				else
				{
					INJECT_DEBUG_MSG("bail socks5_greeting");

					m_state = MSCK_NOT_IRC;
				}
			}
			else if(a_len >= 19 && strncmp("CONNECT ", a_data, 8) == 0) // PROXY: HTTP
			{
				char _dummy1[300];
				unsigned int _dummy2;

				if(sscanf_s(a_data, "CONNECT %299s HTTP/1.%u\r\n", _dummy1, 299, &_dummy2) == 2)
				{
					m_state = MSCK_HTTP_PROXY_HANDSHAKE;
				}
				else
				{
					INJECT_DEBUG_MSG("bail http_connect");

					m_state = MSCK_NOT_IRC;
				}
			}
			else
			{
				// this ain't nothing we know about :(

				INJECT_DEBUG_MSG("Sending unknown initial data packet!");

				m_state = MSCK_NOT_IRC;
			}
		}
		else if(l_bytesSentBefore == 0 && a_ssl && m_sslHandshakeComplete)
			// after the TLS handshake, it's a normal IRC stream, maybe, at least:
		{
			INJECT_DEBUG_MSG("initial (SSL)");
			INJECT_DEBUG_MSG(std::string(a_data, std::min(size_t(30), a_len)));

			if (IsInitialIRCCommand(a_data, a_len))
			{
				m_state = MSCK_IRC_IDENTIFIED;
			}
		}
		else if(m_bytesSent > 2048)
		{
			INJECT_DEBUG_MSG("Sent too much data without any signs for IRC activity.");

			m_state = MSCK_NOT_IRC;
		}
	}
	else if(m_state == MSCK_SOCKS5_AUTHENTICATION)
	{
		if(a_len > sizeof(socks5_conn_request_t))
		{
			socks5_conn_request_t l_req;
			memcpy_s(&l_req, sizeof(socks5_conn_request_t), a_data, sizeof(socks5_conn_request_t));

			if(l_req.version == 0x05 && l_req.command == 0x01 && l_req.addr_type <= 0x04 && l_req.reserved1 == 0)
			{
				m_state = MSCK_SOCKS5_CONNECTION;
			}
		}
	}
	else if (m_state == MSCK_IRC_IDENTIFIED && !m_ssl && a_len >= 8 && memcmp(a_data, "STARTTLS", 8) == 0)
	{
		INJECT_DEBUG_MSG("identified STARTTLS");

		m_usedSTARTTLS = true;
		m_state = MSCK_STARTTLS_SENT;
	}
	else if (m_state == MSCK_STARTTLS_SENT)
	{
		if (IsTLSHandshakePacket(a_data, a_len))
		{
			INJECT_DEBUG_MSG("STARTTLS is continuing");

			m_ssl = true;
			m_state = MSCK_TLS_HANDSHAKE;
		}
		else
		{
			INJECT_DEBUG_MSG("STARTTLS aborted");

			// looks like the server rejected STARTTLS offer, fall back to previous state:
			// (mIRC will probably terminate the connection, so we most likely will not even get here)
			m_state = MSCK_IRC_IDENTIFIED;
		}
	}
	
	if(m_state == MSCK_IRC_IDENTIFIED)
	{
		m_sendingBuffer.append(a_data, a_len);

		std::string l_chunk;
		std::string::size_type l_pos;
		while((l_pos = m_sendingBuffer.find("\n")) != std::string::npos)
		{
			std::string l_line = m_sendingBuffer.substr(0, l_pos + 1);
			m_sendingBuffer.erase(0, l_pos + 1);

			INJECT_DEBUG_MSG(l_line);

			++m_linesSent;

			if (m_engines->OnOutgoingLine(m_socket, l_line))
			{
				INJECT_DEBUG_MSG("encrypted:");
				INJECT_DEBUG_MSG(l_line);

				++m_linesEncrypted;
			}

			l_chunk += l_line;
		}

		m_sendBuffer = l_chunk;

		return true;
	}

	return false;
}


void CSocketInfo::OnReceiving(bool a_ssl, const char* a_data, size_t a_len)
{
	_ASSERT(m_ssl == a_ssl);

	const size_t l_bytesReceivedBefore = m_bytesReceived;

	m_bytesReceived += a_len;

	if(m_state == MSCK_NOT_IRC)
	{
		return;
	}
	else if(m_state == MSCK_IRC_IDENTIFIED)
	{
		m_receivingBuffer.append(a_data, a_len);

		std::string::size_type l_pos;
		while((l_pos = m_receivingBuffer.find("\n")) != std::string::npos)
		{
			std::string l_line = m_receivingBuffer.substr(0, l_pos + 1);
			m_receivingBuffer.erase(0, l_pos + 1);

			INJECT_DEBUG_MSG(l_line);

			++m_linesReceived;

			if (m_engines->OnIncomingLine(m_socket, l_line))
			{
				INJECT_DEBUG_MSG("decrypted:");
				INJECT_DEBUG_MSG(l_line);

				++m_linesDecrypted;
			}

			m_receivedBuffer += l_line;
		}
	}
	else if(m_state == MSCK_HTTP_PROXY_HANDSHAKE)
	{
		if(l_bytesReceivedBefore == 0
			&& a_len >= 18
			&& memcmp("HTTP/1.", a_data, 7) == 0
			&& (strstr(a_data, "\r\n\r\n") != nullptr || strstr(a_data, "\n\n") != nullptr))
			// this will fail if the response is not received in one chunk...
		{
			unsigned int _dummy, l_httpCode = 0;

			if(sscanf_s(a_data, "HTTP/1.%u %u %*s", &_dummy, &l_httpCode) && l_httpCode == 200)
			{
				INJECT_DEBUG_MSG("HTTP proxy response is okay!");

				return OnProxyHandshakeComplete();
			}
		}

		INJECT_DEBUG_MSG("Received bad or unrecognized HTTP proxy response.");

		m_state = MSCK_NOT_IRC;
	}
	else if(m_state == MSCK_SOCKS4_HANDSHAKE)
	{
		if(l_bytesReceivedBefore == 0 && a_len == sizeof(socks4_conn_response_t))
		{
			socks4_conn_response_t l_resp;
			memcpy_s(&l_resp, sizeof(socks4_conn_response_t), a_data, sizeof(socks4_conn_response_t));

			if(l_resp.nulbyte == 0 && l_resp.status == 0x5A)
			{
				INJECT_DEBUG_MSG("SOCKS4 proxy response is okay!");

				return OnProxyHandshakeComplete();
			}
		}

		INJECT_DEBUG_MSG("Received bad or unrecognized SOCKS4 proxy response.");

		m_state = MSCK_NOT_IRC;
	}
	else if(m_state == MSCK_SOCKS5_GREETING)
	{
		if(l_bytesReceivedBefore == 0 && a_len == sizeof(socks5_greeting_response_t))
		{
			socks5_greeting_response_t l_resp;
			memcpy_s(&l_resp, sizeof(socks5_greeting_response_t), a_data, sizeof(socks5_greeting_response_t));

			if(l_resp.version == 0x05 && l_resp.auth_method != 0xFF)
			{
				m_state = MSCK_SOCKS5_AUTHENTICATION;

				return;
			}
		}

		INJECT_DEBUG_MSG("bail socks5_greeting");

		m_state = MSCK_NOT_IRC;
	}
	else if(m_state == MSCK_SOCKS5_CONNECTION)
	{
		if(a_len > sizeof(socks5_conn_response_t))
		{
			socks5_conn_response_t l_resp;
			memcpy_s(&l_resp, sizeof(socks5_conn_response_t), a_data, sizeof(socks5_conn_response_t));

			if(l_resp.version == 0x05 && l_resp.status == 0 && l_resp.addr_type <= 0x04 && l_resp.reserved1 == 0)
			{
				INJECT_DEBUG_MSG("SOCKS5 proxy response is okay!");

				return OnProxyHandshakeComplete();
			}
		}

		INJECT_DEBUG_MSG("bail socks5_response");

		m_state = MSCK_NOT_IRC;
	}
	else if(m_bytesReceived > 2048) // 2 KB ought to be enough for any IRC pre-register message
	{
		INJECT_DEBUG_MSG("Received too much data without any signs for IRC activity.");

		m_state = MSCK_NOT_IRC;
	}
}


void CSocketInfo::OnProxyHandshakeComplete()
{
	INJECT_DEBUG_MSG("");

	// similar to OnSSLHandshakeComplete.
	m_state = MSCK_INITIALIZING;
	m_bytesSent = 0;
	m_bytesReceived = 0;
}


bool CSocketInfo::IsInitialIRCCommand(const char* a_data, size_t a_len)
{
	return (a_len >= 7 && (
			memcmp(a_data, "CAP LS ", 7) == 0 ||
			memcmp(a_data, "CAP LS\n", 7) == 0)
		) || (
			a_len >= 8 && memcmp(a_data, "CAP LS\r\n", 8) == 0)
		;
}


std::string CSocketInfo::GetSendBuffer()
{
	return std::move(m_sendBuffer);
}


bool CSocketInfo::HasReceivedLine() const
{
	return (m_receivedBuffer.find("\n") != std::string::npos);
}


std::string CSocketInfo::ReadFromRecvBuffer(size_t a_max)
{
	std::string l_tmp = m_receivedBuffer.substr(0, a_max);
	m_receivedBuffer.erase(0, a_max);
	return std::move(l_tmp);
}


void CSocketInfo::Discard()
{
	INJECT_DEBUG_MSG("");

	m_state = MSCK_NOT_IRC;
}


std::string CSocketInfo::GetStats() const
{
	std::stringstream s;

	s << "[" << GetState() << (m_ssl ? "S" : "") << " s:" << m_linesSent << " r:" << m_linesReceived << " e:" << m_linesEncrypted << " d:" << m_linesDecrypted << "]";

	return s.str();
}


CSocketInfo::~CSocketInfo()
{
}
