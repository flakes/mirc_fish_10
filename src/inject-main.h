#include "targetver.h"

#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <memory>
#include <map>
#include "patcher.h"


/* function signature typedefs */
typedef int(WSAAPI* connect_proc)(SOCKET s, const struct sockaddr FAR * name, int namelen);
typedef int(WSAAPI* send_proc)(SOCKET, const char*, int, int);
typedef int(WSAAPI* recv_proc)(SOCKET, char*, int, int);
typedef int(WSAAPI* closesocket_proc)(SOCKET);
typedef int(__cdecl* SSL_write_proc)(void *ssl, const void *buf, int num);
typedef int(__cdecl* SSL_read_proc)(void *ssl, void *buf, int num);

typedef int(__cdecl* SSL_state_proc)(const void *ssl);
typedef int(__cdecl* SSL_get_fd_proc)(const void *ssl);

/* from mIRC help file (like some more of the comments below) */
typedef struct {
	DWORD  mVersion;
	HWND   mHwnd;
	BOOL   mKeep;
	BOOL   mUnicode;
} LOADINFO;


typedef enum {
	MSCK_INITIALIZING = 0,
	MSCK_TLS_HANDSHAKE,
	MSCK_SOCKS4_HANDSHAKE,
	MSCK_SOCKS5_HANDSHAKE,
	MSCK_HTTP_PROXY_HANDSHAKE,
	MSCK_IRC_IDENTIFIED,
	MSCK_NOT_IRC
} MIRC_SOCKET_STATE;


/*  */
class CSocketInfo
{
protected:
	SOCKET m_socket;
	MIRC_SOCKET_STATE m_state;

	bool m_ssl;
	bool m_sslHandshakeComplete;
	
	size_t m_bytesSent;
	size_t m_bytesReceived;

	CRITICAL_SECTION m_opLock;

	/** the following buffer variables only activate when the connection
		has been determined to be an IRC connection! **/

	// for unencrypted data, ready to be fetched from outside:
	std::string m_sendBuffer;
	std::string m_receivedBuffer;

	// for incomplete lines:
	std::string m_sendingBuffer;
	std::string m_receivingBuffer;

	void OnProxyHandshakeComplete();

public:
	CSocketInfo(SOCKET s);
	virtual ~CSocketInfo();

	MIRC_SOCKET_STATE GetState() const { return m_state; }
	bool IsSSL() const { return m_ssl; }

	// using a locking mechanism for some crashes that were happening on connections
	// that tried to reconnect a lot, although usually all calls to one socket originate
	// from the same thread.
	void Lock();
	void Unlock();

	// use this for completely unexpected cases:
	void Discard();

	void OnSSLHandshakeComplete();

	/**
	 * @return Modified data placed in m_sendBuffer yes/no
	 **/
	bool OnSending(bool a_ssl, const char* a_data, size_t a_len);
	void OnReceiving(bool a_ssl, const char* a_data, size_t a_len);

	std::string GetSendBuffer();
	bool HasReceivedLine() const;
	std::string ReadFromRecvBuffer(size_t a_max);
};

/** structs for SOCKS proxy detection.
	source: http://en.wikipedia.org/wiki/SOCKS **/

typedef struct {
	uint8_t version; // field 1: SOCKS version number, 1 byte, must be 0x04 for this version
	uint8_t command; // field 2: command code, 1 byte: 0x01 = establish a TCP/IP stream connection / 0x02 = establish a TCP/IP port binding
	uint16_t port;
	uint32_t ip_addr;
	// :TODO: + variable length field 5
} socks4_conn_request_t;

typedef struct {
	uint8_t version;
	uint8_t num_auth_methods;
	// field 3: authentication methods, variable length, 1 byte per method supported
} socks5_greeting_t;

/** imports from main FiSH DLL **/

namespace FiSH_DLL
{
	extern "C"
	{
		__declspec(dllimport) char* __stdcall _OnIncomingIRCLine(SOCKET a_socket, const char* a_line, size_t a_len);
		__declspec(dllimport) char* __stdcall _OnOutgoingIRCLine(SOCKET a_socket, const char* a_line, size_t a_len);
		__declspec(dllimport) void __stdcall _FreeString(const char* a_str);
		__declspec(dllimport) void __stdcall _OnSocketClosed(SOCKET a_socket);
	}
};

/** some debug helper business **/

void _fishInjectDebugMsg(const char* a_file, int a_line, const char* a_function, std::string a_message);

#ifdef _DEBUG
#define INJECT_DEBUG_MSG(A_MSG) _fishInjectDebugMsg(__FILE__, __LINE__, __FUNCTION__, A_MSG)
#else
#define INJECT_DEBUG_MSG(x)
#endif
