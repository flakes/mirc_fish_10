#include "targetver.h"

#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <memory>
#include <map>
#include "patcher.h"


/** here comes the main socket logic class **/

typedef enum {
	MSCK_INITIALIZING = 0,
	MSCK_TLS_HANDSHAKE,
	MSCK_SOCKS4_HANDSHAKE,
	MSCK_SOCKS5_GREETING,
	MSCK_SOCKS5_AUTHENTICATION,
	MSCK_SOCKS5_CONNECTION,
	MSCK_HTTP_PROXY_HANDSHAKE,
	MSCK_IRC_IDENTIFIED,
	MSCK_NOT_IRC
} MIRC_SOCKET_STATE;


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

	// used internally:
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

	// handshake completition must be detected via external means,
	// then reported with this method:
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
	uint8_t nulbyte;
	uint8_t status; // 0x5a = request granted
	uint16_t junk1;
	uint32_t junk2;
} socks4_conn_response_t;

typedef struct {
	uint8_t version; // must be 0x05
	uint8_t num_auth_methods;
	// field 3: authentication methods, variable length, 1 byte per method supported
} socks5_greeting_t;

typedef struct {
	uint8_t version; // must be 0x05
	uint8_t auth_method;
} socks5_greeting_response_t;

typedef struct {
	uint8_t version; // must be 0x05
	uint8_t command; // 0x01 = establish a TCP/IP stream connection
	uint8_t reserved1;
	uint8_t addr_type;
	// field 5: destination address of: 4 bytes for IPv4 address / 1 byte of name length followed by the name for Domain name / 16 bytes for IPv6 address
	// field 6: port number in a network byte order, 2 bytes
} socks5_conn_request_t;

typedef struct {
	uint8_t version; // must be 0x05
	uint8_t status; // 0x00 = request granted
	uint8_t reserved1;
	uint8_t addr_type;
	// field 5: destination address of: 4 bytes for IPv4 address / 1 byte of name length followed by the name for Domain name / 16 bytes for IPv6 address
	// field 6: port number in a network byte order, 2 bytes
} socks5_conn_response_t;


/* function signature typedefs */
typedef int(WSAAPI* connect_proc)(SOCKET s, const struct sockaddr FAR * name, int namelen);
typedef int(WSAAPI* send_proc)(SOCKET, const char*, int, int);
typedef int(WSAAPI* recv_proc)(SOCKET, char*, int, int);
typedef int(WSAAPI* closesocket_proc)(SOCKET);
typedef int(__cdecl* SSL_write_proc)(void *ssl, const void *buf, int num);
typedef int(__cdecl* SSL_read_proc)(void *ssl, void *buf, int num);

typedef int(__cdecl* SSL_state_proc)(const void *ssl);
typedef int(__cdecl* SSL_get_fd_proc)(const void *ssl);


/* from mIRC help file */
typedef struct {
	DWORD  mVersion;
	HWND   mHwnd;
	BOOL   mKeep;
	BOOL   mUnicode;
} LOADINFO;


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

void _fishInjectDebugMsg(const char* a_file, int a_line, const char* a_function, const std::string& a_message);

#ifdef _DEBUG
#define INJECT_DEBUG_MSG(A_MSG) _fishInjectDebugMsg(__FILE__, __LINE__, __FUNCTION__, A_MSG)
#else
#define INJECT_DEBUG_MSG(x)
#endif
