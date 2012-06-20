#include "targetver.h"

#include <ws2tcpip.h>
#include <windows.h>
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


/*  */
class CSocketInfo
{
protected:
	SOCKET m_socket;
	bool m_ssl, m_sslShakingHands;
	bool m_dataExchanged;
	// this is a workaround for when mIRC calls SSL_read before sending CAP LS:
	int m_numSuccessfulReads;

	// for unencrypted data, ready to be fetched from outside:
	std::string m_sendBuffer;
	std::string m_receivedBuffer;

	// for incomplete lines:
	std::string m_sendingBuffer;
	std::string m_receivingBuffer;

public:
	CSocketInfo(SOCKET s);

	/**
	 * @return Modified data placed in m_sendBuffer yes/no
	 **/
	bool OnSending(bool a_ssl, const char* a_data, size_t a_len);
	void OnSendingSSLHandshakePacket() { m_sslShakingHands = true; }

	void OnBeforeReceive(bool a_ssl);
	void OnAfterReceive(const char* a_data, size_t a_len);
	int OnSuccessfulReadDuringInit() { return ++m_numSuccessfulReads; };

	bool IsSSL() const { return m_ssl; }
	bool IsSSLShakingHands() const { return m_sslShakingHands; }
	bool HasExchangedData() const { return m_dataExchanged; }

	std::string GetSendBuffer();
	bool HasReceivedLine() const;
	std::string ReadFromRecvBuffer(size_t a_max);
};


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


void _fishInjectDebugMsg(const char* a_file, int a_line, const char* a_function, std::string a_message);

#ifdef _DEBUG
#define INJECT_DEBUG_MSG(A_MSG) _fishInjectDebugMsg(__FILE__, __LINE__, __FUNCTION__, A_MSG)
#else
#define INJECT_DEBUG_MSG(x)
#endif
