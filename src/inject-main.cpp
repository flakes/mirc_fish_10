#include "inject-main.h"

/******************************************************************************

          FiSH for mIRC 7 via DLL injection and in-memory patching

 Here's how it's done:
 First, we use CPatch from CodeProject to redirect the Winsock API calls
 connect, send and recv to this library. I had to modify CPatch a little so
 that it became able to redirect OpenSSL's SSL_read and SSL_write as well.

 The next step is to figure out whether a connection (identified by its
 SOCKET/fd) is an IRC client connection or something else (DCC, script, ident).
 To do that, we only look at connections that are established using connect
 (and not accept or something). We look at the first bytes that mIRC sends.
 Those are always "CAP LS" if it's a connection like we are looking for. We
 also have to keep track of whether a SOCKET is using SSL or not and we need
 to skip the SSL handshake in send (when firstly invoked from libssl).
 Sounds a bit messy, but gets us a nice list of all SOCKETs that are IRC
 client connections. Using that, we can do our thing in send/SSL_write and
 recv/SSL_read.

 Important: Some libeay32.dll files use send and recv from ws2_32.dll,
 others one or both from wsock32.dll ... and wsock32.dll links one or both
 of those to the imports from ws2_32.dll on some Windowses. Need to work
 around that mess.

 Oh and this code uses some C++0x features so you better get MSVC++ 2010.

******************************************************************************/

/* static vars */
static bool s_loaded = false;

/* CPatch instances */
static CPatch* s_patchConnect;
static CPatch* s_patchSend;
static CPatch* s_patchRecv;
static CPatch* s_patchSendLegacy;
static CPatch* s_patchRecvLegacy;
static CPatch* s_patchCloseSocket;
static CPatch* s_patchSSLWrite;
static CPatch* s_patchSSLRead;

/* pointers to original/previous call locations */
static connect_proc		s_lpfn_connect;
static send_proc		s_lpfn_send, s_lpfn_send_legacy;
static recv_proc		s_lpfn_recv, s_lpfn_recv_legacy;
static closesocket_proc	s_lpfn_closesocket;
static SSL_write_proc	s_lpfn_SSL_write;
static SSL_read_proc	s_lpfn_SSL_read;

/* active sockets */
typedef std::map<SOCKET, std::shared_ptr<CSocketInfo> > MActiveSocks;
static MActiveSocks s_sockets;
static CRITICAL_SECTION s_socketsLock;

/* pointers to utility methods from shared libs */
static SSL_get_fd_proc _SSL_get_fd;


/* patched connect call */
int WSAAPI my_connect(SOCKET s, const struct sockaddr FAR * name, int namelen)
{
	if(s != NULL)
	{
		::EnterCriticalSection(&s_socketsLock);
		s_sockets[s] = std::shared_ptr<CSocketInfo>(new CSocketInfo(s));
		::LeaveCriticalSection(&s_socketsLock);
	}

	return s_lpfn_connect(s, name, namelen);
}


/* patched send calls */
int WSAAPI my_send_actual(SOCKET s, const char FAR * buf, int len, int flags, send_proc a_lpfn_send)
{
	::EnterCriticalSection(&s_socketsLock);
	auto it = s_sockets.find(s);

	if(it != s_sockets.end() && !it->second->IsSSL() && len > 0)
	{
		auto l_sock = it->second;

		::LeaveCriticalSection(&s_socketsLock);

		if(!l_sock->HasExchangedData() && buf != NULL && *buf == 22) // skip SSL handshake packets... oh lord...
			// http://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake_in_detail
			// do this for the first packets only, of course.
		{
			l_sock->OnSendingSSLHandshakePacket();
		}
		else
		{
			bool l_modified = l_sock->OnSending(false, buf, len);

			if(!l_modified && !l_sock->HasExchangedData())
			{
				::EnterCriticalSection(&s_socketsLock);
				s_sockets.erase(s);
				::LeaveCriticalSection(&s_socketsLock);
			}

			if(l_modified)
			{
				const std::string l_buf = l_sock->GetSendBuffer();
				int l_result = a_lpfn_send(s, l_buf.c_str(), l_buf.size(), flags);

				return (l_result > 0 ? len : l_result);
			}
		}
	}
	else
	{
		::LeaveCriticalSection(&s_socketsLock);
	}

	return a_lpfn_send(s, buf, len, flags);
}

int WSAAPI my_send_legacy(SOCKET s, const char FAR * buf, int len, int flags)
{
	return my_send_actual(s, buf, len, flags, s_lpfn_send_legacy);
}

int WSAAPI my_send(SOCKET s, const char FAR * buf, int len, int flags)
{
	return my_send_actual(s, buf, len, flags, s_lpfn_send);
}


/* patched recv call */
int WSAAPI my_recv_actual(SOCKET s, char FAR * buf, int len, int flags, recv_proc a_lpfn_recv)
{
	::EnterCriticalSection(&s_socketsLock);
	auto it = s_sockets.find(s);

	if(it != s_sockets.end() && !it->second->IsSSL() &&
		!it->second->IsSSLShakingHands() && len > 0)
	{
		auto l_sock = it->second;

		::LeaveCriticalSection(&s_socketsLock);

		// important for receiving files via DCC:
		// IRC server connections will always have sent data before receiving any.
		if(!l_sock->HasExchangedData())
		{
			::EnterCriticalSection(&s_socketsLock);
			s_sockets.erase(s);
			::LeaveCriticalSection(&s_socketsLock);

			return a_lpfn_recv(s, buf, len, flags);
		}

		while(!l_sock->HasReceivedLine())
		{
			char l_localBuf[4150];

			int l_ret = a_lpfn_recv(s, l_localBuf, 4150, flags);

			if(l_ret < 1)
			{
				return l_ret;
			}

			l_sock->OnAfterReceive(l_localBuf, l_ret);
		}

		// yay we got a complete line in the buffer.

		const std::string l_tmp = l_sock->ReadFromRecvBuffer(len);

		memcpy(buf, l_tmp.c_str(), l_tmp.size());

		return l_tmp.size();
	}
	else
	{
		::LeaveCriticalSection(&s_socketsLock);
	}

	return a_lpfn_recv(s, buf, len, flags);
}

int WSAAPI my_recv_legacy(SOCKET s, char FAR * buf, int len, int flags)
{
	return my_recv_actual(s, buf, len, flags, s_lpfn_recv_legacy);
}

int WSAAPI my_recv(SOCKET s, char FAR * buf, int len, int flags)
{
	return my_recv_actual(s, buf, len, flags, s_lpfn_recv);
}


/* patched closesocket call */
int WSAAPI my_closesocket(SOCKET s)
{
	::EnterCriticalSection(&s_socketsLock);
	s_sockets.erase(s);
	::LeaveCriticalSection(&s_socketsLock);

	FiSH_DLL::_OnSocketClosed(s);

	return s_lpfn_closesocket(s);
}


/* patched SSL_write call */
int __cdecl my_SSL_write(void *ssl, const void *buf, int num)
{
	SOCKET s = (SOCKET)_SSL_get_fd(ssl);

	::EnterCriticalSection(&s_socketsLock);
	auto it = s_sockets.find(s);

	if(it != s_sockets.end())
	{
		auto l_sock = it->second;

		::LeaveCriticalSection(&s_socketsLock);

		bool l_modified = l_sock->OnSending(true, (const char*)buf, num);

		if(!l_modified && !l_sock->HasExchangedData())
		{
			::EnterCriticalSection(&s_socketsLock);
			s_sockets.erase(s);
			::LeaveCriticalSection(&s_socketsLock);
		}

		if(l_modified)
		{
			const std::string l_buf = l_sock->GetSendBuffer();
			int l_sslResult = s_lpfn_SSL_write(ssl, l_buf.c_str(), l_buf.size());

			return (l_sslResult > 0 ? num : l_sslResult);
		}
	}
	else
	{
		::LeaveCriticalSection(&s_socketsLock);
	}

	return s_lpfn_SSL_write(ssl, buf, num);
}


/* patched SSL_read call */
int __cdecl my_SSL_read(void *ssl, void *buf, int num)
{
	// 1. if local (modified) buffer, read from that
	// 2. else if line incomplete, or empty local buffer, call s_lpfn_SSL_read

	SOCKET s = (SOCKET)_SSL_get_fd(ssl);

	::EnterCriticalSection(&s_socketsLock);
	auto it = s_sockets.find(s);

	if(it != s_sockets.end())
	{
		auto l_sock = it->second;

		::LeaveCriticalSection(&s_socketsLock);

		// in case mIRC ever gets DCC-over-SSL support,
		// we will be prepared:
		if(!l_sock->HasExchangedData())
		{
			::EnterCriticalSection(&s_socketsLock);
			s_sockets.erase(s);
			::LeaveCriticalSection(&s_socketsLock);

			return s_lpfn_SSL_read(ssl, buf, num);
		}

		while(!l_sock->HasReceivedLine())
		{
			char l_localBuf[1024];

			int l_sslRet = s_lpfn_SSL_read(ssl, l_localBuf, 1024);

			if(l_sslRet < 1)
			{
				return l_sslRet;
			}

			l_sock->OnAfterReceive(l_localBuf, l_sslRet);
		}

		// yay we got a complete line in the buffer.

		const std::string l_tmp = l_sock->ReadFromRecvBuffer(num);

		memcpy(buf, l_tmp.c_str(), l_tmp.size());

		return l_tmp.size();
	}
	else
	{
		::LeaveCriticalSection(&s_socketsLock);

		return s_lpfn_SSL_read(ssl, buf, num);
	}
}



/* You can keep a DLL loaded by including a LoadDll() routine in your DLL, which mIRC calls the first time you load the DLL. */

extern "C" void __stdcall LoadDll(LOADINFO* info)
{
	info->mKeep = FALSE;

	HINSTANCE hInstSSLeay = ::GetModuleHandleW(L"ssleay32.dll");

	if(LOWORD(info->mVersion) < 7)
	{
		::MessageBoxW(info->mHwnd, L"FiSH 10 does not support any mIRC version older "
			L"than v7. Disabling.", L"Error", MB_ICONEXCLAMATION);
	}
	else if(hInstSSLeay == NULL)
	{
		::MessageBoxW(info->mHwnd, L"FiSH 10 needs OpenSSL to be installed. Disabling. "
			L"Go to www.mirc.com/ssl.html to install SSL.", L"Error", MB_ICONEXCLAMATION);
	}
	else
	{
		::InitializeCriticalSection(&s_socketsLock);

		HINSTANCE hInstWs2 = ::GetModuleHandleW(L"ws2_32.dll");

		// patch WinSock calls:
		connect_proc xconnect = (connect_proc)::GetProcAddress(hInstWs2, "connect");
		send_proc xsend = (send_proc)::GetProcAddress(hInstWs2, "send");
		recv_proc xrecv = (recv_proc)::GetProcAddress(hInstWs2, "recv");
		closesocket_proc xclosesock = (closesocket_proc)::GetProcAddress(hInstWs2, "closesocket");

		s_patchConnect = new CPatch(xconnect, my_connect, s_lpfn_connect);
		s_patchSend = new CPatch(xsend, my_send, s_lpfn_send);
		s_patchRecv = new CPatch(xrecv, my_recv, s_lpfn_recv);
		s_patchCloseSocket = new CPatch(xclosesock, my_closesocket, s_lpfn_closesocket);

		// patch legacy WinSock calls (may be used by OpenSSL DLLs):
		HINSTANCE hInstWsOld = ::GetModuleHandleW(L"wsock32.dll");

		send_proc xsend_legacy = (send_proc)::GetProcAddress(hInstWsOld, "send");
		recv_proc xrecv_legacy = (recv_proc)::GetProcAddress(hInstWsOld, "recv");

		if(xsend_legacy != NULL && xsend_legacy != xsend) s_patchSendLegacy = new CPatch(xsend_legacy, my_send_legacy, s_lpfn_send_legacy);
		if(xrecv_legacy != NULL && xrecv_legacy != xrecv) s_patchRecvLegacy = new CPatch(xrecv_legacy, my_recv_legacy, s_lpfn_recv_legacy);

		// patch OpenSSL calls:
		SSL_write_proc xsslwrite = (SSL_write_proc)::GetProcAddress(hInstSSLeay, "SSL_write");
		SSL_read_proc xsslread = (SSL_read_proc)::GetProcAddress(hInstSSLeay, "SSL_read");

		s_patchSSLWrite = new CPatch(xsslwrite, my_SSL_write, s_lpfn_SSL_write);
		s_patchSSLRead = new CPatch(xsslread, my_SSL_read, s_lpfn_SSL_read);

		// OpenSSL utility methods:
		_SSL_get_fd = (SSL_get_fd_proc)::GetProcAddress(hInstSSLeay, "SSL_get_fd");

		// check if it worked:
		if(s_patchConnect->patched() && s_patchRecv->patched() && s_patchSend->patched() &&
			(!hInstSSLeay || (s_patchSSLWrite->patched() && s_patchSSLRead->patched())))
		{
			info->mKeep = TRUE;

			s_loaded = true;
		}
		else
		{
			wchar_t wszPatchedInfo[50] = {0};
			swprintf_s(wszPatchedInfo, 50, L"[%i%i%i%i%i%i%i%i]",
				(s_patchConnect->patched() ? 1 : 0),
				(s_patchSend->patched() ? 1 : 0),
				(s_patchRecv->patched() ? 1 : 0),
				(!s_patchRecvLegacy || s_patchRecvLegacy->patched() ? 1 : 0),
				(!s_patchSendLegacy || s_patchSendLegacy->patched() ? 1 : 0),
				(s_patchCloseSocket->patched() ? 1 : 0),
				(s_patchSSLWrite->patched() ? 1 : 0),
				(s_patchSSLRead->patched() ? 1 : 0));

			delete s_patchConnect; s_patchConnect = NULL;
			delete s_patchSend; s_patchSend = NULL;
			delete s_patchRecv; s_patchRecv = NULL;
			delete s_patchRecvLegacy; s_patchRecvLegacy = NULL;
			delete s_patchSendLegacy; s_patchSendLegacy = NULL;
			delete s_patchCloseSocket; s_patchCloseSocket = NULL;
			delete s_patchSSLWrite; s_patchSSLWrite = NULL;
			delete s_patchSSLRead; s_patchSSLRead = NULL;

			std::wstring l_errorInfo = L"FiSH 10 failed to load: Patching functions in memory was unsuccessful.";
			l_errorInfo += L"\r\nDebug info: ";
			l_errorInfo += wszPatchedInfo;

			::MessageBoxW(info->mHwnd, l_errorInfo.c_str(), L"Error", MB_ICONEXCLAMATION);
		}
	}
}


/* You can also define an UnloadDll() routine in your DLL which mIRC will call when unloading a DLL to allow it to clean up. */

extern "C" int __stdcall UnloadDll(int mTimeout)
{
/* The mTimeout value can be:
   0   UnloadDll() is being called due to a DLL being unloaded with /dll -u.
   1   UnloadDll() is being called due to a DLL not being used for ten minutes.
			The UnloadDll() routine can return 0 to keep the DLL loaded, or 1 to allow it to be unloaded.
   2   UnloadDll() is being called due to a DLL being unloaded when mIRC exits.
*/
	if(mTimeout == 1)
	{
		if(!s_loaded) ::DeleteCriticalSection(&s_socketsLock);

		return (s_loaded ? 0 : 1);
	}
	else
	{
		delete s_patchConnect;
		delete s_patchSend;
		delete s_patchRecv;
		delete s_patchRecvLegacy;
		delete s_patchSendLegacy;
		delete s_patchCloseSocket;
		delete s_patchSSLWrite;
		delete s_patchSSLRead;
		::DeleteCriticalSection(&s_socketsLock);

		return 0;
	}
}


/* dummy call to facilitate loading of DLL */

extern "C" int __stdcall _callMe(HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
{
	strcpy_s(data, 900, "/echo -a *** FiSH 10 *** by [c&f] *** fish_inject.dll compiled " __DATE__ " " __TIME__ " ***");
	return 2;
}


#ifdef _DEBUG
/* blergh */

void _fishInjectDebugMsg(const char* a_file, int a_line, const char* a_function, std::string a_message)
{
	wchar_t _tid[20];
	swprintf_s(_tid, 20, L"[%08x] ", GetCurrentThreadId());
	OutputDebugStringW(_tid);
	OutputDebugStringA(a_function);
	if(!a_message.empty())
	{
		OutputDebugStringA(" >> ");
		OutputDebugStringA(a_message.c_str());
		if(a_message.rfind('\n') != a_message.size() - 1) OutputDebugStringA("\n");
	}
	else
	{
		OutputDebugStringA("\n");
	}
}
#endif

static_assert(sizeof(SOCKET) == sizeof(HANDLE), "fail");
