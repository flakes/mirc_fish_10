#include "inject-main.h"
#include "patcher.h"
#include "inject-socket.h"
#include "inject-engines.h"
#include "simple-thread-lock.h"

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

******************************************************************************/

/* global vars */
HMODULE g_hModule = NULL;

/* static vars */
static bool s_loaded = false;

/* CPatch instances */
typedef std::shared_ptr<CPatch> PPatch;
static PPatch s_patchConnect;
static PPatch s_patchSend;
static PPatch s_patchRecv;
static PPatch s_patchSendLegacy;
static PPatch s_patchRecvLegacy;
static PPatch s_patchCloseSocket;
static PPatch s_patchSSLWrite;
static PPatch s_patchSSLRead;

/* pointers to original/previous call locations */
static connect_proc     s_lpfn_connect;
static send_proc        s_lpfn_send, s_lpfn_send_legacy;
static recv_proc        s_lpfn_recv, s_lpfn_recv_legacy;
static closesocket_proc s_lpfn_closesocket;
static SSL_write_proc   s_lpfn_SSL_write;
static SSL_read_proc    s_lpfn_SSL_read;

/* active sockets */
typedef std::map<SOCKET, std::shared_ptr<CSocketInfo>> MActiveSocks;
static MActiveSocks s_sockets;
static CSimpleThreadLock s_socketsAccess;
static PInjectEngines s_engines;

/* pointers to utility methods from shared libs */
static SSL_get_fd_proc _SSL_get_fd;
static SSL_state_proc  _SSL_state;

/* from ssl.h */
#define SSL_ST_CONNECT      0x1000
#define SSL_ST_ACCEPT       0x2000
#define SSL_ST_MASK         0x0FFF
#define SSL_ST_INIT         (SSL_ST_CONNECT|SSL_ST_ACCEPT)
#define SSL_ST_BEFORE       0x4000
#define SSL_ST_OK           0x03
#define SSL_ST_RENEGOTIATE  (0x04|SSL_ST_INIT)

#define SSL_is_init_finished(a) (_SSL_state(a) == SSL_ST_OK)
#define SSL_in_init(a)          (_SSL_state(a)&SSL_ST_INIT)


/* patched connect call */
int WSAAPI my_connect(SOCKET s, const struct sockaddr FAR * name, int namelen)
{
	if(s != NULL)
	{
		CSimpleScopedLock lock(s_socketsAccess);

		s_sockets[s] = std::shared_ptr<CSocketInfo>(new CSocketInfo(s, s_engines));
	}

	return s_lpfn_connect(s, name, namelen);
}


/* patched send calls */
static int my_send_actual(SOCKET s, const char FAR * buf, int len, int flags, send_proc a_lpfn_send)
{
	if(!s || len < 1 || !buf)
		return a_lpfn_send(s, buf, len, flags);

	s_socketsAccess.Lock();
	auto it = s_sockets.find(s);

	if(it != s_sockets.end()
		&& !it->second->IsSSL() // ignore SSL connections, they have been handled in SSL_write
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.Unlock();

		l_sock->Lock();

		bool l_modified = l_sock->OnSending(false, buf, len);
		
		if(l_modified)
		{
			const std::string l_buf = l_sock->GetSendBuffer();

			l_sock->Unlock();

			int l_result = a_lpfn_send(s, l_buf.c_str(), l_buf.size(), flags);

			return (l_result > 0 ? len : l_result);
		}
		else
		{
			l_sock->Unlock();
			// fall through to normal send operation
		}
	}
	else
	{
		if(it != s_sockets.end() && it->second->GetState() == MSCK_NOT_IRC)
		{
			// "garbage collection" of sorts
			s_sockets.erase(it);
		}

		s_socketsAccess.Unlock();
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


/* patched recv calls */
static int my_recv_actual(SOCKET s, char FAR * buf, int len, int flags, recv_proc a_lpfn_recv)
{
	if(!s || !buf || len < 1)
		return a_lpfn_recv(s, buf, len, flags);

	s_socketsAccess.Lock();
	auto it = s_sockets.find(s);

	if(it != s_sockets.end()
		&& !it->second->IsSSL()  // ignore SSL connections, they have been handled in SSL_read
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.Unlock();

		l_sock->Lock();

		if(l_sock->GetState() != MSCK_IRC_IDENTIFIED)
		{
			// don't do much (anything) yet.

			l_sock->Unlock();

			char *l_localBuf = new char[len];

			int l_ret = a_lpfn_recv(s, l_localBuf, len, flags);

			if(l_ret > 0)
			{
				l_sock->Lock();
				l_sock->OnReceiving(false, l_localBuf, l_ret);
				l_sock->Unlock();

				memcpy_s(buf, len, l_localBuf, l_ret);
			}

			delete[] l_localBuf;

			return l_ret;
		}
		else
		{
			// it's an IRC connection, so let's rock.

			while(!l_sock->HasReceivedLine())
			{
				char l_localBuf[4150];

				l_sock->Unlock();

				int l_ret = a_lpfn_recv(s, l_localBuf, 4150, flags);

				if(l_ret < 1)
				{
					return l_ret;
				}

				l_sock->Lock();

				l_sock->OnReceiving(false, l_localBuf, l_ret);
			}

			// yay, there is a complete line in the buffer.

			const std::string l_tmp = l_sock->ReadFromRecvBuffer(len);

			l_sock->Unlock();

			memcpy_s(buf, len, l_tmp.c_str(), l_tmp.size());

			return l_tmp.size();
		}

		// never reached
	}
	else
	{
		if(it != s_sockets.end() && it->second->GetState() == MSCK_NOT_IRC)
		{
			// "garbage collection" of sorts
			s_sockets.erase(it);
		}

		s_socketsAccess.Unlock();
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
	{
		CSimpleScopedLock lock(s_socketsAccess);

		s_sockets.erase(s);
	}

	s_engines->OnSocketClosed(s);

	return s_lpfn_closesocket(s);
}


/* patched SSL_write call */
int __cdecl my_SSL_write(void *ssl, const void *buf, int num)
{
	if(!ssl || num < 1 || !buf)
		return s_lpfn_SSL_write(ssl, buf, num);

	SOCKET s = (SOCKET)_SSL_get_fd(ssl);

	if(!s)
		return s_lpfn_SSL_write(ssl, buf, num);

	s_socketsAccess.Lock();
	auto it = s_sockets.find(s);

	if(it != s_sockets.end()
		&& it->second->IsSSL()
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.Unlock();

		l_sock->Lock();

		if(l_sock->GetState() == MSCK_TLS_HANDSHAKE && SSL_is_init_finished(ssl))
		{
			l_sock->OnSSLHandshakeComplete();
		}

		bool l_modified = l_sock->OnSending(true, (const char*)buf, num);

		if(l_modified)
		{
			const std::string l_buf = l_sock->GetSendBuffer();

			l_sock->Unlock();

			int l_ret = s_lpfn_SSL_write(ssl, l_buf.c_str(), l_buf.size());

			return (l_ret > 0 ? num : l_ret);
		}
		else
		{
			l_sock->Unlock();
			// fall through to normal SSL_write call
		}
	}
	else
	{
		s_socketsAccess.Unlock();
	}

	return s_lpfn_SSL_write(ssl, buf, num);
}


/* patched SSL_read call */
int __cdecl my_SSL_read(void *ssl, void *buf, int num)
{
	if(!ssl || !buf || num < 0)
		return s_lpfn_SSL_read(ssl, buf, num);

	SOCKET s = (SOCKET)_SSL_get_fd(ssl);

	if(!s)
		return s_lpfn_SSL_read(ssl, buf, num);

	s_socketsAccess.Lock();
	auto it = s_sockets.find(s);

	if(it != s_sockets.end()
		&& it->second->IsSSL()
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.Unlock();

		l_sock->Lock();

		// terminate our internal handshake flag if the handshake is complete:
		if(l_sock->GetState() == MSCK_TLS_HANDSHAKE && SSL_is_init_finished(ssl))
		{
			l_sock->OnSSLHandshakeComplete();
		}

		if(l_sock->GetState() != MSCK_IRC_IDENTIFIED)
		{
			// don't do much (anything) yet.

			l_sock->Unlock();

			char *l_localBuf = new char[num];

			int l_ret = s_lpfn_SSL_read(ssl, l_localBuf, 1024);

			if(l_ret > 0)
			{
				l_sock->Lock();
				l_sock->OnReceiving(true, l_localBuf, l_ret);
				l_sock->Unlock();

				memcpy_s(buf, num, l_localBuf, l_ret);
			}

			delete[] l_localBuf;

			return l_ret;
		}
		else
		{
			// it's an IRC connection, so let's rock.
			// 1. if local (modified) buffer, read from that
			// 2. else if line incomplete, or empty local buffer, call s_lpfn_SSL_read

			while(!l_sock->HasReceivedLine())
			{
				char l_localBuf[1024];

				l_sock->Unlock();

				int l_ret = s_lpfn_SSL_read(ssl, l_localBuf, 1024);

				if(l_ret < 1)
				{
					return l_ret;
				}

				l_sock->Lock();

				l_sock->OnReceiving(true, l_localBuf, l_ret);
			}

			// yay, there is a complete line in the buffer.

			const std::string l_tmp = l_sock->ReadFromRecvBuffer(num);

			l_sock->Unlock();

			memcpy_s(buf, num, l_tmp.c_str(), l_tmp.size());

			return l_tmp.size();
		}

		// never reached
	}
	else
	{
		s_socketsAccess.Unlock();
	}
	
	return s_lpfn_SSL_read(ssl, buf, num);
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

		return;
	}
	else if(hInstSSLeay == NULL)
	{
		::MessageBoxW(info->mHwnd, L"FiSH 10 needs OpenSSL to be installed. Disabling. "
			L"Go to www.mirc.com/ssl.html to install SSL.", L"Error", MB_ICONEXCLAMATION);

		return;
	}

	s_engines = PInjectEngines(new CInjectEngines());

	HINSTANCE hInstWs2 = ::GetModuleHandleW(L"ws2_32.dll");

	// patch WinSock calls:
	connect_proc xconnect = (connect_proc)::GetProcAddress(hInstWs2, "connect");
	send_proc xsend = (send_proc)::GetProcAddress(hInstWs2, "send");
	recv_proc xrecv = (recv_proc)::GetProcAddress(hInstWs2, "recv");
	closesocket_proc xclosesock = (closesocket_proc)::GetProcAddress(hInstWs2, "closesocket");

	s_patchConnect = PPatch(new CPatch(xconnect, my_connect, s_lpfn_connect));
	s_patchSend = PPatch(new CPatch(xsend, my_send, s_lpfn_send));
	s_patchRecv = PPatch(new CPatch(xrecv, my_recv, s_lpfn_recv));
	s_patchCloseSocket = PPatch(new CPatch(xclosesock, my_closesocket, s_lpfn_closesocket));

	// patch legacy WinSock calls (may be used by OpenSSL DLLs):
	HINSTANCE hInstWsOld = ::GetModuleHandleW(L"wsock32.dll");

	send_proc xsend_legacy = (send_proc)::GetProcAddress(hInstWsOld, "send");
	recv_proc xrecv_legacy = (recv_proc)::GetProcAddress(hInstWsOld, "recv");

	if (xsend_legacy != NULL && xsend_legacy != xsend)
		s_patchSendLegacy = PPatch(new CPatch(xsend_legacy, my_send_legacy, s_lpfn_send_legacy));
	if (xrecv_legacy != NULL && xrecv_legacy != xrecv)
		s_patchRecvLegacy = PPatch(new CPatch(xrecv_legacy, my_recv_legacy, s_lpfn_recv_legacy));

	// patch OpenSSL calls:
	SSL_write_proc xsslwrite = (SSL_write_proc)::GetProcAddress(hInstSSLeay, "SSL_write");
	SSL_read_proc xsslread = (SSL_read_proc)::GetProcAddress(hInstSSLeay, "SSL_read");

	s_patchSSLWrite = PPatch(new CPatch(xsslwrite, my_SSL_write, s_lpfn_SSL_write));
	s_patchSSLRead = PPatch(new CPatch(xsslread, my_SSL_read, s_lpfn_SSL_read));

	// OpenSSL utility methods:
	_SSL_get_fd = (SSL_get_fd_proc)::GetProcAddress(hInstSSLeay, "SSL_get_fd");
	_SSL_state = (SSL_state_proc)::GetProcAddress(hInstSSLeay, "SSL_state");

	// check if it worked:
	if(s_patchConnect->patched() && s_patchRecv->patched() && s_patchSend->patched() &&
		(!hInstSSLeay || (s_patchSSLWrite->patched() && s_patchSSLRead->patched())) &&
		(_SSL_get_fd != NULL) && (_SSL_state != NULL))
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

		s_patchConnect.reset();
		s_patchSend.reset();
		s_patchRecv.reset();
		s_patchRecvLegacy.reset();
		s_patchSendLegacy.reset();
		s_patchCloseSocket.reset();
		s_patchSSLWrite.reset();
		s_patchSSLRead.reset();

		std::wstring l_errorInfo = L"FiSH 10 failed to load: Patching functions in memory was unsuccessful.";
		l_errorInfo += L"\r\nDebug info: ";
		l_errorInfo += wszPatchedInfo;

		::MessageBoxW(info->mHwnd, l_errorInfo.c_str(), L"Error", MB_ICONEXCLAMATION);
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
		if (!s_loaded)
		{
			s_engines.reset();
		}

		return (s_loaded ? 0 : 1);
	}
	else
	{
		s_loaded = false;

		s_patchConnect.reset();
		s_patchSend.reset();
		s_patchRecv.reset();
		s_patchRecvLegacy.reset();
		s_patchSendLegacy.reset();
		s_patchCloseSocket.reset();
		s_patchSSLWrite.reset();
		s_patchSSLRead.reset();

		s_engines.reset();

		return 0;
	}
}


/* returns 0 on success */
extern "C" int RegisterEngine(const fish_inject_engine_t *pEngine)
{
	if (!s_engines)
		return -1;

	return (s_engines->Register(0, pEngine) ? 0 : 1);
}


/* returns 0 on success */
extern "C" int UnregisterEngine(const fish_inject_engine_t *pEngine)
{
	if (!s_engines)
		return -1;

	return (s_engines->Unregister(pEngine) ? 0 : 1);
}


/* dummy call to facilitate loading of DLL */

extern "C" int __stdcall _callMe(HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
{
	strcpy_s(data, 900, "/echo -a *** FiSH 10.2 *** by [c&f] *** fish_inject.dll compiled " __DATE__ " " __TIME__ " ***");
	return 2;
}


/* DllMain */


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		g_hModule = static_cast<HMODULE>(hinstDLL);
	}

	return TRUE;
}



#ifdef _DEBUG
/* blergh */

void _fishInjectDebugMsg(const char* a_file, int a_line, const char* a_function, const std::string& a_message)
{
	wchar_t _tid[20];
	swprintf_s(_tid, 20, L"[%08x] ", GetCurrentThreadId());

	CSimpleScopedLock lock(s_socketsAccess); // mis-use, but safe currently

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
