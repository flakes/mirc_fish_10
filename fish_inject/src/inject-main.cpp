#include "inject-main.h"
#include "inject-socket.h"
#include "inject-engines.h"
#include "patch.h"

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
HMODULE g_hModule = nullptr;

/* static vars */
static bool s_loaded = false;
static DWORD s_maxMircReturnBytes = MIRC_PARAM_DATA_LENGTH_LOW;

/* CPatch instances */
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
static CMultiReaderSingleWriterLock s_socketsAccess;
static PInjectEngines s_engines;
static size_t s_discardedSockets; // number of sockets that were deemed "not IRC"

/* pointers to utility methods from shared libs */
static SSL_get_fd_proc _SSL_get_fd;
static SSL_is_init_finished_proc _SSL_is_init_finished;


/* patched connect call */
int WSAAPI my_connect(SOCKET s, const struct sockaddr FAR* name, int namelen)
{
	if (s)
	{
		s_socketsAccess.EnterWriter();

		s_sockets[s] = std::make_shared<CSocketInfo>(s, s_engines);

		s_socketsAccess.LeaveWriter();
	}

	return s_lpfn_connect(s, name, namelen);
}


/* patched send calls */
static int my_send_actual(SOCKET s, const char FAR* buf, int len, int flags, send_proc a_lpfn_send)
{
	if (!s || len < 1 || !buf)
		return a_lpfn_send(s, buf, len, flags);

	s_socketsAccess.EnterReader();
	auto it = s_sockets.find(s);

	if (it != s_sockets.end()
		&& !it->second->IsSSL() // ignore SSL connections, they have been handled in SSL_write
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.LeaveReader();

		l_sock->Lock();

		bool l_modified = l_sock->OnSending(false, buf, len);

		if (l_modified)
		{
			const std::string l_buf = l_sock->GetSendBuffer();

			l_sock->Unlock();

			if (!l_buf.empty())
			{
				int l_result = a_lpfn_send(s, l_buf.c_str(), l_buf.size(), flags);

				return (l_result > 0 ? len : l_result);
			}
			else
			{
				// probably a fake message for one of the engines, pretend it has been sent.
				return len;
			}
		}
		else
		{
			l_sock->Unlock();
			// fall through to normal send operation
		}
	}
	else
	{
		if (it != s_sockets.end() && it->second->GetState() == MSCK_NOT_IRC)
		{
			// "garbage collection" of sorts
			s_sockets.erase(it);

			++s_discardedSockets;
		}

		s_socketsAccess.LeaveReader();
	}

	return a_lpfn_send(s, buf, len, flags);
}

int WSAAPI my_send_legacy(SOCKET s, const char FAR* buf, int len, int flags)
{
	return my_send_actual(s, buf, len, flags, s_lpfn_send_legacy);
}

int WSAAPI my_send(SOCKET s, const char FAR* buf, int len, int flags)
{
	return my_send_actual(s, buf, len, flags, s_lpfn_send);
}


/* patched recv calls */
static int my_recv_actual(SOCKET s, char FAR* buf, int len, int flags, recv_proc a_lpfn_recv)
{
	if (!s || !buf || len < 1)
		return a_lpfn_recv(s, buf, len, flags);

	s_socketsAccess.EnterReader();
	auto it = s_sockets.find(s);

	if (it != s_sockets.end()
		&& !it->second->IsSSL()  // ignore SSL connections, they have been handled in SSL_read
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.LeaveReader();

		l_sock->Lock();

		if (l_sock->GetState() != MSCK_IRC_IDENTIFIED)
		{
			// don't do much (anything) yet.

			l_sock->Unlock();

			std::vector<char> l_localBuf;
			l_localBuf.resize(len, 0);

			int l_ret = a_lpfn_recv(s, l_localBuf.data(), len, flags);

			if (l_ret > 0)
			{
				l_sock->Lock();
				l_sock->OnReceiving(false, l_localBuf.data(), l_ret);
				l_sock->Unlock();

				memcpy_s(buf, len, l_localBuf.data(), l_ret);
			}

			return l_ret;
		}
		else
		{
			// it's an IRC connection, so let's rock.

			while (!l_sock->HasReceivedLine())
			{
				char l_localBuf[4150];

				l_sock->Unlock();

				int l_ret = a_lpfn_recv(s, l_localBuf, 4150, flags);

				if (l_ret < 1)
				{
					return l_ret;
				}

				l_sock->Lock();

				l_sock->OnReceiving(false, l_localBuf, l_ret);
			}

			// yay, there is a complete line in the buffer.

			const std::string l_tmp(l_sock->ReadFromRecvBuffer(len));

			l_sock->Unlock();

			memcpy_s(buf, len, l_tmp.c_str(), l_tmp.size());

			return l_tmp.size();
		}

		// never reached
	}
	else
	{
		if (it != s_sockets.end() && it->second->GetState() == MSCK_NOT_IRC)
		{
			// "garbage collection" of sorts
			s_sockets.erase(it);

			++s_discardedSockets;
		}

		s_socketsAccess.LeaveReader();
	}

	return a_lpfn_recv(s, buf, len, flags);
}

int WSAAPI my_recv_legacy(SOCKET s, char FAR* buf, int len, int flags)
{
	return my_recv_actual(s, buf, len, flags, s_lpfn_recv_legacy);
}

int WSAAPI my_recv(SOCKET s, char FAR* buf, int len, int flags)
{
	return my_recv_actual(s, buf, len, flags, s_lpfn_recv);
}


/* patched closesocket call */
int WSAAPI my_closesocket(SOCKET s)
{
	{
		s_socketsAccess.EnterWriter();

		s_sockets.erase(s);

		s_socketsAccess.LeaveWriter();
	}

	s_engines->OnSocketClosed(s);

	return s_lpfn_closesocket(s);
}


/* patched SSL_write call */
int __cdecl my_SSL_write(void* ssl, const void* buf, int num)
{
	if (!ssl || num < 1 || !buf)
		return s_lpfn_SSL_write(ssl, buf, num);

	SOCKET s = (SOCKET)_SSL_get_fd(ssl);

	if (!s)
		return s_lpfn_SSL_write(ssl, buf, num);

	s_socketsAccess.EnterReader();
	auto it = s_sockets.find(s);

	if (it != s_sockets.end()
		&& it->second->IsSSL()
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.LeaveReader();

		l_sock->Lock();

		if (l_sock->GetState() == MSCK_TLS_HANDSHAKE && _SSL_is_init_finished(ssl))
		{
			l_sock->OnSSLHandshakeComplete();
		}

		bool l_modified = l_sock->OnSending(true, (const char*)buf, num);

		if (l_modified)
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
		s_socketsAccess.LeaveReader();
	}

	return s_lpfn_SSL_write(ssl, buf, num);
}


/* patched SSL_read call */
int __cdecl my_SSL_read(void* ssl, void* buf, int num)
{
	if (!ssl || !buf || num < 0)
		return s_lpfn_SSL_read(ssl, buf, num);

	SOCKET s = (SOCKET)_SSL_get_fd(ssl);

	if (!s)
		return s_lpfn_SSL_read(ssl, buf, num);

	s_socketsAccess.EnterReader();
	auto it = s_sockets.find(s);

	if (it != s_sockets.end()
		&& it->second->IsSSL()
		&& it->second->GetState() != MSCK_NOT_IRC)
	{
		auto l_sock = it->second;

		s_socketsAccess.LeaveReader();

		l_sock->Lock();

		// terminate our internal handshake flag if the handshake is complete:
		if (l_sock->GetState() == MSCK_TLS_HANDSHAKE && _SSL_is_init_finished(ssl))
		{
			l_sock->OnSSLHandshakeComplete();
		}

		if (l_sock->GetState() != MSCK_IRC_IDENTIFIED)
		{
			// don't do much (anything) yet.

			l_sock->Unlock();

			std::vector<char> l_localBuf;
			l_localBuf.resize(num, 0);

			int l_ret = s_lpfn_SSL_read(ssl, l_localBuf.data(), 1024);

			if (l_ret > 0)
			{
				l_sock->Lock();
				l_sock->OnReceiving(true, l_localBuf.data(), l_ret);
				l_sock->Unlock();

				memcpy_s(buf, num, l_localBuf.data(), l_ret);
			}

			return l_ret;
		}
		else
		{
			// it's an IRC connection, so let's rock.
			// 1. if local (modified) buffer, read from that
			// 2. else if line incomplete, or empty local buffer, call s_lpfn_SSL_read

			while (!l_sock->HasReceivedLine())
			{
				char l_localBuf[1024];

				l_sock->Unlock();

				int l_ret = s_lpfn_SSL_read(ssl, l_localBuf, 1024);

				if (l_ret < 1)
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
		s_socketsAccess.LeaveReader();
	}

	return s_lpfn_SSL_read(ssl, buf, num);
}


/* You can keep a DLL loaded by including a LoadDll() routine in your DLL, which mIRC calls the first time you load the DLL. */
extern "C" void __stdcall LoadDll(LOADINFO * info)
{
	info->mKeep = TRUE; // always keep DLL around to avoid errors showing up multiple times.
	info->mUnicode = FALSE; // no point in converting back&forth with sockets
	s_maxMircReturnBytes = info->mBytes;

	INJECT_DEBUG_MSG("");

	const HMODULE hInstSSLLib = ::GetModuleHandleW(L"libssl-3.dll");
	const HMODULE hInstCryptoLib = ::GetModuleHandleW(L"libcrypto-3.dll");

	if (LOWORD(info->mVersion) < 7 || HIWORD(info->mVersion) < 73)
	{
		::MessageBoxW(info->mHwnd, L"This version of FiSH does not support any mIRC version older than 7.73. Disabling.", L"Error", MB_ICONEXCLAMATION);

		return;
	}
	else if (hInstSSLLib == nullptr || hInstCryptoLib == nullptr)
	{
		::MessageBoxW(info->mHwnd,
			L"FiSH needs the OpenSSL DLLs to be installed and loaded. Disabling.\r\n\r\n"
			L"Hint: Setting load=1 under [ssl] in mirc.ini is necessary. "
			L"Please check the README or use the provided FiSH installer.",
			L"Error", MB_ICONEXCLAMATION);

		return;
	}

	const auto OSSL_PROVIDER_load = (OSSL_PROVIDER_load_proc)::GetProcAddress(hInstCryptoLib, "OSSL_PROVIDER_load");
	const auto OSSL_PROVIDER_available = (OSSL_PROVIDER_available_proc)::GetProcAddress(hInstCryptoLib, "OSSL_PROVIDER_available");
	void* legacyCryptoAlgorithmsProvider = nullptr;

	if (OSSL_PROVIDER_available != nullptr && !OSSL_PROVIDER_available(nullptr, "legacy") && OSSL_PROVIDER_load != nullptr)
	{
		char cryptLibDirectoryBuf[4096] = { 0 };

		if (::GetModuleFileNameA(hInstCryptoLib, cryptLibDirectoryBuf, 4000) != 0)
		{
			if (::PathRemoveFileSpecA(cryptLibDirectoryBuf)
				&& ::PathAppendA(cryptLibDirectoryBuf, "libcrypto-legacy.dll"))
			{
				legacyCryptoAlgorithmsProvider = OSSL_PROVIDER_load(nullptr, cryptLibDirectoryBuf);
			}
		}
	}

	if (legacyCryptoAlgorithmsProvider == nullptr)
	{
		::MessageBoxW(info->mHwnd,
			L"FiSH needs the OpenSSL Legacy Provider DLL (libcrypto-legacy.dll) to be installed and loaded. Disabling.", L"Error", MB_ICONEXCLAMATION);

		return;
	}

	CPatch::Initialize();

	s_engines = std::make_shared<CInjectEngines>();

	HINSTANCE hInstWs2 = ::GetModuleHandleW(L"ws2_32.dll");

	// patch WinSock calls:
	connect_proc xconnect = (connect_proc)::GetProcAddress(hInstWs2, "connect");
	send_proc xsend = (send_proc)::GetProcAddress(hInstWs2, "send");
	recv_proc xrecv = (recv_proc)::GetProcAddress(hInstWs2, "recv");
	closesocket_proc xclosesock = (closesocket_proc)::GetProcAddress(hInstWs2, "closesocket");

	s_patchConnect = std::make_shared<CPatch>(xconnect, my_connect, s_lpfn_connect);
	s_patchSend = std::make_shared<CPatch>(xsend, my_send, s_lpfn_send);
	s_patchRecv = std::make_shared<CPatch>(xrecv, my_recv, s_lpfn_recv);
	s_patchCloseSocket = std::make_shared<CPatch>(xclosesock, my_closesocket, s_lpfn_closesocket);

	// patch legacy WinSock calls (may be used by OpenSSL DLLs):
	HINSTANCE hInstWsOld = ::GetModuleHandleW(L"wsock32.dll");

	send_proc xsend_legacy = (send_proc)::GetProcAddress(hInstWsOld, "send");
	recv_proc xrecv_legacy = (recv_proc)::GetProcAddress(hInstWsOld, "recv");

	if (xsend_legacy != nullptr && xsend_legacy != xsend)
		s_patchSendLegacy = std::make_shared<CPatch>(xsend_legacy, my_send_legacy, s_lpfn_send_legacy);
	if (xrecv_legacy != nullptr && xrecv_legacy != xrecv)
		s_patchRecvLegacy = std::make_shared<CPatch>(xrecv_legacy, my_recv_legacy, s_lpfn_recv_legacy);

	// patch OpenSSL calls:
	SSL_write_proc xsslwrite = (SSL_write_proc)::GetProcAddress(hInstSSLLib, "SSL_write");
	SSL_read_proc xsslread = (SSL_read_proc)::GetProcAddress(hInstSSLLib, "SSL_read");

	s_patchSSLWrite = std::make_shared<CPatch>(xsslwrite, my_SSL_write, s_lpfn_SSL_write);
	s_patchSSLRead = std::make_shared<CPatch>(xsslread, my_SSL_read, s_lpfn_SSL_read);

	// OpenSSL utility methods:
	_SSL_get_fd = (SSL_get_fd_proc)::GetProcAddress(hInstSSLLib, "SSL_get_fd");
	_SSL_is_init_finished = (SSL_is_init_finished_proc)::GetProcAddress(hInstSSLLib, "SSL_is_init_finished");

	// check if it worked:
	if (s_patchConnect->patched() && s_patchRecv->patched() && s_patchSend->patched() &&
		(!hInstSSLLib || (s_patchSSLWrite->patched() && s_patchSSLRead->patched()))
		&& _SSL_get_fd != nullptr
		&& _SSL_is_init_finished != nullptr)
	{
		INJECT_DEBUG_MSG("Loaded!");

		s_loaded = true;
	}
	else
	{
		wchar_t wszPatchedInfo[50] = { 0 };
		swprintf_s(wszPatchedInfo, 50, L"[%i%i%i%i%i%i%i%i][%i%i]",
			(s_patchConnect->patched() ? 1 : 0),
			(s_patchSend->patched() ? 1 : 0),
			(s_patchRecv->patched() ? 1 : 0),
			(!s_patchRecvLegacy || s_patchRecvLegacy->patched() ? 1 : 0),
			(!s_patchSendLegacy || s_patchSendLegacy->patched() ? 1 : 0),
			(s_patchCloseSocket->patched() ? 1 : 0),
			(s_patchSSLWrite->patched() ? 1 : 0),
			(s_patchSSLRead->patched() ? 1 : 0),
			(_SSL_get_fd ? 1 : 0),
			(_SSL_is_init_finished ? 1 : 0));

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

		INJECT_DEBUG_MSG("Patching problem!");

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

	if (mTimeout == 1)
	{
		if (!s_loaded)
		{
			s_engines.reset();
		}

		INJECT_DEBUG_MSG("mTimeout = 1");

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

		INJECT_DEBUG_MSG("done.");

		CPatch::Unitialize();

		return 0;
	}
}


/* returns 0 on success */
extern "C" int RegisterEngine(const fish_inject_engine_t * pEngine)
{
	if (!s_engines)
		return -1;

	return (s_engines->Register(0, pEngine) ? 0 : 1);
}


/* returns 0 on success */
extern "C" int UnregisterEngine(const fish_inject_engine_t * pEngine)
{
	if (!s_engines)
		return -1;

	return (s_engines->Unregister(pEngine) ? 0 : 1);
}

#define FISH_INJECT_VERSION "*** FiSH 10.23.1 *** by [c&f]\xA0\xA0*** fish_inject.dll compiled " __DATE__ " " __TIME__ " ***"

/* dummy call to facilitate loading of DLL */
MIRC_DLL_EXPORT(_callMe)
{
	static bool version_shown = false;

	if (!version_shown)
	{
		version_shown = true;

		strcpy_s(data, s_maxMircReturnBytes, "/echo -a " FISH_INJECT_VERSION);

		return MIRC_RET_DATA_COMMAND;
	}

	return MIRC_RET_CONTINUE;
}

MIRC_DLL_EXPORT(FiSH_GetInjectVersion)
{
	strcpy_s(data, s_maxMircReturnBytes, FISH_INJECT_VERSION);

	return MIRC_RET_DATA_RETURN;
}

/* for debugging */
MIRC_DLL_EXPORT(InjectDebugInfo)
{
	size_t l_numSockets = 0;
	std::string l_stats;

	{
		s_socketsAccess.EnterReader();

		l_numSockets = s_sockets.size();

		for (const auto& l_sock : s_sockets)
		{
			l_stats += l_sock.second->GetStats();
		}

		s_socketsAccess.LeaveReader();
	}

	const std::string l_engineList = (s_engines ? s_engines->GetEngineList() : "");

	sprintf_s(data, s_maxMircReturnBytes, "/echo -a *** Sockets: Active %d - Discarded %d - %s - Engines: %s",
		l_numSockets, s_discardedSockets, (l_stats.size() < 700 ? l_stats.c_str() : "a lot of data"), l_engineList.c_str());

	return MIRC_RET_DATA_COMMAND;
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

bool CPatch::ms_initialized = false;


#if defined(_DEBUG) || defined(LOG_TO_FILE)

static std::mutex s_debugAccess;
static std::wstring s_logFilePath;

void _fishInjectDebugMsg(const char* a_file, int a_line, const char* a_function, const std::string& a_message)
{
	char tid[20];
	sprintf_s(tid, 20, "[%08x] ", GetCurrentThreadId());

	std::lock_guard<decltype(s_debugAccess)> lock(s_debugAccess);

#ifdef LOG_TO_FILE
	if (s_logFilePath.empty())
	{
		wchar_t buf[MAX_PATH + 1] = { 0 };

		::GetTempPath(MAX_PATH, buf);

		s_logFilePath = buf;
		s_logFilePath += L"\\FiSH10.log";
	}

	FILE* fp = nullptr;
	if (0 == _wfopen_s(&fp, s_logFilePath.c_str(), L"a+"))
	{
		fputs(tid, fp);
		fputs(" ", fp);
		fputs(a_function, fp);
		if (!a_message.empty())
		{
			fputs(" >> ", fp);
			fputs(a_message.c_str(), fp);
			if (a_message.rfind('\n') != a_message.size() - 1) fputs("\n", fp);
		}
		else
		{
			fputs("\n", fp);
		}

		fclose(fp);
	}

#else
	OutputDebugStringA(tid);
	OutputDebugStringA(a_function);
	if (!a_message.empty())
	{
		OutputDebugStringA(" >> ");
		OutputDebugStringA(a_message.c_str());
		if (a_message.rfind('\n') != a_message.size() - 1) OutputDebugStringA("\n");
	}
	else
	{
		OutputDebugStringA("\n");
	}
#endif
}
#endif

static_assert(sizeof(SOCKET) == sizeof(HANDLE), "fail");
