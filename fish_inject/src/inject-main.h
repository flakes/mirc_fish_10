#include "targetver.h"

#include <Windows.h>
#include <ws2tcpip.h>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <algorithm>

#include "mircdll.h"


/* function signature typedefs */
typedef int(WSAAPI* connect_proc)(SOCKET s, const struct sockaddr FAR * name, int namelen);
typedef int(WSAAPI* send_proc)(SOCKET, const char*, int, int);
typedef int(WSAAPI* recv_proc)(SOCKET, char*, int, int);
typedef int(WSAAPI* closesocket_proc)(SOCKET);
typedef int(__cdecl* SSL_write_proc)(void *ssl, const void *buf, int num);
typedef int(__cdecl* SSL_read_proc)(void *ssl, void *buf, int num);

typedef int(__cdecl* SSL_state_proc)(const void *ssl);
typedef int(__cdecl* SSL_get_fd_proc)(const void *ssl);


/* own module handle */
extern HMODULE g_hModule;


/* some debug helper business */
void _fishInjectDebugMsg(const char* a_file, int a_line, const char* a_function, const std::string& a_message);

#if defined(_DEBUG) || defined(LOG_TO_FILE)
#define INJECT_DEBUG_MSG(A_MSG) _fishInjectDebugMsg(__FILE__, __LINE__, __FUNCTION__, A_MSG)
#else
#define INJECT_DEBUG_MSG(x)
#endif
