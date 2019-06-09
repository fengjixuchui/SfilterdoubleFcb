#ifndef __UTILS_H__
#define __UTILS_H__

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(_USRDLL)
	#define DLLAPI _declspec (dllexport)
#else
	#define DLLAPI _declspec (dllimport) 
#endif

	DLLAPI int data_is_available(SOCKET fd, int seconds_to_wait);

	DLLAPI int read_socket(SOCKET fd, char *buf, int len);

	DLLAPI int write_socket(SOCKET fd, const char *buf, size_t len);

	DLLAPI BOOL safe_send(SOCKET fd, const char *buf, size_t len);

	DLLAPI DWORD ClientMain(void *param);

	DLLAPI DWORD ServerMain(void *param);

	DLLAPI DWORD WINAPI Proxy_ConnectionThread(void *param);

	DLLAPI void Proxy_AcceptConnections(SOCKET server_soc);


#if defined(__cplusplus)
}
#endif

#endif
