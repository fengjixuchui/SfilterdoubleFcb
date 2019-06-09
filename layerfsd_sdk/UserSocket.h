#ifndef __USER_SOCKET_H__
#define __USER_SOCKET_H__

#include <WinSock2.h>
#include <Winsvc.h>
#include <stdlib.h>
#include <time.h>

#include <io.h>
#include <direct.h>

#include <tchar.h>
#include <strsafe.h>
#include <WtsApi32.h>
#include <UserEnv.h>

#include "shlwapi.h"

#include <tlhelp32.h>

#include <atlbase.h>
#include <atlstr.h>

#include "layerfsd_sdk.h"

#define BUFFER_SIZE	5000

#define OTHER_TIMEOUT	30

class	CProxySession
{
public:

	DWORD	m_pid;

	char	*m_c_ipaddr;
	unsigned long  m_c_ipaddr_long;
	unsigned short m_c_port;
	SOCKET m_socConnection;

	char	*m_s_ipaddr;
	unsigned long  m_s_ipaddr_long;
	unsigned short m_s_port;

	CProxySession(SOCKET client_soc)
	{
		m_socConnection		= client_soc;

		m_c_ipaddr	= NULL;
		m_s_ipaddr	= NULL;

		m_c_ipaddr_long = 0;
		m_s_ipaddr_long = 0;

		m_c_port	= 0;
		m_s_port	= 0;

	}

public:
public:
	int ProcessRequest(char *buf, int len);
	int	ProcessResponse(char *buf, int len);

};

typedef struct _TestMem
{
	int		Len;
	int		BufferLen;
	int		Type;
	wchar_t Buffer[64];
}TestMem,*PTestMem;

#endif
