#include "stdafx.h"
#include "UserSocket.h"


#pragma comment(lib , "ws2_32.lib")

DWORD WINAPI Proxy_ConnectionThread(void *param)
{
	fd_set	rfds;
	SOCKET	maxfd;
	DWORD	ret	= 0;
	int		len,n;
	char	buf[BUFFER_SIZE]	= "";
	DWORD	flag				= 0; 
	struct timeval	timeout;
	CProxySession *pSession=(CProxySession *)param;


	maxfd = pSession->m_socConnection;

	for (;;)
	{
		FD_ZERO(&rfds);
		if (pSession->m_socConnection != NULL)
		{
			FD_SET(pSession->m_socConnection, &rfds);
		}

		timeout.tv_sec	= OTHER_TIMEOUT;
		timeout.tv_usec	= 0;

		maxfd = pSession->m_socConnection;

		n = select((int)maxfd+1, &rfds, NULL, NULL, &timeout);

		if (n == 0)//timeout
		{
			char Error[1024] = "";
			sprintf_s(Error,"select timeout  %s port: %d TO %s port: %d error:%d !\n",pSession->m_c_ipaddr,ntohs(pSession->m_c_port),pSession->m_s_ipaddr,pSession->m_s_port,WSAGetLastError());
			OutputDebugString(Error);
			//goto clean_up;
			continue;
		}
		else if (n < 0)
		{
			char Error[1024] = "";
			sprintf_s(Error,"select error  %s port: %d TO %s port: %d error:%d !\n",pSession->m_c_ipaddr,ntohs(pSession->m_c_port),pSession->m_s_ipaddr,pSession->m_s_port,WSAGetLastError());
			OutputDebugString(Error);
			ret = -1;
			goto clean_up;
		}

		/*ZeroMemory(buf,BUFFER_SIZE-1);*/

		if ((pSession->m_socConnection != NULL) && FD_ISSET(pSession->m_socConnection,&rfds))
		{
			int		max_bytes_to_read	= sizeof(buf)-1;
			int		trans				= 0;
			char	tmp[BUFFER_SIZE]	= "";
			TestMem	Rcv ,Snd;
			ZeroMemory(&Rcv,sizeof(TestMem));
			ZeroMemory(&Snd,sizeof(TestMem));
			/*ZeroMemory(buf,BUFFER_SIZE);*/
			len	= read_socket(pSession->m_socConnection,(char *)&Rcv,sizeof(TestMem));
			if (len <= 0)
			{
				if (len == 0)
				{
					char Error[1024] = "";
					sprintf_s(Error,"read client socket  %s port: %d TO %s port: %d error:%d  client closed!\n",pSession->m_c_ipaddr,ntohs(pSession->m_c_port),pSession->m_s_ipaddr,pSession->m_s_port,WSAGetLastError());
					OutputDebugString(Error);
				}
				else
				{
					char Error[1024] = "";
					sprintf_s(Error,"read client socket  %s port: %d TO %s port: %d error:%d!\n",pSession->m_c_ipaddr,ntohs(pSession->m_c_port),pSession->m_s_ipaddr,pSession->m_s_port,WSAGetLastError());
					OutputDebugString(Error);
				}

				goto clean_up;
			}
			else
			{
				char Error[256] = "";
				sprintf_s(Error,"User Server Rcved Len:%d,BufferLen:%d,Type:%d,Buffer:%S!\n",Rcv.Len,Rcv.BufferLen,Rcv.Type,Rcv.Buffer);
				OutputDebugString(Error);
			}

			//trans = pSession->ProcessRequest(buf,len);
			//getchar();
			//Sleep(5000);
			if ((trans == 0))
			{
				Snd.Len = sizeof(TestMem);
				Snd.BufferLen = 16;
				Snd.Type = 0x1;
				wcscpy_s(Snd.Buffer,16,L"User Server Send!");

				if (write_socket(pSession->m_socConnection,(char *)&Snd,sizeof(TestMem)))
				{
					char Error[256] = "";
					sprintf_s(Error,"transfer to server error:%d!\n",WSAGetLastError());
					OutputDebugString(Error);
					ret = -1;
					goto clean_up;
				}
			}
			continue;
		}

	}

clean_up:
	if (pSession != NULL)
	{
		if (pSession->m_socConnection != NULL)
		{
			closesocket(pSession->m_socConnection);
			pSession->m_socConnection = NULL;
		}

		if (pSession->m_c_ipaddr != NULL)
		{
			free(pSession->m_c_ipaddr);
		}
		if (pSession->m_s_ipaddr != NULL)
		{
			free(pSession->m_s_ipaddr);
		}

		delete pSession;
		pSession = NULL;
	}

	return ret;
}

void Proxy_AcceptConnections(SOCKET server_soc)
{
	DWORD	dwThreadId; 
	HANDLE	hThread; 

	SOCKET			soc_client;
	CProxySession	*pSession;

	int			len;
	sockaddr_in	nm;

	while(true)
	{
		hThread		= NULL; 
		dwThreadId	= 0; 

		pSession	= NULL;
		soc_client	= NULL;

		ZeroMemory(&nm,sizeof(nm));
		len=sizeof(nm);

		printf("\nWaiting for incoming connection...\n");

		if(INVALID_SOCKET==(soc_client=accept(server_soc,(struct sockaddr *)&nm,&len)))
		{
			printf("Error: Invalid Soceket returned by accept(): %d\n",WSAGetLastError());
		}
		else
		{
			printf("Accepted new connection. Now creating session thread...\n");
		}	

		pSession=new CProxySession(soc_client);
		if (pSession == NULL)
		{
			if (soc_client != NULL)
			{
				closesocket(soc_client);
				soc_client = NULL;
			}
			continue;
		}

		pSession->m_c_port			= nm.sin_port;
		pSession->m_c_ipaddr		= strdup(inet_ntoa(nm.sin_addr));
		pSession->m_c_ipaddr_long	= nm.sin_addr.s_addr;

		hThread = CreateThread( 
			NULL,                        // default security attributes 
			0,                           // use default stack size  
			Proxy_ConnectionThread,                  // thread function 
			(void *)pSession,                // argument to thread function 
			0,                           // use default creation flags 
			&dwThreadId);                // returns the thread identifier 

		// Check the return value for success. 

		if(hThread == NULL) 
		{
			if (pSession != NULL)
			{
				if (pSession->m_socConnection != NULL)
				{
					closesocket(pSession->m_socConnection);
					pSession->m_socConnection = NULL;
				}
				if (pSession->m_c_ipaddr != NULL)
				{
					free(pSession->m_c_ipaddr);
				}
				if (pSession->m_s_ipaddr != NULL)
				{
					free(pSession->m_s_ipaddr);
				}
				delete pSession;
				pSession = NULL;
			}
			printf( "CreateThread failed." ); 
		}
		else
		{
			CloseHandle(hThread);
		}
	}
}

DWORD ServerMain(void *param)
{
	USHORT Port = 60000;
	SOCKET soc;
	SOCKADDR_IN soc_addr;

	do 
	{
		if (Port >= 65535)
		{
			printf("No Port Can use!\n");
			return 0;
		}

		soc=socket(PF_INET, SOCK_STREAM, 0);

		soc_addr.sin_family=AF_INET;
		soc_addr.sin_addr.S_un.S_addr=inet_addr("127.0.0.1")/*INADDR_ANY*/;//soc_addr.sin_addr=*(LPIN_ADDR)(lpHost->h_addr_list[0]);
		soc_addr.sin_port=htons(Port);

		if (bind(soc,(const struct sockaddr*)&soc_addr,sizeof(soc_addr)) == 0)
		{
			if (1/*NpSetPort(Port,MONITOR_OTHER)*/)
			{
				char msg[256] = "";
				sprintf_s(msg,"PROXY PORT :%d!\n",Port);
				OutputDebugString(msg);
				break;
			}
			else
			{
				char msg[256] = "";
				sprintf_s(msg,"NpSetPort error :%d!\n",Port);
				OutputDebugString(msg);

				closesocket(soc);
			}
			//char msg[256] = "";
			//sprintf(msg,"PROXY PORT :%d!\n",Port);
			//OutputDebugString(msg);
			//break;
		}
		else
		{
			char msg[256] = "";
			sprintf_s(msg,"Error: PROXY Can not bind to socket\n error code: %d\n",WSAGetLastError());
			OutputDebugString(msg);
			
			Sleep(1000);
		}

	} while (Port++ < 65535);
	/*InitializeCriticalSection(&m_csState);*/
	if(SOCKET_ERROR==listen(soc,SOMAXCONN))
	{
		char msg[256] = "";
		sprintf_s(msg,"Error: PROXY Can not listen to socket\nQuiting with error code: %d\n",WSAGetLastError());
		OutputDebugString(msg);
		Sleep(5000);
		return 0;
	}

	Proxy_AcceptConnections(soc);
	printf("You should not see this message.\nIt is an abnormal condition.\nTerminating...");
	return 0;
}

DWORD ClientMain(void *param)
{
	int		len;
	USHORT Port = 60000;
	SOCKET soc;
	SOCKADDR_IN soc_addr,serveraddr;
	TestMem	Rcv ,Snd;


	do 
	{
		soc=socket(PF_INET, SOCK_STREAM, 0);

		soc_addr.sin_family=AF_INET;
		soc_addr.sin_addr.S_un.S_addr=inet_addr("127.0.0.1")/*INADDR_ANY*/;//soc_addr.sin_addr=*(LPIN_ADDR)(lpHost->h_addr_list[0]);
		//soc_addr.sin_port=htons(Port);

		if (bind(soc,(const struct sockaddr*)&soc_addr,sizeof(soc_addr)) != 0)
		{
			char msg[256] = "";
			sprintf_s(msg,"Error: Bind Error, error code: %d\n",WSAGetLastError());
			OutputDebugString(msg);
			closesocket(soc);
			break;
		}

		serveraddr.sin_family = AF_INET; 
		serveraddr.sin_port = htons(65000);
		serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");

		if (connect(soc, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) != 0)
		{
			char msg[256] = "";
			sprintf(msg,"Error: Connect Error, error code: %d\n",WSAGetLastError());
			OutputDebugString(msg);
			closesocket(soc);
			break;
		}

		ZeroMemory(&Rcv,sizeof(TestMem));
		ZeroMemory(&Snd,sizeof(TestMem));

		Snd.Len = sizeof(TestMem);
		Snd.BufferLen = 64;
		Snd.Type = 0x1;
		wcscpy_s(Snd.Buffer,64,L"User Client Send!");

		if (write_socket(soc,(char *)&Snd,sizeof(TestMem)))
		{
			char Error[256] = "";
			sprintf_s(Error,"User Client transfer to server error:%d!\n",WSAGetLastError());
			OutputDebugString(Error);
			break;
		}


		len	= read_socket(soc,(char *)&Rcv,sizeof(TestMem));
		if (len <= 0)
		{
			if (len == 0)
			{
				char Error[1024] = "";
				sprintf_s(Error,"User Client socket error:%d  client closed!\n",WSAGetLastError());
				OutputDebugString(Error);
			}
			else
			{
				char Error[1024] = "";
				sprintf_s(Error,"User Client socket error:%d!\n",WSAGetLastError());
				OutputDebugString(Error);
			}

			break;
		}
		else
		{
			char Error[256] = "";
			sprintf_s(Error,"User Client Rcved Len:%d,BufferLen:%d,Type:%d,Buffer:%S!\n",Rcv.Len,Rcv.BufferLen,Rcv.Type,Rcv.Buffer);
			OutputDebugString(Error);
		
		}
	} while (FALSE);


	return 0;
}

//int main(int argc, char *argv[])
//{
	//WSAData wsaData;
	//int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
//
//	////User Socket Server
//	//ServerMain(NULL);
//
//	//User Socket Client
//	ClientMain(NULL);
//
//	getchar();
//	return 0;
//}