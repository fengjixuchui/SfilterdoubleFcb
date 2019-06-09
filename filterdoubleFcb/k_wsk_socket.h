#pragma once

#define SOCKET_ERROR -1

enum
{
	DEINITIALIZED,
	DEINITIALIZING,
	INITIALIZING,
	INITIALIZED
};

typedef enum {
	IRPLOCK_CANCELABLE,
	IRPLOCK_CANCEL_STARTED,
	IRPLOCK_CANCEL_COMPLETE,
	IRPLOCK_COMPLETED
} IRPLOCK, *PIRPLOCK;

#define MAX_TIMEOUT	((long)(~0UL>>1)) 

#define EINVAL					1
#define EOPNOTSUPP				2
#define ENOMEM					3
#define ENOENT					4
#define EMEDIUMTYPE				5
#define EROFS					6
#define	E2BIG					7	/* Argument list too long */    // from linux 2.6.32.61
#define MSG_NOSIGNAL			8
#define ETIMEDOUT				9
#define EBUSY					10
#define	EAGAIN					11	/* Try again */ // from linux 2.6.32.61
#define ENOBUFS					12
#define ENODEV					13
#define EWOULDBLOCK				14
#define EINTR					15
#define ENOSPC					16
#define ECONNRESET				17
#define ERESTARTSYS				18
#define EIO					    5 //19
#define ENOMSG					20
#define EEXIST					21
#define EPERM					22
#define EMSGSIZE				23
#define ESRCH					24
#define ERANGE					25	
#define EINPROGRESS				26	
#define ECONNREFUSED			27	
#define ENETUNREACH				28
#define EHOSTDOWN				29
#define EHOSTUNREACH			30
#define EBADR					31
#define EADDRINUSE              32
#define EINVALADDR              33	// DW-1272 : STATUS_INVALID_ADDRESS_COMPONENT
#define	EOVERFLOW				75	/* Value too large for defined data type */ // from linux 2.6.32.61
#define	ESTALE					116	/* Stale NFS file handle */
#define ECONNABORTED			130 /* Software caused connection abort */ 

#define SIGXCPU					100
#define SIGHUP					101
#define MSG_MORE				102

#define MAX_ERRNO				4095
#define IS_ERR_VALUE(_x)		((_x) >= (unsigned long) -MAX_ERRNO)

#define CR2_FLAG				0x9050207

typedef struct _CANCEL_COMPLETION_SYN
{
	IRPLOCK Lock;
	KEVENT	CompletionEvent;
}CANCEL_COMPLETION_SYN,*PCANCEL_COMPLETION_SYN;

NTSTATUS NTAPI Wsk_WskStartup();
VOID NTAPI Wsk_WskCleanup();

PWSK_SOCKET Wsk_CreateSocket(__in ADDRESS_FAMILY AddressFamily, __in USHORT SocketType, __in ULONG Protocol, __in PVOID *SocketContext, __in CONST VOID *Dispatch, __in ULONG Flags);

NTSTATUS Wsk_CloseSocket(__in PWSK_SOCKET WskSocket);

NTSTATUS Wsk_Bind(__in PWSK_SOCKET WskSocket, __in PSOCKADDR LocalAddress);

PWSK_SOCKET Wsk_Accept(__in PWSK_SOCKET	WskSocket, __out_opt PSOCKADDR LocalAddress, __out_opt PSOCKADDR RemoteAddress, __out_opt NTSTATUS* RetStaus, __in int Timeout /*ms*/);

NTSTATUS Wsk_Connect(__in PWSK_SOCKET WskSocket, __in PSOCKADDR RemoteAddress);

//With a graceful disconnect, the IRP is completed only when the disconnect operation is fully completed by the transport protocol.
//For some transport protocols, the IRP might not complete if there is a problem transmitting data to the remote transport address.
//In this situation, the WSK application can recover by either calling the WskDisconnect function again and specifying the WSK_FLAG_ABORTIVE flag or by calling the WskCloseSocket function.
//In either situation, the WSK subsystem will abortively disconnect the socket and force completion of the pending IRP.
NTSTATUS Wsk_Disconnect(__in PWSK_SOCKET WskSocket,__in ULONG Flags);

PWSK_SOCKET Wsk_CreateSocketConnect(__in USHORT	SocketType, __in ULONG Protocol, __in PSOCKADDR LocalAddress, __in PSOCKADDR RemoteAddress, __inout  NTSTATUS* pStatus);

LONG Wsk_Send(__in PWSK_SOCKET	WskSocket, __in PVOID Buffer, __in ULONG BufferSize, __in ULONG Flags, __in int Timeout /*ms*/);

LONG Wsk_Receive(__in PWSK_SOCKET WskSocket, __out PVOID Buffer, __in  ULONG BufferSize, __in  ULONG Flags, __in int Timeout /*ms*/);

LONG Wsk_SendTo(__in PWSK_SOCKET WskSocket, __in PVOID Buffer, __in ULONG BufferSize, __in_opt PSOCKADDR RemoteAddress);

LONG Wsk_ReceiveFrom(__in PWSK_SOCKET WskSocket, __out PVOID Buffer, __in  ULONG BufferSize, __out_opt PSOCKADDR RemoteAddress, __out_opt PULONG	ControlFlags);

NTSTATUS Wsk_GetRemoteAddress(__in PWSK_SOCKET WskSocket, __out PSOCKADDR pRemoteAddress);

NTSTATUS Wsk_ControlSocket(__in PWSK_SOCKET WskSocket, __in ULONG RequestType, __in ULONG ControlCode, __in ULONG Level, __in SIZE_T InputSize, __in_opt PVOID InputBuffer, __in SIZE_T OutputSize, __out_opt PVOID OutputBuffer, __out_opt SIZE_T *OutputSizeReturned);

//All of a socket's event callback functions, except for a listening socket's WskInspectEvent and WskAbortEvent event callback functions, 
//can be enabled or disabled by using the SO_WSK_EVENT_CALLBACK socket option. 
//A WSK application can enable multiple event callback functions on a socket at the same time. However, 
//a WSK application must disable each event callback function individually.

NTSTATUS Wsk_SetEventCallbacks(__in PWSK_SOCKET	WskSocket, __in ULONG mask, __in BOOLEAN Enable);



//PERMANENT EVENT SOCKET FUNCTIONS

//If a WSK application always enables certain event callback functions on every socket that it creates, 
//the application can configure the WSK subsystem to automatically enable those event callback functions by 
//using the WSK_SET_STATIC_EVENT_CALLBACKS client control operation.
//The event callback functions that are enabled in this manner are always enabled and cannot be disabled or re - enabled later by the WSK application.
//If a WSK application always enables certain event callback functions on every socket that it creates, 
//the application should use this method to automatically enable those event callback functions because it will yield much better performance.

NTSTATUS Wsk_SetPermanentEventMask(__in ULONG mask);

