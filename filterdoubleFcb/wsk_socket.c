#include <ntddk.h>
#include <wsk.h>

#include "..\Inc\k_wsk_socket.h"

////IMPORTANT: You Must Include "Netio.lib;uuid.lib;" In Your Project Linker.

WSK_REGISTRATION         g_WskRegistration;
WSK_PROVIDER_NPI         g_WskProvider;
WSK_CLIENT_DISPATCH      g_WskDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };


LONG     g_SocketsState			= DEINITIALIZED;

IO_COMPLETION_ROUTINE CompletionRoutine_Syn;
IO_COMPLETION_ROUTINE CompletionRoutine_Asyn;

char *GetSockErrorString(NTSTATUS status)
{
	char *ErrorString;
	switch (status) {
	case STATUS_SUCCESS:
		ErrorString = "STATUS_SUCCESS";
		break;
	case STATUS_PENDING:
		ErrorString = "STATUS_PENDING";
		break;
	case STATUS_CONNECTION_RESET:
		ErrorString = "STATUS_CONNECTION_RESET";
		break;
	case STATUS_CONNECTION_DISCONNECTED:
		ErrorString = "STATUS_CONNECTION_DISCONNECTED";
		break;
	case STATUS_CONNECTION_REFUSED:
		ErrorString = "STATUS_CONNECTION_REFUSED";
		break;
	case STATUS_GRACEFUL_DISCONNECT:
		ErrorString = "STATUS_GRACEFUL_DISCONNECT";
		break;
	case STATUS_ADDRESS_ALREADY_ASSOCIATED:
		ErrorString = "STATUS_ADDRESS_ALREADY_ASSOCIATED";
		break;
	case STATUS_ADDRESS_NOT_ASSOCIATED:
		ErrorString = "STATUS_ADDRESS_NOT_ASSOCIATED";
		break;
	case STATUS_CONNECTION_INVALID:
		ErrorString = "STATUS_CONNECTION_INVALID";
		break;
	case STATUS_CONNECTION_ACTIVE:
		ErrorString = "STATUS_CONNECTION_ACTIVE";
		break;
	case STATUS_NETWORK_UNREACHABLE:
		ErrorString = "STATUS_NETWORK_UNREACHABLE";
		break;
	case STATUS_HOST_UNREACHABLE:
		ErrorString = "STATUS_HOST_UNREACHABLE";
		break;
	case STATUS_PROTOCOL_UNREACHABLE:
		ErrorString = "STATUS_PROTOCOL_UNREACHABLE";
		break;
	case STATUS_PORT_UNREACHABLE:
		ErrorString = "STATUS_PORT_UNREACHABLE";
		break;
	case STATUS_REQUEST_ABORTED:
		ErrorString = "STATUS_REQUEST_ABORTED";
		break;
	case STATUS_CONNECTION_ABORTED:
		ErrorString = "STATUS_CONNECTION_ABORTED";
		break;
	case STATUS_CONNECTION_COUNT_LIMIT:
		ErrorString = "STATUS_CONNECTION_COUNT_LIMIT";
		break;
	case STATUS_INVALID_ADDRESS_COMPONENT:
		ErrorString = "STATUS_INVALID_ADDRESS_COMPONENT";
		break;
	case STATUS_IO_TIMEOUT:
		ErrorString = "STATUS_IO_TIMEOUT";
		break;
	case STATUS_INVALID_DEVICE_STATE:
		ErrorString = "STATUS_INVALID_DEVICE_STATE";
		break;
	case STATUS_FILE_FORCED_CLOSED:
		ErrorString = "STATUS_FILE_FORCED_CLOSED";
		break;
	default:
		ErrorString = "unknown error";
		KdPrint(("unknown error NTSTATUS:%x\n", status));
		break;
	}
	return ErrorString;
}

_Use_decl_annotations_ NTSTATUS CompletionRoutine_Syn(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp, __in PVOID Context)
{
	ASSERT(Context);

	PCANCEL_COMPLETION_SYN pSyn = (PCANCEL_COMPLETION_SYN)Context;
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	if (pSyn == NULL)
	{
		return STATUS_MORE_PROCESSING_REQUIRED;
	}

	if (InterlockedExchange((PLONG)&pSyn->Lock, IRPLOCK_COMPLETED) == IRPLOCK_CANCEL_STARTED)
	{
		//
		// Main line code has got the control of the IRP. It will
		// now take the responsibility of completing the IRP.
		// Therefore...

		KdPrint(("Irp Canceling Was Started!\n"));
	}

	KeSetEvent(&pSyn->CompletionEvent, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

_Use_decl_annotations_ NTSTATUS CompletionRoutine_Asyn(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp, __in PVOID Context)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Context);

	IoFreeIrp(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS Wsk_InitWskRequest(__out PIRP* pIrp, __out PCANCEL_COMPLETION_SYN pSyn)
{
	ASSERT(pIrp);

	*pIrp = IoAllocateIrp(1, FALSE);
	if (!*pIrp)
	{
		KdPrint(("Wsk_InitWskRequest(): IoAllocateIrp() failed\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (pSyn == NULL)
	{
		IoSetCompletionRoutine(*pIrp, CompletionRoutine_Asyn, NULL, TRUE, TRUE, TRUE);
	} 
	else
	{
		KeInitializeEvent(&pSyn->CompletionEvent, SynchronizationEvent, FALSE);

		IoSetCompletionRoutine(*pIrp, CompletionRoutine_Syn, pSyn, TRUE, TRUE, TRUE);
	}

	return STATUS_SUCCESS;
}


NTSTATUS Wsk_InitWskBuffer(__in  PVOID Buffer,__in  ULONG BufferSize,__out PWSK_BUF WskBuffer,__in  BOOLEAN	bWriteAccess)
{
	NTSTATUS Status = STATUS_SUCCESS;

	ASSERT(Buffer);
	ASSERT(BufferSize);
	ASSERT(WskBuffer);

	WskBuffer->Offset = 0;
	WskBuffer->Length = BufferSize;

	WskBuffer->Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
	if (!WskBuffer->Mdl)
	{
		KdPrint(("Wsk_InitWskBuffer(): IoAllocateMdl() failed\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, bWriteAccess ? IoWriteAccess : IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Wsk_InitWskBuffer(): MmProbeAndLockPages(%p) failed\n", Buffer));
		IoFreeMdl(WskBuffer->Mdl);
		Status = STATUS_ACCESS_VIOLATION;
	}

	return Status;
}


VOID Wsk_FreeWskBuffer(__in PWSK_BUF WskBuffer)
{
	ASSERT(WskBuffer);

	MmUnlockPages(WskBuffer->Mdl);
	IoFreeMdl(WskBuffer->Mdl);
}

NTSTATUS Wsk_WskStartup()
{
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	WSK_CLIENT_NPI  WskClient = { 0 };
	

	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZING, DEINITIALIZED) != DEINITIALIZED)
	{
		return STATUS_ALREADY_REGISTERED;
	}

	WskClient.ClientContext = NULL;
	WskClient.Dispatch = &g_WskDispatch;

	Status = WskRegister(&WskClient, &g_WskRegistration);
	if (!NT_SUCCESS(Status)) 
	{
		KdPrint(("WskRegister() failed with status 0x%08X\n", Status));
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		return Status;
	}

	Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_NO_WAIT, &g_WskProvider);
	if (!NT_SUCCESS(Status)) 
	{
		KdPrint(("WskCaptureProviderNPI() failed with status 0x%08X\n", Status));
		WskDeregister(&g_WskRegistration);
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		return Status;
	}

	InterlockedExchange(&g_SocketsState, INITIALIZED);
	return STATUS_SUCCESS;
}


VOID Wsk_WskCleanup()
{
	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZED, DEINITIALIZING) != INITIALIZED)
	{
		return;
	}

	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	InterlockedExchange(&g_SocketsState, DEINITIALIZED);
}

//There is no need to set Timeout value for non-data I/O operations. 

PWSK_SOCKET Wsk_CreateSocket(__in ADDRESS_FAMILY AddressFamily,__in USHORT SocketType,__in ULONG Protocol,__in PVOID *SocketContext,__in CONST VOID *Dispatch,__in ULONG Flags)
{
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		WskSocket = NULL;
	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED) 
	{
		return NULL;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return NULL;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status)) 
	{
		ExFreePool(pSyn);
		return NULL;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = g_WskProvider.Dispatch->WskSocket(
		g_WskProvider.Client,
		AddressFamily,
		SocketType,
		Protocol,
		Flags,
		SocketContext,
		Dispatch,
		NULL,
		NULL,
		NULL,
		Irp);

	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;
	IoFreeIrp(Irp);

	ExFreePool(pSyn);

	return (PWSK_SOCKET)WskSocket;
}

NTSTATUS Wsk_CloseSocket(__in PWSK_SOCKET WskSocket)
{
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket) 
	{
		return STATUS_INVALID_PARAMETER;
	}

	Status = Wsk_InitWskRequest(&Irp, NULL);
	if (!NT_SUCCESS(Status)) 
	{
		return Status;
	}
	Status = ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);

	return STATUS_SUCCESS;
}


NTSTATUS Wsk_Connect(__in PWSK_SOCKET WskSocket,__in PSOCKADDR RemoteAddress)
{
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !RemoteAddress)
	{
		return STATUS_INVALID_PARAMETER;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return Status;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pSyn);
		return Status;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskConnect(
		WskSocket,
		RemoteAddress,
		0,
		Irp);

	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	ExFreePool(pSyn);

	return Status;
}

NTSTATUS Wsk_Disconnect(__in PWSK_SOCKET WskSocket, __in ULONG Flags)
{
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket)
	{
		return STATUS_INVALID_PARAMETER;
	}

	Status = Wsk_InitWskRequest(&Irp, NULL);
	if (!NT_SUCCESS(Status)) 
	{
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskDisconnect(
		WskSocket,
		NULL,
		Flags,
		Irp);

	return STATUS_SUCCESS;
}


PWSK_SOCKET Wsk_CreateSocketConnect(__in USHORT	SocketType,__in ULONG Protocol,__in PSOCKADDR LocalAddress,__in PSOCKADDR RemoteAddress,__inout  NTSTATUS* pStatus)
{
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		WskSocket = NULL;
	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !RemoteAddress || !LocalAddress || !pStatus)
	{
		return NULL;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		*pStatus = STATUS_INSUFFICIENT_RESOURCES;
		return NULL;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		*pStatus = Status;
		ExFreePool(pSyn);
		return NULL;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = g_WskProvider.Dispatch->WskSocketConnect(
		g_WskProvider.Client,
		SocketType,
		Protocol,
		LocalAddress,
		RemoteAddress,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		Irp);
	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
		if (!NT_SUCCESS(Status)) 
		{
			KdPrint(("WskSocketConnect Status:%s\n", GetSockErrorString(Irp->IoStatus.Status)));
		}
	}

	*pStatus = Status = Irp->IoStatus.Status;
	WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;

	IoFreeIrp(Irp);
	ExFreePool(pSyn);

	return WskSocket;
}

LONG Wsk_Send(__in PWSK_SOCKET	WskSocket,__in PVOID Buffer,__in ULONG BufferSize,__in ULONG Flags,__in int Timeout /*ms*/)
{
	PIRP			Irp = NULL;
	LONG			BytesSent = SOCKET_ERROR; // DRBC_CHECK_WSK: SOCKET_ERROR be mixed EINVAL?
	WSK_BUF			WskBuffer = { 0 };
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || ((int)BufferSize <= 0)) 
	{
		return SOCKET_ERROR;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return SOCKET_ERROR;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pSyn);
		return SOCKET_ERROR;
	}

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status)) 
	{
		Wsk_FreeWskBuffer(&WskBuffer);
		ExFreePool(pSyn);
		return SOCKET_ERROR;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Flags |= WSK_FLAG_NODELAY;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskSend(
		WskSocket,
		&WskBuffer,
		Flags,
		Irp);

	if (Status == STATUS_PENDING) 
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pWaitTime = NULL;

		if (Timeout < 0 || Timeout == MAX_TIMEOUT)
		{
			pWaitTime = NULL;
		}
		else
		{
			nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);

			pWaitTime = &nWaitTime;
		}

		Status = KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, pWaitTime);
		if (Status == STATUS_TIMEOUT) 
		{
			if (InterlockedExchange((PLONG)&pSyn->Lock, IRPLOCK_CANCEL_STARTED) == IRPLOCK_CANCELABLE)
			{
			//Notes:
			//	It is assumed that the caller has taken the necessary action to ensure
			//	that the packet cannot be fully completed before invoking this routine.
				IoCancelIrp(Irp);
			}
			KeWaitForSingleObject(&pSyn->CompletionEvent,Executive,KernelMode,FALSE,NULL);

			BytesSent = -EAGAIN;

			goto $Send_fail;
		}
	}

	Status = Irp->IoStatus.Status;

	if (Status == STATUS_SUCCESS) 
	{
		BytesSent = (LONG)Irp->IoStatus.Information;
	}
	else 
	{
		switch (Irp->IoStatus.Status) 
		{
		case STATUS_IO_TIMEOUT:
			BytesSent = -EAGAIN;
			KdPrint(("Send timeout... wsk(0x%p)\n", WskSocket));
			break;
		case STATUS_INVALID_DEVICE_STATE:
		case STATUS_FILE_FORCED_CLOSED:
			BytesSent = -ECONNRESET;
			KdPrint(("Send invalid WSK Socket state (%s) wsk(0x%p)\n", GetSockErrorString(Irp->IoStatus.Status), WskSocket));
			break;
		default:
			BytesSent = -ECONNRESET;
			break;
		}
	}

$Send_fail:
	IoFreeIrp(Irp);
	Wsk_FreeWskBuffer(&WskBuffer);
	ExFreePool(pSyn);

	return BytesSent;
}

LONG Wsk_SendTo(__in PWSK_SOCKET WskSocket,__in PVOID Buffer,__in ULONG BufferSize,__in_opt PSOCKADDR RemoteAddress)
{
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
	{
		return SOCKET_ERROR;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return SOCKET_ERROR;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE);
	if (!NT_SUCCESS(Status)) 
	{
		ExFreePool(pSyn);
		return SOCKET_ERROR;
	}

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		Wsk_FreeWskBuffer(&WskBuffer);
		ExFreePool(pSyn);
		return SOCKET_ERROR;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)WskSocket->Dispatch)->WskSendTo(
		WskSocket,
		&WskBuffer,
		0,
		RemoteAddress,
		0,
		NULL,
		Irp);
	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	BytesSent = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

	IoFreeIrp(Irp);
	Wsk_FreeWskBuffer(&WskBuffer);
	ExFreePool(pSyn);

	return BytesSent;
}

LONG Wsk_Receive(__in PWSK_SOCKET WskSocket,__out PVOID Buffer,__in  ULONG BufferSize,__in  ULONG Flags,__in int Timeout /*ms*/)
{
	PIRP		Irp = NULL;
	LONG		BytesReceived = SOCKET_ERROR;
	WSK_BUF		WskBuffer = { 0 };
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer)
	{
		return SOCKET_ERROR;
	}

	if ((int)BufferSize <= 0) 
	{
		return SOCKET_ERROR;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return SOCKET_ERROR;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskBuffer(Buffer, BufferSize, &WskBuffer, TRUE);
	if (!NT_SUCCESS(Status)) 
	{
		return SOCKET_ERROR;
	}

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		Wsk_FreeWskBuffer(&WskBuffer);
		ExFreePool(pSyn);
		return SOCKET_ERROR;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskReceive(
		WskSocket,
		&WskBuffer,
		Flags,
		Irp);

	if (Status == STATUS_PENDING) 
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pWaitTime = NULL;

		if (Timeout < 0 || Timeout == MAX_TIMEOUT)
		{
			pWaitTime = NULL;
		}
		else
		{
			nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);

			pWaitTime = &nWaitTime;
		}

		Status = KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, pWaitTime);
		if (Status == STATUS_TIMEOUT)
		{
			if (InterlockedExchange((PLONG)&pSyn->Lock, IRPLOCK_CANCEL_STARTED) == IRPLOCK_CANCELABLE)
			{
				//Notes:
				//	It is assumed that the caller has taken the necessary action to ensure
				//	that the packet cannot be fully completed before invoking this routine.
				IoCancelIrp(Irp);
			}
			KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);

			BytesReceived = -EAGAIN;

			goto $Recv_fail;
		}
	}

	Status = Irp->IoStatus.Status;
	if (NT_SUCCESS(Status))
	{
		BytesReceived = (LONG)Irp->IoStatus.Information;
	}
	else
	{
		switch (Irp->IoStatus.Status)
		{
		case STATUS_IO_TIMEOUT:
			BytesReceived = -EAGAIN;
			KdPrint(("WskReceive timeout... wsk(0x%p)\n", WskSocket));
			break;
		case STATUS_INVALID_DEVICE_STATE:
		case STATUS_FILE_FORCED_CLOSED:
			BytesReceived = -ECONNRESET;
			KdPrint(("WskReceive invalid WSK Socket state (%s) wsk(0x%p)\n", GetSockErrorString(Irp->IoStatus.Status), WskSocket));
			break;
		default:
			BytesReceived = -ECONNRESET;
			break;
		}
	}

$Recv_fail:
	IoFreeIrp(Irp);
	Wsk_FreeWskBuffer(&WskBuffer);
	ExFreePool(pSyn);

	return BytesReceived;
}


LONG Wsk_ReceiveFrom(__in PWSK_SOCKET WskSocket,__out PVOID Buffer,__in  ULONG BufferSize,__out_opt PSOCKADDR RemoteAddress,__out_opt PULONG ControlFlags)
{
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
	{
		return SOCKET_ERROR;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return SOCKET_ERROR;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pSyn);
		return SOCKET_ERROR;
	}

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		Wsk_FreeWskBuffer(&WskBuffer);
		ExFreePool(pSyn);
		return SOCKET_ERROR;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)WskSocket->Dispatch)->WskReceiveFrom(
		WskSocket,
		&WskBuffer,
		0,
		RemoteAddress,
		0,
		NULL,
		ControlFlags,
		Irp);
	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	BytesReceived = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

	IoFreeIrp(Irp);
	Wsk_FreeWskBuffer(&WskBuffer);
	ExFreePool(pSyn);

	return BytesReceived;
}

NTSTATUS Wsk_Bind(__in PWSK_SOCKET WskSocket,__in PSOCKADDR LocalAddress)
{
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !LocalAddress)
	{
		return STATUS_INVALID_PARAMETER;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return Status;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pSyn);
		return Status;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskBind(
		WskSocket,
		LocalAddress,
		0,
		Irp);

	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	ExFreePool(pSyn);

	return Status;
}

PWSK_SOCKET Wsk_Accept(__in PWSK_SOCKET	WskSocket,__out_opt PSOCKADDR LocalAddress,__out_opt PSOCKADDR RemoteAddress,__out_opt NTSTATUS* RetStaus,__in int Timeout /*ms*/)
{
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		AcceptedSocket = NULL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket) 
	{
		*RetStaus = SOCKET_ERROR;
		return NULL;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		*RetStaus = SOCKET_ERROR;
		return NULL;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		*RetStaus = Status;
		ExFreePool(pSyn);
		return NULL;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = ((PWSK_PROVIDER_LISTEN_DISPATCH)WskSocket->Dispatch)->WskAccept(
		WskSocket,
		0,
		NULL,
		NULL,
		LocalAddress,
		RemoteAddress,
		Irp);

	if (Status == STATUS_PENDING) 
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pWaitTime = NULL;

		if (Timeout < 0 || Timeout == MAX_TIMEOUT)
		{
			pWaitTime = NULL;
		}
		else
		{
			nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);

			pWaitTime = &nWaitTime;
		}

		Status = KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, pWaitTime);
		if (Status == STATUS_TIMEOUT)
		{
			if (InterlockedExchange((PLONG)&pSyn->Lock, IRPLOCK_CANCEL_STARTED) == IRPLOCK_CANCELABLE)
			{
				//Notes:
				//	It is assumed that the caller has taken the necessary action to ensure
				//	that the packet cannot be fully completed before invoking this routine.
				IoCancelIrp(Irp);
			}
			KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		}
	}
	else 
	{
		if (Status != STATUS_SUCCESS) 
		{
			KdPrint(("Accept Error Status=0x%x\n", Status));
		}
	}

	*RetStaus = Status;

	AcceptedSocket = (Status == STATUS_SUCCESS) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;

	IoFreeIrp(Irp);
	ExFreePool(pSyn);

	return AcceptedSocket;
}

NTSTATUS Wsk_ControlSocket(__in PWSK_SOCKET WskSocket,__in ULONG RequestType,__in ULONG ControlCode,__in ULONG Level,__in SIZE_T InputSize,__in_opt PVOID InputBuffer,__in SIZE_T OutputSize,__out_opt PVOID OutputBuffer,__out_opt SIZE_T *OutputSizeReturned)
{
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket)
	{
		return SOCKET_ERROR;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return SOCKET_ERROR;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pSyn);
		KdPrint(("Wsk_InitWskRequest() failed with status 0x%08X\n", Status));
		return SOCKET_ERROR;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskControlSocket(
		WskSocket,
		RequestType, 
		ControlCode,
		Level,
		InputSize,
		InputBuffer,
		OutputSize,
		OutputBuffer,
		OutputSizeReturned,
		Irp);


	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	ExFreePool(pSyn);

	return Status;
}

NTSTATUS Wsk_SetEventCallbacks(__in PWSK_SOCKET	WskSocket,__in ULONG mask,__in BOOLEAN Enable)
{
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;
	WSK_EVENT_CALLBACK_CONTROL callbackControl;

	if (g_SocketsState != INITIALIZED || !WskSocket) 
	{
		return Status;
	}

	if (Enable != TRUE)
	{
		ULONG Tmask = mask & (WSK_EVENT_SEND_BACKLOG || WSK_EVENT_RECEIVE || WSK_EVENT_DISCONNECT || WSK_EVENT_RECEIVE_FROM || WSK_EVENT_ACCEPT);

		if ((Tmask != WSK_EVENT_SEND_BACKLOG) && 
			(Tmask != WSK_EVENT_RECEIVE) && 
			(Tmask != WSK_EVENT_DISCONNECT) && 
			(Tmask != WSK_EVENT_RECEIVE_FROM) && 
			(Tmask != WSK_EVENT_ACCEPT))
		{
			return STATUS_INVALID_PARAMETER;
		}

		mask |= WSK_EVENT_DISABLE;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pSyn);
		KdPrint(("Wsk_InitWskRequest() failed with status 0x%08X\n", Status));
		return Status;
	}

	pSyn->Lock = IRPLOCK_CANCELABLE;

	callbackControl.NpiId = (PNPIID)&NPI_WSK_INTERFACE_ID;

	// Set the event flags for the event callback functions that
	// are to be enabled on the socket

	callbackControl.EventMask = mask;

	// Initiate the control operation on the socket
	Status = ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskControlSocket(
		WskSocket,
		WskSetOption,
		SO_WSK_EVENT_CALLBACK,
		SOL_SOCKET,
		sizeof(WSK_EVENT_CALLBACK_CONTROL),
		&callbackControl,
		0,
		NULL,
		NULL,
		Irp
		);

	if (Status == STATUS_PENDING) 
	{
		KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	ExFreePool(pSyn);

	return Status;
}

NTSTATUS Wsk_GetRemoteAddress(__in PWSK_SOCKET WskSocket,__out PSOCKADDR pRemoteAddress)
{
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	PCANCEL_COMPLETION_SYN pSyn = NULL;

	if (g_SocketsState != INITIALIZED || !WskSocket)
	{
		return SOCKET_ERROR;
	}

	pSyn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CANCEL_COMPLETION_SYN), '_nyS');
	if (pSyn == NULL)
	{
		return SOCKET_ERROR;
	}

	RtlZeroMemory(pSyn, sizeof(CANCEL_COMPLETION_SYN));

	Status = Wsk_InitWskRequest(&Irp, pSyn);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pSyn);
		KdPrint(("Wsk_InitWskRequest() failed with status 0x%08X\n", Status));
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskGetRemoteAddress(WskSocket, pRemoteAddress, Irp);
	if (Status != STATUS_SUCCESS) 
	{
		if (Status == STATUS_PENDING) 
		{
			KeWaitForSingleObject(&pSyn->CompletionEvent, Executive, KernelMode, FALSE, NULL);
			Status = Irp->IoStatus.Status;
		}

		if (Status != STATUS_SUCCESS) 
		{
			if (Status != STATUS_INVALID_DEVICE_STATE) 
			{
				KdPrint(("STATUS_INVALID_DEVICE_STATE....\n"));
			}
			else if (Status != STATUS_FILE_FORCED_CLOSED) 
			{
				KdPrint(("STATUS_FILE_FORCED_CLOSED....\n"));
			}
			else 
			{
				KdPrint(("Status 0x%x\n", Status));
			}
		}
	}

	IoFreeIrp(Irp);
	ExFreePool(pSyn);

	return Status;
}

NTSTATUS Wsk_SetPermanentEventMask(__in ULONG mask)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	WSK_EVENT_CALLBACK_CONTROL	callbackControl;

	if (g_SocketsState != INITIALIZED)
	{
		return Status;
	}

	callbackControl.NpiId = (PNPIID)&NPI_WSK_INTERFACE_ID;
	callbackControl.EventMask = mask;

	Status = g_WskProvider.Dispatch->WskControlClient(
		g_WskProvider.Client,
		WSK_SET_STATIC_EVENT_CALLBACKS,
		sizeof(callbackControl),
		&callbackControl,
		0,
		NULL,
		NULL,
		NULL);
	if (!NT_SUCCESS(Status)) 
	{
		KdPrint(("Failed to WskControlClient(). status(0x%x)\n", Status));
	}

	return Status;
}
