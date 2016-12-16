#include "FileUtils.h"

#include "Log.h"
#include "Data.h"

NTSTATUS
IrpReadWriteIoCompletion(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context
	)
{
	PKEVENT						Event;
	PIO_STATUS_BLOCK			IoStatusBlock;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpIoCompletion -> enter.\n"));

	IoStatusBlock = Irp->UserIosb;
	IoStatusBlock->Information = Irp->IoStatus.Information;
	IoStatusBlock->Status = Irp->IoStatus.Status;

	Event = Irp->UserEvent;

	if (Event)
	{
		KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
	}

	if (Irp->MdlAddress)
	{
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}

	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
IrpIoCompletion(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context
	)
{
	PKEVENT						Event;
	PIO_STATUS_BLOCK			IoStatusBlock;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpIoCompletion -> enter.\n"));

	IoStatusBlock = Irp->UserIosb;
	IoStatusBlock->Information = Irp->IoStatus.Information;
	IoStatusBlock->Status = Irp->IoStatus.Status;

	Event = (PKEVENT) Context;

	if (Event)
	{
		KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
	}

	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS IrpReadFile(IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN ULONG Flags OPTIONAL,
	OUT ULONG *ReadLength OPTIONAL)
{
	PIRP						Irp;
	PMDL						Mdl;
	PIO_STACK_LOCATION			IrpSp;
	KEVENT						UserEvent;
	LARGE_INTEGER				FileOffset = { 0,0 };
	IO_STATUS_BLOCK				IoStatusBlock;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpReadFile -> enter.\n"));

	if (!Buffer || Length == 0)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpReadFile -> Buffer is NULL. %d\n", Length));
		return STATUS_SUCCESS;
	}

	KeClearEvent(&FileObject->Event);

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (!Irp)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpReadFile -> IoAllocateIrp Fail.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&UserEvent, NotificationEvent, FALSE);

	RtlZeroMemory(Buffer, Length);

	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.AuxiliaryBuffer = NULL;
	Irp->RequestorMode = KernelMode;
	Irp->PendingReturned = FALSE;
	Irp->Cancel = FALSE;
	Irp->CancelRoutine = (PDRIVER_CANCEL) NULL;
	Irp->UserEvent = &UserEvent;
	Irp->UserIosb = &IoStatusBlock;
	Irp->AssociatedIrp.SystemBuffer = Buffer;
	Irp->UserBuffer = Buffer;
	Irp->Flags |= IRP_SYNCHRONOUS_API;
	Irp->Flags |= IRP_READ_OPERATION;
	Irp->Flags |= Flags;
	Irp->MdlAddress = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
	if (Irp->MdlAddress == NULL)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpReadFile -> IoAllocateMdl Fail.\n"));
		IoFreeIrp(Irp);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	MmBuildMdlForNonPagedPool(Irp->MdlAddress);

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_READ;
	IrpSp->MinorFunction = IRP_MN_NORMAL;
	IrpSp->FileObject = FileObject;
	IrpSp->Parameters.Read.Length = Length;
	IrpSp->Parameters.Read.Key = 0;

	if (ByteOffset)
	{
		FileOffset = *ByteOffset;
	}
	else
	{
		FileOffset = FileObject->CurrentByteOffset;
	}

	IrpSp->Parameters.Read.ByteOffset = FileOffset;

	IoSetCompletionRoutine(Irp, IrpReadWriteIoCompletion, NULL, TRUE, TRUE, TRUE);

	if (IoCallDriver(DeviceObject, Irp) == STATUS_PENDING)
	{
		//     DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpReadFile -> STATUS_PENDING Begin.\n"));	
		KeWaitForSingleObject(&UserEvent, Executive, KernelMode, FALSE, NULL);
		//     DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpReadFile -> STATUS_PENDING End.\n"));	
	}

	if (ReadLength)
	{
		*ReadLength = IoStatusBlock.Information;
	}

	return IoStatusBlock.Status;
}

NTSTATUS
IrpWriteFile(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN ULONG Flags OPTIONAL,
	OUT ULONG *WriteLength OPTIONAL)
{
	PIRP						Irp;
	PIO_STACK_LOCATION			IrpSp;
	KEVENT						UserEvent;
	LARGE_INTEGER				FileOffset = { 0, 0 };
	IO_STATUS_BLOCK				IoStatusBlock;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpWriteFile -> enter.\n"));

	if (!Buffer || Length == 0)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpWriteFile -> Buffer is NULL. %d\n", Length));
		return STATUS_SUCCESS;
	}

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpWriteFile -> IoAllocateIrp Fail.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&UserEvent, NotificationEvent, FALSE);

	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.AuxiliaryBuffer = NULL;
	Irp->RequestorMode = KernelMode;
	Irp->PendingReturned = FALSE;
	Irp->Cancel = FALSE;
	Irp->CancelRoutine = (PDRIVER_CANCEL) NULL;
	Irp->UserEvent = &UserEvent;
	Irp->UserIosb = &IoStatusBlock;
	Irp->AssociatedIrp.SystemBuffer = Buffer;
	Irp->UserBuffer = Buffer;

	Irp->Flags |= IRP_SYNCHRONOUS_API;
	Irp->Flags |= IRP_WRITE_OPERATION;
	Irp->Flags |= Flags;
	Irp->MdlAddress = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
	if (Irp->MdlAddress == NULL)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpWriteFile -> IoAllocateMdl Fail.\n"));
		IoFreeIrp(Irp);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	MmBuildMdlForNonPagedPool(Irp->MdlAddress);

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_WRITE;
	IrpSp->MinorFunction = 0;
	IrpSp->FileObject = FileObject;

	if (FileObject->Flags & FO_WRITE_THROUGH)
	{
		IrpSp->Flags = SL_WRITE_THROUGH;
	}

	IrpSp->Parameters.Write.Length = Length;
	IrpSp->Parameters.Write.Key = 0;

	if (ByteOffset)
	{
		FileOffset = *ByteOffset;
	}
	else
	{

		FileOffset = FileObject->CurrentByteOffset;
	}

	IrpSp->Parameters.Write.ByteOffset = FileOffset;

	IoSetCompletionRoutine(Irp, IrpReadWriteIoCompletion, NULL, TRUE, TRUE, TRUE);

	if (IoCallDriver(DeviceObject, Irp) == STATUS_PENDING)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpWriteFile -> STATUS_PENDING Begin.\n"));
		KeWaitForSingleObject(&UserEvent, Executive, KernelMode, FALSE, NULL);
		//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpWriteFile -> STATUS_PENDING End.\n"));
	}

	if (WriteLength)
	{
		*WriteLength = IoStatusBlock.Information;
	}


	return IoStatusBlock.Status;
}

NTSTATUS
IrpQueryInformationFile(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	)
{
	NTSTATUS Status;
	PIRP Irp;
	PIO_STACK_LOCATION IrpSp;
	KEVENT UserEvent;
	IO_STATUS_BLOCK IoStatusBlock;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpQueryInformationFile -> enter.\n"));

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpQueryInformationFile -> IoAllocateIrp Fail.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&UserEvent, SynchronizationEvent, FALSE);

	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->RequestorMode = KernelMode;
	Irp->PendingReturned = FALSE;
	Irp->Cancel = FALSE;
	Irp->CancelRoutine = (PDRIVER_CANCEL) NULL;
	Irp->UserEvent = NULL;
	Irp->UserIosb = &IoStatusBlock;
	Irp->Flags = IRP_SYNCHRONOUS_API;
	Irp->AssociatedIrp.SystemBuffer = FileInformation;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_QUERY_INFORMATION;
	IrpSp->FileObject = FileObject;
	IrpSp->DeviceObject = DeviceObject;
	IrpSp->Parameters.QueryFile.Length = Length;
	IrpSp->Parameters.QueryFile.FileInformationClass = FileInformationClass;

	IoSetCompletionRoutine(Irp, IrpIoCompletion, &UserEvent, TRUE, TRUE, TRUE);

	if (IoCallDriver(DeviceObject, Irp) == STATUS_PENDING)
	{
		KeWaitForSingleObject(&UserEvent, Executive, KernelMode, FALSE, NULL);
	}

	return IoStatusBlock.Status;
}

NTSTATUS
IrpSetInformationFile(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	)
{
	PIRP Irp;
	PIO_STACK_LOCATION IrpSp;
	KEVENT UserEvent;
	IO_STATUS_BLOCK IoStatusBlock;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpSetInformationFile -> enter.\n"));

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpSetInformationFile -> IoAllocateIrp Fail.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&UserEvent, SynchronizationEvent, FALSE);

	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->RequestorMode = KernelMode;
	Irp->PendingReturned = FALSE;
	Irp->Cancel = FALSE;
	Irp->CancelRoutine = (PDRIVER_CANCEL) NULL;
	Irp->UserEvent = NULL;
	Irp->UserIosb = &IoStatusBlock;
	Irp->Flags = IRP_SYNCHRONOUS_API;
	Irp->AssociatedIrp.SystemBuffer = FileInformation;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	IrpSp->FileObject = FileObject;
	IrpSp->DeviceObject = DeviceObject;
	IrpSp->Parameters.QueryFile.Length = Length;
	IrpSp->Parameters.QueryFile.FileInformationClass = FileInformationClass;

	IoSetCompletionRoutine(Irp, IrpIoCompletion, &UserEvent, TRUE, TRUE, TRUE);

	if (IoCallDriver(DeviceObject, Irp) == STATUS_PENDING)
	{
		KeWaitForSingleObject(&UserEvent, Executive, KernelMode, FALSE, NULL);
	}

	return IoStatusBlock.Status;
}


NTSTATUS
IrpCloseFileObject(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject)
{
	PIRP Irp;
	PIO_STACK_LOCATION IrpSp;
	KEVENT UserEvent;
	IO_STATUS_BLOCK IoStatusBlock;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!IrpCloseFileObject -> enter.\n"));

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL)
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!IrpCloseFileObject -> IoAllocateIrp Fail.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&UserEvent, SynchronizationEvent, FALSE);

	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->RequestorMode = KernelMode;
	Irp->PendingReturned = FALSE;
	Irp->Cancel = FALSE;
	Irp->CancelRoutine = (PDRIVER_CANCEL) NULL;
	Irp->UserEvent = &UserEvent;
	Irp->UserIosb = &IoStatusBlock;
	Irp->Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_CLEANUP;
	IrpSp->FileObject = FileObject;
	IrpSp->DeviceObject = DeviceObject;

	//    IoSetCompletionRoutine(Irp, IrpIoCompletion, NULL, TRUE, TRUE, TRUE);

	if (IoCallDriver(DeviceObject, Irp) == STATUS_PENDING)
	{
		KeWaitForSingleObject(&UserEvent, Executive, KernelMode, FALSE, NULL);
	}

	IoFreeIrp(Irp);

	return IoStatusBlock.Status;
}


NTSTATUS
CreateFileByFsDevice(
	OUT PHANDLE FileHandle,
	OUT PFILE_OBJECT *FileObject,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG Disposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength,
	IN PVOID DeviceObject
	)
{
	NTSTATUS Status;

	//	DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!CreateFileByFsDevice -> enter.\n"));

	Status = IoCreateFileSpecifyDeviceObjectHint(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		NULL,
		FileAttributes,
		ShareAccess,
		Disposition,
		CreateOptions,
		EaBuffer,
		EaLength,
		CreateFileTypeNone,
		NULL,
		0,
		DeviceObject
		);

	if (!NT_SUCCESS(Status))
	{
		//		DebugTrace(DEBUG_TRACE_FILESUP|DEBUG_TRACE_ERROR, ("FileSup!CreateFileByFsDevice -> IoCreateFileSpecifyDeviceObjectHint Fail. 0x%08x\n", Status));
		return Status;
	}

	if (FileObject)
	{
		Status = ObReferenceObjectByHandle(
			*FileHandle,
			0,
			*IoFileObjectType,
			KernelMode,
			(PVOID*) FileObject,
			NULL
			);

		if (!NT_SUCCESS(Status))
		{
			//			DebugTrace(DEBUG_TRACE_FILESUP|DEBUG_TRACE_ERROR, ("FileSup!CreateFileByFsDevice -> ObReferenceObjectByHandle Fail. 0x%08x\n", Status));
			ZwClose(*FileHandle);
			return Status;
		}

		ObDereferenceObject(*FileObject);
	}

	return Status;
}

NTSTATUS GetBackupDriveFsDeviceObject(IN PDEVICE_OBJECT *DeviceObject)
{
	NTSTATUS					Status;
	UNICODE_STRING				DeviceName;
	PFILE_OBJECT				DeviceFileObject;
	PDEVICE_OBJECT				FsDeviceObject;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!GetBackupDriveFsDeviceObject -> enter.\n"));

	RtlInitUnicodeString(&DeviceName, BackupDriveLetter);

	Status = IoGetDeviceObjectPointer(&DeviceName, SYNCHRONIZE, &DeviceFileObject, &FsDeviceObject);
	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!GetBackupDriveFsDeviceObject -> IoGetDeviceObjectPointer Fail. 0x%08x\n", Status));
		return Status;
	}

	ObDereferenceObject(DeviceFileObject);
	FsDeviceObject = IoGetDeviceAttachmentBaseRef(FsDeviceObject);
	if (FsDeviceObject->Vpb)
	{
		FsDeviceObject = FsDeviceObject->Vpb->DeviceObject;
	}

	*DeviceObject = FsDeviceObject;

	return Status;
}

NTSTATUS CreateFileFromBackupDrive(
	OUT PHANDLE FileHandle,
	OUT PFILE_OBJECT  *FileObject OPTIONAL,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG  FileAttributes,
	IN ULONG  ShareAccess,
	IN ULONG  Disposition,
	IN ULONG  CreateOptions,
	IN PVOID  EaBuffer OPTIONAL,
	IN ULONG  EaLength
	)
{
	NTSTATUS		Status;
	UNICODE_STRING	DeviceName;
	PFILE_OBJECT	DeviceFileObject;
	PFILE_OBJECT	DestFileObject;
	PDEVICE_OBJECT	FsDeviceObject;

	//DebugTrace(DEBUG_TRACE_FILESUP, ("FileSup!CreateFileFromBackupDrive -> enter.\n"));

	Status = GetBackupDriveFsDeviceObject(&FsDeviceObject);
	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_FILESUP | DEBUG_TRACE_ERROR, ("FileSup!CreateFileFromBackupDrive -> GetBackupDriveFsDeviceObject Fail. 0x%08x\n", Status));
		return Status;
	}

	Status = CreateFileByFsDevice(
		FileHandle,
		FileObject,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		FileAttributes,
		ShareAccess,
		Disposition,
		CreateOptions,
		EaBuffer,
		EaLength,
		FsDeviceObject
		);

	return Status;
}

BOOLEAN IsExsitFileA(PCHAR FileName)
{
	NTSTATUS Status;
	BOOLEAN Result = FALSE;
	UNICODE_STRING DestFileName;
	UNICODE_STRING UnicodeFileName;
	ANSI_STRING AnsiString;
	PWCHAR DestFileNameBuf = NULL;
	PWCHAR UnicodeFileNameBuf = NULL;
	HANDLE FileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;


	__try
	{

		DestFileNameBuf = AllocPathLookasideList();
		if (!DestFileNameBuf)
		{
			__leave;
		}
		RtlInitEmptyUnicodeString(&DestFileName, DestFileNameBuf, MAX_PATH_SIZE);

		UnicodeFileNameBuf = AllocPathLookasideList();
		if (!UnicodeFileNameBuf)
		{
			__leave;
		}
		RtlInitEmptyUnicodeString(&UnicodeFileName, UnicodeFileNameBuf, MAX_PATH_SIZE);

		RtlInitAnsiString(&AnsiString, FileName);

		RtlAppendUnicodeToString(&DestFileName, L"\\??\\");
		RtlAnsiStringToUnicodeString(&UnicodeFileName, &AnsiString, FALSE);
		RtlAppendUnicodeStringToString(&DestFileName, &UnicodeFileName);

		//DebugString(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, "SFSSup!IsExsitFileA -> ZwCreateFile = %s\n", DestFileName.Buffer);

		InitializeObjectAttributes(&ObjectAttributes, &DestFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = ZwCreateFile(&FileHandle,
			FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);



		if (!NT_SUCCESS(Status))
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!IsExsitFileA -> ZwCreateFile Fail. status = 0x%08x\n", Status));
			__leave;
		}

		Result = TRUE;

	}
	__finally
	{
		if (FileHandle)
		{
			ZwClose(FileHandle);
		}

		if (DestFileNameBuf)
		{
			FreePathLookasideList(DestFileNameBuf);
		}

		if (UnicodeFileNameBuf)
		{
			FreePathLookasideList(UnicodeFileNameBuf);
		}

	}


	return Result;
}