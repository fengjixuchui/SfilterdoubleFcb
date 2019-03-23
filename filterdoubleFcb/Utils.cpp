#include "Utils.h"
#include "WDK.h"
//#include "Log.h"
#include "Data.h"
//#include "Config.h"
#include "FileUtils.h"
//#include "ProcCallback.h"
#include "Global.h"
#include "CryptBox.h"
#include "RC4.h"
//#include "SafeFile.h"
#include "Include/Policy.h"
#include "Common.h"
#include "Include/Crc32.h"
#include "Include/BaseTypes.h"
#include "CryptUtils.h"
#include "Include/strtod.h"
///
#include "NtMem.h"

//VOID GenerateUUID(CHAR UUID[UUID_LEN], INT random)
//{
//	unsigned char* uuid = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, UUID_LEN, L'uuid');
//
//	LARGE_INTEGER Time, Time1;
//	KeQuerySystemTime(&Time);
//	//	DebugTrace(DEBUG_TRACE_DEBUG, ("UUID Generate1 %d %d", Time.HighPart, Time.LowPart));
//	KeQueryTickCount(&Time1);
//	//	DebugTrace(DEBUG_TRACE_DEBUG, ("UUID Generate2 %d %d", Time1.HighPart, Time1.LowPart));
//	Time.HighPart += Time1.LowPart;
//	Time.LowPart += Time1.HighPart;
//	memcpy(uuid, &Time, 8);
//
//	short random2 = (int)PsGetCurrentProcessId() + g_Config.m_Policy.UserAuth.nUserID + g_Config.m_Policy.UserAuth.nSecretDegree * 100 + random;
//	memcpy(uuid + 8, &random2, 2);
//	//	DebugTrace(DEBUG_TRACE_DEBUG, ("UUID Generate2 %d", random2));
//	memcpy(uuid + 10, g_Config.MACAddress, 6);
//	memcpy(uuid + 16, g_Config.IPAddress, 4);
//
//	rc4_state *RC4State = NULL;
//	RC4State = (rc4_state*)ExAllocatePoolWithTag(NonPagedPool, sizeof(rc4_state), L'rc4s');
//	unsigned char key[20] = { 0x2B, 0x2E, 0xE6, 0xCB, 0x94, 0x1C, 0x45, 0xBA, 0xA3, 0x0B, 0x48, 0xBB, 0x68, 0x91, 0xE4, 0x08, 0x57, 0x1D, 0xFB, 0x22 };
//	rc4_setup(RC4State, uuid, UUID_LEN);
//	rc4_crypt(RC4State, uuid, UUID_LEN);
//	memcpy(UUID, uuid, UUID_LEN);
//	ExFreePool(RC4State);
//	ExFreePool(uuid);
//}
int BinToHex(PCHAR szInBuffer, int len, char* szOutBuffer)
{
	if (szInBuffer == NULL || szOutBuffer == NULL)
	{
		return ISAFE_BUFFER_NULL;
	}

	char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	int i = 0, p = 0;
	unsigned char d;

	while (i < len)
	{
		d = szInBuffer[i++];
		szOutBuffer[p++] = lookup[d / 0x10];
		szOutBuffer[p++] = lookup[d % 0x10];
	}
	szOutBuffer[p] = '\0';
	return ISAFE_STATUS_SUCCESS;
}
int UUIDToString(CHAR szInBuffer[UUID_LEN], char* szOutBuffer)
{
	if (szInBuffer == NULL || szOutBuffer == NULL)
	{
		return ISAFE_BUFFER_NULL;
	}

	char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	int i = 0, p = 0;
	unsigned char d;

	while (i < UUID_LEN)
	{
		d = szInBuffer[i++];
		szOutBuffer[p++] = lookup[d / 0x10];
		szOutBuffer[p++] = lookup[d % 0x10];
	}
	szOutBuffer[p] = '\0';
	return ISAFE_STATUS_SUCCESS;
}



static
NTSTATUS FileReadWriteComplete(
	PDEVICE_OBJECT dev,
	PIRP irp,
	PVOID context
)
{
	*irp->UserIosb = irp->IoStatus;
	KeSetEvent(irp->UserEvent, 0, FALSE);
	IoFreeIrp(irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
FileReadWrite(
	IN ULONG MajorFunction,
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER ByteOffset,
	IN ULONG Length,
	IN PVOID Buffer,
	OUT PULONG ByteReadWrite,
	IN FLT_IO_OPERATION_FLAGS FltFlags
)
{
	ULONG i;
	PIRP irp;
	KEVENT Event;
	PIO_STACK_LOCATION ioStackLocation;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	PDEVICE_OBJECT pVolumeDevObj = NULL;
	PDEVICE_OBJECT pFileSysDevObj = NULL;
	PDEVICE_OBJECT pNextDevObj = NULL;

	pVolumeDevObj = IoGetDeviceAttachmentBaseRef(FileObject->DeviceObject);
	if (NULL == pVolumeDevObj) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NULL == pVolumeDevObj->Vpb) {
		return STATUS_UNSUCCESSFUL;
	}

	pFileSysDevObj = pVolumeDevObj->Vpb->DeviceObject;
	pNextDevObj = pFileSysDevObj;

	if (NULL == pNextDevObj) {
		ObDereferenceObject(pVolumeDevObj);
		return STATUS_UNSUCCESSFUL;
	}

	KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	irp = IoAllocateIrp(pNextDevObj->StackSize, FALSE);

	if (NULL == irp) {
		ObDereferenceObject(pVolumeDevObj);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irp->AssociatedIrp.SystemBuffer = NULL;
	irp->MdlAddress = NULL;
	irp->UserBuffer = Buffer;
	irp->UserEvent = &Event;
	irp->UserIosb = &IoStatusBlock;
	irp->Tail.Overlay.Thread = PsGetCurrentThread();
	irp->RequestorMode = KernelMode;

	if (MajorFunction == IRP_MJ_READ) {
		irp->Flags = IRP_DEFER_IO_COMPLETION | IRP_READ_OPERATION | IRP_NOCACHE;
	}
	else if (IRP_MJ_WRITE == MajorFunction) {
		irp->Flags = IRP_DEFER_IO_COMPLETION | IRP_WRITE_OPERATION | IRP_NOCACHE;
	}
	else {
		ObDereferenceObject(pVolumeDevObj);
		return STATUS_UNSUCCESSFUL;
	}

	if ((FltFlags & FLTFL_IO_OPERATION_PAGING) == FLTFL_IO_OPERATION_PAGING) {
		irp->Flags |= IRP_PAGING_IO;
	}

	ioStackLocation = IoGetNextIrpStackLocation(irp);
	ioStackLocation->MajorFunction = (UCHAR)MajorFunction;
	ioStackLocation->MinorFunction = (UCHAR)IRP_MN_NORMAL;
	ioStackLocation->DeviceObject = pNextDevObj;
	ioStackLocation->FileObject = FileObject;
	if (MajorFunction == IRP_MJ_READ) {
		ioStackLocation->Parameters.Read.ByteOffset = *ByteOffset;
		ioStackLocation->Parameters.Read.Length = Length;
	}
	else {
		ioStackLocation->Parameters.Write.ByteOffset = *ByteOffset;
		ioStackLocation->Parameters.Write.Length = Length;
	}

	IoSetCompletionRoutine(irp, FileReadWriteComplete, 0, TRUE, TRUE, TRUE);
	IoCallDriver(pNextDevObj, irp);
	KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);
	*ByteReadWrite = IoStatusBlock.Information;

	ObDereferenceObject(pVolumeDevObj);
	return IoStatusBlock.Status;
}


VOID SetNextIrpStack(IN PDEVICE_OBJECT RealFsDevice, IN PFILE_OBJECT RealFileObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION NextIrpSp;

	IoCopyCurrentIrpStackLocationToNext(Irp);

	NextIrpSp = IoGetNextIrpStackLocation(Irp);
	NextIrpSp->FileObject = RealFileObject;
	NextIrpSp->DeviceObject = RealFsDevice;
	Irp->Tail.Overlay.OriginalFileObject = RealFileObject;
}

VOID ReleasePathNameInformation(PPATH_NAME_INFORMATION PathNameInformation)
{
	if (!PathNameInformation)
	{
		return;
	}

	if (PathNameInformation->Name.Buffer)
	{
		ExFreePool(PathNameInformation->Name.Buffer);
	}

	if (PathNameInformation->VolumePath.Buffer)
	{
		ExFreePool(PathNameInformation->VolumePath.Buffer);
	}

	if (PathNameInformation->ParentPath.Buffer)
	{
		ExFreePool(PathNameInformation->ParentPath.Buffer);
	}

	if (PathNameInformation->FullFileName.Buffer)
	{
		ExFreePool(PathNameInformation->FullFileName.Buffer);
	}

	if (PathNameInformation->FileName.Buffer)
	{
		ExFreePool(PathNameInformation->FileName.Buffer);
	}

	ExFreePool(PathNameInformation);
}

BOOLEAN GetFullFilePath(IN PFILE_OBJECT FileObject, OUT PPATH_NAME_INFORMATION *PathNameInfo)
{
	NTSTATUS					Status;
	POBJECT_NAME_INFORMATION	NameInfo = NULL;
	PPATH_NAME_INFORMATION		PathNameInformation = NULL;

	PWCHAR						VolumePathBuf = NULL;
	PWCHAR						ParentPathBuf = NULL;
	PWCHAR						FileNameBuf = NULL;
	PWCHAR						FullFileNameBuf = NULL;
	PWCHAR						NameBuf = NULL;

	UNICODE_STRING				TempName;

	ULONG						ReturnLong;
	PVOID						Object = NULL;

	if (!FileObject || !FileObject->DeviceObject)
	{
		return FALSE;
	}

	if (!PathNameInfo)
	{
		return FALSE;
	}

	if (FileObject->FileName.Length >= MAX_PATH_SIZE)
	{
		//      DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!GetFullFilePath -> FileObject->FileName.Length >= MAX_PATH_SIZE  length = %d.\n", FileObject->FileName.Length));
		return FALSE;
	}

	if (FileObject->RelatedFileObject && FileObject->RelatedFileObject->FileName.Length != 0)
	{
		if ((FileObject->RelatedFileObject->FileName.Length + FileObject->FileName.Length + sizeof(WCHAR)) >= MAX_PATH_SIZE)
		{
			//          DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!GetFullFilePath -> FileObject->RelatedFileObject->FileName.Length + FileObject->FileName.Length + sizeof(WCHAR)) >= MAX_PATH_SIZE length = %d.\n", FileObject->RelatedFileObject->FileName.Length + FileObject->FileName.Length + sizeof(WCHAR)));
			return FALSE;
		}
	}

	*PathNameInfo = (PPATH_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(PATH_NAME_INFORMATION), 'PNIM');
	if (!*PathNameInfo)
	{
		goto Error_Cleanup;
	}
	PathNameInformation = *PathNameInfo;
	RtlZeroMemory(PathNameInformation, sizeof(PATH_NAME_INFORMATION));

	NameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'Tn0g');
	if (!NameBuf)
	{
		goto Error_Cleanup;
	}
	RtlZeroMemory(NameBuf, MAX_PATH_SIZE);
	RtlInitEmptyUnicodeString(&PathNameInformation->Name, NameBuf, MAX_PATH_SIZE);

	FullFileNameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'Tn0g');
	if (!FullFileNameBuf)
	{
		goto Error_Cleanup;
	}
	RtlZeroMemory(FullFileNameBuf, MAX_PATH_SIZE);
	RtlInitEmptyUnicodeString(&PathNameInformation->FullFileName, FullFileNameBuf, MAX_PATH_SIZE);

	NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'Tn0g');
	if (!NameInfo)
	{
		goto Error_Cleanup;
	}
	RtlZeroMemory(NameInfo, MAX_PATH_SIZE);

	Object = FileObject->DeviceObject;
	Status = ObQueryNameString(Object, NameInfo, MAX_PATH_SIZE, &ReturnLong);
	if (STATUS_INFO_LENGTH_MISMATCH == Status)
	{
		ExFreePool(NameInfo);
		NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLong, 'Tn0g');
		if (!NameInfo)
		{
			goto Error_Cleanup;
		}
		RtlZeroMemory(NameInfo, ReturnLong);
		Status = ObQueryNameString(Object, NameInfo, ReturnLong, &ReturnLong);

		if (!NT_SUCCESS(Status))
		{
			goto Error_Cleanup;
		}
	}

	VolumePathBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, NameInfo->Name.Length + sizeof(WCHAR), 'Tn0g');
	if (!VolumePathBuf)
	{
		goto Error_Cleanup;
	}
	RtlZeroMemory(VolumePathBuf, NameInfo->Name.Length + sizeof(WCHAR));
	RtlInitEmptyUnicodeString(&PathNameInformation->VolumePath, VolumePathBuf, NameInfo->Name.Length);
	RtlUnicodeStringCbCopyN(&PathNameInformation->VolumePath, &NameInfo->Name, NameInfo->Name.Length);

	ExFreePool(NameInfo);
	NameInfo = NULL;

	if (FileObject->RelatedFileObject)
	{
		Object = FileObject->RelatedFileObject;

		NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'Tn0g');
		if (!NameInfo)
		{
			goto Error_Cleanup;
		}
		RtlZeroMemory(NameInfo, MAX_PATH_SIZE);
		Status = ObQueryNameString(Object, NameInfo, MAX_PATH_SIZE, &ReturnLong);
		if (STATUS_INFO_LENGTH_MISMATCH == Status)
		{
			ExFreePool(NameInfo);
			NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLong, 'Tn0g');
			if (!NameInfo)
			{
				goto Error_Cleanup;
			}
			RtlZeroMemory(NameInfo, ReturnLong);
			Status = ObQueryNameString(Object, NameInfo, ReturnLong, &ReturnLong);

			if (!NT_SUCCESS(Status))
			{
				goto Error_Cleanup;
			}
		}

		ParentPathBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, NameInfo->Name.Length + sizeof(WCHAR), 'Tn0g');
		if (!ParentPathBuf)
		{
			goto Error_Cleanup;
		}

		RtlZeroMemory(ParentPathBuf, NameInfo->Name.Length + sizeof(WCHAR));
		RtlInitEmptyUnicodeString(&PathNameInformation->ParentPath, ParentPathBuf, NameInfo->Name.Length);

		RtlUnicodeStringCbCopyN(&PathNameInformation->ParentPath, &NameInfo->Name, NameInfo->Name.Length);
		RtlUnicodeStringCbCopyN(&PathNameInformation->Name, &NameInfo->Name, NameInfo->Name.Length);

		ExFreePool(NameInfo);
		NameInfo = NULL;
	}
	else
	{
		RtlUnicodeStringCbCopyN(&PathNameInformation->Name, &PathNameInformation->VolumePath, PathNameInformation->VolumePath.Length);

		if (!PathNameInformation->ParentPath.Buffer)
		{
			if (!FileObject->FileName.Buffer || (FileObject->FileName.Buffer[0] == L'\\' && FileObject->FileName.Length == sizeof(WCHAR)))
			{
				PathNameInformation->IsRootPath = TRUE;
			}
		}
	}

	if (PathNameInformation->Name.Length > 2 && PathNameInformation->Name.Buffer[PathNameInformation->Name.Length / sizeof(WCHAR) - 1] != L'\\')
	{
		RtlAppendUnicodeToString(&PathNameInformation->Name, L"\\");
	}

	if (FileObject->FileName.Buffer && FileObject->FileName.Length != 0)
	{
		FileNameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, FileObject->FileName.Length + sizeof(WCHAR), 'Tn0g');
		if (!FileNameBuf)
		{
			goto Error_Cleanup;
		}
		RtlZeroMemory(FileNameBuf, FileObject->FileName.Length + sizeof(WCHAR));
		RtlInitEmptyUnicodeString(&PathNameInformation->FileName, FileNameBuf, FileObject->FileName.Length);
		RtlUnicodeStringCbCopyN(&PathNameInformation->FileName, &FileObject->FileName, FileObject->FileName.Length);

		if (PathNameInformation->FileName.Buffer[0] == L'\\' || PathNameInformation->FileName.Buffer[0] == L':')
		{
			PathNameInformation->Name.Length -= sizeof(WCHAR);
		}

		RtlAppendUnicodeStringToString(&PathNameInformation->Name, &FileObject->FileName);
	}

	//    DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!GetFullFilePath -> PathNameInformation->Name.Length = %d, wcslen = %d, maxlength = %d .\n", PathNameInformation->Name.Length, wcslen(PathNameInformation->Name.Buffer) * sizeof(WCHAR), PathNameInformation->Name.MaximumLength));

	if (PathNameInformation->Name.Length >= MAX_PATH_SIZE)
	{
		goto Error_Cleanup;
	}

	TempName = PathNameInformation->Name;

	if (!PathNameInformation->IsRootPath)
	{
		TempName.Buffer += PathNameInformation->VolumePath.Length / sizeof(WCHAR);
		TempName.Length -= PathNameInformation->VolumePath.Length;
		RtlUnicodeStringCbCopyN(&PathNameInformation->FullFileName, &TempName, TempName.Length);
	}
	return TRUE;

Error_Cleanup:

	if (PathNameInformation)
	{
		ExFreePool(PathNameInformation);
	}

	if (NameInfo)
	{
		ExFreePool(NameInfo);
	}

	if (VolumePathBuf)
	{
		ExFreePool(VolumePathBuf);
	}

	if (ParentPathBuf)
	{
		ExFreePool(ParentPathBuf);
	}

	if (FileNameBuf)
	{
		ExFreePool(FileNameBuf);
	}

	if (NameBuf)
	{
		ExFreePool(NameBuf);
	}

	if (FullFileNameBuf)
	{
		ExFreePool(FullFileNameBuf);
	}

	*PathNameInfo = NULL;

	return FALSE;
}

BOOLEAN GetFullFilePathForDevice(IN PFILE_OBJECT FileObject, IN PDEVICE_OBJECT Device, OUT PUNICODE_STRING Name)
{
	NTSTATUS						Status;
	BOOLEAN							IsTrue = TRUE;
	ULONG							ReturnLong;
	PPATH_NAME_INFORMATION			PathNameInfo = NULL;
	POBJECT_NAME_INFORMATION		NameInfo = NULL;
	PWCHAR							NameBuf;

	if (!FileObject || !Device || !Name)
	{
		return FALSE;
	}

	Status = GetFullFilePath(FileObject, &PathNameInfo);
	if (!Status)
	{
		return FALSE;
	}

	NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'Tn0g');
	if (!NameInfo)
	{
		return FALSE;
	}

	RtlZeroMemory(NameInfo, MAX_PATH_SIZE);

	Status = ObQueryNameString(Device, NameInfo, MAX_PATH_SIZE, &ReturnLong);
	if (STATUS_INFO_LENGTH_MISMATCH == Status)
	{
		ExFreePool(NameInfo);
		NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLong, 'Tn0g');
		if (!NameInfo)
		{
			IsTrue = FALSE;
			goto Cleanup;
		}

		RtlZeroMemory(NameInfo, MAX_PATH_SIZE);
		Status = ObQueryNameString(Device, NameInfo, ReturnLong, &ReturnLong);

		if (!NT_SUCCESS(Status))
		{
			IsTrue = FALSE;
			goto Cleanup;
		}
	}

	NameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, NameInfo->Name.Length + PathNameInfo->FullFileName.Length + sizeof(WCHAR), 'Tn0g');
	if (!NameBuf)
	{
		IsTrue = FALSE;
		goto Cleanup;
	}

	RtlZeroMemory(NameBuf, NameInfo->Name.Length + PathNameInfo->FullFileName.Length + sizeof(WCHAR));
	RtlInitEmptyUnicodeString(Name, NameBuf, NameInfo->Name.Length + PathNameInfo->FullFileName.Length + sizeof(WCHAR));

	RtlUnicodeStringCbCopyN(Name, &NameInfo->Name, NameInfo->Name.Length);
	RtlAppendUnicodeStringToString(Name, &PathNameInfo->FullFileName);

Cleanup:
	if (PathNameInfo)
	{
		ReleasePathNameInformation(PathNameInfo);
	}

	if (NameInfo)
	{
		ExFreePool(NameInfo);
	}

	return IsTrue;
}

BOOLEAN GetSFSFullFilePath(OUT PWCHAR FullFilePath, IN PPATH_NAME_INFORMATION PathNameInfo)
{
	if (!FullFilePath)
	{
		return FALSE;
	}

	if (!PathNameInfo)
	{
		return FALSE;
	}

	if (PathNameInfo->IsRootPath)
	{
		RtlStringCchCopyW(FullFilePath, MAX_PATH, PathNameInfo->VolumePath.Buffer);
		RtlStringCchCatW(FullFilePath, MAX_PATH, L"_SFS\\");
	}
	else
	{
		RtlStringCchCopyW(FullFilePath, MAX_PATH, PathNameInfo->VolumePath.Buffer);
		RtlStringCchCatW(FullFilePath, MAX_PATH, L"_SFS");
		RtlStringCchCatW(FullFilePath, MAX_PATH, PathNameInfo->FullFileName.Buffer);
	}
	return TRUE;
}

PIRP IsIrpTopLevel(IN PIRP Irp)
{
	PIRP OldTopIrp;
	OldTopIrp = IoGetTopLevelIrp();
	if (OldTopIrp == NULL)
	{
		IoSetTopLevelIrp(Irp);

	}
	return OldTopIrp;
}







VOID ClearCache(IN PFILE_OBJECT FileObject, IN PLARGE_INTEGER ByteOffset, IN ULONG ByteCount)
{
	NTSTATUS						Status;
	PFSRTL_ADVANCED_FCB_HEADER		Fcb;
	IO_STATUS_BLOCK					IoStatus;
	FILE_STANDARD_INFORMATION		StandardInfo;
	VBO                             StartingVbo;

	if (!ByteOffset)
	{
		StartingVbo = 0;
	}
	else
	{
		StartingVbo = ByteOffset->QuadPart;
	}


	Fcb = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;

	if (FileObject->SectionObjectPointer
		&& (FileObject->SectionObjectPointer->DataSectionObject
			|| FileObject->SectionObjectPointer->ImageSectionObject
			|| FileObject->SectionObjectPointer->SharedCacheMap))
	{
		if ((StartingVbo + ByteCount) > Fcb->FileSize.QuadPart)
		{
			ByteCount = Fcb->FileSize.QuadPart;
		}

		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!ClearCache -> CcFlushCache.\n"));

		CcFlushCache(
			FileObject->SectionObjectPointer,
			WriteToEof ? &Fcb->FileSize : ByteOffset,
			ByteCount,
			&IoStatus
		);


		if (!NT_SUCCESS(IoStatus.Status))
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!ClearCache -> CcFlushCache status = %x.\n", IoStatus.Status));
			return;
		}

		//        DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!ClearCache -> MmFlushImageSection.\n"));

		MmFlushImageSection(FileObject->SectionObjectPointer, MmFlushForWrite);

		//        DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!ClearCache -> CcPurgeCacheSection.\n"));

		CcPurgeCacheSection(
			FileObject->SectionObjectPointer,
			WriteToEof ? &Fcb->FileSize : ByteOffset,
			ByteCount,
			FALSE
		);

	}
}


VOID SFSFlushCache(IN PFILE_OBJECT FileObject, IN PLARGE_INTEGER ByteOffset, IN ULONG ByteCount)
{
	NTSTATUS						Status;
	PFSRTL_ADVANCED_FCB_HEADER		Fcb;
	IO_STATUS_BLOCK					IoStatus;
	FILE_STANDARD_INFORMATION		StandardInfo;
	VBO                             StartingVbo;

	if (!ByteOffset)
	{
		StartingVbo = 0;
	}
	else
	{
		StartingVbo = ByteOffset->QuadPart;
	}


	Fcb = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;

	if (FileObject->SectionObjectPointer
		&& (FileObject->SectionObjectPointer->DataSectionObject
			|| FileObject->SectionObjectPointer->ImageSectionObject
			|| FileObject->SectionObjectPointer->SharedCacheMap))
	{
		if ((StartingVbo + ByteCount) > Fcb->FileSize.QuadPart)
		{
			ByteCount = Fcb->FileSize.QuadPart;
		}

		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!ClearCache -> CcFlushCache.\n"));

		CcFlushCache(
			FileObject->SectionObjectPointer,
			WriteToEof ? &Fcb->FileSize : ByteOffset,
			ByteCount,
			&IoStatus
		);


		if (!NT_SUCCESS(IoStatus.Status))
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!ClearCache -> CcFlushCache status = %x.\n", IoStatus.Status));
			return;
		}

		MmFlushImageSection(FileObject->SectionObjectPointer, MmFlushForWrite);
	}
}

VOID SFSFlushFile(IN PFCB Fcb)
{
	IO_STATUS_BLOCK				IoStatus;
	PSECTION_OBJECT_POINTERS	SectionObjectPointer;

	SectionObjectPointer = &Fcb->NonPaged->SectionObjectPointers;

	CcFlushCache(
		SectionObjectPointer,
		NULL,
		0,
		NULL
	);

}


VOID SFSFlushFileObject(IN PFILE_OBJECT FileObject)
{
	IO_STATUS_BLOCK				IoStatus;
	PSECTION_OBJECT_POINTERS	SectionObjectPointer;

	SectionObjectPointer = FileObject->SectionObjectPointer;
	if (!SectionObjectPointer)
	{
		return;
	}

	CcFlushCache(
		SectionObjectPointer,
		NULL,
		0,
		NULL
	);
}

VOID FlushFile(IN PFILE_OBJECT FileObject)
{
	PFSRTL_ADVANCED_FCB_HEADER	Fcb;
	IO_STATUS_BLOCK				IoStatus;

	Fcb = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;

	if (!FileObject->SectionObjectPointer || !FileObject->SectionObjectPointer->DataSectionObject)
	{
		return;
	}

	CcFlushCache(FileObject->SectionObjectPointer, NULL, 0, &IoStatus);

	if (!NT_SUCCESS(IoStatus.Status))
	{
		return;
	}
}


NTSTATUS
CallLowerDriverIoCompletion(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context
)
{

#if 0
	NTSTATUS					Status = STATUS_SUCCESS;
	PKEVENT						Event;

	if (BooleanFlagOn(Irp->Flags, IRP_DEFER_IO_COMPLETION))
	{
		Status = STATUS_MORE_PROCESSING_REQUIRED;
	}

	Event = (PKEVENT)Context;
	Irp->PendingReturned = FALSE;

	KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
#endif
	NTSTATUS					Status = STATUS_MORE_PROCESSING_REQUIRED;
	PKEVENT						Event;

	Event = (PKEVENT)Context;
	Irp->PendingReturned = FALSE;
	KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
	return Status;
}


NTSTATUS CallLowerDriver(IN PIRP_CONTEXT IrpContext)
{
	NTSTATUS				Status;
	PDEVICE_OBJECT			RealFsDevice;
	PFILE_OBJECT			RealFileObject;
	PIRP					Irp;
	KEVENT					Event;

	RealFsDevice = IrpContext->RealFsDevice;
	RealFileObject = IrpContext->RealFileObject;
	Irp = IrpContext->OriginatingIrp;
	KeClearEvent(&RealFileObject->Event);
	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	IoSetCompletionRoutine(Irp, CallLowerDriverIoCompletion, &Event, TRUE, TRUE, TRUE);
	Status = IoCallDriver(RealFsDevice, Irp);
	if (Status == STATUS_PENDING)
	{
		//     //KdPrint(("STATUS_PENDING Begin\n"));
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		//     //KdPrint(("STATUS_PENDING End\n"));
		Status = RealFileObject->FinalStatus;
	}
	return Status;
}

VOID BalanceObject(IN PIRP Irp, IN PFILE_OBJECT SFSFileObject, IN PFILE_OBJECT RealFileObject, IN NTSTATUS Status)
{
	if (BooleanFlagOn(Irp->Flags, (IRP_PAGING_IO | IRP_CLOSE_OPERATION)))
	{
		ObDereferenceObject(RealFileObject);
	}
	else if (BooleanFlagOn(Irp->Flags, IRP_DEFER_IO_COMPLETION))
	{
		if (Status == STATUS_PENDING)
		{
			ObDereferenceObject(SFSFileObject);

		}
		else if (!BooleanFlagOn(Irp->Flags, IRP_CREATE_OPERATION))
		{
			ObDereferenceObject(RealFileObject);
		}
	}
	else
	{
		ObDereferenceObject(SFSFileObject);
	}
}

VOID BalanceObjectFlags(IN ULONG Flags, IN PFILE_OBJECT SFSFileObject, IN PFILE_OBJECT RealFileObject, IN NTSTATUS Status)
{
	if (BooleanFlagOn(Flags, (IRP_PAGING_IO | IRP_CLOSE_OPERATION)))
	{
		ObDereferenceObject(RealFileObject);
	}
	else if (BooleanFlagOn(Flags, IRP_DEFER_IO_COMPLETION))
	{
		if (Status == STATUS_PENDING)
		{
			ObDereferenceObject(SFSFileObject);

		}
		else if (!BooleanFlagOn(Flags, IRP_CREATE_OPERATION))
		{
			ObDereferenceObject(RealFileObject);
		}
	}
	else
	{
		ObDereferenceObject(SFSFileObject);
	}
}

NTSTATUS CallRealFsDriver(IN PIRP_CONTEXT IrpContext)
{
	NTSTATUS				Status;
	PDEVICE_OBJECT			RealFsDevice;
	PFILE_OBJECT			RealFileObject;
	PFILE_OBJECT			FileObject;
	PIRP					Irp;

	RealFsDevice = IrpContext->RealFsDevice;
	RealFileObject = IrpContext->RealFileObject;
	FileObject = IrpContext->FileObject;
	Irp = IrpContext->OriginatingIrp;

	ObReferenceObject(RealFileObject);
	SetNextIrpStack(RealFsDevice, RealFileObject, Irp);

	Status = CallLowerDriver(IrpContext);

	BalanceObject(Irp, FileObject, RealFileObject, Status);
	UpdateFileObject(FileObject, RealFileObject);

	CompleteRequest(NULL, Irp, Status);
#if 0
	if (!BooleanFlagOn(Irp->Flags, IRP_DEFER_IO_COMPLETION))
	{
		CompleteRequest(NULL, Irp, Status);
	}
#endif
	return Status;
}

BOOLEAN UpdateFileObject(IN OUT PFILE_OBJECT FileObject, IN PFILE_OBJECT RealFileObject)
{
	PFSRTL_ADVANCED_FCB_HEADER	Fcb;
	PFSRTL_ADVANCED_FCB_HEADER	RealFcb;
	PCCB						Ccb;
#if 0
	FileObject->FinalStatus = RealFileObject->FinalStatus;
	FileObject->LockOperation = RealFileObject->LockOperation;
	FileObject->DeletePending = RealFileObject->DeletePending;
	FileObject->Flags = RealFileObject->Flags;
	FileObject->Flags &= ~(FO_FILE_OBJECT_HAS_EXTENSION);
	//    FileObject->Flags           |= FO_WRITE_THROUGH;
	//	FileObject->Flags			&=~(FO_CACHE_SUPPORTED);
	FileObject->CurrentByteOffset = RealFileObject->CurrentByteOffset;
	FileObject->Waiters = RealFileObject->Waiters;
	FileObject->Busy = RealFileObject->Busy;
	FileObject->LastLock = RealFileObject->LastLock;
#endif 

	FileObject->ReadAccess = RealFileObject->ReadAccess;
	FileObject->WriteAccess = RealFileObject->WriteAccess;
	FileObject->DeleteAccess = RealFileObject->DeleteAccess;
	FileObject->SharedRead = RealFileObject->SharedRead;
	FileObject->SharedWrite = RealFileObject->SharedWrite;
	FileObject->SharedDelete = RealFileObject->SharedDelete;

	//    FileObject->Flags			= RealFileObject->Flags;

	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateFileObject -> ReadAccess = %d, WriteAccess = %d, DeleteAccess = %d, SharedRead = %d, SharedWrite = %d, SharedDelete = %d\n",
	//	RealFileObject->ReadAccess, RealFileObject->WriteAccess, RealFileObject->DeleteAccess,
	//	RealFileObject->SharedRead, RealFileObject->SharedWrite, RealFileObject->SharedDelete
	//	));

#if 1
	if (FileObject->FileName.Buffer)
	{
		ExFreePool(FileObject->FileName.Buffer);
		FileObject->FileName.Buffer = NULL;
		FileObject->FileName.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, RealFileObject->FileName.MaximumLength, 'tagN');
		if (!FileObject->FileName.Buffer)
		{
			return FALSE;
		}

		FileObject->FileName.Length = RealFileObject->FileName.Length;
		FileObject->FileName.MaximumLength = RealFileObject->FileName.MaximumLength;

		RtlCopyMemory(FileObject->FileName.Buffer, RealFileObject->FileName.Buffer, RealFileObject->FileName.MaximumLength);
	}
#endif 


	Ccb = (PCCB)FileObject->FsContext2;
	if (Ccb && Ccb->NodeTypeCode == SFS_NTC_CCB)
	{
		Ccb->IsCacheSupported = BooleanFlagOn(RealFileObject->Flags, FO_CACHE_SUPPORTED);
	}


	Fcb = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;
	RealFcb = (PFSRTL_ADVANCED_FCB_HEADER)RealFileObject->FsContext;

	if (Fcb && RealFcb)
	{
#if 0
		Fcb->FileSize.QuadPart = RealFcb->FileSize.QuadPart;
		Fcb->ValidDataLength.QuadPart = RealFcb->FileSize.QuadPart;
		Fcb->AllocationSize.QuadPart = RealFcb->AllocationSize.QuadPart;
#endif 
		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateFileObject -> Fcb FileSize = %I64d, ValidDataLength = %I64d, AllocationSize = %I64d.\n",
		//	Fcb->FileSize.QuadPart, Fcb->ValidDataLength.QuadPart, Fcb->AllocationSize.QuadPart));

		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateFileObject -> RealFcb FileSize = %I64d, ValidDataLength = %I64d, AllocationSize = %I64d.\n",
		//	RealFcb->FileSize.QuadPart, RealFcb->ValidDataLength.QuadPart, RealFcb->AllocationSize.QuadPart));

		if (FileObject->SectionObjectPointer->SharedCacheMap)
		{

			LARGE_INTEGER a = CcGetFlushedValidData(FileObject->SectionObjectPointer, TRUE);
			//DebugTrace(DEBUG_TRACE_FILEINFO, ("FileInfo!UpdateFileObject -> FileSizeTemp = %I64d \n", a.QuadPart));
			//    PSHARED_CACHE_MAP a = FileObject->SectionObjectPointer->SharedCacheMap;

		}

	}
	return TRUE;
}

PFILE_OBJECT GetRealFileObject(IN PFILE_OBJECT FileObject)
{
	PCCB					Ccb;
	PFCB					Fcb;
	PFILE_OBJECT			RealFileObject;

	if (!FileObject)
	{
		return NULL;
	}

	Ccb = (PCCB)FileObject->FsContext2;
	if (!Ccb || Ccb->NodeTypeCode != SFS_NTC_CCB)
	{
		return NULL;
	}

	Fcb = (PFCB)FileObject->FsContext;
	if (!Fcb || Fcb->Header.NodeTypeCode != SFS_NTC_FCB)
	{
		return NULL;
	}

	RealFileObject = Ccb->RealFileObject;
	if (!RealFileObject)
	{
		return NULL;
	}

	RealFileObject->Flags = FileObject->Flags;
	RealFileObject->Flags &= ~(FO_CLEANUP_COMPLETE);
	RealFileObject->Flags &= ~(FO_FILE_OBJECT_HAS_EXTENSION);
	RealFileObject->Flags &= ~(FO_WRITE_THROUGH);


	//  FileObject->Flags           |= FO_WRITE_THROUGH;

	if (Ccb->IsCacheSupported)
	{
		SetFlag(RealFileObject->Flags, FO_CACHE_SUPPORTED);
	}
#if 0
	RealFileObject->FinalStatus = FileObject->FinalStatus;
	RealFileObject->LockOperation = FileObject->LockOperation;
	RealFileObject->DeletePending = FileObject->DeletePending;
	RealFileObject->ReadAccess = FileObject->ReadAccess;
	RealFileObject->WriteAccess = FileObject->WriteAccess;
	RealFileObject->DeleteAccess = FileObject->DeleteAccess;
	RealFileObject->SharedRead = FileObject->SharedRead;
	RealFileObject->SharedWrite = FileObject->SharedWrite;
	RealFileObject->SharedDelete = FileObject->SharedDelete;
	RealFileObject->CurrentByteOffset = FileObject->CurrentByteOffset;
	RealFileObject->Waiters = FileObject->Waiters;
	RealFileObject->Busy = FileObject->Busy;
	RealFileObject->LastLock = FileObject->LastLock;
#endif
#if 1
	RealFileObject->CurrentByteOffset = FileObject->CurrentByteOffset;
#endif 

	return RealFileObject;
}


PFILE_OBJECT GetRealFileObject2(IN PFILE_OBJECT FileObject)
{
	PCCB					Ccb;
	PFCB					Fcb;
	PFILE_OBJECT			RealFileObject;

	if (!FileObject)
	{
		return NULL;
	}

	Ccb = (PCCB)FileObject->FsContext2;
	if (!Ccb || Ccb->NodeTypeCode != SFS_NTC_CCB)
	{
		return NULL;
	}

	Fcb = (PFCB)FileObject->FsContext;
	if (!Fcb || Fcb->Header.NodeTypeCode != SFS_NTC_FCB)
	{
		return NULL;
	}

	RealFileObject = Ccb->RealFileObject;
	if (!RealFileObject)
	{
		return NULL;
	}

	return RealFileObject;
}

VOID FreeRealFileObject(IN PFILE_OBJECT FileObject)
{
	PCCB				Ccb;
	PFCB				Fcb;
	PVCB				Vcb;
	PFILE_OBJECT		RealFileObject;
	FILE_CONTEXT		FileContext;
	ULONG_PTR			PointerCount;
	ULONG i;

	if (!FileObject)
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!FreeRealFileObject -> FileObject is null.\n"));
		return;
	}

	Ccb = (PCCB)FileObject->FsContext2;
	if (!Ccb || Ccb->NodeTypeCode != SFS_NTC_CCB)
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!FreeRealFileObject -> FileObject is not sfsobject.\n"));
		return;
	}

	RealFileObject = Ccb->RealFileObject;
	if (RealFileObject)
	{
		//DebugObject(DEBUG_TRACE_OBJECT, "SFSSup!FreeRealFileObject -> RealFileObject", RealFileObject);
		ObDereferenceObject(RealFileObject);
	}

	FileObject->FsContext2 = NULL;
	Ccb->RealFileObject = NULL;
}

BOOLEAN IsStreamFile(IN UNICODE_STRING FileName)
{
	LONG Index;

	if (!FileName.Buffer)
	{
		return FALSE;
	}

	if (FileName.Buffer[0] == L':')
	{
		return TRUE;
	}

	for (Index = (FileName.Length / 2) - 1; Index >= 0; Index--)
	{
		if (FileName.Buffer[Index] == L':')
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN IsSFSFileObject(IN PFILE_OBJECT FileObject)
{
	PFSRTL_COMMON_FCB_HEADER Fcb;

	if (!FileObject)
	{
		return FALSE;
	}

	Fcb = (PFSRTL_COMMON_FCB_HEADER)FileObject->FsContext;
	if (!Fcb || Fcb->NodeTypeCode != SFS_NTC_FCB)
	{
		return FALSE;
	}

	return TRUE;
}

#define BugCheck(A,B,C) { KeBugCheckEx(FILE_SYSTEM, 0, A, B, C); }

ULONG ExceptionFilter(IN PIRP_CONTEXT IrpContext, IN PEXCEPTION_POINTERS ExceptionPointer)
{
	NTSTATUS ExceptionCode;

	ExceptionCode = ExceptionPointer->ExceptionRecord->ExceptionCode;

	if (ExceptionCode == STATUS_IN_PAGE_ERROR)
	{
		if (ExceptionPointer->ExceptionRecord->NumberParameters >= 3)
		{
			ExceptionCode = (NTSTATUS)ExceptionPointer->ExceptionRecord->ExceptionInformation[2];
		}
	}

	if (FsRtlIsNtstatusExpected(ExceptionCode))
	{
		if (IrpContext)
		{
			if (IrpContext->ExceptionStatus == 0)
			{
				IrpContext->ExceptionStatus = ExceptionCode;
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}
	else
	{
		BugCheck(
			(ULONG_PTR)ExceptionPointer->ExceptionRecord,
			(ULONG_PTR)ExceptionPointer->ContextRecord,
			(ULONG_PTR)ExceptionPointer->ExceptionRecord->ExceptionAddress
		);
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

VOID FreeIrpContext(IN PIRP_CONTEXT IrpContext)
{
	if (IrpContext)
	{
		ExFreePool(IrpContext);
	}
}

VOID CompleteRequest(IN PIRP_CONTEXT IrpContext OPTIONAL, IN PIRP Irp OPTIONAL, IN NTSTATUS Status)
{
	if (IrpContext != NULL)
	{
		FreeIrpContext(IrpContext);
	}

	if (Irp)
	{
		if (NT_ERROR(Status) && FlagOn(Irp->Flags, IRP_INPUT_OPERATION))
		{
			Irp->IoStatus.Information = 0;
		}

		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, IO_DISK_INCREMENT);
	}
}

PIRP_CONTEXT CreateIrpContext(IN PIRP Irp, IN BOOLEAN Wait)
{
	PIRP_CONTEXT			IrpContext;
	PFS_DEVICE_OBJECT		FsDeviceObject;
	PFILE_OBJECT			FileObject;

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	IrpContext = (PIRP_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(IRP_CONTEXT), 'Itag');
	if (!IrpContext)
	{
		return NULL;
	}

	RtlZeroMemory(IrpContext, sizeof(IRP_CONTEXT));

	IrpContext->NodeTypeCode = SFS_NTC_IRP_CONTEXT;
	IrpContext->NodeByteSize = sizeof(IRP_CONTEXT);

	if (Wait)
	{
		IrpContext->Flags |= IRP_CONTEXT_FLAG_WAIT;
	}

	IrpContext->OriginatingIrp = Irp;

	IrpContext->MajorFunction = IrpSp->MajorFunction;
	IrpContext->MinorFunction = IrpSp->MinorFunction;

	FsDeviceObject = (PFS_DEVICE_OBJECT)IrpSp->DeviceObject;

	IrpContext->FsDevice = FsDeviceObject;
	IrpContext->Vcb = &FsDeviceObject->Vcb;
	IrpContext->RealFsDevice = IrpContext->Vcb->RealFsDevice;

	FileObject = IrpSp->FileObject;

	if (FileObject)
	{
		IrpContext->FileObject = FileObject;
		IrpContext->RealFileObject = GetRealFileObject(FileObject);
		if (IrpContext->RealFileObject)
		{
			IrpContext->RealFcb = (PFSRTL_ADVANCED_FCB_HEADER)IrpContext->RealFileObject->FsContext;
		}
	}

	if (Wait)
	{
		SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
	}

	IrpContext->IrpSp = IrpSp;
	IrpContext->Options = IrpSp->Parameters.Create.Options;
	IrpContext->IrpSpFlags = IrpSp->Flags;
	IrpContext->IrpFlags = Irp->Flags;

	return IrpContext;
}

NTSTATUS CallRealFsDevice(IN PFS_DEVICE_OBJECT FsDeviceObject, IN PIRP Irp)
{
	NTSTATUS					Status;
	PIO_STACK_LOCATION			IrpSp;
	PDEVICE_OBJECT				RealFsDevice;
	PFILE_OBJECT				FileObject;
	PFILE_OBJECT				RelatedFileObject;

	RealFsDevice = FsDeviceObject->Vcb.RealFsDevice;
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	IrpSp->DeviceObject = RealFsDevice;
	FileObject = IrpSp->FileObject;

	FileObject->DeviceObject = FsDeviceObject->Vcb.RealDevice;

	RelatedFileObject = FileObject->RelatedFileObject;
	if (RelatedFileObject)
	{
		if (IsSFSFileObject(RelatedFileObject))
		{
			RelatedFileObject = GetRealFileObject(RelatedFileObject);
			if (!RelatedFileObject)
			{
				ObDereferenceObject(FileObject);
				return STATUS_INVALID_PARAMETER;
			}

			FileObject->RelatedFileObject = RelatedFileObject;
		}
	}

	IoSkipCurrentIrpStackLocation(Irp);
	Status = IoCallDriver(RealFsDevice, Irp);

	return Status;
}

//解析文件对象
TYPE_OF_OPEN DecodeFileObject(
	IN PFILE_OBJECT FileObject,
	OUT PVCB *Vcb,
	OUT PFCB *Fcb,
	OUT PCCB *Ccb
)
{
	TYPE_OF_OPEN			TypeOfOpen;
	PVOID					FsContext;
	PVOID					FsContext2;

	FsContext = FileObject->FsContext;
	FsContext2 = FileObject->FsContext2;

	if (FsContext == NULL)
	{
		if (Ccb)
		{
			*Ccb = NULL;
		}
		if (Fcb)
		{
			*Fcb = NULL;
		}
		if (Vcb)
		{
			*Vcb = NULL;
		}

		TypeOfOpen = UnopenedFileObject;
	}
	else
	{
		if (SFS_NTC_FCB == NodeType(FsContext))
		{
			if (Fcb)
			{
				*Fcb = (PFCB)FsContext;
				if (Vcb)
				{
					*Vcb = (*Fcb)->Vcb;
				}
			}

			if (Ccb)
			{
				*Ccb = (PCCB)FsContext2;
			}

			TypeOfOpen = (FsContext2 == NULL ? EaFile : UserFileOpen);
		}
	}

	return TypeOfOpen;
}

RTL_GENERIC_COMPARE_RESULTS
GenericCompareRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID FirstStruct,
	IN PVOID SecondStruct
)
{
	PFILE_CONTEXT FirstFileCtx = (PFILE_CONTEXT)FirstStruct;
	PFILE_CONTEXT SecondFileCtx = (PFILE_CONTEXT)SecondStruct;

	UNREFERENCED_PARAMETER(Table);

	if (FirstFileCtx->FileObject < SecondFileCtx->FileObject)
	{
		return GenericLessThan;
	}
	else if (FirstFileCtx->FileObject > SecondFileCtx->FileObject)
	{
		return GenericGreaterThan;
	}

	return GenericEqual;
}

PVOID
GenericAllocateRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN CLONG ByteSize
)
{
	PVOID Buffer = NULL;

	UNREFERENCED_PARAMETER(Table);

	Buffer = ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'Ftag');
	if (Buffer)
	{
		RtlZeroMemory(Buffer, ByteSize);
	}
	return Buffer;
}

VOID
GenericFreeRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID Buffer
)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePool(Buffer);
}

BOOLEAN IsFilterExtName(UNICODE_STRING Path)
{
	/*
		if(wcsstr(Path.Buffer, L".txt"))
		{
			return TRUE;
		}

		if(wcsstr(Path.Buffer, L".TXT"))
		{
			return TRUE;
		}

	*/

	if (wcsstr(Path.Buffer, L".doc"))
	{
		return TRUE;
	}

	if (wcsstr(Path.Buffer, L".DOC"))
	{
		return TRUE;
	}

	if (wcsstr(Path.Buffer, L".tmp"))
	{
		return TRUE;
	}

	if (wcsstr(Path.Buffer, L".TMP"))
	{
		return TRUE;
	}

	/*
		if (wcsstr(Path.Buffer, L".ppt"))
		{
			return TRUE;
		}

		if (wcsstr(Path.Buffer, L".PPT"))
		{
			return TRUE;
		}

		if (wcsstr(Path.Buffer, L".tmp"))
		{
			return TRUE;
		}

		if (wcsstr(Path.Buffer, L".TMP"))
		{
			return TRUE;
		}
		*/
		/*
			if (wcsstr(Path.Buffer, L".dat"))
			{
				return TRUE;
			}

			if (wcsstr(Path.Buffer, L".DAT"))
			{
				return TRUE;
			}

			if (wcsstr(Path.Buffer, L".pip"))
			{
				return TRUE;
			}

			if (wcsstr(Path.Buffer, L".PIP"))
			{
				return TRUE;
			}


			if (wcsstr(Path.Buffer, L".lnk"))
			{
				return TRUE;
			}

			if (wcsstr(Path.Buffer, L".LNK"))
			{
				return TRUE;
			}



		   if (wcsstr(Path.Buffer, L".xls"))
			{
				return TRUE;
			}

			if (wcsstr(Path.Buffer, L".XLS"))
			{
				return TRUE;
			}

			if (wcsstr(Path.Buffer, L".tmp"))
			{
				return TRUE;
			}

			if (wcsstr(Path.Buffer, L".TMP"))
			{
				return TRUE;
			}
		*/

	return FALSE;
}


VOID ClearFcbCacheFromVcbList(IN PVCB Vcb)
{
	PLIST_ENTRY P;
	PFCB_NODE Node;

	ExAcquireResourceExclusiveLite(&Vcb->Resource, TRUE);
	for (P = Vcb->FcbList.Flink; P != &Vcb->FcbList; P = P->Flink)
	{
		Node = (PFCB_NODE)P;
		SFSFlushFile(Node->Fcb);
	}

	ExReleaseResourceLite(&Vcb->Resource);
}

VOID CreateInClearFcbCache(IN PFCB Fcb)
{
	PSECTION_OBJECT_POINTERS SectionObjectPointer;

	SectionObjectPointer = &Fcb->NonPaged->SectionObjectPointers;
	SetFlag(Fcb->Vcb->VcbState, VCB_STATE_FLAG_CREATE_IN_PROGRESS);
	CcFlushCache(SectionObjectPointer, NULL, 0, NULL);
	MmFlushImageSection(SectionObjectPointer, MmFlushForWrite);

	ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
	ExReleaseResourceLite(Fcb->Header.PagingIoResource);

	CcPurgeCacheSection(SectionObjectPointer, NULL, 0, FALSE);
	ClearFlag(Fcb->Vcb->VcbState, VCB_STATE_FLAG_CREATE_IN_PROGRESS);
}

NTSTATUS GetSymbolicLink(IN PUNICODE_STRING SymbolicLinkName, OUT PUNICODE_STRING LinkValue)
{
	NTSTATUS				Status;
	HANDLE					Handle;
	OBJECT_ATTRIBUTES		ObjectAttributes;
	ULONG					LinkLength;

	InitializeObjectAttributes(&ObjectAttributes, SymbolicLinkName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwOpenSymbolicLinkObject(&Handle, GENERIC_READ, &ObjectAttributes);

	if (NT_SUCCESS(Status))
	{
		RtlZeroMemory(LinkValue->Buffer, LinkValue->MaximumLength);
		Status = ZwQuerySymbolicLinkObject(Handle, LinkValue, &LinkLength);
		ZwClose(Handle);
	}

	return Status;
}

BOOLEAN IsBackupDirVolume(IN UNICODE_STRING VolumePath)
{
	NTSTATUS				Status;
	BOOLEAN					IsTrue = FALSE;
	UNICODE_STRING			TempDriveLetter;
	UNICODE_STRING			LinkValue;
	PWCHAR					TempDriveLetterBuf = NULL;
	PWCHAR					LinkValueBuf = NULL;

	TempDriveLetterBuf = AllocPathLookasideList();
	if (!TempDriveLetterBuf)
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!IsBackupDirVolume -> AllocPathLookasideList is null.\n"));
		return FALSE;
	}

	RtlInitUnicodeString(&TempDriveLetter, BackupDriveLetter);
	//	RtlInitUnicodeString(&TempDriveLetter, g_Config.m_Policy.UserAuth.wszBackupPath);
	if (0 == RtlCompareUnicodeString(&TempDriveLetter, &VolumePath, TRUE))
	{
		return TRUE;
	}

	__try {

		LinkValueBuf = AllocPathLookasideList();
		if (!LinkValueBuf)
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!IsBackupDirVolume -> AllocPathLookasideList is null.\n"));
			__leave;
		}

		RtlStringCchCopyW(TempDriveLetterBuf, MAX_PATH_SIZE, BackupDriveLetter);
		RtlInitUnicodeString(&TempDriveLetter, TempDriveLetterBuf);
		RtlInitEmptyUnicodeString(&LinkValue, LinkValueBuf, MAX_PATH_SIZE);

		Status = GetSymbolicLink(&TempDriveLetter, &LinkValue);

		if (!NT_SUCCESS(Status))
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!IsBackupDirVolume -> GetSymbolicLink Fail. 0x%08x\n", Status));
			__leave;
		}

		if (0 == RtlCompareUnicodeString(&LinkValue, &VolumePath, TRUE))
		{
			IsTrue = TRUE;
		}
		else
		{
			IsTrue = FALSE;
		}
	}
	__finally
	{
		if (TempDriveLetterBuf)
		{
			FreePathLookasideList(TempDriveLetterBuf);
		}

		if (LinkValueBuf)
		{
			FreePathLookasideList(LinkValueBuf);
		}
	}

	return IsTrue;
}


BOOLEAN GetDriveLetter(IN PUNICODE_STRING VolumeName, OUT PWCHAR DriveLetter)
{
	BOOLEAN			Result = FALSE;
	NTSTATUS		Status;
	UCHAR			i;

	PWCHAR			TempDriveLetterBuf = NULL;
	PWCHAR			LinkValueBuf = NULL;

	UNICODE_STRING	TempDriveLetter;
	UNICODE_STRING	LinkValue;

	TempDriveLetterBuf = AllocPathLookasideList();
	if (!TempDriveLetterBuf)
	{
		return FALSE;
	}

	__try
	{
		LinkValueBuf = AllocPathLookasideList();
		if (!LinkValueBuf)
		{
			__leave;
		}

		for (i = 'A'; i <= 'Z'; i++)
		{
			RtlZeroMemory(TempDriveLetterBuf, MAX_PATH_SIZE);
			RtlZeroMemory(LinkValueBuf, MAX_PATH_SIZE);
			RtlStringCchPrintfW(TempDriveLetterBuf, MAX_PATH, L"\\??\\%c:", i);//大写A-Z
			RtlInitUnicodeString(&TempDriveLetter, TempDriveLetterBuf);
			RtlInitEmptyUnicodeString(&LinkValue, LinkValueBuf, MAX_PATH_SIZE);
			Status = GetSymbolicLink(&TempDriveLetter, &LinkValue);

			if (NT_SUCCESS(Status))
			{
				if (RtlCompareUnicodeString(VolumeName, &LinkValue, TRUE) == 0)
				{
					RtlStringCchPrintfW(DriveLetter, MAX_PATH, L"%c", i);
					Result = TRUE;
					__leave;
				}
			}
		}

		for (i = 'a'; i <= 'z'; i++)
		{
			RtlZeroMemory(TempDriveLetterBuf, MAX_PATH_SIZE);
			RtlZeroMemory(LinkValueBuf, MAX_PATH_SIZE);
			RtlStringCchPrintfW(TempDriveLetterBuf, MAX_PATH, L"\\??\\%c:", i);//小写A-Z
			RtlInitUnicodeString(&TempDriveLetter, TempDriveLetterBuf);
			RtlInitEmptyUnicodeString(&LinkValue, LinkValueBuf, MAX_PATH_SIZE);
			Status = GetSymbolicLink(&TempDriveLetter, &LinkValue);

			if (NT_SUCCESS(Status))
			{
				if (RtlCompareUnicodeString(VolumeName, &LinkValue, TRUE) == 0)
				{
					RtlStringCchPrintfW(DriveLetter, MAX_PATH, L"%c", i);
					Result = TRUE;
					__leave;
				}
			}
		}
	}
	__finally
	{
		if (TempDriveLetterBuf)
		{
			FreePathLookasideList(TempDriveLetterBuf);
		}

		if (LinkValueBuf)
		{
			FreePathLookasideList(LinkValueBuf);
		}
	}
	return Result;
}


//VOID GetBackupFileName(IN PUNICODE_STRING DestFileName, IN PPATH_NAME_INFORMATION PathNameInfo)
//{
//	WCHAR DriveLetter[2] = { 0 };
//	LARGE_INTEGER Time;
//
//	TIME_FIELDS CurrentTimeFields;
//
//	KeQuerySystemTime(&Time);
//
//	RtlTimeToTimeFields(&Time, &CurrentTimeFields);
//
//
//	RtlAppendUnicodeToString(DestFileName, BackupDriveLetter);
//	RtlAppendUnicodeToString(DestFileName, BackupDir);
//
//	if (DestFileName->Length <= sizeof(WCHAR))
//	{
//		return;
//	}
//
//	//添加用户名路径和日期路径
//
//	if (DestFileName->Buffer[DestFileName->Length / sizeof(WCHAR) - 1] != L'\\')
//	{
//		RtlAppendUnicodeToString(DestFileName, L"\\");
//	}
//
//	RtlAppendUnicodeToString(DestFileName, g_Config.m_Policy.UserAuth.wszUserName);
//
//
//	//    RtlAppendUnicodeToString(DestFileName, L"\\");
//	//    RtlAppendUnicodeToString(DestFileName, g_Config.m_Policy.UserAuth.wszUserName);
//
//	if (GetDriveLetter(&PathNameInfo->VolumePath, DriveLetter))
//	{
//		RtlAppendUnicodeToString(DestFileName, L"\\");
//		RtlAppendUnicodeToString(DestFileName, DriveLetter);
//	}
//	RtlAppendUnicodeStringToString(DestFileName, &PathNameInfo->FullFileName);
//	//	RtlAppendUnicodeToString(DestFileName, L".bak");
//}

BOOLEAN GetBackupFileInfo(IN UNICODE_STRING BackupFileName, OUT PLARGE_INTEGER Time, OUT PLARGE_INTEGER FileSize)
{
	NTSTATUS					Status;
	BOOLEAN						Result = FALSE;
	OBJECT_ATTRIBUTES			ObjectAttributes;
	IO_STATUS_BLOCK				IoStatusBlock;
	FILE_STANDARD_INFORMATION	FileStandardInfo;
	FILE_BASIC_INFORMATION		FileBaseInfo;
	HANDLE						Handle = NULL;
	PFILE_OBJECT				FileObject;
	PDEVICE_OBJECT				BackupFsDevice;

	Status = GetBackupDriveFsDeviceObject(&BackupFsDevice);
	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!GetBackupFileInfo -> GetBackupDriveFsDeviceObject Fail. 0x%08x\n", Status));
		return FALSE;
	}

	InitializeObjectAttributes(&ObjectAttributes, &BackupFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
#if 0
	Status = CreateFileFromBackupDrive(
		&Handle,
		&FileObject,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);
#endif
	Status = CreateFileByFsDevice(
		&Handle,
		&FileObject,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		BackupFsDevice
	);

	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!GetBackupFileInfo -> CreateFileByFsDevice Fail. 0x%08x\n", Status));
		return FALSE;
	}

	__try
	{
		Status = IrpQueryInformationFile(BackupFsDevice, FileObject, &FileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (!NT_SUCCESS(Status))
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!GetBackupFileInfo -> IrpQueryInformationFile Fail. 0x%08x\n", Status));
			__leave;
		}

		*FileSize = FileStandardInfo.EndOfFile;

		if (FileSize->QuadPart == 0)
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!GetBackupFileInfo -> FileSize is zero.\n"));
			__leave;
		}

		Status = IrpQueryInformationFile(BackupFsDevice, FileObject, &FileBaseInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
		if (!NT_SUCCESS(Status))
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!GetBackupFileInfo -> IrpQueryInformationFile Fail. 0x%08x\n", Status));
			__leave;
		}

		*Time = FileBaseInfo.LastWriteTime;
		Result = TRUE;
	}
	__finally
	{
		if (Handle)
		{
			ZwClose(Handle);
		}
	}
	return Result;
}

NTSTATUS DeleteFile(IN PDEVICE_OBJECT DeviceObject, IN UNICODE_STRING FileName)
{
	NTSTATUS							Status;
	OBJECT_ATTRIBUTES					ObjectAttributes;
	IO_STATUS_BLOCK						IoStatusBlock;
	HANDLE								FileHandle;
	PFILE_OBJECT						FileObject;
	FILE_BASIC_INFORMATION				FileBaseInfo;
	FILE_DISPOSITION_INFORMATION		FileDispositionInfo;

	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DeleteFile -> enter.\n"));

	InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = CreateFileByFsDevice(
		&FileHandle,
		&FileObject,
		GENERIC_ALL | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		DeviceObject
	);

	if (Status == STATUS_CANNOT_DELETE)
	{
		Status = CreateFileByFsDevice(
			&FileHandle,
			&FileObject,
			GENERIC_READ | SYNCHRONIZE,
			&ObjectAttributes,
			&IoStatusBlock,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0,
			DeviceObject
		);

		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		Status = IrpQueryInformationFile(DeviceObject, FileObject, &FileBaseInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
		if (!NT_SUCCESS(Status))
		{
			ZwClose(FileHandle);
			return Status;
		}

		ClearFlag(FileBaseInfo.FileAttributes, FILE_ATTRIBUTE_READONLY);
		Status = IrpSetInformationFile(DeviceObject, FileObject, &FileBaseInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
		if (!NT_SUCCESS(Status))
		{
			ZwClose(FileHandle);
			return Status;
		}

		ZwClose(FileHandle);

		Status = CreateFileByFsDevice(
			&FileHandle,
			NULL,
			GENERIC_ALL | SYNCHRONIZE,
			&ObjectAttributes,
			&IoStatusBlock,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0,
			DeviceObject
		);

		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
	}
	else if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	FileDispositionInfo.DeleteFile = TRUE;
	Status = IrpSetInformationFile(DeviceObject, FileObject, &FileDispositionInfo, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);
	ZwClose(FileHandle);
	return Status;
}


BOOLEAN BackupCopyFile(IN UNICODE_STRING DestFileName, IN PIRP_CONTEXT IrpContext)
{
	NTSTATUS					Status;
	BOOLEAN						Result = FALSE;
	HANDLE						DestFileHandle = NULL;
	LONGLONG					FileSize;
	PFILE_OBJECT				RealFileObject;
	OBJECT_ATTRIBUTES			ObjectAttributes;
	IO_STATUS_BLOCK				IoStatusBlock;

	PVOID						Buffer = NULL;
	ULONG						i;
	ULONG						PageCount;
	ULONG						Remain;
	LARGE_INTEGER				Offset;
	PFILE_OBJECT				DestFileObject;
	PDEVICE_OBJECT				RealFsDevice;
	PDEVICE_OBJECT				BackupFsDevice;

	RealFileObject = IrpContext->RealFileObject;
	RealFsDevice = IrpContext->RealFsDevice;

	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BackupCopyFile -> enter.\n"));

	Status = GetBackupDriveFsDeviceObject(&BackupFsDevice);
	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupCopyFile -> GetBackupDriveFsDeviceObject Fail. status = 0x%08x\n", Status));
		return FALSE;
	}

	CreateBackupDirAll(DestFileName);
	InitializeObjectAttributes(&ObjectAttributes, &DestFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = CreateFileByFsDevice(
		&DestFileHandle,
		&DestFileObject,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		BackupFsDevice
	);

	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupCopyFile -> CreateFileByFsDevice Fail. status = 0x%08x\n", Status));
		return Result;
	}

	FileSize = IrpContext->RealFcb->FileSize.QuadPart;
	PageCount = (ULONG)(FileSize / PAGE_SIZE);
	Remain = FileSize % PAGE_SIZE;

	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BackupCopyFile -> FileSize = %d, PageCount = %d, Remain = %d.\n", FileSize, PageCount, Remain));

	__try
	{
		Buffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'Btag');
		if (!Buffer)
		{
			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupCopyFile -> ExAllocatePoolWithTag is null.\n"));
			__leave;
		}

		RtlZeroMemory(Buffer, PAGE_SIZE);

		for (i = 0; i < PageCount; i++)
		{
			Offset.QuadPart = i * PAGE_SIZE;
			Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, PAGE_SIZE, &Offset, 0, NULL);

			if (NT_SUCCESS(Status))
			{
				Status = IrpWriteFile(BackupFsDevice, DestFileObject, Buffer, PAGE_SIZE, &Offset, 0, NULL);
				if (!NT_SUCCESS(Status))
				{
					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupCopyFile -> IrpWriteFile Fail. status = 0x%08x\n", Status));
					__leave;
				}
			}
			else
			{
				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupCopyFile -> IrpReadFile Fail. status = 0x%08x\n", Status));
				__leave;
			}

		}

		if (Remain)
		{
			Offset.QuadPart = PageCount * PAGE_SIZE;
			Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, Remain, &Offset, 0, NULL);
			if (NT_SUCCESS(Status))
			{
				Status = IrpWriteFile(BackupFsDevice, DestFileObject, Buffer, Remain, &Offset, 0, NULL);
				if (!NT_SUCCESS(Status))
				{
					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupCopyFile -> IrpWriteFile Remain Fail. status = 0x%08x\n", Status));
					__leave;
				}
			}
			else
			{
				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupCopyFile -> IrpReadFile Remain Fail. status = 0x%08x\n", Status));
				__leave;
			}
		}

		Status = STATUS_SUCCESS;
	}
	__finally
	{
		if (DestFileHandle)
		{
			ZwClose(DestFileHandle);
		}

		if (Buffer)
		{
			ExFreePool(Buffer);
		}

		if (!NT_SUCCESS(Status))
		{
			DeleteFile(BackupFsDevice, DestFileName);
		}

		RealFileObject->CurrentByteOffset.QuadPart = 0;
	}
	return Result;
}

//VOID BackupFile(IN PIRP_CONTEXT IrpContext)
//{
//	PFILE_OBJECT				RealFileObject;
//	UNICODE_STRING				DestFileName;
//	PWCHAR						DestFileNameBuf;
//
//	LARGE_INTEGER				BackupFileTime;
//	LARGE_INTEGER				CurrentTime;
//	LARGE_INTEGER				BackFileSize;
//	LONGLONG                    FileIntervalTime;
//	LONGLONG                    BackupIntervalTime;
//
//	//	TIME_FIELDS					CurrentTimeFields;
//	//	TIME_FIELDS					BackupFileTimeFields;
//
//	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BackupFile -> enter.\n"));
//
//	DestFileNameBuf = AllocPathLookasideList();
//	if (!DestFileNameBuf)
//	{
//		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!BackupFile -> ExAllocatePoolWithTag is null.\n"));
//		return;
//	}
//
//	RtlInitEmptyUnicodeString(&DestFileName, DestFileNameBuf, MAX_PATH_SIZE);
//	GetBackupFileName(&DestFileName, IrpContext->PathNameInfo);
//
//	__try
//	{
//		//DebugString(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, "SFSSup!BackupFile -> BackupFileName = %s\n", DestFileName.Buffer);
//
//		if (IrpContext->RealFcb->FileSize.QuadPart == 0)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BackupFile -> FileSize is zero.\n"));
//			__leave;
//		}
//#if 1
//		if (GetBackupFileInfo(DestFileName, &BackupFileTime, &BackFileSize))
//		{
//
//			if (IrpContext->RealFcb->FileSize.QuadPart == BackFileSize.QuadPart)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BackupFile -> FileSize same.\n"));
//				__leave;
//			}
//
//			KeQuerySystemTime(&CurrentTime);
//
//			FileIntervalTime = CurrentTime.QuadPart - BackupFileTime.QuadPart;
//
//
//			BackupIntervalTime = (LONGLONG)1000000000 * 60 * 60 / 100 * g_Config.m_Policy.UserAuth.nBackupInterval;
//
//
//
//			if (FileIntervalTime <= 0)
//			{
//				__leave;
//			}
//
//			if (FileIntervalTime <= BackupIntervalTime)
//			{
//				__leave;
//			}
//
//			/*
//						RtlTimeToTimeFields(&Time, &BackupFileTimeFields);
//
//						KeQuerySystemTime(&Time);
//
//						RtlTimeToTimeFields(&Time, &CurrentTimeFields);
//
//						DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BackupFile -> CurrentTimeFields Year = %d Month = %d Day = %d \n", CurrentTimeFields.Year, CurrentTimeFields.Month, CurrentTimeFields.Day));
//						DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BackupFile -> BackupFileTimeFields Year = %d Month = %d Day = %d \n", BackupFileTimeFields.Year, BackupFileTimeFields.Month, BackupFileTimeFields.Day));
//
//						if(CurrentTimeFields.Year == BackupFileTimeFields.Year &&
//							CurrentTimeFields.Month == BackupFileTimeFields.Month &&
//							CurrentTimeFields.Day == BackupFileTimeFields.Day)
//						{
//							__leave;
//						}
//			*/
//
//
//
//		}
//#endif 
//		BackupCopyFile(DestFileName, IrpContext);
//	}
//	__finally
//	{
//		if (DestFileNameBuf)
//		{
//			FreePathLookasideList(DestFileNameBuf);
//		}
//	}
//}

NTSTATUS CreateBackupDir(IN UNICODE_STRING DirectoryName)
{
	NTSTATUS					Status;
	OBJECT_ATTRIBUTES			ObjectAttributes;
	IO_STATUS_BLOCK				IoStatus;
	PFILE_OBJECT				FileObject;
	FILE_BASIC_INFORMATION		FileBaseInfo;
	HANDLE						FileHandle;

	//DebugString(DEBUG_TRACE_SFSSup, "SFSSup!CreateBackupDir -> PathName = %s\n", DirectoryName.Buffer);

	InitializeObjectAttributes(
		&ObjectAttributes,
		&DirectoryName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	Status = CreateFileFromBackupDrive(
		&FileHandle,
		&FileObject,
		FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatus,
		FILE_ATTRIBUTE_HIDDEN,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_CREATE,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CreateBackupDir -> CreateFileFromBackupDrive Fail. status = 0x%08x\n", Status));
		return Status;
	}

	ZwClose(FileHandle);
	return Status;
}

VOID CreateBackupDirAll(IN UNICODE_STRING PathName)
{
	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!CreateBackupDirAll -> enter.\n"));
	//DebugString(DEBUG_TRACE_SFSSup, "SFSSup!CreateBackupDirAll -> PathName = %s\n", PathName.Buffer);
	PWCHAR SubPathName = NULL;
	ULONG_PTR SubLength;

	SubPathName = PathName.Buffer;

	while (TRUE)
	{
		SubPathName = wcschr(SubPathName, L'\\');

		if (!SubPathName)
		{
			break;
		}

		SubLength = (ULONG_PTR)SubPathName - (ULONG_PTR)PathName.Buffer;

		if (SubLength == 0)
		{
			SubPathName++;
			continue;
		}

		SubPathName++;
		PathName.Length = (USHORT)SubLength;

		CreateBackupDir(PathName);
	}
}



VOID UpdateFileHeader(IN PUCHAR Buffer,
	IN ULONG Length,
	IN PIO_CONTEXT IoContext,
	OUT PENCRYPT_IO EncryptIo)
{
	PLARGE_INTEGER			ByteOffset;
	LARGE_INTEGER			Offset;
	USHORT					Align;
	ULONG					Remain;

	ByteOffset = &IoContext->ByteOffset;

	if (ByteOffset->QuadPart < BLOCK_SIZE)
	{
		Align = ByteOffset->LowPart & 0x1FF;

		Remain = BLOCK_SIZE - Align;
		if (Remain > Length)
		{
			Remain = Length;
		}

		RtlCopyMemory(EncryptIo->FileHeader + Align, Buffer, Remain);
	}
}

//NTSTATUS UpdateFileInfo(OUT tagFileInfo *FileInfo, OUT PENCRYPT_IO EncryptIo, IN PFILE_OBJECT RealFileObject)
//{
//	NTSTATUS                Status = STATUS_SUCCESS;
//
//	PPATH_NAME_INFORMATION  PathNameInfo = NULL;
//	PFILE_INFO              EncryptFileInfo;
//	PPROCESS_INFO           ProcessInfo;
//
//	__try
//	{
//
//		ExAcquireResourceExclusiveLite(&SFSData.ProcessInfoListResource, TRUE);
//		ProcessInfo = FindProcessInfo(PsGetCurrentProcessId());
//		if (!ProcessInfo)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileInfo -> ProcessInfo is null. ProcessId = %x\n", PsGetCurrentProcessId()));
//			//    Status = STATUS_UNSUCCESSFUL;
//			ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//			__leave;
//		}
//		ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//
//		if (!GetFullFilePath(RealFileObject, &PathNameInfo))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileInfo -> GetFullFilePath return false.\n"));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//
//		EncryptFileInfo = FindEncryptFileInfo(ProcessInfo, PathNameInfo->Name);
//		if (EncryptFileInfo)
//		{
//			FileInfo->bFileControlFlag = EncryptFileInfo->bFileControlFlag;
//			FileInfo->nUserID = EncryptFileInfo->nUserID;
//			FileInfo->nNodeID_1 = EncryptFileInfo->nNodeID_1;
//			FileInfo->nNodeID_2 = EncryptFileInfo->nNodeID_2;
//			FileInfo->nNodeID_3 = EncryptFileInfo->nNodeID_3;
//			FileInfo->nNodeID_4 = EncryptFileInfo->nNodeID_4;
//
//			FileInfo->bGroupOnlyFlag = EncryptFileInfo->bGroupOnlyFlag;
//			FileInfo->bModifyFlag = EncryptFileInfo->bModifyFlag;
//			FileInfo->bCopyFlag = EncryptFileInfo->bCopyFlag;
//			FileInfo->bPrintFlag = EncryptFileInfo->bPrintFlag;
//			FileInfo->bPrintTimesFlag = EncryptFileInfo->bPrintTimesFlag;
//			FileInfo->bReadTimesFlag = EncryptFileInfo->bReadTimesFlag;
//			FileInfo->bLifeCycleFlag = EncryptFileInfo->bLifeCycleFlag;
//			FileInfo->nPrintTimes = EncryptFileInfo->nPrintTimes;
//			FileInfo->nReadTimes = EncryptFileInfo->nReadTimes;
//			FileInfo->nBeginTime = EncryptFileInfo->nBeginTime;
//			FileInfo->nEndTime = EncryptFileInfo->nEndTime;
//
//			FileInfo->bFileCrcFlag = EncryptFileInfo->bFileCrcFlag;
//			FileInfo->bModifyAuthFlag = EncryptFileInfo->bModifyAuthFlag;
//			FileInfo->bSelfDestoryFlag = EncryptFileInfo->bSelfDestoryFlag;
//			FileInfo->bPasswordFlag = EncryptFileInfo->bPasswordFlag;
//			FileInfo->nFileCrc32 = 0;
//
//			EncryptIo->Modify = EncryptFileInfo->bModifyFlag;
//			EncryptIo->LifeCycle = EncryptFileInfo->bLifeCycleFlag;
//			EncryptIo->FileControl = EncryptFileInfo->bFileControlFlag;
//		}
//
//	}
//	__finally
//	{
//		if (PathNameInfo)
//		{
//			ReleasePathNameInformation(PathNameInfo);
//		}
//	}
//	return Status;
//}

//NTSTATUS EncryptFileBuffer(IN PUCHAR Buffer,
//	IN ULONG Length,
//	IN PIRP Irp,
//	IN OUT PIO_CONTEXT IoContext)
//{
//	NTSTATUS				Status = STATUS_SUCCESS;
//	int						Ret;
//	unsigned int			DataLen;
//	PLARGE_INTEGER			ByteOffset;
//	LARGE_INTEGER			Offset;
//	USHORT					Align;
//	ULONG					Remain;
//	USHORT                  FileHeadLength;
//	LONGLONG                FileSize;
//	PUCHAR					TempBuffer = NULL;
//	PUCHAR                  BackupBuffer = NULL;
//	rc4_state				*RC4State = NULL;
//	PFCB					Fcb;
//	PENCRYPT_IO				EncryptIo;
//	PDEVICE_OBJECT			RealFsDevice;
//	PFILE_OBJECT			RealFileObject;
//	ULONGLONG				OldOffset;
//	tagFileInfo				*FileInfo = NULL;
//
//
//	if (Length == 0)
//	{
//		return STATUS_SUCCESS;
//	}
//
//	DecodeFileObject(IoContext->FileObject, NULL, &Fcb, NULL);
//
//	EncryptIo = &Fcb->EncryptIo;
//	EncryptIo->Change = TRUE;
//
//	UpdateFileHeader(Buffer, Length, IoContext, EncryptIo);
//
//	if (!EncryptIo->Encrypt)
//	{
//		return STATUS_SUCCESS;
//	}
//
//	ByteOffset = &IoContext->ByteOffset;
//	RealFsDevice = IoContext->RealFsDevice;
//	RealFileObject = IoContext->RealFileObject;
//	FileSize = Fcb->Header.FileSize.QuadPart;
//
//	RC4State = (rc4_state*)ExAllocatePoolWithTag(NonPagedPool, sizeof(rc4_state), L'rc4s');
//	if (!RC4State)
//	{
//		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> ExAllocatePoolWithTag is null.\n"));
//		return STATUS_INSUFFICIENT_RESOURCES;
//	}
//
//	OldOffset = RealFileObject->CurrentByteOffset.QuadPart;
//
//	__try
//	{
//
//		BackupBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, Length, L'bakb');
//		if (!BackupBuffer)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> ExAllocatePoolWithTag is null.\n"));
//			Status = STATUS_INSUFFICIENT_RESOURCES;
//			__leave;
//		}
//		RtlCopyMemory(BackupBuffer, Buffer, Length);
//
//		Align = ByteOffset->LowPart & 0x1FF;
//
//		Remain = BLOCK_SIZE - Align;
//		if (Remain > Length)
//		{
//			Remain = Length;
//		}
//
//		if (FileSize >= BLOCK_SIZE)
//		{
//			FileHeadLength = BLOCK_SIZE;
//		}
//		else
//		{
//			if ((ByteOffset->QuadPart + Length) >= BLOCK_SIZE)
//			{
//				FileHeadLength = BLOCK_SIZE;
//			}
//			else
//			{
//				if ((ByteOffset->QuadPart + Length) > FileSize)
//				{
//					FileHeadLength = ByteOffset->QuadPart + Length;
//				}
//				else
//				{
//					FileHeadLength = FileSize;
//				}
//
//			}
//		}
//
//
//		if (ByteOffset->QuadPart < BLOCK_SIZE || Align != 0)
//		{
//			TempBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, L'temp');
//			if (!TempBuffer)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> ExAllocatePoolWithTag is null.\n"));
//				Status = STATUS_INSUFFICIENT_RESOURCES;
//				__leave;
//			}
//
//			RtlZeroMemory(TempBuffer, BLOCK_SIZE);
//
//			if (ByteOffset->QuadPart < BLOCK_SIZE)
//			{
//
//				Offset.QuadPart = 0;
//				FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//				if (!FileInfo)
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> ExAllocatePoolWithTag is null.\n"));
//					Status = STATUS_INSUFFICIENT_RESOURCES;
//					__leave;
//				}
//
//				RtlZeroMemory(FileInfo, sizeof(tagFileInfo));
//				Ret = PolicyToFileInfo(&g_Config.m_Policy, FileInfo);
//				if (Ret != ISAFE_STATUS_SUCCESS)
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> PolicyToFileInfo Status = %x.\n", Ret));
//					Status = STATUS_UNSUCCESSFUL;
//					__leave;
//				}
//
//				Status = UpdateFileInfo(FileInfo, EncryptIo, RealFileObject);
//				if (!NT_SUCCESS(Status))
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> UpdateFileInfo Status = %x.\n", Status));
//					Status = STATUS_UNSUCCESSFUL;
//					__leave;
//				}
//
//#if 0
//				Status = IrpReadFile(RealFsDevice, RealFileObject, TempBuffer, BLOCK_SIZE, &Offset, IRP_PAGING_IO, NULL);
//				if (!NT_SUCCESS(Status))
//				{
//					__leave;
//				}
//
//				Ret = DecryptFileHeadSelf(EncryptIo, FileInfo, TempBuffer, BLOCK_SIZE, DataLen);
//				if (Ret != ISAFE_STATUS_SUCCESS)
//				{
//					Status = STATUS_UNSUCCESSFUL;
//					__leave;
//				}
//#endif
//
//
//				RtlCopyMemory(TempBuffer, EncryptIo->FileHeader, BLOCK_SIZE);
//				RtlCopyMemory(TempBuffer + Align, Buffer, Remain);
//				RtlCopyMemory(EncryptIo->FileHeader, TempBuffer, BLOCK_SIZE);
//				//    RtlCopyMemory(TempBuffer + Align, Buffer, Remain);
//
//				Ret = EncryptFileHeadSelf(EncryptIo, FileInfo, TempBuffer, FileHeadLength, DataLen);
//				if (Ret != ISAFE_STATUS_SUCCESS)
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> EncryptFileHeadSelf Status = %x.\n", Ret));
//					Status = STATUS_UNSUCCESSFUL;
//					__leave;
//				}
//
//
//				//                ClearCache(RealFileObject, &Offset, DataLen);
//
//				//				Status = IrpWriteFile(RealFsDevice, RealFileObject, TempBuffer, BLOCK_SIZE, &Offset, IRP_PAGING_IO, NULL);
//				Status = IrpWriteFile(RealFsDevice, RealFileObject, TempBuffer, DataLen, &Offset, NULL, NULL);
//
//				if (!NT_SUCCESS(Status))
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> IrpWriteFile return status = %x\n", Status));
//					__leave;
//				}
//			}
//			else
//			{
//				RtlCopyMemory(TempBuffer + Align, Buffer, Remain);
//				BlockEncrypt(TempBuffer, BLOCK_SIZE, EncryptIo->EncryptKey, EncryptIo->KeyLen, RC4State, BLOCK_SIZE);
//			}
//
//			RtlCopyMemory(Buffer, TempBuffer + Align, Remain);
//
//			Length -= Remain;
//			Buffer += Remain;
//		}
//
//		if (Length)
//		{
//			BlockEncrypt(Buffer, Length, EncryptIo->EncryptKey, EncryptIo->KeyLen, RC4State, BLOCK_SIZE);
//		}
//
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!EncryptFileBuffer -> Encrypt Complete.\n"));
//	}
//	__finally
//	{
//
//		if (!NT_SUCCESS(Status) && BackupBuffer)
//		{
//			RtlCopyMemory(Buffer, BackupBuffer, Length);
//		}
//
//		if (BackupBuffer)
//		{
//			ExFreePool(BackupBuffer);
//		}
//
//		if (TempBuffer)
//		{
//			ExFreePool(TempBuffer);
//		}
//
//		if (RC4State)
//		{
//			ExFreePool(RC4State);
//		}
//
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//
//		RealFileObject->CurrentByteOffset.QuadPart = OldOffset;
//	}
//
//	return Status;
//}


//NTSTATUS EncryptFile(PIRP_CONTEXT IrpContext)
//{
//	NTSTATUS				Status = STATUS_UNSUCCESSFUL;
//	int						Ret;
//	rc4_state				*RC4State = NULL;
//	PFCB					Fcb;
//	PENCRYPT_IO				EncryptIo;
//	tagFileInfo				*FileInfo = NULL;
//
//	PFILE_INFO              EncryptFileInfo;
//	PPROCESS_INFO           ProcessInfo;
//
//	PFILE_OBJECT            FileObject;
//	PFILE_OBJECT			RealFileObject;
//	PDEVICE_OBJECT			RealFsDevice;
//	unsigned int			DataLen;
//	PUCHAR					Buffer = NULL;
//	LARGE_INTEGER			Offset;
//	LONGLONG				FileSize;
//	tagKeyItemNew				Key;
//	ULONG					Length;
//	ULONG					ReturnLength;
//	ULONGLONG				OldOffset;
//
//	BOOLEAN					PagingIo;
//	BOOLEAN					NonCachedIo;
//	BOOLEAN                 SynPagingIo;
//
//	ULONG                   Flags = 0;
//
//	BOOLEAN                 IsGetPathName = FALSE;
//
//
//	RealFsDevice = IrpContext->RealFsDevice;
//	RealFileObject = IrpContext->RealFileObject;
//	FileObject = IrpContext->FileObject;
//
//	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!EncryptFile -> Irp Flags = %x\n", IrpContext->IrpFlags));
//
//#if 1
//	PagingIo = BooleanFlagOn(IrpContext->IrpFlags, IRP_PAGING_IO);
//	NonCachedIo = BooleanFlagOn(IrpContext->IrpFlags, IRP_NOCACHE);
//	SynPagingIo = BooleanFlagOn(IrpContext->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO);
//
//
//	if (PagingIo)
//	{
//		Flags |= IRP_PAGING_IO;
//	}
//
//	if (NonCachedIo)
//	{
//		Flags |= IRP_NOCACHE;
//	}
//
//	if (SynPagingIo)
//	{
//		Flags |= IRP_SYNCHRONOUS_PAGING_IO;
//	}
//#endif
//
//	FileSize = IrpContext->RealFcb->FileSize.QuadPart;
//	/*	if(FileSize < BLOCK_SIZE)
//		{
//			DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!EncryptFile -> FileSize < BLOCK_SIZE\n"));
//			return Status;
//		}
//	*/
//	DecodeFileObject(IrpContext->FileObject, NULL, &Fcb, NULL);
//
//	EncryptIo = &Fcb->EncryptIo;
//
//	if (EncryptIo->Encrypt || !EncryptIo->EncryptAble)
//	{
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!EncryptFile -> EncryptIo->Encrypt || !EncryptIo->EncryptAble\n"));
//		return Status;
//	}
//
//	if (NonCachedIo && PagingIo)
//	{
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!EncryptFile -> NonCachedIo && PagingIo.\n"));
//		return STATUS_SUCCESS;
//	}
//
//
//	ExAcquireResourceExclusiveLite(EncryptIo->EncryptResource, TRUE);
//
//	if (EncryptIo->Encrypt || !EncryptIo->EncryptAble)
//	{
//		ExReleaseResourceLite(EncryptIo->EncryptResource);
//		return Status;
//	}
//
//	SFSFlushFileObject(FileObject);
//
//	OldOffset = RealFileObject->CurrentByteOffset.QuadPart;
//
//	__try
//	{
//		Key.nKeyDegree = g_Config.m_Policy.UserAuth.nSecretDegree;
//		Ret = GetKey(g_Config.m_TempPolicy.userConfig.keyList, Key);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> GetKey = %x\n", Ret));
//			__leave;
//		}
//
//		Ret = InitKeys(Key.nKey, EncryptIo->EncryptKey, MAX_KEY_LEN, Key.nKeyLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> InitKeys = %x\n", Ret));
//			__leave;
//		}
//
//		EncryptIo->nKey = Key.nKey;
//		EncryptIo->KeyLen = Key.nKeyLen;
//		EncryptIo->KeyIndex = Key.nKeyIndex;
//
//		FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//		if (!FileInfo)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> FileInfo is null\n"));
//			__leave;
//		}
//
//		RtlZeroMemory(FileInfo, sizeof(tagFileInfo));
//
//		Ret = PolicyToFileInfo(&g_Config.m_Policy, FileInfo);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> PolicyToFileInfo = %x\n", Ret));
//			__leave;
//		}
//
//
//		Status = UpdateFileInfo(FileInfo, EncryptIo, RealFileObject);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFileBuffer -> UpdateFileInfo Status = %x.\n", Status));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, L'buff');
//		if (!Buffer)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> Buffer is null\n"));
//			__leave;
//		}
//		RtlZeroMemory(Buffer, PAGE_SIZE);
//
//		Offset.QuadPart = 0;
//
//#if 0
//
//		ClearCache(RealFileObject, &Offset, BLOCK_SIZE);
//#endif  
//
//		Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, BLOCK_SIZE, &Offset, NULL, &ReturnLength);
//
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> IrpReadFile return status = %x\n", Status));
//			__leave;
//		}
//
//		RtlCopyMemory(EncryptIo->FileHeader, Buffer, ReturnLength);
//
//		Ret = EncryptFileHeadSelf(EncryptIo, FileInfo, Buffer, ReturnLength, DataLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> EncryptFileHeadSelf status = %x\n", Ret));
//			__leave;
//		}
//
//		if (DataLen > BLOCK_SIZE)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> DataLen > BLOCK_SIZE\n"));
//			__leave;
//		}
//
//		if (ReturnLength != DataLen)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> ReturnLength != DataLen\n"));
//			__leave;
//		}
//
//		Offset.QuadPart = 0;
//#if 0
//		ClearCache(RealFileObject, &Offset, DataLen);
//#endif   
//		Status = IrpWriteFile(RealFsDevice, RealFileObject, Buffer, DataLen, &Offset, NULL, &ReturnLength);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> IrpWriteFile return status = %x\n", Status));
//			__leave;
//		}
//
//		EncryptIo->Encrypt = TRUE;
//
//		RC4State = (rc4_state*)ExAllocatePoolWithTag(NonPagedPool, sizeof(rc4_state), L'rc4s');
//		if (!RC4State)
//		{
//			DecryptFile(IrpContext, ReturnLength);
//			__leave;
//		}
//
//
//		FileSize -= ReturnLength;
//		Offset.QuadPart += ReturnLength;
//
//		while (FileSize > 0)
//		{
//			if (FileSize >= PAGE_SIZE)
//			{
//				Length = PAGE_SIZE;
//			}
//			else
//			{
//				Length = FileSize;
//			}
//
//#if 0
//			ClearCache(RealFileObject, &Offset, Length);
//#endif
//			Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, Length, &Offset, NULL, &ReturnLength);
//			if (NT_SUCCESS(Status) && Length == ReturnLength)
//			{
//
//				BlockEncrypt(Buffer, Length, EncryptIo->EncryptKey, EncryptIo->KeyLen, RC4State, BLOCK_SIZE);
//
//#if 0
//				ClearCache(RealFileObject, &Offset, Length);
//#endif
//				Status = IrpWriteFile(RealFsDevice, RealFileObject, Buffer, Length, &Offset, NULL, &ReturnLength);
//				if (!NT_SUCCESS(Status))
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> IrpWriteFile status = %x\n", Status));
//					DecryptFile(IrpContext, Offset.QuadPart);
//					__leave;
//				}
//
//			}
//			else
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!EncryptFile -> IrpReadFile status = %x\n", Status));
//				DecryptFile(IrpContext, Offset.QuadPart);
//				__leave;
//			}
//
//			FileSize -= Length;
//			Offset.QuadPart += Length;
//		}
//
//		Status = STATUS_SUCCESS;
//
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!EncryptFile -> Encrypt Complete.\n"));
//
//	}
//	__finally
//	{
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//
//		if (Buffer)
//		{
//			ExFreePool(Buffer);
//		}
//
//		if (RC4State)
//		{
//			ExFreePool(RC4State);
//		}
//
//		RealFileObject->CurrentByteOffset.QuadPart = OldOffset;
//	}
//
//	ExReleaseResourceLite(EncryptIo->EncryptResource);
//
//	return Status;
//
//}


//VOID DecryptFile(PIRP_CONTEXT IrpContext, ULONGLONG DecryptLength)
//{
//	NTSTATUS				Status;
//	int						Ret;
//	rc4_state				*RC4State = NULL;
//	PFCB					Fcb;
//	PENCRYPT_IO				EncryptIo;
//	PFILE_OBJECT            FileObject;
//	PFILE_OBJECT			RealFileObject;
//	PDEVICE_OBJECT			RealFsDevice;
//	unsigned int			DataLen;
//	PUCHAR					Buffer = NULL;
//	LARGE_INTEGER			Offset;
//	LONGLONG				FileSize;
//	ULONG					Length;
//	ULONG					ReturnLength;
//	ULONGLONG				OldOffset;
//
//	BOOLEAN					PagingIo;
//	BOOLEAN					NonCachedIo;
//	BOOLEAN                 SynPagingIo;
//
//	ULONG                   Flags = 0;
//
//	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> Decrypt Entry.\n"));
//
//	RealFsDevice = IrpContext->RealFsDevice;
//	RealFileObject = IrpContext->RealFileObject;
//	FileObject = IrpContext->FileObject;
//
//#if 1
//	PagingIo = BooleanFlagOn(IrpContext->IrpFlags, IRP_PAGING_IO);
//	NonCachedIo = BooleanFlagOn(IrpContext->IrpFlags, IRP_NOCACHE);
//	SynPagingIo = BooleanFlagOn(IrpContext->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO);
//
//	if (PagingIo)
//	{
//		Flags |= IRP_PAGING_IO;
//	}
//
//	if (NonCachedIo)
//	{
//		Flags |= IRP_NOCACHE;
//	}
//
//	if (SynPagingIo)
//	{
//		Flags |= IRP_SYNCHRONOUS_PAGING_IO;
//	}
//#endif
//
//	if (DecryptLength)
//	{
//		FileSize = DecryptLength;
//	}
//	else
//	{
//		FileSize = IrpContext->RealFcb->FileSize.QuadPart;
//	}
//	/*
//	if(FileSize < BLOCK_SIZE)
//	{
//		return;
//	}
//	*/
//	DecodeFileObject(IrpContext->FileObject, NULL, &Fcb, NULL);
//
//	EncryptIo = &Fcb->EncryptIo;
//
//	if (!EncryptIo->Encrypt)
//	{
//		return;
//	}
//
//	ExAcquireResourceExclusiveLite(EncryptIo->EncryptResource, TRUE);
//
//	if (!EncryptIo->Encrypt)
//	{
//		ExReleaseResourceLite(EncryptIo->EncryptResource);
//		return;
//	}
//
//	SFSFlushFileObject(FileObject);
//
//	OldOffset = RealFileObject->CurrentByteOffset.QuadPart;
//	__try
//	{
//
//		Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, L'buff');
//		if (!Buffer)
//		{
//			__leave;
//		}
//		RtlZeroMemory(Buffer, PAGE_SIZE);
//
//		Offset.QuadPart = 0;
//
//		//      SFSFlushCache(FileObject, &Offset, BLOCK_SIZE);
//#if 0
//	//    if (NonCachedIo)
//		{
//			ClearCache(RealFileObject, &Offset, BLOCK_SIZE);
//		}
//#endif
//		Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, BLOCK_SIZE, &Offset, NULL, &ReturnLength);
//
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> IrpReadFile fails status = %x.\n", Status));
//			__leave;
//		}
//
//
//		Ret = DecryptFileHeadSelf(EncryptIo, Buffer, ReturnLength, DataLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> DecryptFileHeadSelf fails status = %x.\n", Ret));
//			__leave;
//		}
//
//		if (DataLen > BLOCK_SIZE)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> DataLen > BLOCK_SIZE = %d.\n", DataLen));
//			__leave;
//		}
//
//		Offset.QuadPart = 0;
//		//       SFSFlushCache(FileObject, &Offset, BLOCK_SIZE);
//
//#if 0
//	//    if (NonCachedIo)
//		{
//			ClearCache(RealFileObject, &Offset, DataLen);
//		}
//#endif
//		Status = IrpWriteFile(RealFsDevice, RealFileObject, Buffer, DataLen, &Offset, NULL, &ReturnLength);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> IrpWriteFile fails status = %x.\n", Status));
//			__leave;
//		}
//
//		RC4State = (rc4_state*)ExAllocatePoolWithTag(NonPagedPool, sizeof(rc4_state), L'rc4s');
//		if (!RC4State)
//		{
//			__leave;
//		}
//
//		FileSize -= ReturnLength;
//		Offset.QuadPart += ReturnLength;
//
//		while (FileSize > 0)
//		{
//			if (FileSize >= PAGE_SIZE)
//			{
//				Length = PAGE_SIZE;
//			}
//			else
//			{
//				Length = FileSize;
//			}
//
//			//         SFSFlushCache(FileObject, &Offset, BLOCK_SIZE);
//#if 0
//	//        if (NonCachedIo)
//			{
//				ClearCache(RealFileObject, &Offset, Length);
//			}
//#endif
//			Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, Length, &Offset, NULL, &ReturnLength);
//			if (NT_SUCCESS(Status) && Length == ReturnLength)
//			{
//				BlockEncrypt(Buffer, Length, EncryptIo->EncryptKey, EncryptIo->KeyLen, RC4State, BLOCK_SIZE);
//				//               SFSFlushCache(FileObject, &Offset, BLOCK_SIZE);
//#if 0
//	//            if (NonCachedIo)
//				{
//					ClearCache(RealFileObject, &Offset, Length);
//				}
//#endif
//				Status = IrpWriteFile(RealFsDevice, RealFileObject, Buffer, Length, &Offset, NULL, &ReturnLength);
//				if (!NT_SUCCESS(Status))
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> IrpWriteFile fails status = %x.\n", Status));
//					__leave;
//				}
//
//			}
//			else
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> IrpReadFile fails status = %x.\n", Status));
//				__leave;
//			}
//
//			FileSize -= Length;
//			Offset.QuadPart += Length;
//		}
//
//		EncryptIo->Encrypt = FALSE;
//		EncryptIo->KeyLen = 0;
//		EncryptIo->KeyIndex = 0;
//		RtlZeroMemory(EncryptIo->EncryptKey, MAX_KEY_LEN);
//
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!DecryptFile -> Decrypt Complete.\n"));
//
//	}
//	__finally
//	{
//		if (Buffer)
//		{
//			ExFreePool(Buffer);
//		}
//
//		if (RC4State)
//		{
//			ExFreePool(RC4State);
//		}
//
//		RealFileObject->CurrentByteOffset.QuadPart = OldOffset;
//	}
//
//	ExReleaseResourceLite(EncryptIo->EncryptResource);
//
//}



VOID
LockUserBuffer(
	IN PIRP_CONTEXT IrpContext,
	IN OUT PIRP Irp,
	IN LOCK_OPERATION Operation,
	IN ULONG BufferLength
)
{
	PMDL Mdl = NULL;

	if (Irp->MdlAddress == NULL) {

		Mdl = IoAllocateMdl(Irp->UserBuffer, BufferLength, FALSE, FALSE, Irp);

		if (Mdl == NULL) {

			RaiseStatus(IrpContext, STATUS_INSUFFICIENT_RESOURCES);
		}

		__try
		{
			MmProbeAndLockPages(Mdl,
				Irp->RequestorMode,
				Operation);

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			NTSTATUS Status = GetExceptionCode();

			IoFreeMdl(Mdl);
			Irp->MdlAddress = NULL;

			RaiseStatus(IrpContext, FsRtlIsNtstatusExpected(Status) ? Status : STATUS_INVALID_USER_BUFFER);
		}
	}
}

VOID
PrePostIrp(
	IN PVOID Context,
	IN PIRP Irp
)
{

	PIO_STACK_LOCATION IrpSp;
	PIRP_CONTEXT IrpContext;

	if (Irp == NULL) {

		return;
	}

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	IrpContext = (PIRP_CONTEXT)Context;


	if ((IrpContext->IoContext != NULL) &&
		FlagOn(IrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT)) {

		ClearFlag(IrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT);
		IrpContext->IoContext = NULL;
	}


	if (IrpContext->MajorFunction == IRP_MJ_READ ||
		IrpContext->MajorFunction == IRP_MJ_WRITE) {

		if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL)) {

			LockUserBuffer(
				IrpContext,
				Irp,
				(IrpContext->MajorFunction == IRP_MJ_READ) ? IoWriteAccess : IoReadAccess,
				(IrpContext->MajorFunction == IRP_MJ_READ) ? IrpSp->Parameters.Read.Length : IrpSp->Parameters.Write.Length
			);
		}

	}
	else if (IrpContext->MajorFunction == IRP_MJ_DIRECTORY_CONTROL
		&& IrpContext->MinorFunction == IRP_MN_QUERY_DIRECTORY) {

		LockUserBuffer(IrpContext,
			Irp,
			IoWriteAccess,
			IrpSp->Parameters.QueryDirectory.Length);

	}
	else if (IrpContext->MajorFunction == IRP_MJ_QUERY_EA) {

		LockUserBuffer(IrpContext,
			Irp,
			IoWriteAccess,
			IrpSp->Parameters.QueryEa.Length);


	}
	else if (IrpContext->MajorFunction == IRP_MJ_SET_EA) {

		LockUserBuffer(IrpContext,
			Irp,
			IoReadAccess,
			IrpSp->Parameters.SetEa.Length);


	}
	else if ((IrpContext->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		(IrpContext->MinorFunction == IRP_MN_USER_FS_REQUEST) &&
		((IrpSp->Parameters.FileSystemControl.FsControlCode == FSCTL_GET_VOLUME_BITMAP) ||
		(IrpSp->Parameters.FileSystemControl.FsControlCode == FSCTL_GET_RETRIEVAL_POINTERS))) {

		LockUserBuffer(IrpContext,
			Irp,
			IoWriteAccess,
			IrpSp->Parameters.FileSystemControl.OutputBufferLength);
	}

	IoMarkIrpPending(Irp);

	return;
}


PVOID
RemoveOverflowEntry(
	IN PFS_DEVICE_OBJECT FsDevice
)
{
	PVOID Entry = NULL;
	KIRQL SavedIrql;

	KeAcquireSpinLock(&FsDevice->OverflowQueueSpinLock, &SavedIrql);

	if (FsDevice->OverflowQueueCount > 0) {

		FsDevice->OverflowQueueCount -= 1;

		if (!IsListEmpty(&FsDevice->OverflowQueue))
		{
			Entry = RemoveHeadList(&FsDevice->OverflowQueue);
		}

	}
	else {

		Entry = NULL;
	}

	KeReleaseSpinLock(&FsDevice->OverflowQueueSpinLock, SavedIrql);

	return Entry;
}

VOID
VerifyOperationIsLegal(
	IN PIRP_CONTEXT IrpContext
)
{
	PIRP Irp;
	PFILE_OBJECT FileObject;

	Irp = IrpContext->OriginatingIrp;

	if (Irp == NULL) {

		return;
	}

	FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

	if (FileObject == NULL) {

		return;
	}


	if (FlagOn(FileObject->Flags, FO_CLEANUP_COMPLETE)) {

		PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

		if ((FlagOn(Irp->Flags, IRP_PAGING_IO)) ||
			(IrpSp->MajorFunction == IRP_MJ_CLOSE) ||
			(IrpSp->MajorFunction == IRP_MJ_SET_INFORMATION) ||
			(IrpSp->MajorFunction == IRP_MJ_QUERY_INFORMATION) ||
			(((IrpSp->MajorFunction == IRP_MJ_READ) ||
			(IrpSp->MajorFunction == IRP_MJ_WRITE)) &&
				FlagOn(IrpSp->MinorFunction, IRP_MN_COMPLETE))) {

			NOTHING;

		}
		else {

			RaiseStatus(IrpContext, STATUS_FILE_CLOSED);
		}
	}

	return;
}


BOOLEAN
AcquireExclusiveFcb(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
)
{

RetryFcbExclusive:

	if (ExAcquireResourceExclusiveLite(Fcb->Header.Resource, BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))) {

		if ((Fcb->NonPaged->OutstandingAsyncWrites != 0) &&
			((IrpContext->MajorFunction != IRP_MJ_WRITE) ||
				!FlagOn(IrpContext->OriginatingIrp->Flags, IRP_NOCACHE) ||
				(ExGetSharedWaiterCount(Fcb->Header.Resource) != 0) ||
				(ExGetExclusiveWaiterCount(Fcb->Header.Resource) != 0))) {

			KeWaitForSingleObject(Fcb->NonPaged->OutstandingAsyncEvent,
				Executive,
				KernelMode,
				FALSE,
				(PLARGE_INTEGER)NULL);

			ExReleaseResourceLite(Fcb->Header.Resource);

			goto RetryFcbExclusive;
		}
#if 0
		__try
		{

			VerifyOperationIsLegal(IrpContext);

		}
		__finally
		{

			if (AbnormalTermination()) {

				ExReleaseResourceLite(Fcb->Header.Resource);
			}
		}
#endif
		return TRUE;

	}
	else {

		return FALSE;
	}
}

BOOLEAN
AcquireSharedFcbWaitForEx(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
)
{

	ASSERT(FlagOn(IrpContext->OriginatingIrp->Flags, IRP_NOCACHE));
	ASSERT(!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT));

RetryFcbSharedWaitEx:

	if (ExAcquireSharedWaitForExclusive(Fcb->Header.Resource, FALSE)) {

		if ((Fcb->NonPaged->OutstandingAsyncWrites != 0) &&
			(IrpContext->MajorFunction != IRP_MJ_WRITE)) {

			KeWaitForSingleObject(Fcb->NonPaged->OutstandingAsyncEvent,
				Executive,
				KernelMode,
				FALSE,
				(PLARGE_INTEGER)NULL);

			ExReleaseResourceLite(Fcb->Header.Resource);

			goto RetryFcbSharedWaitEx;
		}

		__try
		{

			VerifyOperationIsLegal(IrpContext);

		}
		__finally
		{
			if (AbnormalTermination()) {

				ExReleaseResourceLite(Fcb->Header.Resource);
			}
		}


		return TRUE;

	}
	else {

		return FALSE;
	}
}


BOOLEAN
AcquireSharedFcb(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
)
{

RetryFcbShared:

	if (ExAcquireResourceSharedLite(Fcb->Header.Resource, BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))) {

		if ((Fcb->NonPaged->OutstandingAsyncWrites != 0) &&
			((IrpContext->MajorFunction != IRP_MJ_WRITE) ||
				!FlagOn(IrpContext->OriginatingIrp->Flags, IRP_NOCACHE) ||
				(ExGetSharedWaiterCount(Fcb->Header.Resource) != 0) ||
				(ExGetExclusiveWaiterCount(Fcb->Header.Resource) != 0))) {

			KeWaitForSingleObject(Fcb->NonPaged->OutstandingAsyncEvent,
				Executive,
				KernelMode,
				FALSE,
				(PLARGE_INTEGER)NULL);

			ExReleaseResourceLite(Fcb->Header.Resource);

			goto RetryFcbShared;
		}

		__try {

			VerifyOperationIsLegal(IrpContext);

		}
		__finally
		{

			if (AbnormalTermination()) {

				ExReleaseResourceLite(Fcb->Header.Resource);
			}
		}


		return TRUE;

	}
	else {

		return FALSE;
	}
}



VOID
LookupFileAllocationSize(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
)
{

	NTSTATUS                    Status;
	LBO                         Lbo;
	ULONG                       ByteCount;
	FILE_ALLOCATION_INFORMATION Info;

	Status = IrpQueryInformationFile(IrpContext->RealFsDevice,
		IrpContext->RealFileObject,
		&Info,
		sizeof(FILE_ALLOCATION_INFORMATION),
		FileAllocationInformation);

	if (NT_SUCCESS(Status))
	{
		Fcb->Header.AllocationSize.QuadPart = Info.AllocationSize.QuadPart;

		if (Fcb->Header.FileSize.QuadPart <= Fcb->Header.AllocationSize.QuadPart)
		{

			return;

		}
		else
		{
			RaiseStatus(IrpContext, STATUS_FILE_CORRUPT_ERROR);
		}
	}
	else
	{
		RaiseStatus(IrpContext, STATUS_FILE_CORRUPT_ERROR);
	}
}


VOID DeleteFileObject(PFILE_OBJECT FileObject)
{
	if (FileObject)
	{
		if (FileObject->FsContext)
		{
			ClearCache(FileObject, NULL, 0);
		}

		if (FileObject->PrivateCacheMap)
		{
			CcUninitializeCacheMap(FileObject, NULL, NULL);
		}

		FileObject->Flags |= (FO_HANDLE_CREATED | FO_CLEANUP_COMPLETE);

		if (FileObject->Flags & FO_FILE_OPEN_CANCELLED)
		{

			ObDereferenceObject(FileObject);
		}
		else
		{
#if 0
			if (FileObject->FileName.Length)
			{
				ExFreePool(FileObject->FileName.Buffer);
				FileObject->FileName.Buffer = NULL;
				FileObject->FileName.Length = 0;
			}
#endif
			//FileObject->DeviceObject = (PDEVICE_OBJECT) NULL;

			ObDereferenceObject(FileObject);

		}
	}
}



BOOLEAN FindSubString(UNICODE_STRING Str, PWCHAR SubStr)
{
	BOOLEAN Result = FALSE;
	PWCHAR ProcessNameBuf;
	UNICODE_STRING UnicodeString;

	ProcessNameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'pnam');
	if (!ProcessNameBuf)
	{
		return FALSE;
	}
	RtlZeroMemory(ProcessNameBuf, MAX_PATH_SIZE);
	RtlInitEmptyUnicodeString(&UnicodeString, ProcessNameBuf, MAX_PATH_SIZE);

	RtlUpcaseUnicodeString(&UnicodeString, &Str, FALSE);

	if (wcsstr(UnicodeString.Buffer, SubStr))
	{
		Result = TRUE;
	}

	ExFreePool(ProcessNameBuf);

	return Result;

}





BOOLEAN MatchOkay(PWCHAR Pattern)
{

	while (*Pattern)
	{
		if (*Pattern == L'*') Pattern++;
		else return FALSE;
	}

	return TRUE;
}


BOOLEAN  MatchWithPattern(PWCHAR Pattern, PWCHAR Name)
{
	PWCHAR pTmp;
	ULONG PatternLen = 0, NameLen = 0;


	if (!*Pattern)
	{
		return FALSE;
	}

	if (*Pattern == L'*')
	{
		Pattern++;

		//////////////////////////////////////////////////////////////////////////
		//special process, * ,*.xxx
		do {
			pTmp = Pattern;
			while (*pTmp)
			{
				if ((*pTmp == L'*') || (*pTmp == L'?')) NameLen++;
				PatternLen++;
				pTmp++;
			}
			if (PatternLen == 0) return TRUE; //*
			if (NameLen) break;		//not *.xxxx
			NameLen = wcslen(Name); //*.XXX 	
			if (NameLen < PatternLen) return FALSE;

			pTmp = Name + (NameLen - PatternLen);
			if (_wcsicmp(pTmp, Pattern) == 0) return TRUE;
			else return FALSE;

		} while (FALSE);

		//////////////////////////////////////////////////////////////////////////

		//pattern the next substring
		while (*Name && *Pattern)
		{

			//
			// See if this substring matches
			//
			if ((*Pattern == *Name) || (*Pattern == L'?')) {

				if (MatchWithPattern(Pattern + 1, Name + 1)) {
					return TRUE;
				}
			}

			//
			// Try the next substring
			//
			Name++;
		}

		// end of Name
		// See if match condition was met
		//
		return MatchOkay(Pattern);
	}

	//
	// Do straight compare until we hit a wild card
	//
	while (*Name && (*Pattern != L'*'))
	{

		if ((*Pattern == *Name) || (*Pattern == L'?'))

		{
			Pattern++;
			Name++;

		}
		else	return FALSE;
	}

	//
	// If not done, recurse
	//
	if (*Name) {

		return MatchWithPattern(Pattern, Name);
	}

	// end of Name
	// Make sure its a match
	//
	return MatchOkay(Pattern); //*Name == '\0'
}


PFILE_INFO FindEncryptFileInfo(PPROCESS_INFO ProcessInfo, UNICODE_STRING Name)
{
	PLIST_ENTRY Links;
	PFILE_INFO Node;


	for (Links = ProcessInfo->EncryptFileList.Flink; Links != &ProcessInfo->EncryptFileList; Links = Links->Flink)
	{
		Node = (PFILE_INFO)Links;
		//DebugString(DEBUG_TRACE_FILEINFO, "FileInfo!FindEncryptFileInfo -> Node->Name = %s\n", Node->Name.Buffer);
		if (RtlCompareUnicodeString(&Node->Name, &Name, TRUE) == 0)
		{
			return Node;
		}
	}

	return NULL;
}

//检查文件是否允许打印
//BOOLEAN CheckPrint(PPROCESS_INFO ProcessInfo, PWCHAR Name)
//{
//	NTSTATUS                    Status;
//
//	PLIST_ENTRY                 Links;
//	PFILE_INFO                  Node = NULL;
//	BOOLEAN                     Result = TRUE;
//
//	PWCHAR                      FileNameBuf = NULL;
//	PWCHAR                      PrintFileNameBuf = NULL;
//	PWCHAR                      NoExtFileNameBuf = NULL;
//
//	LARGE_INTEGER				FileSize;
//	LARGE_INTEGER				FileOffset = { 0, 0 };
//	HANDLE						Handle = NULL;
//	PFILE_OBJECT				FileObject;
//	OBJECT_ATTRIBUTES			ObjectAttributes;
//	IO_STATUS_BLOCK				IoStatusBlock;
//
//
//	PUCHAR						Buffer = NULL;
//
//	LARGE_INTEGER				Offset;
//	tagFileInfo*                FileInfo = NULL;
//
//	PDEVICE_OBJECT              RealFsDevice;
//
//	int						    Ret;
//
//	PENCRYPT_IO					EncryptIo = NULL;
//
//	tagKeyItemNew				Key;
//
//	unsigned int			    DataLen;
//
//	ULONG_PTR                   ExtNameOffset;
//
//	BOOLEAN                     IsMatch = FALSE;
//
//	FileNameBuf = AllocPathLookasideList();
//	if (!FileNameBuf)
//	{
//		//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> AllocPathLookasideList is null.\n"));
//	}
//
//	NoExtFileNameBuf = AllocPathLookasideList();
//	if (!NoExtFileNameBuf)
//	{
//		//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> AllocPathLookasideList is null.\n"));
//	}
//
//	_wcsupr(Name);
//
//	//DebugString(DEBUG_TRACE_FILEINFO, "FileInfo!FindEncryptFileInfo -> Name = %s\n", Name);
//
//	__try
//	{
//
//		for (Links = ProcessInfo->EncryptFileList.Flink; Links != &ProcessInfo->EncryptFileList; Links = Links->Flink)
//		{
//			Node = (PFILE_INFO)Links;
//			//DebugString(DEBUG_TRACE_FILEINFO, "FileInfo!FindEncryptFileInfo -> Node->Name = %s\n", Node->Name.Buffer);
//
//
//			RtlZeroMemory(FileNameBuf, MAX_PATH_SIZE);
//			RtlCopyMemory(FileNameBuf, Node->Name.Buffer, Node->Name.Length);
//			_wcsupr(FileNameBuf);
//			PrintFileNameBuf = wcsrchr(FileNameBuf, L'\\');
//			if (!PrintFileNameBuf)
//			{
//				//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> wcsrchr return null\n"));
//				continue;
//			}
//			PrintFileNameBuf++;
//			if (wcslen(PrintFileNameBuf) == 0)
//			{
//				//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> PrintFileNameBuf length is 0 \n"));
//				continue;
//			}
//
//			if (wcslen(PrintFileNameBuf) > wcslen(Name))
//			{
//				//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> length error\n"));
//				continue;
//			}
//
//			//DebugString(DEBUG_TRACE_SFSSup, "SFSSup!CheckPrint -> PrintFileName = %s\n", PrintFileNameBuf);
//
//			if (!wcsstr(Name, PrintFileNameBuf))
//			{
//				continue;
//			}
//
//			IsMatch = TRUE;
//		}
//
//		if (!IsMatch)
//		{
//			for (Links = ProcessInfo->EncryptFileList.Flink; Links != &ProcessInfo->EncryptFileList; Links = Links->Flink)
//			{
//				Node = (PFILE_INFO)Links;
//				//DebugString(DEBUG_TRACE_FILEINFO, "FileInfo!FindEncryptFileInfo -> Node->Name = %s\n", Node->Name.Buffer);
//
//				RtlZeroMemory(FileNameBuf, MAX_PATH_SIZE);
//				RtlCopyMemory(FileNameBuf, Node->Name.Buffer, Node->Name.Length);
//				_wcsupr(FileNameBuf);
//				PrintFileNameBuf = wcsrchr(FileNameBuf, L'\\');
//				if (!PrintFileNameBuf)
//				{
//					//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> wcsrchr return null\n"));
//					continue;
//				}
//				PrintFileNameBuf++;
//				if (wcslen(PrintFileNameBuf) == 0)
//				{
//					//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> PrintFileNameBuf length is 0 \n"));
//					continue;
//				}
//
//				if (wcslen(PrintFileNameBuf) > wcslen(Name))
//				{
//					//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> length error\n"));
//					continue;
//				}
//
//				//DebugString(DEBUG_TRACE_SFSSup, "SFSSup!CheckPrint -> PrintFileName = %s\n", PrintFileNameBuf);
//
//				ExtNameOffset = (ULONG_PTR)wcsrchr(PrintFileNameBuf, L'.');
//				if (ExtNameOffset)
//				{
//					RtlZeroMemory(NoExtFileNameBuf, MAX_PATH_SIZE);
//					RtlCopyMemory(NoExtFileNameBuf, PrintFileNameBuf, ExtNameOffset - (ULONG_PTR)PrintFileNameBuf);
//					//DebugString(DEBUG_TRACE_SFSSup, "SFSSup!CheckPrint -> NoExtFileNameBuf = %s\n", NoExtFileNameBuf);
//				}
//
//				if (ExtNameOffset)
//				{
//					if (!wcsstr(Name, NoExtFileNameBuf))
//					{
//						continue;
//					}
//					IsMatch = TRUE;
//				}
//
//			}
//		}
//
//
//		if (IsMatch)
//		{
//
//			if (!Node->bPrintFlag)
//			{
//				Result = FALSE;
//				__leave;
//			}
//
//			if (!Node->bPrintTimesFlag)
//			{
//				__leave;
//			}
//
//			if (Node->nPrintTimes <= 0)
//			{
//				Result = FALSE;
//				__leave;
//			}
//
//			RealFsDevice = Node->RealFsDevice;
//
//			InitializeObjectAttributes(&ObjectAttributes, &Node->LetterName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//
//			Status = CreateFileByFsDevice(
//				&Handle,
//				&FileObject,
//				GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
//				&ObjectAttributes,
//				&IoStatusBlock,
//				FILE_ATTRIBUTE_NORMAL,
//				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//				FILE_OPEN,
//				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
//				NULL,
//				0,
//				RealFsDevice
//			);
//
//			if (!NT_SUCCESS(Status))
//			{
//				//DebugTrace(DEBUG_TRACE_CONFIG | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> CreateFileByFsDevice Fail. 0x%08x\n", Status));
//				Result = FALSE;
//				__leave;
//			}
//
//
//			Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, 'Btag');
//			if (!Buffer)
//			{
//				Result = FALSE;
//				__leave;
//			}
//
//			RtlZeroMemory(Buffer, BLOCK_SIZE);
//
//
//			FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//			if (!FileInfo)
//			{
//				Result = FALSE;
//				__leave;
//			}
//			RtlZeroMemory(FileInfo, sizeof(tagFileInfo));
//
//
//			Offset.QuadPart = 0;
//			Status = IrpReadFile(RealFsDevice, FileObject, Buffer, BLOCK_SIZE, &Offset, 0, NULL);
//			if (!NT_SUCCESS(Status))
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> IrpReadFile Status = %x.\n", Status));
//				Result = FALSE;
//				__leave;
//			}
//
//			if (!IsEncryptBuffer(Buffer, BLOCK_SIZE))
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> !IsEncryptBuffer.\n"));
//				Result = FALSE;
//				__leave;
//			}
//
//
//			EncryptIo = (ENCRYPT_IO*)ExAllocatePoolWithTag(NonPagedPool, sizeof(ENCRYPT_IO), L'ency');
//			if (!EncryptIo)
//			{
//				Result = FALSE;
//				__leave;
//			}
//			RtlZeroMemory(EncryptIo, sizeof(ENCRYPT_IO));
//
//			Ret = GetFileHeadInfo(FileInfo, Buffer, BLOCK_SIZE);
//			if (Ret != ISAFE_STATUS_SUCCESS)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> GetFileHeadInfo Fail. 0x%08x\n", Ret));
//				Result = FALSE;
//				__leave;
//			}
//
//			Ret = GetKeyByKeyIndex(g_Config.m_TempPolicy.userConfig.keyList, FileInfo->nKeyIndex, Key);
//			if (Ret != ISAFE_STATUS_SUCCESS)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> GetKeyByKeyIndex Fail. 0x%08x\n", Ret));
//				Result = FALSE;
//				__leave;
//			}
//
//			Ret = InitKeys(Key.nKey, EncryptIo->EncryptKey, MAX_KEY_LEN, Key.nKeyLen);
//			if (Ret != ISAFE_STATUS_SUCCESS)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> InitKeys Fail. 0x%08x\n", Ret));
//				Result = FALSE;
//				__leave;
//			}
//
//			EncryptIo->KeyLen = Key.nKeyLen;
//			EncryptIo->KeyIndex = FileInfo->nKeyIndex;
//			EncryptIo->Encrypt = TRUE;
//
//
//			Ret = DecryptFileHeadSelf(EncryptIo, FileInfo, Buffer, BLOCK_SIZE, DataLen);
//			if (Ret != ISAFE_STATUS_SUCCESS)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> DecryptFileHeadSelf Status = %x.\n", Ret));
//				Result = FALSE;
//				__leave;
//			}
//
//			if (FileInfo->nPrintTimes <= 0)
//			{
//				Result = FALSE;
//				__leave;
//			}
//
//			FileInfo->nPrintTimes--;
//
//			Ret = EncryptFileHeadSelf(EncryptIo, FileInfo, Buffer, BLOCK_SIZE, DataLen);
//			if (Ret != ISAFE_STATUS_SUCCESS)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> EncryptFileHeadSelf Status = %x.\n", Ret));
//				Result = FALSE;
//				__leave;
//			}
//
//			Status = IrpWriteFile(RealFsDevice, FileObject, Buffer, BLOCK_SIZE, &Offset, 0, NULL);
//			if (!NT_SUCCESS(Status))
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> IrpWriteFile Status = %x.\n", Status));
//				Result = FALSE;
//				__leave;
//			}
//		}
//
//	}
//	__finally
//	{
//		if (EncryptIo)
//		{
//			ExFreePool(EncryptIo);
//		}
//
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//
//		if (Buffer)
//		{
//			ExFreePool(Buffer);
//		}
//
//		if (Handle)
//		{
//			ZwClose(Handle);
//		}
//
//		if (FileNameBuf)
//		{
//			FreePathLookasideList(FileNameBuf);
//		}
//
//		if (NoExtFileNameBuf)
//		{
//			FreePathLookasideList(NoExtFileNameBuf);
//		}
//	}
//
//	return Result;
//}

#if 0
VOID AddEncryptFileInfo(PPROCESS_INFO ProcessInfo, IN PFILE_INFO FileInfo)
{
	PFCB_NODE Node;

	Node = (PFCB_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(FCB_NODE), 'tagN');
	if (Node)
	{
		Node->Fcb = FileInfo;
		InsertHeadList(&ProcessInfo->ListEntry, (PLIST_ENTRY)Node);
	}

}
#endif 

VOID RemoveEncryptFileInfo(PPROCESS_INFO ProcessInfo)
{
	PFILE_INFO Entry;

	/*
		for(Links = ProcessInfo->EncryptFileList.Flink; Links != &ProcessInfo->EncryptFileList; Links = Links->Flink)
		{
			DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> RemoveEncryptFileInfo Links = %x.\n", Links));
			RemoveEntryList(Links);

			ExFreePool(Links);
		}
	*/
	while (!IsListEmpty(&ProcessInfo->EncryptFileList))
	{
		Entry = (PFILE_INFO)RemoveHeadList(&ProcessInfo->EncryptFileList);
		if (Entry->Name.Buffer)
		{
			ExFreePool(Entry->Name.Buffer);
		}

		if (Entry->LetterName.Buffer)
		{
			ExFreePool(Entry->LetterName.Buffer);
		}

		ExFreePool(Entry);
	}

}


unsigned int CurrentTime()
{

	TIME_FIELDS					TimeFields;
	LARGE_INTEGER				Time, LocalTime;
	unsigned int                nTime = 0;

	KeQuerySystemTime(&Time);
	ExSystemTimeToLocalTime(&Time, &LocalTime);
	RtlTimeToTimeFields(&LocalTime, &TimeFields);

	nTime += (TimeFields.Year - 1900) & 0xff;
	nTime = (nTime << 4);
	nTime += TimeFields.Month & 0xf;
	nTime = (nTime << 5);
	nTime += TimeFields.Day & 0x1f;
	nTime = (nTime << 5);
	nTime += TimeFields.Hour & 0x1f;
	nTime = (nTime << 6);
	nTime += TimeFields.Minute & 0x3f;

	return nTime;
}

VOID ConvertUT(PTIME_FIELDS TimeFields, int nTime)
{
	if (TimeFields != NULL)
	{
		RtlZeroMemory(TimeFields, sizeof(TIME_FIELDS));
		TimeFields->Minute = (nTime) & 0x3f;
		nTime = (nTime >> 6);
		TimeFields->Hour = (nTime) & 0x1f;
		nTime = (nTime >> 5);
		TimeFields->Day = (nTime) & 0x1f;
		nTime = (nTime >> 5);
		TimeFields->Month = (nTime) & 0xf;
		nTime = (nTime >> 4);
		TimeFields->Year = (nTime) & 0xff;
		TimeFields->Year += 1900;
	}
}



//NTSTATUS UpdateEncryptFileInfo(IN PIRP_CONTEXT IrpContext, IN PFCB Fcb)
//{
//	NTSTATUS					Status = STATUS_UNSUCCESSFUL;
//	PENCRYPT_IO					EncryptIo;
//	tagKeyItem					Key;
//	tagFileInfo					*FileInfo = NULL;
//	int							nRet = 0;
//	PFSRTL_ADVANCED_FCB_HEADER	RealFcb;
//	PDEVICE_OBJECT				RealFsDevice;
//	PFILE_OBJECT				RealFileObject;
//	PUCHAR						Buffer = NULL;
//	LARGE_INTEGER				Offset;
//	unsigned int				DataLen;
//	FILE_BASIC_INFORMATION      FileBaseInfo;
//	PFILE_INFO                  EncryptFileInfo;
//	PPROCESS_INFO               ProcessInfo;
//	PPATH_NAME_INFORMATION		PathNameInfo;
//	WCHAR           			DriveLetter[2] = { 0 };
//
//
//
//	RealFsDevice = IrpContext->RealFsDevice;
//	RealFileObject = IrpContext->RealFileObject;
//	RealFcb = IrpContext->RealFcb;
//
//	EncryptIo = &Fcb->EncryptIo;
//
//	if (!EncryptIo->Encrypt || !EncryptIo->FileControl)
//	{
//		return STATUS_SUCCESS;
//	}
//
//	if (RealFcb->FileSize.QuadPart < BLOCK_SIZE)
//	{
//		return STATUS_SUCCESS;
//	}
//
//	Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, L'BUFF');
//	if (!Buffer)
//	{
//		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> ExAllocatePoolWithTag is null.\n"));
//		return Status;
//	}
//
//	__try
//	{
//
//		Offset.QuadPart = 0;
//		Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, BLOCK_SIZE, &Offset, 0, NULL);
//		RealFileObject->CurrentByteOffset.QuadPart = 0;
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> IrpReadFile Fail. 0x%08x \n", Status));
//			__leave;
//		}
//
//		FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//		if (!FileInfo)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> ExAllocatePoolWithTag is null.\n"));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		nRet = DecryptFileHeadSelf(EncryptIo, FileInfo, Buffer, BLOCK_SIZE, DataLen);
//		if (nRet != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> DecryptFileHeadSelf Status = %x.\n", nRet));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		if (FileInfo->nSecretDegree > g_Config.m_Policy.UserAuth.nSecretDegree)
//		{
//			//	SendLogAudit(GenerateLogMsg(LOG_RESULT_FAILURE, LOG_OBJECT_FILE, L"文件%S密级错误", IrpContext->PathNameInfo->Name.Buffer));
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> SecretDegree error.\n"));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		if (FileInfo->bGroupOnlyFlag)
//		{
//			if (FileInfo->nNodeID_1 != g_Config.m_Policy.UserAuth.nNodeID1)
//			{
//				//	SendLogAudit(GenerateLogMsg(LOG_RESULT_FAILURE, LOG_OBJECT_FILE, L"文件%S不在同一组内", IrpContext->PathNameInfo->Name.Buffer));
//				//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> GroupOnly error.\n"));
//				Status = STATUS_UNSUCCESSFUL;
//				__leave;
//			}
//		}
//
//		ExAcquireResourceExclusiveLite(&SFSData.ProcessInfoListResource, TRUE);
//
//		ProcessInfo = FindProcessInfo(PsGetCurrentProcessId());
//		if (!ProcessInfo)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> ProcessInfo is null. ProcessId = %x\n", PsGetCurrentProcessId()));
//			Status = STATUS_UNSUCCESSFUL;
//			ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//			__leave;
//		}
//
//		PathNameInfo = IrpContext->PathNameInfo;
//
//		EncryptFileInfo = FindEncryptFileInfo(ProcessInfo, PathNameInfo->Name);
//		if (!EncryptFileInfo)
//		{
//			EncryptFileInfo = (PFILE_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_INFO), L'file');
//			if (!EncryptFileInfo)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> ExAllocatePoolWithTag is null.\n"));
//				Status = STATUS_UNSUCCESSFUL;
//				ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//				__leave;
//			}
//			RtlZeroMemory(EncryptFileInfo, sizeof(FILE_INFO));
//
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> PathNameInfo->Name.MaximumLength = %d.\n", PathNameInfo->Name.MaximumLength));
//
//			EncryptFileInfo->Name.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, PathNameInfo->Name.MaximumLength, 'FILE');
//			if (!EncryptFileInfo->Name.Buffer)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> ExAllocatePoolWithTag Fail."));
//				Status = STATUS_UNSUCCESSFUL;
//				ExFreePool(EncryptFileInfo);
//				ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//				__leave;
//			}
//
//			RtlCopyMemory(EncryptFileInfo->Name.Buffer, PathNameInfo->Name.Buffer, PathNameInfo->Name.MaximumLength);
//
//			EncryptFileInfo->Name.MaximumLength = PathNameInfo->Name.MaximumLength;
//			EncryptFileInfo->Name.Length = PathNameInfo->Name.Length;
//
//
//
//			/////////////////////////////////////////////////////////////////////////////////////////////////////
//
//
//			EncryptFileInfo->LetterName.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, PathNameInfo->Name.MaximumLength, 'FILE');
//			if (!EncryptFileInfo->LetterName.Buffer)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> ExAllocatePoolWithTag Fail."));
//				Status = STATUS_UNSUCCESSFUL;
//				ExFreePool(EncryptFileInfo);
//				ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//				__leave;
//			}
//			EncryptFileInfo->LetterName.MaximumLength = PathNameInfo->Name.MaximumLength;
//
//			RtlZeroMemory(EncryptFileInfo->LetterName.Buffer, PathNameInfo->Name.MaximumLength);
//			EncryptFileInfo->LetterName.Length = 0;
//
//			//  PathNameInfo->VolumePath.Length -= 8;
//			if (!GetDriverLetter(&PathNameInfo->VolumePath, DriveLetter))
//			{
//				//DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> GetDriverLetter return FALSE.\n"));
//				Status = STATUS_UNSUCCESSFUL;
//
//				ExFreePool(EncryptFileInfo->LetterName.Buffer);
//				ExFreePool(EncryptFileInfo->Name.Buffer);
//				ExFreePool(EncryptFileInfo);
//				ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//				__leave;
//			}
//
//			RtlAppendUnicodeToString(&EncryptFileInfo->LetterName, L"\\??\\");
//			RtlAppendUnicodeToString(&EncryptFileInfo->LetterName, DriveLetter);
//			RtlAppendUnicodeToString(&EncryptFileInfo->LetterName, L":");
//			RtlAppendUnicodeStringToString(&EncryptFileInfo->LetterName, &PathNameInfo->FullFileName);
//
//			//DebugString(DEBUG_TRACE_SFSSup, "SFSSup!UpdateEncryptFileInfo -> LetterName = %s.\n", EncryptFileInfo->LetterName.Buffer);
//			////////////////////////////////////////////////////////////////////////////////////////////////////////////
//#if 1
//			if (FileInfo->bFileControlFlag)
//			{
//				if (FileInfo->bReadTimesFlag)
//				{
//					if (FileInfo->nReadTimes <= 0)
//					{
//						//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> FileInfo->nReadTimes == 0.\n"));
//						if (FileInfo->bSelfDestoryFlag)
//						{
//							//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> SelfDestory.\n"));
//							Status = STATUS_DELETE_PENDING;
//						}
//						else
//						{
//							Status = STATUS_UNSUCCESSFUL;
//						}
//
//						ExFreePool(EncryptFileInfo);
//						ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//						__leave;
//
//					}
//
//					if (FileInfo->nReadTimes > 0)
//					{
//						FileInfo->nReadTimes--;
//					}
//				}
//
//				if (FileInfo->bLifeCycleFlag)
//				{
//					TIME_FIELDS					BeginTimeFields;
//					TIME_FIELDS					EndTimeFields;
//					TIME_FIELDS					LastTimeFields;
//
//					LARGE_INTEGER               BeginTime;
//					LARGE_INTEGER               EndTime;
//					LARGE_INTEGER               LastTime;
//
//					unsigned int                nLastTime;
//
//					//nLastTime = CurrentTime();
//
//					nLastTime = nTime;
//
//					ConvertUT(&BeginTimeFields, FileInfo->nBeginTime);
//					ConvertUT(&EndTimeFields, FileInfo->nEndTime);
//					ConvertUT(&LastTimeFields, nLastTime);
//
//					RtlTimeFieldsToTime(&BeginTimeFields, &BeginTime);
//					RtlTimeFieldsToTime(&EndTimeFields, &EndTime);
//					RtlTimeFieldsToTime(&LastTimeFields, &LastTime);
//
//					if (LastTime.QuadPart < BeginTime.QuadPart
//						|| LastTime.QuadPart > EndTime.QuadPart)
//					{
//						//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> File is not life-cycle.\n"));
//						if (FileInfo->bSelfDestoryFlag && LastTime.QuadPart > EndTime.QuadPart)
//						{
//							//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateEncryptFileInfo -> SelfDestory.\n"));
//							Status = STATUS_DELETE_PENDING;
//						}
//						else
//						{
//							Status = STATUS_UNSUCCESSFUL;
//						}
//
//						ExFreePool(EncryptFileInfo);
//						ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//						__leave;
//					}
//
//				}
//
//				nRet = EncryptFileHeadSelf(EncryptIo, FileInfo, Buffer, BLOCK_SIZE, DataLen);
//				if (nRet != ISAFE_STATUS_SUCCESS)
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> EncryptFileHeadSelf Status = %x.\n", nRet));
//					ExFreePool(EncryptFileInfo);
//					ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//					Status = STATUS_UNSUCCESSFUL;
//					__leave;
//				}
//
//				Status = IrpWriteFile(RealFsDevice, RealFileObject, Buffer, BLOCK_SIZE, &Offset, 0, NULL);
//				if (!NT_SUCCESS(Status))
//				{
//					//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> IrpWriteFile Fail. 0x%08x\n", Status));
//					ExFreePool(EncryptFileInfo);
//					ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//					__leave;
//				}
//
//			}
//#endif
//			InsertHeadList(&ProcessInfo->EncryptFileList, &EncryptFileInfo->ListEntry);
//		}
//
//		EncryptFileInfo->RealFsDevice = RealFsDevice;
//		EncryptFileInfo->bFileControlFlag = FileInfo->bFileControlFlag;
//		EncryptFileInfo->nUserID = FileInfo->nUserID;
//		EncryptFileInfo->nNodeID_1 = FileInfo->nNodeID_1;
//		EncryptFileInfo->nNodeID_2 = FileInfo->nNodeID_2;
//		EncryptFileInfo->nNodeID_3 = FileInfo->nNodeID_3;
//		EncryptFileInfo->nNodeID_4 = FileInfo->nNodeID_4;
//
//		EncryptFileInfo->bGroupOnlyFlag = FileInfo->bGroupOnlyFlag;
//		EncryptFileInfo->bModifyFlag = FileInfo->bModifyFlag;
//		EncryptFileInfo->bCopyFlag = FileInfo->bCopyFlag;
//		EncryptFileInfo->bPrintFlag = FileInfo->bPrintFlag;
//		EncryptFileInfo->bPrintTimesFlag = FileInfo->bPrintTimesFlag;
//		EncryptFileInfo->bReadTimesFlag = FileInfo->bReadTimesFlag;
//		EncryptFileInfo->bLifeCycleFlag = FileInfo->bLifeCycleFlag;
//		EncryptFileInfo->nPrintTimes = FileInfo->nPrintTimes;
//		EncryptFileInfo->nReadTimes = FileInfo->nReadTimes;
//		EncryptFileInfo->nBeginTime = FileInfo->nBeginTime;
//		EncryptFileInfo->nEndTime = FileInfo->nEndTime;
//		EncryptFileInfo->bFileCrcFlag = FileInfo->bFileCrcFlag;
//		EncryptFileInfo->bModifyAuthFlag = FileInfo->bModifyAuthFlag;
//		EncryptFileInfo->bSelfDestoryFlag = FileInfo->bSelfDestoryFlag;
//		EncryptFileInfo->bPasswordFlag = FileInfo->bPasswordFlag;
//
//
//		ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//
//
//
//
//		if (FileInfo->bFileControlFlag)
//		{
//			Status = IrpQueryInformationFile(IrpContext->RealFsDevice, IrpContext->RealFileObject, &FileBaseInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
//
//			if (!NT_SUCCESS(Status))
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> IrpQueryInformationFile Fail. 0x%08x\n", Status));
//				__leave;
//			}
//
//			if (!FileInfo->bCopyFlag)
//			{
//				ProcessInfo->IsOpenedNoCopyFile = TRUE;
//			}
//
//			if (!FileInfo->bModifyFlag)
//			{
//				ProcessInfo->IsOpenedOnlyFile = TRUE;
//				if (!FlagOn(FileBaseInfo.FileAttributes, FILE_ATTRIBUTE_READONLY))
//				{
//					FileBaseInfo.FileAttributes |= FILE_ATTRIBUTE_READONLY;
//					Status = IrpSetInformationFile(IrpContext->RealFsDevice, IrpContext->RealFileObject, &FileBaseInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
//					if (!NT_SUCCESS(Status))
//					{
//						//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> IrpSetInformationFile Fail. 0x%08x\n", Status));
//						__leave;
//					}
//				}
//			}
//			else
//			{
//				if (FlagOn(FileBaseInfo.FileAttributes, FILE_ATTRIBUTE_READONLY))
//				{
//					FileBaseInfo.FileAttributes &= ~FILE_ATTRIBUTE_READONLY;
//					Status = IrpSetInformationFile(IrpContext->RealFsDevice, IrpContext->RealFileObject, &FileBaseInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
//					if (!NT_SUCCESS(Status))
//					{
//						//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateEncryptFileInfo -> IrpSetInformationFile Fail. 0x%08x\n", Status));
//						__leave;
//					}
//				}
//			}
//
//		}
//
//		Status = STATUS_SUCCESS;
//
//	}
//	__finally
//	{
//		if (Buffer)
//		{
//			ExFreePool(Buffer);
//		}
//
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//	}
//
//	return Status;
//
//
//}


//NTSTATUS WriteEncryptFileInfo(IN PIRP_CONTEXT IrpContext, UNICODE_STRING Name)
//{
//	NTSTATUS                        Status = STATUS_UNSUCCESSFUL;
//	PPATH_NAME_INFORMATION			PathNameInfo = NULL;
//	PPROCESS_INFO                   ProcessInfo;
//	PFILE_INFO                      EncryptFileInfo;
//	tagFileInfo			        	*FileInfo = NULL;
//	PDEVICE_OBJECT	        		RealFsDevice;
//	PFILE_OBJECT	        		RealFileObject;
//	int						        Ret;
//	PUCHAR		        			TempBuffer = NULL;
//	LARGE_INTEGER		        	Offset;
//	PFCB					        Fcb;
//	PENCRYPT_IO			        	EncryptIo;
//	unsigned int			        DataLen;
//
//	PathNameInfo = IrpContext->PathNameInfo;
//	RealFsDevice = IrpContext->RealFsDevice;
//	RealFileObject = IrpContext->RealFileObject;
//
//	DecodeFileObject(IrpContext->FileObject, NULL, &Fcb, NULL);
//
//	EncryptIo = &Fcb->EncryptIo;
//
//	if (!EncryptIo->Encrypt)
//	{
//		return Status;
//	}
//
//	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!WriteEncryptFileInfo -> Entry.\n"));
//
//	ExAcquireResourceExclusiveLite(&SFSData.ProcessInfoListResource, TRUE);
//
//	__try
//	{
//
//		ProcessInfo = FindProcessInfo(PsGetCurrentProcessId());
//		if (!ProcessInfo)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> ProcessInfo is null.\n"));
//			__leave;
//		}
//
//		EncryptFileInfo = FindEncryptFileInfo(ProcessInfo, Name);
//		if (!EncryptFileInfo)
//		{
//			if (!EncryptIo->FileControl)
//			{
//				__leave;
//			}
//
//			EncryptFileInfo = (PFILE_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_INFO), L'file');
//			if (!EncryptFileInfo)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> ExAllocatePoolWithTag is null.\n"));
//				__leave;
//			}
//			RtlZeroMemory(EncryptFileInfo, sizeof(FILE_INFO));
//
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!WriteEncryptFileInfo -> Name.MaximumLength = %d.\n", Name.MaximumLength));
//
//			EncryptFileInfo->Name.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, Name.MaximumLength, 'FILE');
//			if (!EncryptFileInfo->Name.Buffer)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> ExAllocatePoolWithTag Fail."));
//				ExFreePool(EncryptFileInfo);
//				__leave;
//			}
//
//			RtlCopyMemory(EncryptFileInfo->Name.Buffer, Name.Buffer, Name.MaximumLength);
//
//			EncryptFileInfo->Name.MaximumLength = Name.MaximumLength;
//			EncryptFileInfo->Name.Length = Name.Length;
//
//			InsertHeadList(&ProcessInfo->EncryptFileList, &EncryptFileInfo->ListEntry);
//			__leave;
//		}
//
//		FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//		if (!FileInfo)
//		{
//			Status = STATUS_INSUFFICIENT_RESOURCES;
//			__leave;
//		}
//
//		RtlZeroMemory(FileInfo, sizeof(tagFileInfo));
//
//
//		TempBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, L'temp');
//		if (!TempBuffer)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> ExAllocatePoolWithTag is null.\n"));
//			Status = STATUS_INSUFFICIENT_RESOURCES;
//			__leave;
//		}
//
//		RtlZeroMemory(TempBuffer, BLOCK_SIZE);
//
//		Offset.QuadPart = 0;
//		Status = IrpReadFile(RealFsDevice, RealFileObject, TempBuffer, BLOCK_SIZE, &Offset, NULL, NULL);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> IrpReadFile Status = %x.\n", Status));
//			__leave;
//		}
//
//		Ret = DecryptFileHeadSelf(EncryptIo, FileInfo, TempBuffer, BLOCK_SIZE, DataLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> DecryptFileHeadSelf Status = %x.\n", Ret));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//
//		FileInfo->bFileControlFlag = EncryptFileInfo->bFileControlFlag;
//		FileInfo->nUserID = EncryptFileInfo->nUserID;
//		FileInfo->nNodeID_1 = EncryptFileInfo->nNodeID_1;
//		FileInfo->nNodeID_2 = EncryptFileInfo->nNodeID_2;
//		FileInfo->nNodeID_3 = EncryptFileInfo->nNodeID_3;
//		FileInfo->nNodeID_4 = EncryptFileInfo->nNodeID_4;
//
//		FileInfo->bGroupOnlyFlag = EncryptFileInfo->bGroupOnlyFlag;
//		FileInfo->bModifyFlag = EncryptFileInfo->bModifyFlag;
//		FileInfo->bCopyFlag = EncryptFileInfo->bCopyFlag;
//		FileInfo->bPrintFlag = EncryptFileInfo->bPrintFlag;
//		FileInfo->bPrintTimesFlag = EncryptFileInfo->bPrintTimesFlag;
//		FileInfo->bReadTimesFlag = EncryptFileInfo->bReadTimesFlag;
//		FileInfo->bLifeCycleFlag = EncryptFileInfo->bLifeCycleFlag;
//		FileInfo->nPrintTimes = EncryptFileInfo->nPrintTimes;
//		FileInfo->nReadTimes = EncryptFileInfo->nReadTimes;
//		FileInfo->nBeginTime = EncryptFileInfo->nBeginTime;
//		FileInfo->nEndTime = EncryptFileInfo->nEndTime;
//
//		FileInfo->bFileCrcFlag = EncryptFileInfo->bFileCrcFlag;
//		FileInfo->bModifyAuthFlag = EncryptFileInfo->bModifyAuthFlag;
//		FileInfo->bSelfDestoryFlag = EncryptFileInfo->bSelfDestoryFlag;
//		FileInfo->bPasswordFlag = EncryptFileInfo->bPasswordFlag;
//
//		EncryptIo->Modify = EncryptFileInfo->bModifyFlag;
//		EncryptIo->LifeCycle = EncryptFileInfo->bLifeCycleFlag;
//		EncryptIo->FileControl = EncryptFileInfo->bFileControlFlag;
//
//
//
//
//		Ret = EncryptFileHeadSelf(EncryptIo, FileInfo, TempBuffer, BLOCK_SIZE, DataLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> EncryptFileHeadSelf Status = %x.\n", Ret));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		Status = IrpWriteFile(RealFsDevice, RealFileObject, TempBuffer, BLOCK_SIZE, &Offset, NULL, NULL);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!WriteEncryptFileInfo -> IrpWriteFile Status = %x.\n", Status));
//			__leave;
//		}
//	}
//	__finally
//	{
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//
//		if (TempBuffer)
//		{
//			ExFreePool(TempBuffer);
//		}
//
//		ExReleaseResourceLite(&SFSData.ProcessInfoListResource);
//	}
//
//	return Status;
//}


//NTSTATUS UpdateFileKey(IN PIRP_CONTEXT IrpContext, IN PFCB Fcb)
//{
//	NTSTATUS					Status = STATUS_SUCCESS;
//	int						    nRet;
//
//	PENCRYPT_IO					EncryptIo;
//	tagKeyItemNew                  Key;
//
//	EncryptIo = &Fcb->EncryptIo;
//
//	if (!EncryptIo->Encrypt)
//	{
//		return Status;
//	}
//
//	__try
//	{
//		Key.nKeyDegree = g_Config.m_Policy.UserAuth.nSecretDegree;
//
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateFileKey -> Key.nKeyDegree = %d.\n", Key.nKeyDegree));
//
//		nRet = GetKey(g_Config.m_TempPolicy.userConfig.keyList, Key);
//		if (nRet != ISAFE_STATUS_SUCCESS)
//		{
//			//	SendLogAudit(GenerateLogMsg(LOG_RESULT_FAILURE, LOG_OBJECT_FILE, L"获取迷药失败"));
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileKey -> GetKey Status = %x.\n", nRet));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		if (Key.nKey == EncryptIo->nKey)
//		{
//			__leave;
//		}
//
//		DecryptFile(IrpContext, 0);
//#if 0
//		nRet = InitKeys(Key.nKey, EncryptIo->EncryptKey, MAX_KEY_LEN, Key.nKeyLen);
//		if (nRet != ISAFE_STATUS_SUCCESS)
//		{
//			DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileKey -> InitKeys Status = %x.\n", nRet));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		EncryptIo->KeyIndex = Key.nKeyIndex;
//		EncryptIo->KeyLen = Key.nKeyLen;
//#endif
//		Status = EncryptFile(IrpContext);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileKey -> EncryptFile Status = %x.\n", Status));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateFileKey -> UpdateFileKey Completed.\n"));
//
//	}
//	__finally
//	{
//		NOTHING
//	}
//
//	return Status;
//}


//NTSTATUS UpdateFileCRC(PIRP_CONTEXT IrpContext)
//{
//	NTSTATUS					Status;
//	BOOLEAN						Result = FALSE;
//	int						    Ret;
//	LONGLONG					FileSize;
//	PFILE_OBJECT				RealFileObject;
//	PDEVICE_OBJECT              RealFsDevice;
//
//	PFCB                        Fcb;
//	PFSRTL_ADVANCED_FCB_HEADER	RealFcb;
//
//	PUCHAR						Buffer = NULL;
//	ULONG				    	Length;
//	ULONG					    ReturnLength;
//
//	unsigned int			    Crc;
//	unsigned int			    DataLen;
//	LARGE_INTEGER				Offset;
//	tagFileInfo 	        	*FileInfo = NULL;
//	PENCRYPT_IO					EncryptIo;
//
//
//	RealFsDevice = IrpContext->RealFsDevice;
//	RealFileObject = IrpContext->RealFileObject;
//	RealFcb = IrpContext->RealFcb;
//
//	DecodeFileObject(IrpContext->FileObject, NULL, &Fcb, NULL);
//
//	EncryptIo = &Fcb->EncryptIo;
//
//	if (!EncryptIo->Encrypt || !EncryptIo->Change || !EncryptIo->FileControl || !EncryptIo->FileCrc)
//	{
//		return STATUS_UNSUCCESSFUL;
//	}
//
//	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateFileCRC -> enter.\n"));
//
//	__try
//	{
//
//		FileSize = RealFcb->FileSize.QuadPart;
//
//		//     DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!UpdateFileCRC -> FileSize = %d, PageCount = %d, Remain = %d.\n", StandardInfo, PageCount, Remain));
//
//		Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, 'Btag');
//		if (!Buffer)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileCRC -> ExAllocatePoolWithTag is null.\n"));
//			__leave;
//		}
//
//		RtlZeroMemory(Buffer, BLOCK_SIZE);
//
//		FileSize -= BLOCK_SIZE;
//		Offset.QuadPart = BLOCK_SIZE;
//
//		Crc = 0xFFFFFFFF;
//
//		while (FileSize > 0)
//		{
//			if (FileSize >= BLOCK_SIZE)
//			{
//				Length = BLOCK_SIZE;
//			}
//			else
//			{
//				Length = FileSize;
//			}
//
//
//
//			Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, Length, &Offset, IRP_PAGING_IO | IRP_NOCACHE, &ReturnLength);
//			if (NT_SUCCESS(Status) && Length == ReturnLength)
//			{
//				CalcCrc32(Buffer, Length, Crc);
//
//			}
//			else
//			{
//				__leave;
//			}
//
//			FileSize -= Length;
//			Offset.QuadPart += Length;
//		}
//
//
//
//		FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//		if (!FileInfo)
//		{
//			Status = STATUS_INSUFFICIENT_RESOURCES;
//			__leave;
//		}
//		RtlZeroMemory(FileInfo, sizeof(tagFileInfo));
//
//
//		Offset.QuadPart = 0;
//		Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, BLOCK_SIZE, &Offset, IRP_PAGING_IO | IRP_NOCACHE, NULL);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileCRC -> IrpReadFile Status = %x.\n", Status));
//			__leave;
//		}
//
//		if (!IsEncryptBuffer(Buffer, BLOCK_SIZE))
//		{
//			//DebugTrace(DEBUG_TRACE_CREATE | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileCRC -> !IsEncryptBuffer.\n"));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//
//		Ret = DecryptFileHeadSelf(EncryptIo, FileInfo, Buffer, BLOCK_SIZE, DataLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileCRC -> DecryptFileHeadSelf Status = %x.\n", Ret));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		FileInfo->nFileCrc32 = Crc;
//
//		Ret = EncryptFileHeadSelf(EncryptIo, FileInfo, Buffer, BLOCK_SIZE, DataLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileCRC -> EncryptFileHeadSelf Status = %x.\n", Ret));
//			Status = STATUS_UNSUCCESSFUL;
//			__leave;
//		}
//
//		Status = IrpWriteFile(RealFsDevice, RealFileObject, Buffer, BLOCK_SIZE, &Offset, IRP_PAGING_IO | IRP_NOCACHE, NULL);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!UpdateFileCRC -> IrpWriteFile Status = %x.\n", Status));
//			__leave;
//		}
//
//
//		Status = STATUS_SUCCESS;
//
//	}
//	__finally
//	{
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//
//		if (Buffer)
//		{
//			ExFreePool(Buffer);
//		}
//
//	}
//	return Status;
//}



//NTSTATUS CheckFileCRC(PIRP_CONTEXT IrpContext, PFCB Fcb)
//{
//	NTSTATUS					Status = STATUS_SUCCESS;
//	BOOLEAN						Result = FALSE;
//	int						    Ret;
//	LONGLONG					FileSize;
//	PFILE_OBJECT				RealFileObject;
//	PDEVICE_OBJECT              RealFsDevice;
//
//	PFSRTL_ADVANCED_FCB_HEADER	RealFcb;
//
//	PUCHAR						Buffer = NULL;
//	ULONG				    	Length;
//	ULONG					    ReturnLength;
//
//	unsigned int			    Crc;
//	unsigned int			    DataLen;
//	LARGE_INTEGER				Offset;
//	tagFileInfo 	        	*FileInfo = NULL;
//	PENCRYPT_IO					EncryptIo;
//
//
//	RealFsDevice = IrpContext->RealFsDevice;
//	RealFileObject = IrpContext->RealFileObject;
//	RealFcb = IrpContext->RealFcb;
//
//	EncryptIo = &Fcb->EncryptIo;
//
//	if (!EncryptIo->Encrypt || !EncryptIo->FileControl || !EncryptIo->FileCrc)
//	{
//		return STATUS_SUCCESS;
//	}
//
//	//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!CheckFileCRC -> enter.\n"));
//
//	__try
//	{
//
//		FileSize = RealFcb->FileSize.QuadPart;
//
//		Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, 'Btag');
//		if (!Buffer)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckFileCRC -> ExAllocatePoolWithTag is null.\n"));
//			__leave;
//		}
//
//		RtlZeroMemory(Buffer, BLOCK_SIZE);
//
//
//		FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//		if (!FileInfo)
//		{
//			Status = STATUS_SUCCESS;
//			__leave;
//		}
//		RtlZeroMemory(FileInfo, sizeof(tagFileInfo));
//
//
//		Offset.QuadPart = 0;
//		Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, BLOCK_SIZE, &Offset, NULL, NULL);
//		if (!NT_SUCCESS(Status))
//		{
//			Status = STATUS_SUCCESS;
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckFileCRC -> IrpReadFile Status = %x.\n", Status));
//			__leave;
//		}
//
//		if (!IsEncryptBuffer(Buffer, BLOCK_SIZE))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckFileCRC -> !IsEncryptBuffer.\n"));
//			Status = STATUS_SUCCESS;
//			__leave;
//		}
//
//		Ret = GetFileHeadInfo(FileInfo, Buffer, BLOCK_SIZE);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckFileCRC -> GetFileHeadInfo Fail. 0x%08x\n", Ret));
//			Status = STATUS_SUCCESS;
//			__leave;
//		}
//
//		if (FileInfo->nFileCrc32 == 0)
//		{
//			Status = STATUS_SUCCESS;
//			__leave;
//		}
//
//
//		FileSize -= BLOCK_SIZE;
//		Offset.QuadPart = BLOCK_SIZE;
//
//		Crc = 0xFFFFFFFF;
//
//		while (FileSize > 0)
//		{
//			if (FileSize >= BLOCK_SIZE)
//			{
//				Length = BLOCK_SIZE;
//			}
//			else
//			{
//				Length = FileSize;
//			}
//
//			Status = IrpReadFile(RealFsDevice, RealFileObject, Buffer, Length, &Offset, NULL, &ReturnLength);
//			if (NT_SUCCESS(Status) && Length == ReturnLength)
//			{
//				CalcCrc32(Buffer, Length, Crc);
//				//        DebugTrace(DEBUG_TRACE_SFSSup|DEBUG_TRACE_ERROR, ("SFSSup!CheckFileCRC -> CRC. %u\n", Crc));
//			}
//			else
//			{
//				__leave;
//			}
//
//			FileSize -= Length;
//			Offset.QuadPart += Length;
//		}
//
//
//		//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!CheckFileCRC -> FileInfo->nFileCrc32 = %x, Crc = %x.\n", FileInfo->nFileCrc32, Crc));
//
//		if (FileInfo->nFileCrc32 == Crc)
//		{
//			Status = STATUS_SUCCESS;
//			__leave;
//		}
//
//		Status = STATUS_UNSUCCESSFUL;
//
//	}
//	__finally
//	{
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//
//		if (Buffer)
//		{
//			ExFreePool(Buffer);
//		}
//
//	}
//	return Status;
//}


VOID UnicodeToAnsi(IN PCHAR AnsiBuf, IN PWCHAR UnicodeBuf)
{
	ANSI_STRING AnsiString;
	UNICODE_STRING UnicodeString;

	RtlInitEmptyAnsiString(&AnsiString, AnsiBuf, MAX_PATH);

	RtlInitUnicodeString(&UnicodeString, UnicodeBuf);

	RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, FALSE);
}


//VOID ClearSFSFcbCache(IN PCFLT_RELATED_OBJECTS FltObjects, IN PPATH_NAME_INFORMATION PathNameInfo)
//{
//    NTSTATUS Status;
//    PDEVICE_OBJECT MiniFsDevice	= NULL;
//    PFS_DEVICE_OBJECT FsDeviceObject;
//    PDEVICE_INFO_NODE Node;
//    PVCB Vcb = NULL;
//    PFCB Fcb;
//
//    Status = FltGetDeviceObject(FltObjects->Volume, &MiniFsDevice);
//
//    if(!NT_SUCCESS(Status)) 
//    {
//        DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!FltGetDeviceObject Fail. 0x%08x\n" , Status));
//        return;
//    }
//
//    __try
//    {
//
//        Node = GetDeviceInfoForMiniFsDevice(MiniFsDevice);
//        if (!Node)
//        {
//            __leave;
//        }
//
//        FsDeviceObject = Node->FsDevice;
//        Vcb = &FsDeviceObject->Vcb;
//
//        ExAcquireResourceExclusiveLite(&Vcb->Resource, TRUE);
//
//        Fcb = GetFcbFromVcbList(Vcb, PathNameInfo->FullFileName);
//        if (!Fcb)
//        {
//            ExReleaseResourceLite(&Vcb->Resource);
//            __leave;
//        }
//        CreateInClearFcbCache(Fcb); //   RemoveFcbFromVcbList(Vcb, Fcb);
//
//        ExReleaseResourceLite(&Vcb->Resource);
//
//    }
//    __finally
//    {
//        if (MiniFsDevice)
//        {
//            ObDereferenceObject(MiniFsDevice);
//        }
//    }
//}


//BOOLEAN IsNetworkVolume(PFLT_VOLUME Volume)
//{
//    NTSTATUS Status;
//    PDEVICE_OBJECT MiniFsDevice	= NULL;
//    PFS_DEVICE_OBJECT FsDeviceObject;
//    PDEVICE_INFO_NODE Node;
//
//    Status = FltGetDeviceObject(Volume, &MiniFsDevice);
//
//    if(!NT_SUCCESS(Status)) 
//    {
//        DebugTrace(DEBUG_TRACE_ERROR, ("SFSSup!IsNetworkVolume Fail. 0x%08x\n" , Status));
//        return FALSE;
//    }
//
//    __try
//    {
//
//        Node = GetDeviceInfoForMiniFsDevice(MiniFsDevice);
//        if (!Node)
//        {
//            __leave;
//        }
//
//        FsDeviceObject = Node->FsDevice;
//
//        if (FsDeviceObject->DeviceObject.DeviceType &FILE_DEVICE_NETWORK_FILE_SYSTEM)
//        {
//            return TRUE;
//        }
//       
//    }
//    __finally
//    {
//        if (MiniFsDevice)
//        {
//            ObDereferenceObject(MiniFsDevice);
//        }
//    }
//
//    return FALSE;
//}

BOOLEAN CheckFileControl(PFILE_OBJECT FileObject)
{
	PFCB Fcb;

	if (!FileObject)
	{
		return FALSE;
	}

	DecodeFileObject(FileObject, NULL, &Fcb, NULL);

	if (!Fcb)
	{
		return FALSE;
	}

	if (Fcb->EncryptIo.FileControl)
	{
		return TRUE;
	}

	return FALSE;
}


//BOOLEAN CheckNoModify(IN PFILE_OBJECT FileObject, IN PFLT_INSTANCE Instance)
//{
//	NTSTATUS					Status;
//	BOOLEAN                     Result = FALSE;
//
//	PWCHAR                      FileNameBuf = NULL;
//
//	LARGE_INTEGER				FileOffset = { 0, 0 };
//	ULONG                       BytesRead;
//
//	PUCHAR						Buffer = NULL;
//
//	LARGE_INTEGER				Offset;
//	tagFileInfo*                FileInfo = NULL;
//
//	int						    Ret;
//
//	PENCRYPT_IO					EncryptIo = NULL;
//
//	tagKeyItemNew				Key;
//
//	unsigned int			    DataLen;
//
//	BOOLEAN                     IsMatch = FALSE;
//
//	__try
//	{
//
//		Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, 'Btag');
//		if (!Buffer)
//		{
//			__leave;
//		}
//
//		RtlZeroMemory(Buffer, BLOCK_SIZE);
//
//
//		FileInfo = (tagFileInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(tagFileInfo), L'file');
//		if (!FileInfo)
//		{
//			__leave;
//		}
//		RtlZeroMemory(FileInfo, sizeof(tagFileInfo));
//
//
//		Offset.QuadPart = 0;
//		Status = FltReadFile(Instance, FileObject, &Offset, BLOCK_SIZE, Buffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BytesRead, NULL, NULL);
//		if (!NT_SUCCESS(Status))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> IrpReadFile Status = %x.\n", Status));
//			__leave;
//		}
//
//		if (BytesRead < FILEHEAD_INFO_LEN)
//		{
//			__leave;
//		}
//
//		if (!IsEncryptBuffer(Buffer, BLOCK_SIZE))
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> !IsEncryptBuffer.\n"));
//			__leave;
//		}
//
//
//		EncryptIo = (ENCRYPT_IO*)ExAllocatePoolWithTag(NonPagedPool, sizeof(ENCRYPT_IO), L'ency');
//		if (!EncryptIo)
//		{
//			__leave;
//		}
//		RtlZeroMemory(EncryptIo, sizeof(ENCRYPT_IO));
//
//		Ret = GetFileHeadInfo(FileInfo, Buffer, BLOCK_SIZE);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> GetFileHeadInfo Fail. 0x%08x\n", Ret));
//			__leave;
//		}
//
//		Ret = GetKeyByKeyIndex(g_Config.m_TempPolicy.userConfig.keyList, FileInfo->nKeyIndex, Key);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> GetKeyByKeyIndex Fail. 0x%08x\n", Ret));
//			__leave;
//		}
//
//		Ret = InitKeys(Key.nKey, EncryptIo->EncryptKey, MAX_KEY_LEN, Key.nKeyLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> InitKeys Fail. 0x%08x\n", Ret));
//			__leave;
//		}
//
//		EncryptIo->KeyLen = Key.nKeyLen;
//		EncryptIo->KeyIndex = FileInfo->nKeyIndex;
//		EncryptIo->Encrypt = TRUE;
//
//
//		Ret = DecryptFileHeadSelf(EncryptIo, FileInfo, Buffer, BLOCK_SIZE, DataLen);
//		if (Ret != ISAFE_STATUS_SUCCESS)
//		{
//			//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!CheckPrint -> DecryptFileHeadSelf Status = %x.\n", Ret));
//			__leave;
//		}
//
//		if (FileInfo->bFileControlFlag && !FileInfo->bModifyFlag)
//		{
//			Result = TRUE;
//			__leave;
//		}
//
//
//	}
//	__finally
//	{
//		if (EncryptIo)
//		{
//			ExFreePool(EncryptIo);
//		}
//
//		if (FileInfo)
//		{
//			ExFreePool(FileInfo);
//		}
//
//		if (Buffer)
//		{
//			ExFreePool(Buffer);
//		}
//	}
//
//	return Result;
//}


/*
* 文件重命名、移动位置
*/
//BOOLEAN CheckRenameFile(IN PFILE_RENAME_INFORMATION RenameInfo, IN PFLT_FILE_NAME_INFORMATION OriginalFileNameInfo)
//{
//	BOOLEAN         Result = FALSE;
//	PWCHAR          NewFileNameBuf = NULL;
//	PWCHAR          OriginalFileNameBuf = NULL;
//	ULONG           OriginalFileNameLength = 0;
//	UNICODE_STRING  NewFileName;
//	UNICODE_STRING  OriginalFileName;
//
//
//	OriginalFileNameLength = OriginalFileNameInfo->Share.Length + OriginalFileNameInfo->ParentDir.Length + sizeof(WCHAR);
//
//	__try
//	{
//
//		NewFileNameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, RenameInfo->FileNameLength + sizeof(WCHAR), 'newf');
//		if (!NewFileNameBuf)
//		{
//			__leave;
//		}
//
//		RtlZeroMemory(NewFileNameBuf, RenameInfo->FileNameLength + sizeof(WCHAR));
//		RtlCopyMemory(NewFileNameBuf, RenameInfo->FileName, RenameInfo->FileNameLength);
//
//		OriginalFileNameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, OriginalFileNameLength, 'newf');
//		if (!OriginalFileNameBuf)
//		{
//			__leave;
//		}
//
//		RtlZeroMemory(OriginalFileNameBuf, OriginalFileNameLength);
//
//		RtlInitEmptyUnicodeString(&OriginalFileName, OriginalFileNameBuf, OriginalFileNameLength);
//		RtlInitEmptyUnicodeString(&NewFileName, NewFileNameBuf, RenameInfo->FileNameLength + sizeof(WCHAR));
//
//		RtlUnicodeStringCat(&OriginalFileName, &OriginalFileNameInfo->Share);
//		RtlUnicodeStringCat(&OriginalFileName, &OriginalFileNameInfo->ParentDir);
//
//		//wcsncmp(NewFileNameBuf, L"\\??\\", wcslen(L"\\??\\") == 0))
//		if (NewFileNameBuf[0] == L'\\' &&
//			NewFileNameBuf[1] == L'?' &&
//			NewFileNameBuf[2] == L'?' &&
//			NewFileNameBuf[3] == L'\\')
//		{
//			NewFileName.Buffer += wcslen(L"\\??\\");
//			NewFileName.Buffer = wcschr(NewFileName.Buffer, L'\\');
//			NewFileName.Length = wcslen(NewFileName.Buffer) * sizeof(WCHAR);
//			NewFileName.Length -= wcslen(wcsrchr(NewFileName.Buffer, L'\\')) * sizeof(WCHAR);
//			NewFileName.Length += sizeof(WCHAR);
//
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!CheckRenameFile -> NewFileName. %S\n", NewFileName.Buffer));
//			//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!CheckRenameFile -> OriginalFileName. %S\n", OriginalFileName.Buffer));
//
//			if (RtlCompareUnicodeString(&OriginalFileName, &NewFileName, TRUE) == 0)
//			{
//				//DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!CheckRenameFile -> Same Dir\n"));
//				Result = TRUE;
//			}
//		}
//
//	}
//	__finally
//	{
//		if (NewFileNameBuf)
//		{
//			ExFreePool(NewFileNameBuf);
//		}
//
//		if (OriginalFileNameBuf)
//		{
//			ExFreePool(OriginalFileNameBuf);
//		}
//	}
//
//	return Result;
//}

/*
 *	ip转Hex;
 *  123.124.125.126 转为 7B 7C 7D 7E
 */
void IP2Hex(char *ipString, unsigned char ipHex[4]) {
	int ipLen = strlen(ipString) + 1;
	char *hex = new char[ipLen];
	memcpy(hex, ipString, ipLen);
	char *index = hex;
	int count = 0;
	while (*index) {
		if ('.' == *index) {
			count++;
			*index = 0;
		}
		index++;
	}

	index = hex;
	if (3 == count) {
		ipHex[0] = p_strtod(index, &index);
		index++;
		ipHex[1] = p_strtod(index, &index);
		index++;
		ipHex[2] = p_strtod(index, &index);
		index++;
		ipHex[3] = p_strtod(index, NULL);
	}
	else {
		*(int *)ipHex = 0;
	}
	delete hex;
}

NTSTATUS QuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
) {

	OBJECT_ATTRIBUTES oa = { 0 };
	NTSTATUS status = 0;
	HANDLE handle = NULL;

	InitializeObjectAttributes(&oa, SymbolicLinkName, OBJ_CASE_INSENSITIVE, 0, 0);

	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	LinkTarget->MaximumLength = MAX_PATH * sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, 'SOD');
	if (!LinkTarget->Buffer) {
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);

	if (!NT_SUCCESS(status)) {
		ExFreePool(LinkTarget->Buffer);
	}
	return status;
}

NTSTATUS MyRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING	DeviceName,
	OUT PUNICODE_STRING	DosName
) {
	NTSTATUS		status = 0;
	UNICODE_STRING	driveLetterName = { 0 };
	WCHAR			driveLetterNameBuf[128] = { 0 };
	WCHAR			c = L'\0';
	WCHAR			DriLetter[3] = { 0 };
	UNICODE_STRING	linkTarget = { 0 };

	for (c = L'A'; c <= L'Z'; c++) {
		RtlInitEmptyUnicodeString(&driveLetterName, driveLetterNameBuf, sizeof(driveLetterNameBuf));
		RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
		DriLetter[0] = c;
		DriLetter[1] = L':';
		DriLetter[2] = 0;
		RtlAppendUnicodeToString(&driveLetterName, DriLetter);

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);

		if (!NT_SUCCESS(status)) {
			continue;
		}

		//DebugTrace(DEBUG_TRACE_DEBUG, ("--------------------%wZ---%wZ-------", &linkTarget, DeviceName));

		if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE)) {
			ExFreePool(linkTarget.Buffer);
			break;
		}

		ExFreePool(linkTarget.Buffer);
	}
	if (c <= L'Z') {
		DosName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, 3 * sizeof(WCHAR), 'SOD');
		if (!DosName->Buffer) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DosName->MaximumLength = 6;
		DosName->Length = 4;
		*DosName->Buffer = c;
		*(DosName->Buffer + 1) = ':';
		*(DosName->Buffer + 2) = 0;
		return STATUS_SUCCESS;
	}
	return status;
}

// \\Device\\HarddiskVolume1\\*** -> C:\***
BOOLEAN NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName) {
	UNICODE_STRING ustrFileName = { 0 };
	UNICODE_STRING ustrDosName = { 0 };
	UNICODE_STRING ustrDeviceName = { 0 };

	WCHAR			*pPath = NULL;
	ULONG			i = 0;
	ULONG			ulSepNum = 0;

	if (wszFileName == NULL ||
		wszNTName == NULL ||
		_wcsnicmp(wszNTName, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume")) != 0)
	{
		return FALSE;
	}

	ustrFileName.Buffer = wszFileName;
	ustrFileName.Length = 0;
	ustrFileName.MaximumLength = sizeof(WCHAR) * MAX_PATH;

	while (wszNTName[i] != L'\0') {
		if (wszNTName[i] == L'\0') {
			break;
		}
		if (wszNTName[i] == L'\\') {
			ulSepNum++;
		}
		if (ulSepNum == 3) {
			wszNTName[i] = UNICODE_NULL;
			pPath = &wszNTName[i + 1];
			break;
		}
		i++;
	}

	if (pPath == NULL) {
		return FALSE;
	}

	RtlInitUnicodeString(&ustrDeviceName, wszNTName);

	if (!NT_SUCCESS(RtlVolumeDeviceToDosName(&ustrDeviceName, &ustrDosName))) {
		return FALSE;
	}

	RtlCopyUnicodeString(&ustrFileName, &ustrDosName);
	RtlAppendUnicodeToString(&ustrFileName, L"\\");
	RtlAppendUnicodeToString(&ustrFileName, pPath);

	ExFreePool(ustrDosName.Buffer);

	return TRUE;
}

BOOLEAN NTAPI GetNTLinkNameU(PUNICODE_STRING NTName, WCHAR *wszFileName) {
	UNICODE_STRING ustrFileName = { 0 };
	UNICODE_STRING ustrDosName = { 0 };
	UNICODE_STRING ustrDeviceName = { 0 };
	WCHAR			wszNTNameBuf[MAX_PATH];
	WCHAR			*pPath = NULL;
	ULONG			i = 0;
	ULONG			ulSepNum = 0;

	RtlInitEmptyUnicodeString(&ustrDeviceName, wszNTNameBuf, sizeof(WCHAR) * MAX_PATH);
	RtlCopyUnicodeString(&ustrDeviceName, NTName);

	if (wszFileName == NULL ||
		NTName == NULL ||
		NTName->Buffer == NULL ||
		_wcsnicmp(NTName->Buffer, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume")) != 0)
	{
		return FALSE;
	}

	ustrFileName.Buffer = wszFileName;
	ustrFileName.Length = 0;
	ustrFileName.MaximumLength = sizeof(WCHAR) * MAX_PATH;

	while (ustrDeviceName.Buffer[i] != L'\0') {
		if (i>ustrDeviceName.Length  || ustrDeviceName.Buffer[i] == L'\0') {
			break;
		}
		if (ustrDeviceName.Buffer[i] == L'\\') {
			ulSepNum++;
		}
		if (ulSepNum == 3) {
			ustrDeviceName.Buffer[i] = UNICODE_NULL;
			pPath = &ustrDeviceName.Buffer[i + 1];
			ustrDeviceName.Length = i * sizeof(WCHAR);
			break;
		}
		i++;
	}

	if (pPath == NULL) {
		return FALSE;
	}

	if (!NT_SUCCESS(MyRtlVolumeDeviceToDosName(&ustrDeviceName, &ustrDosName))) {
		return FALSE;
	}
	RtlCopyUnicodeString(&ustrFileName, &ustrDosName);
	RtlAppendUnicodeToString(&ustrFileName, L"\\");
	RtlAppendUnicodeToString(&ustrFileName, pPath);

	ExFreePool(ustrDosName.Buffer);

	return TRUE;
}