/**
 * @file sys/mup.c
 *
 * @copyright 2015-2019 Bill Zissimopoulos
 */
/*
 * This file is part of WinFsp.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 3 as published by the Free Software
 * Foundation.
 *
 * Licensees holding a valid commercial license may use this software
 * in accordance with the commercial license agreement provided in
 * conjunction with the software.  The terms and conditions of any such
 * commercial license agreement shall govern, supersede, and render
 * ineffective any application of the GPLv3 license to this software,
 * notwithstanding of any reference thereto in the software or
 * associated repository.
 */

//#include <sys/driver.h>

#include "mup.h"
#include "fspyKern.h"
#include <wdmsec.h>
/*
 * FSP_MUP_PREFIX_CLASS
 *
 * Define the following macro to claim "class" prefixes during prefix
 * resolution. A "class" prefix is of the form \ClassName. The alternative
 * is a "full" prefix, which is of the form \ClassName\InstanceName.
 *
 * Claiming a class prefix has advantages and disadvantages. The main
 * advantage is that by claiming a \ClassName prefix, paths such as
 * \ClassName\IPC$ will be handled by WinFsp, thus speeding up prefix
 * resolution for all \ClassName prefixed names. The disadvantage is
 * it is no longer possible for WinFsp and another redirector to handle
 * instances ("shares") under the same \ClassName prefix.
 */
#define FSP_MUP_PREFIX_CLASS



//PVOID FspAllocatePoolMustSucceed(POOL_TYPE PoolType, SIZE_T Size, ULONG Tag)
//{
//	// !PAGED_CODE();
//
//	PVOID Result;
//	LARGE_INTEGER Delay;
//
//	for (ULONG i = 0, n = sizeof(Delays) / sizeof(Delays[0]);; i++)
//	{
//		Result = DEBUGTEST(99) ? ExAllocatePoolWithTag(PoolType, Size, Tag) : 0;
//		if (0 != Result)
//			return Result;
//
//		Delay.QuadPart = n > i ? Delays[i] : Delays[n - 1];
//		KeDelayExecutionThread(KernelMode, FALSE, &Delay);
//	}
//}


/* IoCreateDeviceSecure default SDDL's */
#define FSP_FSCTL_DEVICE_SDDL           "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)"
	/* System:GENERIC_ALL, Administrators:GENERIC_ALL, World:GENERIC_READ */
#define FSP_FSVRT_DEVICE_SDDL           "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;WD)"
	/* System:GENERIC_ALL, Administrators:GENERIC_ALL, World:GENERIC_READ|GENERIC_EXECUTE */

/* private NTSTATUS codes */
#define FSP_STATUS_PRIVATE_BIT          (0x20000000)
#define FSP_STATUS_IGNORE_BIT           (0x10000000)
#define FSP_STATUS_IOQ_POST             (FSP_STATUS_PRIVATE_BIT | 0x0000)
#define FSP_STATUS_IOQ_POST_BEST_EFFORT (FSP_STATUS_PRIVATE_BIT | 0x0001)

/* misc macros */
#define FSP_ALLOC_INTERNAL_TAG          'IpsF'
#define FSP_ALLOC_EXTERNAL_TAG          'XpsF'
#define FSP_IO_INCREMENT                IO_NETWORK_INCREMENT


PDRIVER_OBJECT FspDriverObject = NULL;
/* memory allocation */
#define FspAlloc(Size)                  ExAllocatePoolWithTag(PagedPool, Size, FSP_ALLOC_INTERNAL_TAG)
#define FspAllocNonPaged(Size)          ExAllocatePoolWithTag(NonPagedPool, Size, FSP_ALLOC_INTERNAL_TAG)
//#define FspAllocMustSucceed(Size)       FspAllocatePoolMustSucceed(PagedPool, Size, FSP_ALLOC_INTERNAL_TAG)
#define FspFree(Pointer)                ExFreePoolWithTag(Pointer, FSP_ALLOC_INTERNAL_TAG)
#define FspAllocExternal(Size)          ExAllocatePoolWithTag(PagedPool, Size, FSP_ALLOC_EXTERNAL_TAG)
#define FspAllocNonPagedExternal(Size)  ExAllocatePoolWithTag(NonPagedPool, Size, FSP_ALLOC_EXTERNAL_TAG)
#define FspFreeExternal(Pointer)        ExFreePool(Pointer)

static NTSTATUS FspMupGetClassName(
    PUNICODE_STRING Prefix, PUNICODE_STRING ClassName);
NTSTATUS FspMupRegister(
    PDEVICE_OBJECT FsmupDeviceObject, PDEVICE_OBJECT FsvolDeviceObject);
VOID FspMupUnregister(
    PDEVICE_OBJECT FsmupDeviceObject, PDEVICE_OBJECT FsvolDeviceObject);
NTSTATUS FspMupHandleIrp(
    PDEVICE_OBJECT FsmupDeviceObject, PIRP Irp);
static NTSTATUS FspMupRedirQueryPathEx(
    PDEVICE_OBJECT FsmupDeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FspMupGetClassName)
#pragma alloc_text(PAGE, FspMupRegister)
#pragma alloc_text(PAGE, FspMupUnregister)
#pragma alloc_text(PAGE, FspMupHandleIrp)
#pragma alloc_text(PAGE, FspMupRedirQueryPathEx)
#endif

typedef struct _FSP_MUP_CLASS
{
    LONG RefCount;
    UNICODE_STRING Name;
    UNICODE_PREFIX_TABLE_ENTRY Entry;
    WCHAR Buffer[];
} FSP_MUP_CLASS;


BOOLEAN
IsFspFileObjectHasOurFCB(
	IN PFILE_OBJECT pFileObject
)
{

	BOOLEAN b = FALSE;

	b = (pFileObject && (pFileObject->FsContext) && ((PPfpFCB)pFileObject->FsContext)->Header.NodeTypeCode == -32768);

	return b;

}

NTSTATUS FspDeviceCreateSecure(UINT32 Kind, ULONG ExtraSize,
	PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics,
	PUNICODE_STRING DeviceSddl, LPCGUID DeviceClassGuid,
	PDEVICE_OBJECT* PDeviceObject)
{
	PAGED_CODE();

	NTSTATUS Result;
	ULONG DeviceExtensionSize;
	PDEVICE_OBJECT DeviceObject;
	FSP_DEVICE_EXTENSION* DeviceExtension;

	*PDeviceObject = 0;

	switch (Kind)
	{
	case FspFsvolDeviceExtensionKind:
		DeviceExtensionSize = sizeof(FSP_FSVOL_DEVICE_EXTENSION);
		break;
	case FspFsmupDeviceExtensionKind:
		DeviceExtensionSize = sizeof(FSP_FSMUP_DEVICE_EXTENSION);
		break;
	case FspFsvrtDeviceExtensionKind:
	case FspFsctlDeviceExtensionKind:
		DeviceExtensionSize = sizeof(FSP_DEVICE_EXTENSION);
		break;
	default:
		ASSERT(0);
		return STATUS_INVALID_PARAMETER;
	}

	if (0 != DeviceSddl)
		Result = IoCreateDeviceSecure(FspDriverObject,
			DeviceExtensionSize + ExtraSize, DeviceName, DeviceType,
			DeviceCharacteristics, FALSE,
			DeviceSddl, DeviceClassGuid,
			&DeviceObject);
	else
		Result = IoCreateDevice(FspDriverObject,
			DeviceExtensionSize + ExtraSize, DeviceName, DeviceType,
			DeviceCharacteristics, FALSE,
			&DeviceObject);
	if (!NT_SUCCESS(Result))
		return Result;

	DeviceExtension = FspDeviceExtension(DeviceObject);
	KeInitializeSpinLock(&DeviceExtension->SpinLock);
	DeviceExtension->RefCount = 1;
	DeviceExtension->Kind = Kind;

	*PDeviceObject = DeviceObject;

	return Result;
}


static NTSTATUS FspMupGetClassName(
    PUNICODE_STRING VolumePrefix, PUNICODE_STRING ClassName)
{
    PAGED_CODE();

    RtlZeroMemory(ClassName, sizeof *ClassName);

    if (L'\\' == VolumePrefix->Buffer[0])
        for (PWSTR P = VolumePrefix->Buffer + 1,
            EndP = VolumePrefix->Buffer + VolumePrefix->Length / sizeof(WCHAR);
            EndP > P; P++)
        {
            if (L'\\' == *P)
            {
                ClassName->Buffer = VolumePrefix->Buffer;
                ClassName->Length = (USHORT)((P - ClassName->Buffer) * sizeof(WCHAR));
                ClassName->MaximumLength = ClassName->Length;
                return STATUS_SUCCESS;
            }
        }

    return STATUS_INVALID_PARAMETER;
}

VOID FspDeviceDelete(PDEVICE_OBJECT DeviceObject)
{
	PAGED_CODE();

	FSP_DEVICE_EXTENSION* DeviceExtension = FspDeviceExtension(DeviceObject);

	switch (DeviceExtension->Kind)
	{
		//清理扩展内存,这里我先不清理,这系统太复杂了
	case FspFsvolDeviceExtensionKind:
		//FspFsvolDeviceFini(DeviceObject);
		break;
	case FspFsmupDeviceExtensionKind:
		//FspFsmupDeviceFini(DeviceObject);
		break;
	case FspFsvrtDeviceExtensionKind:
	case FspFsctlDeviceExtensionKind:
		break;
	default:
		ASSERT(0);
		return;
	}

#if DBG
#pragma prefast(suppress:28175, "Debugging only: ok to access DeviceObject->Size")
	RtlFillMemory(&DeviceExtension->Kind,
		(PUINT8)DeviceObject + DeviceObject->Size - (PUINT8)& DeviceExtension->Kind, 0xBD);
#endif

	IoDeleteDevice(DeviceObject);
}

VOID FspDeviceDereference(PDEVICE_OBJECT DeviceObject)
{
	// !PAGED_CODE();

	BOOLEAN Delete = FALSE;
	FSP_DEVICE_EXTENSION* DeviceExtension;
	KIRQL Irql;

	DeviceExtension = FspDeviceExtension(DeviceObject);
	KeAcquireSpinLock(&DeviceExtension->SpinLock, &Irql);
	if (0 != DeviceExtension->RefCount)
	{
		DeviceExtension->RefCount--;
		Delete = 0 == DeviceExtension->RefCount;
	}
	KeReleaseSpinLock(&DeviceExtension->SpinLock, Irql);

	if (Delete)
		FspDeviceDelete(DeviceObject);
}

BOOLEAN FspDeviceReference(PDEVICE_OBJECT DeviceObject)
{
	// !PAGED_CODE();

	BOOLEAN Result;
	FSP_DEVICE_EXTENSION* DeviceExtension;
	KIRQL Irql;

	DeviceExtension = FspDeviceExtension(DeviceObject);
	KeAcquireSpinLock(&DeviceExtension->SpinLock, &Irql);
	Result = 0 != DeviceExtension->RefCount;
	if (Result)
		DeviceExtension->RefCount++;
	KeReleaseSpinLock(&DeviceExtension->SpinLock, Irql);

	return Result;
}


NTSTATUS FspMupRegister(
    PDEVICE_OBJECT FsmupDeviceObject, PDEVICE_OBJECT FsvolDeviceObject)
{
    PAGED_CODE();

    NTSTATUS Result;
    BOOLEAN Success;
    FSP_FSMUP_DEVICE_EXTENSION *FsmupDeviceExtension = FspFsmupDeviceExtension(FsmupDeviceObject);
    FSP_FSVOL_DEVICE_EXTENSION *FsvolDeviceExtension = FspFsvolDeviceExtension(FsvolDeviceObject);
    PUNICODE_PREFIX_TABLE_ENTRY ClassEntry;
    UNICODE_STRING ClassName;
    FSP_MUP_CLASS *Class = 0;

    Result = FspMupGetClassName(&FsvolDeviceExtension->VolumePrefix, &ClassName);
    ASSERT(NT_SUCCESS(Result));

    Class = FspAlloc(sizeof *Class + ClassName.Length);
    if (0 == Class)
    {
        Result = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    RtlZeroMemory(Class, sizeof *Class);
    Class->RefCount = 1;
    Class->Name.Length = ClassName.Length;
    Class->Name.MaximumLength = ClassName.MaximumLength;
    Class->Name.Buffer = Class->Buffer;
    RtlCopyMemory(Class->Buffer, ClassName.Buffer, ClassName.Length);

    ExAcquireResourceExclusiveLite(&FsmupDeviceExtension->PrefixTableResource, TRUE);
    Success = RtlInsertUnicodePrefix(&FsmupDeviceExtension->PrefixTable,
        &FsvolDeviceExtension->VolumePrefix, &FsvolDeviceExtension->VolumePrefixEntry);
    if (Success)
    {
        FspDeviceReference(FsvolDeviceObject);

        ClassEntry = RtlFindUnicodePrefix(&FsmupDeviceExtension->ClassTable,
            &Class->Name, 0);
        if (0 == ClassEntry)
        {
            Success = RtlInsertUnicodePrefix(&FsmupDeviceExtension->ClassTable,
                &Class->Name, &Class->Entry);
            ASSERT(Success);
            Class = 0;
        }
        else
            CONTAINING_RECORD(ClassEntry, FSP_MUP_CLASS, Entry)->RefCount++;

        Result = STATUS_SUCCESS;
    }
    else
        Result = STATUS_OBJECT_NAME_COLLISION;
    ExReleaseResourceLite(&FsmupDeviceExtension->PrefixTableResource);

exit:
    if (0 != Class)
        FspFree(Class);

    return Result;
}

VOID FspMupUnregister(
    PDEVICE_OBJECT FsmupDeviceObject, PDEVICE_OBJECT FsvolDeviceObject)
{
    PAGED_CODE();

    NTSTATUS Result;
    FSP_FSMUP_DEVICE_EXTENSION *FsmupDeviceExtension = FspFsmupDeviceExtension(FsmupDeviceObject);
    FSP_FSVOL_DEVICE_EXTENSION *FsvolDeviceExtension = FspFsvolDeviceExtension(FsvolDeviceObject);
    PUNICODE_PREFIX_TABLE_ENTRY PrefixEntry;
    PUNICODE_PREFIX_TABLE_ENTRY ClassEntry;
    UNICODE_STRING ClassName;
    FSP_MUP_CLASS *Class;

    Result = FspMupGetClassName(&FsvolDeviceExtension->VolumePrefix, &ClassName);
    ASSERT(NT_SUCCESS(Result));

    ExAcquireResourceExclusiveLite(&FsmupDeviceExtension->PrefixTableResource, TRUE);
    PrefixEntry = RtlFindUnicodePrefix(&FsmupDeviceExtension->PrefixTable,
        &FsvolDeviceExtension->VolumePrefix, 0);
    if (0 != PrefixEntry)
    {
        RtlRemoveUnicodePrefix(&FsmupDeviceExtension->PrefixTable,
            &FsvolDeviceExtension->VolumePrefixEntry);
        FspDeviceDereference(FsvolDeviceObject);

        ClassEntry = RtlFindUnicodePrefix(&FsmupDeviceExtension->ClassTable,
            &ClassName, 0);
        if (0 != ClassEntry)
        {
            Class = CONTAINING_RECORD(ClassEntry, FSP_MUP_CLASS, Entry);
            if (0 == --Class->RefCount)
            {
                RtlRemoveUnicodePrefix(&FsmupDeviceExtension->ClassTable,
                    ClassEntry);
                FspFree(Class);
            }
        }
    }
    ExReleaseResourceLite(&FsmupDeviceExtension->PrefixTableResource);
}

NTSTATUS FspMupHandleIrp(
    PDEVICE_OBJECT FsmupDeviceObject, PIRP Irp)
{
    PAGED_CODE();

    FSP_FSMUP_DEVICE_EXTENSION *FsmupDeviceExtension = FspFsmupDeviceExtension(FsmupDeviceObject);
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PDEVICE_OBJECT FsvolDeviceObject = 0;
    PUNICODE_PREFIX_TABLE_ENTRY PrefixEntry;
    BOOLEAN DeviceDeref = FALSE;
    NTSTATUS Result;

    FsRtlEnterFileSystem();

    switch (IrpSp->MajorFunction)
    {
    case IRP_MJ_CREATE:
        /*
         * A CREATE request with an empty file name indicates that the fsmup device
         * is being opened. Check for this case and handle it.
         */
        if (0 == FileObject->FileName.Length)
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = FILE_OPENED;
            IoCompleteRequest(Irp, FSP_IO_INCREMENT);
            Result = Irp->IoStatus.Status;
            goto exit;
        }

        /*
         * Every other CREATE request must be forwarded to the appropriate fsvol device.
         */

        if (0 != FileObject->RelatedFileObject)
            FileObject = FileObject->RelatedFileObject;

        ExAcquireResourceExclusiveLite(&FsmupDeviceExtension->PrefixTableResource, TRUE);
        PrefixEntry = RtlFindUnicodePrefix(&FsmupDeviceExtension->PrefixTable,
            &FileObject->FileName, 0);
        if (0 != PrefixEntry)
        {
            FsvolDeviceObject = CONTAINING_RECORD(PrefixEntry,
                FSP_FSVOL_DEVICE_EXTENSION, VolumePrefixEntry)->FsvolDeviceObject;
            FspDeviceReference(FsvolDeviceObject);
            DeviceDeref = TRUE;
        }
        ExReleaseResourceLite(&FsmupDeviceExtension->PrefixTableResource);
        break;

    case IRP_MJ_DEVICE_CONTROL:
        /*
         * A DEVICE_CONTROL request with IOCTL_REDIR_QUERY_PATH_EX must be handled
         * by the fsmup device. Check for this case and handle it.
         */
        if (IOCTL_REDIR_QUERY_PATH_EX == IrpSp->Parameters.DeviceIoControl.IoControlCode)
        {
            Irp->IoStatus.Status = FspMupRedirQueryPathEx(FsmupDeviceObject, Irp, IrpSp);
            IoCompleteRequest(Irp, FSP_IO_INCREMENT);
            Result = Irp->IoStatus.Status;
            goto exit;
        }

        /*
         * Every other DEVICE_CONTROL request must be forwarded to the appropriate fsvol device.
         */

        /* fall through! */

    default:
        /*
         * Every other request must be forwarded to the appropriate fsvol device. If there is no
         * fsvol device, then we must return the appropriate status code (see below).
         *
         * Please note that since we allow the fsmup device to be opened, we must also handle
         * CLEANUP and CLOSE requests for it.
         */

        /*if (0 != FileObject)
        {
            if (FspFileNodeIsValid(FileObject->FsContext))
                FsvolDeviceObject = ((FSP_FILE_NODE *)FileObject->FsContext)->FsvolDeviceObject;
            else if (0 != FileObject->FsContext2 &&
                3 == ((PDEVICE_OBJECT)FileObject->FsContext2)->Type &&
                0 != ((PDEVICE_OBJECT)FileObject->FsContext2)->DeviceExtension &&
                FspFsvolDeviceExtensionKind == FspDeviceExtension((PDEVICE_OBJECT)FileObject->FsContext2)->Kind)
                FsvolDeviceObject = (PDEVICE_OBJECT)FileObject->FsContext2;
        }*/
		if (0 != FileObject)
		{
			if (IsFspFileObjectHasOurFCB(FileObject))
			{
				FsvolDeviceObject = ((PPfpFCB*)FileObject->FsContext)->FsvolDeviceObject;
			}else if (0 != FileObject->FsContext2 &&
				3 == ((PDEVICE_OBJECT)FileObject->FsContext2)->Type &&
				0 != ((PDEVICE_OBJECT)FileObject->FsContext2)->DeviceExtension &&
				FspFsvolDeviceExtensionKind == FspDeviceExtension((PDEVICE_OBJECT)FileObject->FsContext2)->Kind)
				FsvolDeviceObject = (PDEVICE_OBJECT)FileObject->FsContext2;
		}


		//这里判断是否是我们的Fake_fcb

        break;
    }

    if (0 == FsvolDeviceObject)
    {
        /*
         * We were not able to find an fsvol device to forward this IRP to. We will complete
         * the IRP with an appropriate status code.
         */

        switch (IrpSp->MajorFunction)
        {
        case IRP_MJ_CREATE:
            /*
             * For CREATE requests we return STATUS_BAD_NETWORK_PATH. Here is why.
             *
             * When a file \ClassName\InstanceName\Path is opened by an application, this request
             * first goes to MUP. The MUP gives DFS a first chance to handle the request and if
             * that fails the MUP proceeds with prefix resolution. The DFS attempts to open the
             * file \ClassName\IPC$, this results in a prefix resolution for \ClassName\IPC$
             * through a recursive MUP call! If this resolution fails the DFS returns to the MUP,
             * which now attempts prefix resolution for \ClassName\InstanceName\Path.
             *
             * Under the new fsmup design we respond to IOCTL_REDIR_QUERY_PATH_EX by handling all
             * paths with a \ClassName prefix (that we know). This way we ensure that we will get
             * all opens for paths with a \ClassName prefix and avoid delays for requests of
             * \ClassName\IPC$, which if left unhandled will be forwarded to all network
             * redirectors.
             *
             * In order to successfully short-circuit requests for \ClassName\IPC$ we must also
             * return STATUS_BAD_NETWORK_PATH in CREATE. This makes DFS think that prefix
             * resolution failed and does not complain if it cannot open \ClassName\IPC$. Other
             * error codes cause DFS to completely fail the open issued by the application.
             */
            Irp->IoStatus.Status = STATUS_BAD_NETWORK_PATH;
            break;
		case IRP_MJ_READ:
			if (NULL != FileObject)
			{

			}

			break;
		case IRP_MJ_WRITE:
			if (NULL != FileObject)
			{

			}
			break;
        case IRP_MJ_CLEANUP:
        case IRP_MJ_CLOSE:
            /*
             * CLEANUP and CLOSE requests ignore their status code (except for STATUS_PENDING).
             * So return STATUS_SUCCESS. This works regardless of whether this is a legitimate
             * fsmup request or an erroneous CLOSE request that we should not have seen.
             */
            Irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        case IRP_MJ_QUERY_INFORMATION:
        case IRP_MJ_SET_INFORMATION:
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
        default:
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }

        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, FSP_IO_INCREMENT);
        Result = Irp->IoStatus.Status;
        goto exit;
    }

    ASSERT(FspFsvolDeviceExtensionKind == FspDeviceExtension(FsvolDeviceObject)->Kind);

    /*
     * Forward the IRP to the appropriate fsvol device. The fsvol device will take care
     * to complete the IRP, etc.
     */
    IoSkipCurrentIrpStackLocation(Irp);
	//直接通知我们的设备对象
    Result = IoCallDriver(FsvolDeviceObject, Irp);

    if (DeviceDeref)
        FspDeviceDereference(FsvolDeviceObject);

exit:
    FsRtlExitFileSystem();

    return Result;
}

static NTSTATUS FspMupRedirQueryPathEx(
    PDEVICE_OBJECT FsmupDeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    PAGED_CODE();

    ASSERT(IRP_MJ_DEVICE_CONTROL == IrpSp->MajorFunction);
    ASSERT(IOCTL_REDIR_QUERY_PATH_EX == IrpSp->Parameters.DeviceIoControl.IoControlCode);

    Irp->IoStatus.Information = 0;

    if (KernelMode != Irp->RequestorMode)
        return STATUS_INVALID_DEVICE_REQUEST;

    /* check parameters */
    ULONG InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    QUERY_PATH_REQUEST_EX *QueryPathRequest = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    QUERY_PATH_RESPONSE *QueryPathResponse = Irp->UserBuffer;
    if (sizeof(QUERY_PATH_REQUEST_EX) > InputBufferLength ||
        0 == QueryPathRequest || 0 == QueryPathResponse)
        return STATUS_INVALID_PARAMETER;
    if (sizeof(QUERY_PATH_RESPONSE) > OutputBufferLength)
        return STATUS_BUFFER_TOO_SMALL;

    NTSTATUS Result;
    FSP_FSMUP_DEVICE_EXTENSION *FsmupDeviceExtension = FspFsmupDeviceExtension(FsmupDeviceObject);
    PUNICODE_PREFIX_TABLE_ENTRY Entry;

#if defined(FSP_MUP_PREFIX_CLASS)
    UNICODE_STRING ClassName;

    Result = FspMupGetClassName(&QueryPathRequest->PathName, &ClassName);
    if (!NT_SUCCESS(Result))
        return STATUS_BAD_NETWORK_PATH;

    Result = STATUS_BAD_NETWORK_PATH;
    ExAcquireResourceExclusiveLite(&FsmupDeviceExtension->PrefixTableResource, TRUE);
    Entry = RtlFindUnicodePrefix(&FsmupDeviceExtension->ClassTable, &ClassName, 0);
    if (0 != Entry)
    {
        QueryPathResponse->LengthAccepted = ClassName.Length;
        Result = STATUS_SUCCESS;
    }
    ExReleaseResourceLite(&FsmupDeviceExtension->PrefixTableResource);
#else
    FSP_FSVOL_DEVICE_EXTENSION *FsvolDeviceExtension;

    Result = STATUS_BAD_NETWORK_PATH;
    ExAcquireResourceExclusiveLite(&FsmupDeviceExtension->PrefixTableResource, TRUE);
    Entry = RtlFindUnicodePrefix(&FsmupDeviceExtension->PrefixTable,
        &QueryPathRequest->PathName, 0);
    if (0 != Entry)
    {
        FsvolDeviceExtension = CONTAINING_RECORD(Entry, FSP_FSVOL_DEVICE_EXTENSION, VolumePrefixEntry);
        if (!FspIoqStopped(FsvolDeviceExtension->Ioq))
        {
            if (0 < FsvolDeviceExtension->VolumePrefix.Length &&
                FspFsvolDeviceVolumePrefixInString(
                    FsvolDeviceExtension->FsvolDeviceObject, &QueryPathRequest->PathName) &&
                (QueryPathRequest->PathName.Length == FsvolDeviceExtension->VolumePrefix.Length ||
                    '\\' == QueryPathRequest->PathName.Buffer[FsvolDeviceExtension->VolumePrefix.Length / sizeof(WCHAR)]))
            {
                QueryPathResponse->LengthAccepted = FsvolDeviceExtension->VolumePrefix.Length;
                Result = STATUS_SUCCESS;
            }
        }
    }
    ExReleaseResourceLite(&FsmupDeviceExtension->PrefixTableResource);
#endif

    return Result;
}


NTSTATUS FspDeviceCreateSecure(UINT32 Kind, ULONG ExtraSize,
	PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics,
	PUNICODE_STRING DeviceSddl, LPCGUID DeviceClassGuid,
	PDEVICE_OBJECT* PDeviceObject)
{
	PAGED_CODE();

	NTSTATUS Result;
	ULONG DeviceExtensionSize;
	PDEVICE_OBJECT DeviceObject;
	FSP_DEVICE_EXTENSION* DeviceExtension;

	*PDeviceObject = 0;

	switch (Kind)
	{
	case FspFsvolDeviceExtensionKind:
		DeviceExtensionSize = sizeof(FSP_FSVOL_DEVICE_EXTENSION);
		break;
	case FspFsmupDeviceExtensionKind:
		DeviceExtensionSize = sizeof(FSP_FSMUP_DEVICE_EXTENSION);
		break;
	case FspFsvrtDeviceExtensionKind:
	case FspFsctlDeviceExtensionKind:
		DeviceExtensionSize = sizeof(FSP_DEVICE_EXTENSION);
		break;
	default:
		ASSERT(0);
		return STATUS_INVALID_PARAMETER;
	}

	if (0 != DeviceSddl)
		Result = IoCreateDeviceSecure(FspDriverObject,
			DeviceExtensionSize + ExtraSize, DeviceName, DeviceType,
			DeviceCharacteristics, FALSE,
			DeviceSddl, DeviceClassGuid,
			&DeviceObject);
	else
		Result = IoCreateDevice(FspDriverObject,
			DeviceExtensionSize + ExtraSize, DeviceName, DeviceType,
			DeviceCharacteristics, FALSE,
			&DeviceObject);
	if (!NT_SUCCESS(Result))
		return Result;

	DeviceExtension = FspDeviceExtension(DeviceObject);
	KeInitializeSpinLock(&DeviceExtension->SpinLock);
	DeviceExtension->RefCount = 1;
	DeviceExtension->Kind = Kind;

	*PDeviceObject = DeviceObject;

	return Result;
}

NTSTATUS FspDeviceCreate(UINT32 Kind, ULONG ExtraSize,
	DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics,
	PDEVICE_OBJECT* PDeviceObject)
{
	PAGED_CODE();

	return FspDeviceCreateSecure(Kind, ExtraSize, 0, DeviceType, DeviceCharacteristics,
		0, 0, PDeviceObject);
}