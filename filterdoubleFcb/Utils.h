#pragma once
#ifndef __UTILS_INCLUDED
#define __UTILS_INCLUDED

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "Struct.h"

typedef struct _FILE_HEAD {
	char fileTag[5];
	char warning[200];
	INT key;
	int openCount;
} FILE_HEAD, *PFILE_HEAD;

VOID GenerateUUID(CHAR UUID[UUID_LEN], INT random);
int UUIDToString(CHAR szInBuffer[UUID_LEN], char* szOutBuffer);
//PUNICODE_STRING GetProcNameByEproc (IN PEPROCESS pEproc);
//BOOLEAN GetEProcessNameOffset();
//PCHAR GetCurrentProcessName();
//BOOLEAN CheckProcess(PCHAR ProcessName);
NTSTATUS FileSetSize(
	IN PFLT_CALLBACK_DATA Data,
	IN PCFLT_RELATED_OBJECTS FltObjects,
	IN PLARGE_INTEGER FileSize);

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
	);
VOID
ReleasePathNameInformation(
	PPATH_NAME_INFORMATION PathNameInformation
	);

BOOLEAN
GetFullFilePath(
	IN PFILE_OBJECT FileObject,
	OUT PPATH_NAME_INFORMATION *PathNameInfo
	);

BOOLEAN
GetFullFilePathForDevice(
	IN PFILE_OBJECT FileObject,
	IN PDEVICE_OBJECT Device,
	OUT PUNICODE_STRING Name
	);

BOOLEAN
GetSFSFullFilePath(
	OUT PWCHAR FullFilePath,
	IN PPATH_NAME_INFORMATION PathNameInfo
	);

PIRP
IsIrpTopLevel(
	IN PIRP Irp
	);
VOID
ClearCache(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER ByteOffset,
	IN ULONG ByteCount
	);

VOID
SFSFlushFile(
	IN PFCB Fcb
	);

VOID
SFSFlushFileObject(
	IN PFILE_OBJECT FileObject
	);

NTSTATUS
CallLowerDriverIoCompletion(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context
	);

NTSTATUS
CallLowerDriver(
	IN PIRP_CONTEXT IrpContext
	);

VOID
BalanceObject(
	IN PIRP Irp,
	IN PFILE_OBJECT SFSFileObject,
	IN PFILE_OBJECT RealFileObject,
	IN NTSTATUS Status
	);

VOID BalanceObjectFlags(IN ULONG Flags,
	IN PFILE_OBJECT SFSFileObject,
	IN PFILE_OBJECT RealFileObject,
	IN NTSTATUS Status);

NTSTATUS
CallRealFsDriver(
	IN PIRP_CONTEXT IrpContext
	);

BOOLEAN
UpdateFileObject(
	IN OUT PFILE_OBJECT FileObject,
	IN PFILE_OBJECT RealFileObject
	);

PFILE_OBJECT
GetRealFileObject(
	IN PFILE_OBJECT FileObject
	);

VOID
FreeRealFileObject(
	IN PFILE_OBJECT FileObject
	);

BOOLEAN
IsStreamFile(
	IN UNICODE_STRING FileName
	);

BOOLEAN
IsSFSFileObject(
	IN PFILE_OBJECT FileObject
	);

ULONG
ExceptionFilter(
	IN PIRP_CONTEXT IrpContext,
	IN PEXCEPTION_POINTERS ExceptionPointer
	);

VOID
FreeIrpContext(
	IN PIRP_CONTEXT IrpContext
	);

VOID
CompleteRequest(
	IN PIRP_CONTEXT IrpContext OPTIONAL,
	IN PIRP Irp OPTIONAL,
	IN NTSTATUS Status
	);

PIRP_CONTEXT
CreateIrpContext(
	IN PIRP Irp,
	IN BOOLEAN Wait
	);

NTSTATUS
CallRealFsDevice(
	IN PFS_DEVICE_OBJECT FsDeviceObject,
	IN PIRP Irp
	);

TYPE_OF_OPEN
DecodeFileObject(
	IN PFILE_OBJECT FileObject,
	OUT PVCB *Vcb,
	OUT PFCB *Fcb,
	OUT PCCB *Ccb
	);

RTL_GENERIC_COMPARE_RESULTS
GenericCompareRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID FirstStruct,
	IN PVOID SecondStruct
	);

PVOID
GenericAllocateRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN CLONG ByteSize
	);

VOID
GenericFreeRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID Buffer
	);

BOOLEAN IsFilterExtName(UNICODE_STRING Path);

VOID ClearFcbCacheFromVcbList(IN PVCB Vcb);

VOID CreateInClearFcbCache(IN PFCB Fcb);

NTSTATUS GetSymbolicLink(IN PUNICODE_STRING SymbolicLinkName, OUT PUNICODE_STRING LinkValue);

BOOLEAN IsBackupDirVolume(IN UNICODE_STRING VolumePath);

BOOLEAN GetDriveLetter(IN PUNICODE_STRING VolumeName, OUT PWCHAR DriveLetter);

VOID GetBackupFileName(IN PUNICODE_STRING DestFileName, IN PPATH_NAME_INFORMATION PathNameInfo);

BOOLEAN GetBackupFileInfo(IN UNICODE_STRING BackupFileName, OUT PLARGE_INTEGER Time, OUT PLARGE_INTEGER FileSize);

NTSTATUS DeleteFile(IN PDEVICE_OBJECT DeviceObject, IN UNICODE_STRING FileName);

BOOLEAN BackupCopyFile(IN UNICODE_STRING DestFileName, IN PIRP_CONTEXT IrpContext);

VOID BackupFile(IN PIRP_CONTEXT IrpContext);

NTSTATUS CreateBackupDir(IN UNICODE_STRING DirectoryName);

VOID CreateBackupDirAll(IN UNICODE_STRING PathName);

BOOLEAN  MatchWithPattern(PWCHAR Pattern, PWCHAR Name);

EXTERN_C NTSTATUS
ZwQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

NTSTATUS DecryptFileBuffer(PUCHAR Buffer, ULONG Length, PIO_CONTEXT IoContext);

NTSTATUS EncryptFileBuffer(PUCHAR Buffer, ULONG Length, IN PIRP Irp, PIO_CONTEXT IoContext);

NTSTATUS EncryptFile(PIRP_CONTEXT IrpContext);

VOID DecryptFile(PIRP_CONTEXT IrpContext, ULONGLONG DecryptLength);

VOID
AddToWorkque(
	IN PIRP_CONTEXT IrpContext,
	IN PIRP Irp
	);

VOID
PrePostIrp(
	IN PVOID Context,
	IN PIRP Irp
	);

BOOLEAN
AcquireExclusiveFcb(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
	);

BOOLEAN
AcquireSharedFcbWaitForEx(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
	);

BOOLEAN
AcquireSharedFcb(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
	);

VOID
LookupFileAllocationSize(
	IN PIRP_CONTEXT IrpContext,
	IN PFCB Fcb
	);

NTSTATUS
NonCachedIoWrite(
	IN PIRP_CONTEXT IrpContext,
	IN PIRP Irp,
	IN PLARGE_INTEGER StartingByte,
	IN ULONGLONG ByteCount
	);

NTSTATUS
FsdPostRequest(
	IN PIRP_CONTEXT IrpContext,
	IN PIRP Irp
	);


VOID DeleteFileObject(PFILE_OBJECT FileObject);


BOOLEAN FindSubString(UNICODE_STRING Str, PWCHAR SubStr);

BOOLEAN CheckExt(PWCHAR Str, PWCHAR Ext);

BOOLEAN CheckRelatedProcess();

BOOLEAN CheckRelatedProcessByID(HANDLE nProcessID);

BOOLEAN CheckEncryptPolicy(UNICODE_STRING Name);

BOOLEAN CheckGlobalEncryptPolicy(UNICODE_STRING Name);

BOOLEAN CheckProcessSign(PPROCESS_INFO ProcessInfo);

VOID RemoveEncryptFileInfo(PPROCESS_INFO ProcessInfo);

PFILE_INFO FindEncryptFileInfo(PPROCESS_INFO ProcessInfo, UNICODE_STRING Name);

NTSTATUS WriteEncryptFileInfo(IN PIRP_CONTEXT IrpContext, UNICODE_STRING Name);

NTSTATUS UpdateFileKey(IN PIRP_CONTEXT IrpContext, IN PFCB Fcb);

NTSTATUS UpdateEncryptFileInfo(IN PIRP_CONTEXT IrpContext, IN PFCB Fcb);

NTSTATUS UpdateFileCRC(PIRP_CONTEXT IrpContext);

NTSTATUS CheckFileCRC(PIRP_CONTEXT IrpContext, PFCB Fcb);

VOID UnicodeToAnsi(IN PCHAR AnsiBuf, IN PWCHAR UnicodeBuf);

BOOLEAN IsExsitFileA(PCHAR FileName);

BOOLEAN IsSystemUserProcess();

//VOID ClearSFSFcbCache(IN PCFLT_RELATED_OBJECTS FltObjects, IN PPATH_NAME_INFORMATION PathNameInfo);

//BOOLEAN IsNetworkVolume(PFLT_VOLUME Volume);

BOOLEAN CheckBackupDirAccess(PPATH_NAME_INFORMATION PathNameInfo);

PGLOBAL_ENCRYPT_FILE FindGlobalEncryptFile(PWCHAR Name);

BOOLEAN IsExistGlobalEncryptFile(IN PWCHAR Name);

VOID InsertEncryptFile(IN PDEVICE_OBJECT RealFsDevice, IN PPATH_NAME_INFORMATION PathNameInfo);

VOID SFSFlushCache(IN PFILE_OBJECT FileObject, IN PLARGE_INTEGER ByteOffset, IN ULONG ByteCount);

BOOLEAN CheckFileControl(PFILE_OBJECT FileObject);

BOOLEAN CheckRenameFile(IN PFILE_RENAME_INFORMATION RenameInfo, IN PFLT_FILE_NAME_INFORMATION OriginalFileNameInfo);

BOOLEAN CheckNoModify(IN PFILE_OBJECT FileObject, IN PFLT_INSTANCE Instance);

//BOOLEAN CheckDirAccess(IN PFLT_FILE_NAME_INFORMATION FileNameInfo, IN PWCHAR ProtectDir);

//PWCHAR GenerateLogMsg(PWCHAR LogObject, PWCHAR LogResult, PWCHAR LogDetails);

PWCHAR GenerateLogMsg(PWCHAR LogObject, PWCHAR LogResult, PWCHAR MsgFmt, ...);

/*
*	ipתHex;
*  123.124.125.126 תΪ 7B 7C 7D 7E
*/
void IP2Hex(char *ipString, unsigned char ipHex[4]);

int BinToHex(PCHAR szInBuffer, int len, char* szOutBuffer);

NTSTATUS QuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
);

NTSTATUS MyRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING	DeviceName,
	OUT PUNICODE_STRING	DosName
);

// \\Device\\HarddiskVolume1\\*** -> C:\***
BOOLEAN NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName);
BOOLEAN NTAPI GetNTLinkNameU(PUNICODE_STRING NTName, WCHAR *wszFileName);

#endif