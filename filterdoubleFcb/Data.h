#pragma once
#ifndef __DATA_INCLUDED
#define __DATA_INCLUDED

#include <fltKernel.h>
#include "Struct.h"

#define MAX_DELAYED_CLOSES         ((ULONG)16)
#define MAX_COM_NUM 32
//  Data
typedef struct _SFS_DATA
{
	UNICODE_STRING			PortName; //通讯端口名

	PFLT_PORT				ServerPort; //驱动端通讯端口
	PFLT_PORT				ClientPort; //客户端通讯端口

	UNICODE_STRING			ScanPortName; //扫描识别端口，用于服务端在局域网内扫描设备

	PFLT_PORT				ScanServerPort; //
	PFLT_PORT				ScanClientPort; //

	PSECURITY_DESCRIPTOR	SecurityDescriptor;
	OBJECT_ATTRIBUTES		ObjectAttr;

	NODE_TYPE_CODE			NodeTypeCode;
	NODE_BYTE_SIZE			NodeByteSize;

	PDRIVER_OBJECT			DriverObject; //当前驱动对象
	PDEVICE_OBJECT			FileSystemDeviceObject;
	FAST_IO_DISPATCH		FsdFastIoDispatch;
	PFLT_FILTER				FilterHandle;
	PEPROCESS				CurrentProcess;

	BOOLEAN					ShutdownStarted; //即将关闭
	BOOLEAN					AsyncCloseActive; //

	BOOLEAN					HighAsync;
	BOOLEAN					HighDelayed;

	KSPIN_LOCK              GeneralSpinLock;

	LIST_ENTRY				VcbQueue;

	ULONG					AsyncCloseCount;
	LIST_ENTRY				AsyncCloseList;

	ULONG					DelayedCloseCount;
	LIST_ENTRY				DelayedCloseList;
	ULONG					MaxDelayedCloseCount;

	PIO_WORKITEM			CloseItem;
	ERESOURCE				Resource;
	FAST_MUTEX				CloseQueueMutex;

	PIO_WORKITEM			EncryptItem;
	ULONGLONG               EncryptWorkerCount;
	LIST_ENTRY				EncryptFileList;
	ERESOURCE				EncryptFileListResource;
	KEVENT                  EncryptCompletedEvent;

	RTL_GENERIC_TABLE		FileCtxTable;
	FAST_MUTEX				FileCtxTableMutex;

	//LIST_ENTRY				DeviceInfoList;
	//ERESOURCE				DeviceInfoListResource;

	LIST_ENTRY				ProcessInfoList;
	ERESOURCE				ProcessInfoListResource;

	BOOLEAN                 WorkModeFlag;  //模式
	BOOLEAN                 OnlineFlag;  //是否在线

	PVOID                   LazyWriteThread;

	CACHE_MANAGER_CALLBACKS CacheManagerCallbacks;
	CACHE_MANAGER_CALLBACKS CacheManagerNoOpCallbacks;

	PDEVICE_OBJECT tcpDevObjReal;
	PDEVICE_OBJECT tcpDevObjFlt;
	PDEVICE_OBJECT udpDevObjReal;
	PDEVICE_OBJECT udpDevObjFlt;
	PDEVICE_OBJECT ComDevObjFlt[MAX_COM_NUM];
	PDEVICE_OBJECT ComDevObjReal[MAX_COM_NUM];
}SFS_DATA, *PSFS_DATA;



typedef struct  _reprocessInfo
{
	LIST_ENTRY ProcessInfoList;
	ULONG pid;
	wchar_t *PName;
	ULONG Crc;
}ReprocessInfo, *PReprocessInfo;

extern PCHAR	ImportFunName;
extern CHAR	DllNameStr[MAX_PATH];
extern CHAR	DllNameStr64[MAX_PATH];

extern WCHAR BackupDriveLetter[MAX_PATH];
extern WCHAR BackupDir[MAX_PATH];

//extern PWCHAR BackupDriveLetter;
//extern PWCHAR BackupDir;

extern WCHAR SystemRootDriveLetter[10];
extern WCHAR SystemRootPathName[MAX_PATH];

extern WCHAR PolicyPath[MAX_PATH];
extern WCHAR DriverPath[MAX_PATH];

extern int nTime;

extern SFS_DATA SFSData;

// System Function
//extern ZwWriteVirtualMemoryType					pZwProtectVirtualMemory;
//extern ZwProtectVirtualMemoryType					pZwProtectVirtualMemory;
//extern FsRtlRegisterFileSystemFilterCallbacksType	pFsRtlRegisterFileSystemFilterCallbacks;
//extern IoAttachDeviceToDeviceStackSafeType			pIoAttachDeviceToDeviceStackSafe;
//extern IoEnumerateDeviceObjectListType				pIoEnumerateDeviceObjectList;
//extern IoGetLowerDeviceObjectType					pIoGetLowerDeviceObject;
//extern IoGetDeviceAttachmentBaseRefType				pIoGetDeviceAttachmentBaseRef;
//extern IoGetDiskDeviceObjectType					pIoGetDiskDeviceObject;
//extern IoGetAttachedDeviceReferenceType				pIoGetAttachedDeviceReference;
//extern RtlGetVersionType							pRtlGetVersion;
//extern ObCreateObjectType							pObCreateObject;
//extern PsRemoveLoadImageNotifyRoutineType			pPsRemoveLoadImageNotifyRoutine;
//extern ZwQueryInformationProcess					pZwQueryInformationProcess;

#ifdef __cplusplus
extern "C" {
#endif

	//NTSTATUS			IoSuccessCompleteRequest(PIRP Irp);
	//VOID				DeviceInfoListInit();
	//BOOLEAN				IsExsitDeviceInfoForMiniFsDevice(IN PVOID Object);
	//PDEVICE_INFO_NODE	GetDeviceInfoForMiniFsDevice(IN PVOID Object);
	//PDEVICE_INFO_NODE   GetDeviceInfoForRealDiskDevice(IN PVOID Object);
	//
	//VOID 
	//AddDeviceInfo(	
	//			  PDEVICE_OBJECT MiniFsDevice,
	//			  PFS_DEVICE_OBJECT FsDevice,
	//			  PDEVICE_OBJECT Device,
	//			  PDEVICE_OBJECT RealDevice 
	//			 );
	//
	//VOID				RemoveDeviceInfo(IN PVOID Object);
	//VOID                RemoveDeviceInfoForRealDiskDevice(IN PVOID Object);
	BOOLEAN				IsExistFcbFromVcbList(IN PVCB Vcb, IN PFCB Fcb);
	PFCB				GetFcbFromVcbList(IN PVCB Vcb, IN UNICODE_STRING FullFileName);
	VOID				AddFcbToVcbList(IN PVCB Vcb, IN PFCB Fcb);
	VOID				RemoveFcbFromVcbList(IN PVCB Vcb, IN PFCB Fcb);

	VOID				InitData(PDRIVER_OBJECT DriverObject);
	BOOLEAN				InitFunction();
	BOOLEAN				GetEProcessNameOffset();
	PCHAR				GetCurrentProcessName();
	BOOLEAN				CheckProcess(PCHAR ProcessName);
	BOOLEAN				CheckProcessW(PWCHAR ProcessName);
	VOID				InitPathLookasideList();
	VOID				DeletePathLookasideList();
	PWCHAR				AllocPathLookasideList();
	VOID				FreePathLookasideList(PVOID Path);
	PWCHAR				AllocBufferNonPagedPool();

#ifdef __cplusplus
}
#endif

#endif// _DATA_