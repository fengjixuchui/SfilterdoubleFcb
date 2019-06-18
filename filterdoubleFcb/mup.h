#pragma once
#include <ntifs.h>
#include <ntddk.h>

extern PDRIVER_OBJECT FspDriverObject;

typedef struct
{
	KTIMER Timer;
	KDPC Dpc;
	WORK_QUEUE_ITEM WorkQueueItem;
} FSP_DELAYED_WORK_ITEM;

enum
{
	FspFsvolDeviceSecurityCacheCapacity = 100,
	FspFsvolDeviceSecurityCacheItemSizeMax = 4096,
	FspFsvolDeviceDirInfoCacheCapacity = 100,
	//FspFsvolDeviceDirInfoCacheItemSizeMax = FSP_FSCTL_ALIGN_UP(16384, PAGE_SIZE),
	FspFsvolDeviceStreamInfoCacheCapacity = 100,
	//FspFsvolDeviceStreamInfoCacheItemSizeMax = FSP_FSCTL_ALIGN_UP(16384, PAGE_SIZE),
	FspFsvolDeviceEaCacheCapacity = 100,
	//FspFsvolDeviceEaCacheItemSizeMax = FSP_FSCTL_ALIGN_UP(16384, PAGE_SIZE),
};
typedef struct
{
	PUNICODE_STRING FileName;
	PVOID Context;
} FSP_DEVICE_CONTEXT_BY_NAME_TABLE_ELEMENT_DATA;
typedef struct
{
	RTL_BALANCED_LINKS Header;
	FSP_DEVICE_CONTEXT_BY_NAME_TABLE_ELEMENT_DATA Data;
} FSP_DEVICE_CONTEXT_BY_NAME_TABLE_ELEMENT;
typedef struct
{
	PVOID RestartKey;
	ULONG DeleteCount;
} FSP_DEVICE_CONTEXT_BY_NAME_TABLE_RESTART_KEY;
enum
{
	FspFsctlDeviceExtensionKind = '\0ltC',  /* file system control device (e.g. \Device\WinFsp.Disk) */
	FspFsmupDeviceExtensionKind = '\0puM',  /* our own MUP device (linked to \Device\WinFsp.Mup) */
	FspFsvrtDeviceExtensionKind = '\0trV',  /* virtual volume device (e.g. \Device\Volume{GUID}) */
	FspFsvolDeviceExtensionKind = '\0loV',  /* file system volume device (unnamed) */
};
typedef struct
{
	KSPIN_LOCK SpinLock;
	LONG RefCount;
	UINT32 Kind;
} FSP_DEVICE_EXTENSION;
typedef struct
{
	FSP_DEVICE_EXTENSION Base;
	UINT32 InitDoneFsvrt : 1, InitDoneIoq : 1, InitDoneSec : 1, InitDoneDir : 1, InitDoneStrm : 1, InitDoneEa : 1,
		InitDoneCtxTab : 1, InitDoneTimer : 1, InitDoneInfo : 1, InitDoneNotify : 1, InitDoneStat : 1;
	PDEVICE_OBJECT FsctlDeviceObject;
	PDEVICE_OBJECT FsvrtDeviceObject;
	PDEVICE_OBJECT FsvolDeviceObject;
	PVPB SwapVpb;
	FSP_DELAYED_WORK_ITEM DeleteVolumeDelayedWorkItem;
	//FSP_FSCTL_VOLUME_PARAMS VolumeParams;
	UNICODE_STRING VolumePrefix;
	UNICODE_PREFIX_TABLE_ENTRY VolumePrefixEntry;
	//FSP_IOQ* Ioq;
	//FSP_META_CACHE* SecurityCache;
	//FSP_META_CACHE* DirInfoCache;
	//FSP_META_CACHE* StreamInfoCache;
	//FSP_META_CACHE* EaCache;
	KSPIN_LOCK ExpirationLock;
	WORK_QUEUE_ITEM ExpirationWorkItem;
	BOOLEAN ExpirationInProgress;
	ERESOURCE FileRenameResource;
	ERESOURCE ContextTableResource;
	LIST_ENTRY ContextList;
	RTL_AVL_TABLE ContextByNameTable;
	PVOID ContextByNameTableElementStorage;
	UNICODE_STRING VolumeName;
	//WCHAR VolumeNameBuf[FSP_FSCTL_VOLUME_NAME_SIZE / sizeof(WCHAR)];
	KSPIN_LOCK InfoSpinLock;
	UINT64 InfoExpirationTime;
	//FSP_FSCTL_VOLUME_INFO VolumeInfo;
	PNOTIFY_SYNC NotifySync;
	LIST_ENTRY NotifyList;
	//FSP_STATISTICS* Statistics;
} FSP_FSVOL_DEVICE_EXTENSION;
typedef struct
{
	FSP_DEVICE_EXTENSION Base;
	UINT32 InitDonePfxTab : 1;
	ERESOURCE PrefixTableResource;
	UNICODE_PREFIX_TABLE PrefixTable;
	UNICODE_PREFIX_TABLE ClassTable;
} FSP_FSMUP_DEVICE_EXTENSION;
static inline
FSP_DEVICE_EXTENSION* FspDeviceExtension(PDEVICE_OBJECT DeviceObject)
{
	return DeviceObject->DeviceExtension;
}
static inline
FSP_FSVOL_DEVICE_EXTENSION* FspFsvolDeviceExtension(PDEVICE_OBJECT DeviceObject)
{
	ASSERT(FspFsvolDeviceExtensionKind == ((FSP_DEVICE_EXTENSION*)DeviceObject->DeviceExtension)->Kind);
	return DeviceObject->DeviceExtension;
}
static inline
FSP_FSMUP_DEVICE_EXTENSION* FspFsmupDeviceExtension(PDEVICE_OBJECT DeviceObject)
{
	ASSERT(FspFsmupDeviceExtensionKind == ((FSP_DEVICE_EXTENSION*)DeviceObject->DeviceExtension)->Kind);
	return DeviceObject->DeviceExtension;
}

NTSTATUS FspDeviceCreate(UINT32 Kind, ULONG ExtraSize,
	DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics,
	PDEVICE_OBJECT* PDeviceObject);


NTSTATUS FspDeviceCreateSecure(UINT32 Kind, ULONG ExtraSize,
	PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics,
	PUNICODE_STRING DeviceSddl, LPCGUID DeviceClassGuid,
	PDEVICE_OBJECT* PDeviceObject);