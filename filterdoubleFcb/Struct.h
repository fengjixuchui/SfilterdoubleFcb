#pragma once
#ifndef _STRUCT_
#define _STRUCT_

#include "Include/MySTL.h"
#ifdef  _WIN64
#define offsetof(s,m)   (size_t)( (ptrdiff_t)&(((s *)0)->m) )
#else
#define offsetof(s,m)   (size_t)&(((s *)0)->m)
#endif

typedef CSHORT NODE_TYPE_CODE;
typedef NODE_TYPE_CODE *PNODE_TYPE_CODE;

typedef CSHORT NODE_BYTE_SIZE;

#define NodeType(Ptr)(*((PNODE_TYPE_CODE)(Ptr)))

#ifndef MAX_PATH
#define MAX_PATH							512
#endif

#define MAX_PATH_SIZE						(1024)

#define BLOCK_SIZE							(512)

#define FO_FILE_OBJECT_HAS_EXTENSION		(0x00800000)

#define CCB_FLAG_DELETE_ON_CLOSE			(0x0400)
#define CCB_FLAG_CLOSE_CONTEXT				(0x8000)

#define SFS_NTC_DATA_HEADER					((NODE_TYPE_CODE)0x9558)
#define SFS_NTC_FCB							((NODE_TYPE_CODE)0x4387)
#define SFS_NTC_CCB							((NODE_TYPE_CODE)0x3154)
#define SFS_NTC_VCB							((NODE_TYPE_CODE)0x5875)
#define SFS_NTC_IRP_CONTEXT					((NODE_TYPE_CODE)0x3252)

#define NTFS_NTC_CCB_DATA                   ((NODE_TYPE_CODE)0x709)
#define NTFS_CCB_FLAG_CLEANUP               (0x00008000)

#define SIGN_MAX_SIZE						(1024 * 256)
#define SIGN_BLOCK_NUM						(5)
#define SIGN_SECTION_SIZE					1024

#define VCB_STATE_FLAG_LOCKED					(0x00000001)
#define VCB_STATE_FLAG_REMOVABLE_MEDIA			(0x00000002)
#define VCB_STATE_FLAG_VOLUME_DIRTY				(0x00000004)
#define VCB_STATE_FLAG_MOUNTED_DIRTY			(0x00000010)
#define VCB_STATE_FLAG_SHUTDOWN					(0x00000040)
#define VCB_STATE_FLAG_CLOSE_IN_PROGRESS		(0x00000080)
#define VCB_STATE_FLAG_DELETED_FCB				(0x00000100)
#define VCB_STATE_FLAG_CREATE_IN_PROGRESS		(0x00000200)
#define VCB_STATE_FLAG_BOOT_OR_PAGING_FILE		(0x00000800)
#define VCB_STATE_FLAG_DEFERRED_FLUSH			(0x00001000)
#define VCB_STATE_FLAG_ASYNC_CLOSE_ACTIVE		(0x00002000)
#define VCB_STATE_FLAG_WRITE_PROTECTED			(0x00004000)
#define VCB_STATE_FLAG_REMOVAL_PREVENTED		(0x00008000)
#define VCB_STATE_FLAG_VOLUME_DISMOUNTED		(0x00010000)
#define VCB_STATE_FLAG_VPB_MUST_BE_FREED		(0x00040000)
#define VCB_STATE_FLAG_DISMOUNT_IN_PROGRESS		(0x00080000)

#define FSP_PER_DEVICE_THRESHOLD                (2)

#define IOCTL_RESUMEDATA CTL_CODE(\
			FILE_DEVICE_UNKNOWN, \
			0x800, \
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

typedef LONGLONG VBO;
typedef VBO *PVBO;

typedef LONGLONG LBO;
typedef LBO *PLBO;

#define WriteToEof                              (StartingVbo < 0)

#define FCB_LOOKUP_ALLOCATIONSIZE_HINT          ((LONGLONG) -1)
#define READ_AHEAD_GRANULARITY                  (0x10000)

typedef struct _PATH_NAME_INFORMATION
{
	UNICODE_STRING				VolumePath;//\Device\HarddiskVolume2
	UNICODE_STRING				ParentPath;//\Device\HarddiskVolume2\ABC
	UNICODE_STRING				FileName;//\A.exe
	UNICODE_STRING				FullFileName;//\ABC\A.exe
	UNICODE_STRING				Name;//\Device\HarddiskVolume2\ABC\A.exe
	BOOLEAN						IsRootPath;

}PATH_NAME_INFORMATION, *PPATH_NAME_INFORMATION;

typedef struct _VIRTUAL_DISK_EXT
{
	ULONG						Flag;
	DEVICE_OBJECT				*RealFSDevice;

}VIRTUAL_DISK_EXT, *PVIRTUAL_DISK_EXT;

typedef enum _VCB_CONDITION
{
	VcbGood = 1,
	VcbNotMounted,
	VcbBad,

}VCB_CONDITION;

typedef struct _VCB
{
	FSRTL_ADVANCED_FCB_HEADER	VolumeFileHeader;
	PDEVICE_OBJECT				TargetDeviceObject;
	PVPB						Vpb;
	ULONG						VcbState;
	VCB_CONDITION				VcbCondition;
	ERESOURCE					Resource;
	LIST_ENTRY					VcbLinks;
	LIST_ENTRY					AsyncCloseList;
	LIST_ENTRY					DelayedCloseList;
	CLONG						OpenFileCount;
	ERESOURCE					FcbListResource;
	LIST_ENTRY					FcbList;
	FAST_MUTEX					AdvancedFcbHeaderMutex;
	PDEVICE_OBJECT				RealFsDevice;
	PDEVICE_OBJECT				BaseFsDevice;
	PDEVICE_OBJECT				RealDevice;

}VCB, *PVCB;

typedef struct _VOLUME_DEVICE_OBJECT
{
	DEVICE_OBJECT				DeviceObject;
	FSRTL_COMMON_FCB_HEADER		VolumeFileHeader;
	VCB							Vcb;

}VOLUME_DEVICE_OBJECT, *PVOLUME_DEVICE_OBJECT;

typedef struct _FS_DEVICE_OBJECT
{
	DEVICE_OBJECT				DeviceObject;
	ULONG						PostedRequestCount;
	ULONG						OverflowQueueCount;
	LIST_ENTRY					OverflowQueue;
	KSPIN_LOCK					OverflowQueueSpinLock;
	FSRTL_COMMON_FCB_HEADER		VolumeFileHeader;
	VCB							Vcb;

}FS_DEVICE_OBJECT, *PFS_DEVICE_OBJECT;

#define FCB_STATE_DELETE_ON_CLOSE			(0x00000001)
#define FCB_STATE_TRUNCATE_ON_CLOSE			(0x00000002)
#define FCB_STATE_PAGING_FILE				(0x00000004)
#define FCB_STATE_FORCE_MISS_IN_PROGRESS	(0x00000008)
#define FCB_STATE_FLUSH_FAT					(0x00000010)
#define FCB_STATE_TEMPORARY					(0x00000020)
#define FCB_STATE_SYSTEM_FILE				(0x00000080)
#define FCB_STATE_NAMES_IN_SPLAY_TREE		(0x00000100)
#define FCB_STATE_HAS_OEM_LONG_NAME			(0x00000200)
#define FCB_STATE_HAS_UNICODE_LONG_NAME		(0x00000400)
#define FCB_STATE_DELAY_CLOSE				(0x00000800)

typedef enum _FCB_CONDITION
{
	FcbGood = 1,
	FcbBad,
	FcbNeedsToBeVerified,

}FCB_CONDITION;

typedef struct _NON_PAGED_FCB
{
	SECTION_OBJECT_POINTERS		SectionObjectPointers;
	ULONG						OutstandingAsyncWrites;
	PKEVENT						OutstandingAsyncEvent;
	FAST_MUTEX					AdvancedFcbHeaderMutex;

}NON_PAGED_FCB, *PNON_PAGED_FCB;

#define MAX_KEY_LEN 256


typedef struct _ENCRYPT_IO {
	UCHAR						FileHeader[BLOCK_SIZE];
	//	BOOLEAN						FileHeaderValid;
	USHORT						KeyLen;
	UCHAR						EncryptKey[MAX_KEY_LEN];
	ULONG						KeyIndex;
	ULONG						nKey;
	BOOLEAN						Change;
	BOOLEAN						Encrypt;
	BOOLEAN                     EncryptAble;
	UCHAR						SecretDegree;
	BOOLEAN                     FileControl;
	BOOLEAN						Modify;
	BOOLEAN						ModifyNotify;
	BOOLEAN						ReadTimes;
	BOOLEAN						LifeCycle;
	BOOLEAN						FileCrc;
	PERESOURCE					EncryptResource;
} ENCRYPT_IO, *PENCRYPT_IO;


/*
 * 文件控制块，每个文件一个
 */
typedef struct _FCB
{
	FSRTL_ADVANCED_FCB_HEADER	Header;
	PNON_PAGED_FCB				NonPaged;
	PVCB						Vcb;
	ULONG						FcbState;
	FCB_CONDITION				FcbCondition;
	SHARE_ACCESS				ShareAccess;
	CLONG						UncleanCount;
	CLONG						OpenCount;
	CLONG						NonCachedUncleanCount;

	LARGE_INTEGER				CreationTime;
	LARGE_INTEGER				LastAccessTime;
	LARGE_INTEGER				LastWriteTime;

	ULONGLONG					ValidDataToDisk;

	struct
	{
		FILE_LOCK				FileLock;
		OPLOCK					Oplock;
		PVOID                   LazyWriteThread;
	} Fcb;

	UNICODE_STRING				FullFileName;
	PFSRTL_ADVANCED_FCB_HEADER	RealFcb;
	BOOLEAN Directory;

	ENCRYPT_IO					EncryptIo;

}FCB, *PFCB;

typedef struct _CLOSE_CONTEXT
{
	LIST_ENTRY					GlobalLinks;
	LIST_ENTRY					VcbLinks;

	PVCB						Vcb;
	PFCB						Fcb;
	BOOLEAN						Free;

}CLOSE_CONTEXT, *PCLOSE_CONTEXT;

/*
 * 文件记录块，打开文件生成文件记录块
 */
typedef struct _CCB
{
	NODE_TYPE_CODE				NodeTypeCode;
	NODE_BYTE_SIZE				NodeByteSize;

	PFILE_OBJECT				RealFileObject;
	BOOLEAN						IsCacheSupported;
	ULONG						Flags : 24;
	CLOSE_CONTEXT				CloseContext;

}CCB, *PCCB;

typedef enum _TYPE_OF_OPEN
{
	UnopenedFileObject = 1,
	UserFileOpen,
	UserDirectoryOpen,
	UserVolumeOpen,
	VirtualVolumeFile,
	DirectoryFile,
	EaFile,

}TYPE_OF_OPEN;

#define IRP_CONTEXT_FLAG_DISABLE_DIRTY             (0x00000001)
#define IRP_CONTEXT_FLAG_WAIT                      (0x00000002)
#define IRP_CONTEXT_FLAG_WRITE_THROUGH             (0x00000004)
#define IRP_CONTEXT_FLAG_DISABLE_WRITE_THROUGH     (0x00000008)
#define IRP_CONTEXT_FLAG_RECURSIVE_CALL            (0x00000010)
#define IRP_CONTEXT_FLAG_DISABLE_POPUPS            (0x00000020)
#define IRP_CONTEXT_FLAG_DEFERRED_WRITE            (0x00000040)
#define IRP_CONTEXT_FLAG_VERIFY_READ               (0x00000080)
#define IRP_CONTEXT_STACK_IO_CONTEXT               (0x00000100)
#define IRP_CONTEXT_FLAG_IN_FSP                    (0x00000200)
#define IRP_CONTEXT_FLAG_USER_IO                   (0x00000400)       // for performance counters
#define IRP_CONTEXT_FLAG_DISABLE_RAISE             (0x00000800)
#define IRP_CONTEXT_FLAG_PARENT_BY_CHILD           (0x80000000)


typedef struct _BUFFER_CONTEXT
{
	PVOID							UserBuffer;
	PMDL							Mdl;
	ULONG							Length;

	PVOID							EncryptBuffer;

}BUFFER_CONTEXT, *PBUFFER_CONTEXT;

typedef struct _IO_CONTEXT
{
	ULONG                           Flags;
	LONG                            IrpCount;
	PIRP                            MasterIrp;

	PMDL                            ZeroMdl;

	union {

		struct {
			PERESOURCE              Resource;
			PERESOURCE              Resource2;
			ERESOURCE_THREAD        ResourceThreadId;
			ULONG                   RequestedByteCount;
			PFILE_OBJECT            FileObject;
			PNON_PAGED_FCB          NonPagedFcb;
		} Async;

		KEVENT                      SyncEvent;

	} Wait;

	KEVENT							SyncEvent;
	PDEVICE_OBJECT					RealFsDevice;
	PFILE_OBJECT					FileObject;
	PFILE_OBJECT					RealFileObject;
	LARGE_INTEGER					ByteOffset;
	BUFFER_CONTEXT					BufferContext;

} IO_CONTEXT, *PIO_CONTEXT;

typedef struct _IRP_CONTEXT
{
	NODE_TYPE_CODE					NodeTypeCode; //文件节点类型
	NODE_BYTE_SIZE					NodeByteSize; //节点大小
	WORK_QUEUE_ITEM                 WorkQueueItem; //
	PIRP							OriginatingIrp; //
	PFS_DEVICE_OBJECT				FsDevice; ///所在驱动器
	PDEVICE_OBJECT					RealFsDevice; //真实的驱动器
	PVCB							Vcb; //
	UCHAR							MajorFunction;
	UCHAR							MinorFunction;
	ULONG							Flags;
	ULONG							IrpSpFlags;
	ULONG                           IrpFlags;
	NTSTATUS						ExceptionStatus;
	PIO_STACK_LOCATION				IrpSp;
	ACCESS_MASK                     DesiredAccess;
	ULONG							Options; //

	PFILE_OBJECT					FileObject;	//文件对象
	PFILE_OBJECT					RealFileObject; //真实文件对象

	PFSRTL_ADVANCED_FCB_HEADER		RealFcb; //真实文件对象结构
	PPATH_NAME_INFORMATION			PathNameInfo; //路径名信息

	PIO_CONTEXT                     IoContext;

}IRP_CONTEXT, *PIRP_CONTEXT;


#define RaiseStatus(IRPCONTEXT,STATUS) {                \
    (IRPCONTEXT)->ExceptionStatus = (STATUS);           \
    ExRaiseStatus( (STATUS) );                          \
}

#define try_return(S) { S; goto try_exit; }
#define try_leave(S) { S; __leave; }

typedef struct _FILE_CONTEXT
{
	PFILE_OBJECT					FileObject;
	PFILE_OBJECT					SFSFileObject;

}FILE_CONTEXT, *PFILE_CONTEXT;

typedef struct _OBJECT_CREATE_INFORMATION
{
	ULONG							Attributes;
	HANDLE							RootDirectory;
	PVOID							ParseContext;
	KPROCESSOR_MODE					ProbeMode;
	ULONG							PagedPoolCharge;
	ULONG							NonPagedPoolCharge;
	ULONG							SecurityDescriptorCharge;
	PSECURITY_DESCRIPTOR			SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE	SecurityQos;
	SECURITY_QUALITY_OF_SERVICE		SecurityQualityOfService;

}OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HEADER
{
	LONG_PTR						PointerCount;
	union
	{
		LONG_PTR					HandleCount;
		PVOID						NextToFree;
	};
	POBJECT_TYPE					Type;
	UCHAR							NameInfoOffset;
	UCHAR							HandleInfoOffset;
	UCHAR							QuotaInfoOffset;
	UCHAR							Flags;

	union
	{
		POBJECT_CREATE_INFORMATION	ObjectCreateInfo;
		PVOID						QuotaBlockCharged;
	};

	PSECURITY_DESCRIPTOR			SecurityDescriptor;
	QUAD							Body;

} OBJECT_HEADER, *POBJECT_HEADER;

#define OBJECT_TO_OBJECT_HEADER(o) \
	CONTAINING_RECORD((o), OBJECT_HEADER, Body)

typedef struct _MMSECTION_FLAGS
{
	unsigned						BeingDeleted : 1;
	unsigned						BeingCreated : 1;
	unsigned						BeingPurged : 1;
	unsigned						NoModifiedWriting : 1;

	unsigned						FailAllIo : 1;
	unsigned						Image : 1;
	unsigned						Based : 1;
	unsigned						File : 1;

	unsigned						Networked : 1;
	unsigned						NoCache : 1;
	unsigned						PhysicalMemory : 1;
	unsigned						CopyOnWrite : 1;

	unsigned						Reserve : 1;  // not a spare bit!
	unsigned						Commit : 1;
	unsigned						FloppyMedia : 1;
	unsigned						WasPurged : 1;

	unsigned						UserReference : 1;
	unsigned						GlobalMemory : 1;
	unsigned						DeleteOnClose : 1;
	unsigned						FilePointerNull : 1;

	unsigned						DebugSymbolsLoaded : 1;
	unsigned						SetMappedFileIoComplete : 1;
	unsigned						CollidedFlush : 1;
	unsigned						NoChange : 1;

	unsigned						filler0 : 1;
	unsigned						ImageMappedInSystemSpace : 1;
	unsigned						UserWritable : 1;
	unsigned						Accessed : 1;

	unsigned						GlobalOnlyPerSession : 1;
	unsigned						Rom : 1;
	unsigned						WriteCombined : 1;
	unsigned						filler : 1;

} MMSECTION_FLAGS;

typedef struct _EVENT_COUNTER
{
	SLIST_ENTRY						ListEntry;
	ULONG							RefCount;
	KEVENT							Event;

}EVENT_COUNTER, *PEVENT_COUNTER;

typedef struct _CONTROL_AREA
{
	PVOID							Segment;
	LIST_ENTRY						DereferenceList;
	ULONG							NumberOfSectionReferences;
	ULONG							NumberOfPfnReferences;
	ULONG							NumberOfMappedViews;

	ULONG							NumberOfSystemCacheViews;
	ULONG							NumberOfUserReferences;
	union
	{
		ULONG						LongFlags;
		MMSECTION_FLAGS				Flags;
	} u;
	PFILE_OBJECT					FilePointer;
	PEVENT_COUNTER					WaitingForDeletion;
	USHORT							ModifiedWriteCount;
	USHORT							FlushInProgressCount;
	ULONG							WritableUserReferences;

#if!defined(_WIN64)
	ULONG							QuadwordPad;
#endif

} CONTROL_AREA, *PCONTROL_AREA;


typedef struct _CCB_HEAD
{
	NODE_TYPE_CODE NodeTypeCode;
	NODE_BYTE_SIZE NodeByteSize;

	ULONG Flags;
} CCB_HEAD, *PCCB_HEAD;

typedef struct _DEVICE_NODE
{
	LIST_ENTRY						ListEntry;
	PVOID							DeviceObject;

}DEVICE_NODE, *PDEVICE_NODE;

typedef struct _FCB_NODE
{
	LIST_ENTRY						ListEntry;
	PFCB							Fcb;

}FCB_NODE, *PFCB_NODE;

typedef struct _DEVICE_INFO_NODE
{
	LIST_ENTRY						ListEntry;
	PFLT_VOLUME						Volume;
	PDEVICE_OBJECT					MiniFsDevice;
	PFS_DEVICE_OBJECT				FsDevice;
	PDEVICE_OBJECT					Device;
	PDEVICE_OBJECT					RealDevice;

}DEVICE_INFO_NODE, *PDEVICE_INFO_NODE;

typedef NTSTATUS
(__stdcall *ZwProtectVirtualMemoryType)(
	IN HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
	);

typedef NTSTATUS
(__stdcall *ZwWriteVirtualMemoryType)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN PSIZE_T RegionSize,
	OUT PULONG OldProtect
	);

typedef NTSTATUS
(*FsRtlRegisterFileSystemFilterCallbacksType)(
	IN PDRIVER_OBJECT  FilterDriverObject,
	IN PFS_FILTER_CALLBACKS  Callbacks
	);

typedef NTSTATUS
(*IoAttachDeviceToDeviceStackSafeType)(
	IN PDEVICE_OBJECT  SourceDevice,
	IN PDEVICE_OBJECT  TargetDevice,
	IN OUT PDEVICE_OBJECT  *AttachedToDeviceObject
	);

typedef NTSTATUS
(*IoEnumerateDeviceObjectListType)(
	IN PDRIVER_OBJECT  DriverObject,
	IN PDEVICE_OBJECT  *DeviceObjectList,
	IN ULONG  DeviceObjectListSize,
	OUT PULONG  ActualNumberDeviceObjects
	);

typedef PDEVICE_OBJECT
(*IoGetLowerDeviceObjectType)(
	IN PDEVICE_OBJECT  DeviceObject
	);


typedef PDEVICE_OBJECT
(*IoGetDeviceAttachmentBaseRefType)(
	IN PDEVICE_OBJECT  DeviceObject
	);


typedef NTSTATUS
(*IoGetDiskDeviceObjectType)(
	IN PDEVICE_OBJECT  FileSystemDeviceObject,
	OUT PDEVICE_OBJECT  *DeviceObject
	);

typedef PDEVICE_OBJECT
(*IoGetAttachedDeviceReferenceType)(
	IN PDEVICE_OBJECT  DeviceObject
	);

typedef NTSTATUS
(*RtlGetVersionType)(
	IN OUT PRTL_OSVERSIONINFOW  lpVersionInformation
	);

typedef NTSTATUS
(*ObCreateObjectType)(
	IN KPROCESSOR_MODE ProbeMode,
	IN POBJECT_TYPE ObjectType,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN KPROCESSOR_MODE OwnershipMode,
	IN OPTIONAL PVOID ParseContext,
	IN ULONG ObjectBodySize,
	IN ULONG PagedPoolCharge,
	IN ULONG NonPagedPoolCharge,
	OUT PVOID *Object
	);

typedef NTSTATUS
(__stdcall *PsRemoveLoadImageNotifyRoutineType)(
	IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
	);

typedef struct _FILE_OBJECTS_INFO
{
	LIST_ENTRY ListEntry;
	PFILE_OBJECT FileObject;
} FILE_OBJECTS_INFO, *PFILE_OBJECTS_INFO;

#include "Include/FileConf.h"

typedef struct _FILE_INFO1
{
	LIST_ENTRY		ListEntry;
	UNICODE_STRING  Name;
	VOID *			FsContext;
	INT				FileType; //0、原始加密文件 1、新建文件
	PDEVICE_OBJECT	DeviceObject;
} FILE_INFO1, *PFILE_INFO1;

typedef struct _PROCESS_INFO
{
	LIST_ENTRY ListEntry;
	HANDLE ProcessId;
	HANDLE FprocessId;
	ULONG FileSize;
	UCHAR Sign[16];
	WCHAR ProcessName[32];
	WCHAR* FullPath;
	INT SignID;
	ERESOURCE m_processResouce;

	BOOLEAN IsProtectProcess;

	BOOLEAN IsInject;
	BOOLEAN IsKill;

	BOOLEAN IsOpenedOnlyFile;
	BOOLEAN IsOpenedNoCopyFile;

	LIST_ENTRY EncryptFileList;

	PVOID BackupDataBuffer;
	PVOID BackupDataAddress;
	ULONG_PTR BackupDataSize;

	PVOID BackupDataDirectoryBuffer;
	PVOID BackupDataDirectoryAddress;
	ULONG_PTR BackupDataDirectorySize;
	ULONG ExeType;

	INT pCrc;
	ULONG Tempcout;
	BOOLEAN IsExistProcess;

	BOOLEAN isOpeningEncryptFile;
	//PVOID FsContext;
	tagFileInfo fileHead;
	CHAR unknownAlert;
	CHAR UUID[UUID_LEN];
	CArray<PWCHAR> Encryptcontent;
} PROCESS_INFO, *PPROCESS_INFO;

typedef struct _PEB_STUB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN SpareBits : 7;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;

} *PPEB_STUB;

typedef union
{
	WCHAR Name[sizeof(ULARGE_INTEGER) / sizeof(WCHAR)];
	ULARGE_INTEGER Alignment;

} ALIGNEDNAME;

typedef struct _AUX_ACCESS_DATA
{
	PPRIVILEGE_SET PrivilegesUsed;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK AccessesToAudit;
	ACCESS_MASK MaximumAuditMask;
	ULONG Unknown[41];

} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

typedef struct _OB_TEMP_BUFFER
{
	ACCESS_STATE LocalAccessState;
	//	OBJECT_CREATE_INFORMATION ObjectCreateInfo;
	AUX_ACCESS_DATA AuxData;

} OB_TEMP_BUFFER, *POB_TEMP_BUFFER;


typedef struct _FILE_INFO
{
	LIST_ENTRY ListEntry;

	UNICODE_STRING  Name;

	UNICODE_STRING  LetterName;

	PDEVICE_OBJECT  RealFsDevice;

	VOID *			FsContent;

	unsigned int	nUserID;			// 创建者ID

	unsigned char	bFileControlFlag : 1;	// 文件权限控制标志

	unsigned char   bGroupOnlyFlag : 1;	// 仅组内成员
	unsigned char	bModifyFlag : 1;		// 修改权限
	unsigned char	bCopyFlag : 1;		// 内容复制权限
	unsigned char	bPrintFlag : 1;		// 打印权限
	unsigned char	bPrintTimesFlag : 1;	// 打印次数控制
	unsigned char	bReadTimesFlag : 1;	// 解密次数
	unsigned char	bLifeCycleFlag : 1;	// 生命周期控制

	unsigned char	bFileCrcFlag : 1;				// 开启文件完整性校验
	unsigned char	bModifyAuthFlag : 1;			// 是否允许修改权限
	unsigned char	bSelfDestoryFlag : 1;			// 是否自动销毁
	unsigned char	bPasswordFlag : 1;			// 开启密码访问

	unsigned char	nNodeID_1;			// 用户组ID 0-255
	unsigned char	nNodeID_2;			// 用户组ID 0-255
	unsigned char	nNodeID_3;			// 用户组ID 0-255
	unsigned char	nNodeID_4;			// 用户组ID 0-255

	unsigned char	nPrintTimes;		// 当前打印次数 0-255

	unsigned char	nReadTimes;			// 当前解密次数	0-255

	unsigned int	nBeginTime;			// 开始时间
	unsigned int	nEndTime;			// 截止时间

} FILE_INFO, *PFILE_INFO;

typedef struct _GLOBAL_ENCRYPT_FILE
{
	LIST_ENTRY      ListEntry;
	WCHAR           Name[MAX_PATH];
	PDEVICE_OBJECT  FsDevice;
} GLOBAL_ENCRYPT_FILE, *PGLOBAL_ENCRYPT_FILE;


typedef struct _ASK_PASSWORD_INFO
{
	ULONG   ResultValue;
	WCHAR   Password[0];
} ASK_PASSWORD_INFO, *PASK_PASSWORD_INFO;

#endif// _STRUCT_