#include "Data.h"
#include "Utils.h"
#include "Common.h"
#include "WDK.h"
#include "Data_Extern_C.h"
//#include "Log.h"

PCHAR ImportFunName = "StartGuard";//"InitDll";
CHAR DllNameStr[MAX_PATH] = { 0 };//		= "Guard.dll";
CHAR DllNameStr64[MAX_PATH] = { 0 };//    = "Guard64.dll";



//CHAR DllNameStr[MAX_PATH] = "C:\\Guard.dll";
//CHAR DllNameStr64[MAX_PATH] = "C:\\Guard64.dll";


//CHAR DllNameStr[MAX_PATH] = "Guard.dll";

//WCHAR BackupDriveLetter[MAX_PATH] = {0};
//WCHAR BackupDir[MAX_PATH] = {0};

WCHAR BackupDriveLetter[MAX_PATH] = L"\\??\\C:";
WCHAR BackupDir[MAX_PATH] = L"\\$BackupDir$";


WCHAR SystemRootDriveLetter[10] = { 0 };
WCHAR SystemRootPathName[MAX_PATH] = { 0 };


WCHAR PolicyPath[MAX_PATH] = { 0 };
WCHAR DriverPath[MAX_PATH] = { 0 };


//PWCHAR BackupDriveLetter = L"\\??\\C:";
//PWCHAR BackupDriveLetter = L"\\Device\\LanmanRedirector";
//PWCHAR BackupDir = L"\\$BackupDir$";
//PWCHAR BackupDir = L"\\192.168.0.195\\share\\BackupDir";

int nTime = 0;

SFS_DATA SFSData;

ReprocessInfo ReprocInfo;
ZwWriteVirtualMemoryType						pZwWriteVirtualMemory;
ZwProtectVirtualMemoryType						pZwProtectVirtualMemory;
FsRtlRegisterFileSystemFilterCallbacksType		pFsRtlRegisterFileSystemFilterCallbacks;
IoAttachDeviceToDeviceStackSafeType				pIoAttachDeviceToDeviceStackSafe;
IoEnumerateDeviceObjectListType					pIoEnumerateDeviceObjectList;
IoGetLowerDeviceObjectType						pIoGetLowerDeviceObject;
IoGetDeviceAttachmentBaseRefType				pIoGetDeviceAttachmentBaseRef;
IoGetDiskDeviceObjectType						pIoGetDiskDeviceObject;
IoGetAttachedDeviceReferenceType				pIoGetAttachedDeviceReference;
RtlGetVersionType								pRtlGetVersion;
ObCreateObjectType								pObCreateObject;
PsRemoveLoadImageNotifyRoutineType				pPsRemoveLoadImageNotifyRoutine;


// ZwWaitForSingleObject  start
// ZwUnlockFile  end


VOID InitData(PDRIVER_OBJECT DriverObject) {
	SFSData.NodeTypeCode = SFS_NTC_DATA_HEADER;
	SFSData.NodeByteSize = sizeof(SFS_DATA);

	SFSData.DriverObject = DriverObject;
	SFSData.CurrentProcess = PsGetCurrentProcess();

	SFSData.WorkModeFlag = FALSE;
	SFSData.OnlineFlag = FALSE;



	InitializeListHead(&SFSData.ProcessInfoList);
	/////////////////////////////////////////////////
	InitializeListHead(&ReprocInfo.ProcessInfoList);
	/////////////////////////////////////////////////
	ExInitializeResourceLite(&SFSData.ProcessInfoListResource);

	InitPathLookasideList();
}



#ifdef _WIN64
ULONG_PTR GetPreviousFunctionAddress64(PWCHAR FunctionName, ULONG PreviousCount)
{
	PUCHAR Begin = 0;
	PUCHAR End = 0;
	ULONG Index = 0;

	UNICODE_STRING RoutineName;
	UNICODE_STRING EndRoutineName;

	RtlInitUnicodeString(&EndRoutineName, L"ZwWaitForSingleObject");
	RtlInitUnicodeString(&RoutineName, FunctionName);

	Begin = (PUCHAR) MmGetSystemRoutineAddress(&RoutineName);
	if (!Begin)
	{
		return 0;
	}

	End = (PUCHAR) MmGetSystemRoutineAddress(&EndRoutineName);
	if (!End)
	{
		return 0;
	}

	if (0x48 == *Begin && 0x8B == *(Begin + 1) && 0xC4 == *(Begin + 2))
	{
		Begin--;

		for (; Begin >= End; Begin--)
		{
			if (0x48 == *Begin && 0x8B == *(Begin + 1) && 0xC4 == *(Begin + 2))
			{
				PreviousCount--;
				if (PreviousCount == 0)
				{
					return (ULONG_PTR) Begin;
				}
			}
		}
		return 0;
	}

	return 0;

}

#else

ULONG GetPreviousFunctionAddress32(PWCHAR FunctionName, ULONG PreCount)
{
	PUCHAR Begin = 0;
	PUCHAR End = 0;
	ULONG Index = 0;

	UNICODE_STRING RoutineName;
	UNICODE_STRING EndRoutineName;
	RtlInitUnicodeString(&EndRoutineName, L"ZwAccessCheckAndAuditAlarm");
	RtlInitUnicodeString(&RoutineName, FunctionName);

	Begin = (PUCHAR) MmGetSystemRoutineAddress(&RoutineName);
	if (!Begin)
	{
		return 0;
	}

	End = (PUCHAR) MmGetSystemRoutineAddress(&EndRoutineName);

	if (0xB8 == *Begin)
	{
		Begin++;
		Index = *(PULONG) Begin;
		Index -= PreCount;

		Begin -= sizeof(ULONG);

		for (; Begin >= End; Begin--)
		{
			if (0xB8 == *Begin
				&& Index == *(PULONG) (Begin + 1)
				&& 0x8D == *(Begin + 1 + sizeof(ULONG)))
			{
				return (ULONG) Begin;
			}
		}
		return 0;
	}

	return 0;

}


ULONG GetNextFunctionAddress32(PWCHAR FunctionName, ULONG NextCount)
{
	PUCHAR Begin = 0;
	PUCHAR End = 0;
	ULONG Index = 0;

	UNICODE_STRING RoutineName;
	UNICODE_STRING EndRoutineName;
	RtlInitUnicodeString(&EndRoutineName, L"ZwYieldExecution");
	RtlInitUnicodeString(&RoutineName, FunctionName);

	Begin = (PUCHAR) MmGetSystemRoutineAddress(&RoutineName);
	if (!Begin)
	{
		return 0;
	}

	End = (PUCHAR) MmGetSystemRoutineAddress(&EndRoutineName);

	if (0xB8 == *Begin)
	{
		Begin++;
		Index = *(PULONG) Begin;
		Index += NextCount;

		Begin += sizeof(ULONG);

		for (; Begin <= End; Begin++)
		{
			if (0xB8 == *Begin
				&& Index == *(PULONG) (Begin + 1)
				&& 0x8D == *(Begin + 1 + sizeof(ULONG)))
			{
				return (ULONG) Begin;
			}
		}
		return 0;
	}

	return 0;

}
#endif

ULONG_PTR GetZwSetInformationToken()
{

	UNICODE_STRING RoutineName;
	PVOID FunAddr = NULL;
	RtlInitUnicodeString(&RoutineName, L"ZwSetInformationToken");

	FunAddr = MmGetSystemRoutineAddress(&RoutineName);

	if (FunAddr)
	{
		return (ULONG_PTR) FunAddr;
	}

#ifdef _WIN64
	return GetPreviousFunctionAddress64(L"ZwSetSecurityObject", 7);
#else
	return GetNextFunctionAddress32(L"ZwSetInformationThread", 1);
#endif
}

ULONG_PTR GetZwProtectVirtualMemory()
{
	/*
	#ifdef _WIN64
		return GetPreviousFunctionAddress64(L"ZwQuerySection", 1);
	#else
		return GetPreviousFunctionAddress32(L"ZwPulseEvent", 1);
	#endif
	*/

#if (WINVER <= _WIN32_WINNT_WINXP)
	//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!GetZwProtectVirtualMemory -> _WIN32_WINNT_WINXP\n"));
	return GetPreviousFunctionAddress32(L"ZwPulseEvent", 1);
#elif (WINVER <= _WIN32_WINNT_WIN7)
#ifdef _WIN64
	//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!GetZwProtectVirtualMemory -> _WIN32_WINNT_WIN7 WIN64\n"));
	return GetPreviousFunctionAddress64(L"ZwQuerySection", 1);
#else
	//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!GetZwProtectVirtualMemory -> _WIN32_WINNT_WIN7 WIN32\n"));
	return GetPreviousFunctionAddress32(L"ZwPulseEvent", 1);
#endif
#elif (WINVER <= _WIN32_WINNT_WINBLUE)
#ifdef _WIN64
	//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!GetZwProtectVirtualMemory -> _WIN32_WINNT_WIN8 WIN64\n"));
	return GetPreviousFunctionAddress64(L"ZwQuerySection", 1);
#else
	//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!GetZwProtectVirtualMemory -> _WIN32_WINNT_WIN8 WIN32\n"));
	return GetNextFunctionAddress32(L"ZwPulseEvent", 1);
#endif
#else
	//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!GetZwProtectVirtualMemory -> WINVER = %x\n", WINVER));
	return 0;
#endif
}


//
//NTSTATUS IoSuccessCompleteRequest(PIRP Irp)
//{
//	Irp->IoStatus.Status = STATUS_SUCCESS;
//	Irp->IoStatus.Information = FILE_OPENED;
//
//	IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//	return STATUS_SUCCESS;
//}

//// Device Info List
//
//VOID DeviceInfoListInit()
//{
//	InitializeListHead(&SFSData.DeviceInfoList);
//	ExInitializeResourceLite(&SFSData.DeviceInfoListResource);
//}

//BOOLEAN IsExsitDeviceInfoForMiniFsDevice(IN PVOID Object)
//{
//	PLIST_ENTRY Links;
//	PDEVICE_INFO_NODE Node;
//
//	for(Links = SFSData.DeviceInfoList.Flink; Links != &SFSData.DeviceInfoList; Links = Links->Flink)
//	{
//		Node =(PDEVICE_INFO_NODE)Links;
//		if(Node->MiniFsDevice == Object)
//		{
//			return TRUE;
//		}
//	}
//
//	return FALSE;
//}
//
//PDEVICE_INFO_NODE GetDeviceInfoForMiniFsDevice(IN PVOID Object)
//{
//	PLIST_ENTRY Links;
//	PDEVICE_INFO_NODE Node;
//
//	ExAcquireResourceSharedLite(&SFSData.DeviceInfoListResource, TRUE);
//
//	for(Links = SFSData.DeviceInfoList.Flink; Links != &SFSData.DeviceInfoList; Links = Links->Flink)
//	{
//		Node =(PDEVICE_INFO_NODE)Links;
//		if(Node->MiniFsDevice == Object)
//		{
//			ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//			return Node;
//		}
//	}
//
//	ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//
//	return NULL;
//}
//
//
//PDEVICE_INFO_NODE GetDeviceInfoForRealDiskDevice(IN PVOID Object)
//{
//    PLIST_ENTRY Links;
//    PDEVICE_INFO_NODE Node;
//
//    ExAcquireResourceSharedLite(&SFSData.DeviceInfoListResource, TRUE);
//
//    for (Links = SFSData.DeviceInfoList.Flink; Links != &SFSData.DeviceInfoList; Links = Links->Flink)
//    {
//        Node = (PDEVICE_INFO_NODE)Links;
//        if (Node->RealDevice == Object)
//        {
//            ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//            return Node;
//        }
//    }
//
//    ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//
//    return NULL;
//}

//VOID 
//AddDeviceInfo(	
//			  PDEVICE_OBJECT MiniFsDevice,
//			  PFS_DEVICE_OBJECT FsDevice,
//			  PDEVICE_OBJECT Device,
//			  PDEVICE_OBJECT RealDevice 
//			 )
//{
//	PDEVICE_INFO_NODE Node;
//	ExAcquireResourceExclusiveLite(&SFSData.DeviceInfoListResource, TRUE);
//
//	if(!IsExsitDeviceInfoForMiniFsDevice(MiniFsDevice)) 
//	{
//		Node =(PDEVICE_INFO_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_INFO_NODE), 'tagN');
//		if(!Node)
//		{
//			ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//			return;
//		}
//
//		Node->MiniFsDevice = MiniFsDevice;
//		Node->FsDevice = FsDevice;
//		Node->Device = Device;
//		Node->RealDevice = RealDevice;
//
//		InsertHeadList(&SFSData.DeviceInfoList, (PLIST_ENTRY)Node);
//		
//	}
//	ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//}
//
//VOID RemoveDeviceInfo(IN PVOID Object)
//{
//	PLIST_ENTRY Links;
//	PDEVICE_INFO_NODE Node;
//
//	ExAcquireResourceExclusiveLite(&SFSData.DeviceInfoListResource, TRUE);
//
//	for(Links = SFSData.DeviceInfoList.Flink; Links != &SFSData.DeviceInfoList; Links = Links->Flink)
//	{
//		Node =(PDEVICE_INFO_NODE)Links;
//		if(Node->MiniFsDevice == Object)
//		{		
//			RemoveEntryList((PLIST_ENTRY)Links);
//			ExFreePool(Node);
//			ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//			return;
//		}
//	}
//
//	ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//}
//
//VOID RemoveDeviceInfoForRealDiskDevice(IN PVOID Object)
//{
//    PLIST_ENTRY Links;
//    PDEVICE_INFO_NODE Node;
//
//    ExAcquireResourceExclusiveLite(&SFSData.DeviceInfoListResource, TRUE);
//
//    for (Links = SFSData.DeviceInfoList.Flink; Links != &SFSData.DeviceInfoList; Links = Links->Flink)
//    {
//        Node = (PDEVICE_INFO_NODE)Links;
//        if (Node->RealDevice == Object)
//        {
//            RemoveEntryList((PLIST_ENTRY)Links);
//            ExFreePool(Node);
//            ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//            return;
//        }
//    }
//
//    ExReleaseResourceLite(&SFSData.DeviceInfoListResource);
//}

// Fcb List

BOOLEAN IsExistFcbFromVcbList(IN PVCB Vcb, IN PFCB Fcb)
{
	PLIST_ENTRY Links;
	PFCB_NODE Node;

	for (Links = Vcb->FcbList.Flink; Links != &Vcb->FcbList; Links = Links->Flink)
	{
		Node = (PFCB_NODE) Links;
		if (Node->Fcb == Fcb)
		{
			return TRUE;
		}
	}
	return FALSE;
}

PFCB GetFcbFromVcbList(IN PVCB Vcb, IN UNICODE_STRING FullFileName)
{
	PLIST_ENTRY Links;
	PFCB_NODE Node;

	for (Links = Vcb->FcbList.Flink; Links != &Vcb->FcbList; Links = Links->Flink)
	{
		Node = (PFCB_NODE) Links;
		if (RtlCompareUnicodeString(&Node->Fcb->FullFileName, &FullFileName, TRUE) == 0)
		{
			return Node->Fcb;
		}
	}
	return NULL;
}

VOID AddFcbToVcbList(IN PVCB Vcb, IN PFCB Fcb)
{
	PFCB_NODE Node;

	if (!IsExistFcbFromVcbList(Vcb, Fcb))
	{
		Node = (PFCB_NODE) ExAllocatePoolWithTag(NonPagedPool, sizeof(FCB_NODE), 'tagN');
		if (Node)
		{
			Node->Fcb = Fcb;
			InsertHeadList(&Vcb->FcbList, (PLIST_ENTRY) Node);
		}
	}
}

VOID RemoveFcbFromVcbList(IN PVCB Vcb, IN PFCB Fcb)
{
	PLIST_ENTRY Links;
	PFCB_NODE Node;

	for (Links = Vcb->FcbList.Flink; Links != &Vcb->FcbList; Links = Links->Flink)
	{
		Node = (PFCB_NODE) Links;
		if (Node->Fcb == Fcb)
		{
			RemoveEntryList((PLIST_ENTRY) Links);
			ExFreePool(Node);
			return;
		}
	}
}

/*
 * 获取ring0层函数SSDT地址
 */
BOOLEAN InitFunction()
{
	UNICODE_STRING DestinationString;

	RtlInitUnicodeString(&DestinationString, L"FsRtlRegisterFileSystemFilterCallbacks");
	pFsRtlRegisterFileSystemFilterCallbacks = (FsRtlRegisterFileSystemFilterCallbacksType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pFsRtlRegisterFileSystemFilterCallbacks)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"IoAttachDeviceToDeviceStackSafe");
	pIoAttachDeviceToDeviceStackSafe = (IoAttachDeviceToDeviceStackSafeType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pIoAttachDeviceToDeviceStackSafe)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"IoEnumerateDeviceObjectList");
	pIoEnumerateDeviceObjectList = (IoEnumerateDeviceObjectListType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pIoEnumerateDeviceObjectList)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"IoGetLowerDeviceObject");
	pIoGetLowerDeviceObject = (IoGetLowerDeviceObjectType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pIoGetLowerDeviceObject)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"IoGetDeviceAttachmentBaseRef");
	pIoGetDeviceAttachmentBaseRef = (IoGetDeviceAttachmentBaseRefType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pIoGetDeviceAttachmentBaseRef)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"IoGetDiskDeviceObject");
	pIoGetDiskDeviceObject = (IoGetDiskDeviceObjectType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pIoGetDiskDeviceObject)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"IoGetAttachedDeviceReference");
	pIoGetAttachedDeviceReference = (IoGetAttachedDeviceReferenceType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pIoGetAttachedDeviceReference)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"RtlGetVersion");
	pRtlGetVersion = (RtlGetVersionType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pRtlGetVersion)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&DestinationString, L"ObCreateObject");
	pObCreateObject = (ObCreateObjectType) MmGetSystemRoutineAddress(&DestinationString);
	if (!pObCreateObject)
	{
		return FALSE;
	}

#if 1
	pZwProtectVirtualMemory = (ZwProtectVirtualMemoryType) GetZwProtectVirtualMemory();
	if (!pZwProtectVirtualMemory)
	{
		return FALSE;
	}
	//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitFunction -> ZwProtectVirtualMemory = %p \n", pZwProtectVirtualMemory));
#endif
	//pZwWriteVirtualMemory = (ZwWriteVirtualMemoryType)GetZwWriteVirtualMemory();
	return TRUE;
}



NTSTATUS InitSystemRootPath()
{
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;

	WCHAR           SystemRootName[20] = { 0 };
	WCHAR			DriveLetter[2] = { 0 };

	PWCHAR          SystemRootPathBuf = NULL;
	PWCHAR          VolumeNameBuf = NULL;
	PWCHAR          SystemRootNameTemp = NULL;

	UNICODE_STRING  SystemRootLinkName;
	UNICODE_STRING  SystemRootPath;
	UNICODE_STRING  VolumeName;

	__try
	{

		SystemRootPathBuf = AllocPathLookasideList();
		if (!SystemRootPathBuf)
		{
			//DebugTrace(DEBUG_TRACE_ERROR, ("Data!InitSystemRootPath -> AllocPathLookasideList is null.\n"));
			__leave;
		}

		VolumeNameBuf = AllocPathLookasideList();
		if (!VolumeNameBuf)
		{
			//DebugTrace(DEBUG_TRACE_ERROR, ("Data!InitSystemRootPath -> AllocPathLookasideList is null.\n"));
			__leave;
		}

		RtlInitUnicodeString(&SystemRootLinkName, L"\\SystemRoot");
		RtlInitEmptyUnicodeString(&SystemRootPath, SystemRootPathBuf, MAX_PATH_SIZE);
		RtlInitEmptyUnicodeString(&VolumeName, VolumeNameBuf, MAX_PATH_SIZE);

		Status = GetSymbolicLink(&SystemRootLinkName, &SystemRootPath);
		if (!NT_SUCCESS(Status))
		{
			//DebugTrace(DEBUG_TRACE_ERROR, ("Data!InitSystemRootPath -> GetSymbolicLink fail. Status = %x \n", Status));
			__leave;
		}
		//win8以上以\结尾， 去除掉
		SystemRootNameTemp = (SystemRootPath.Buffer + wcslen(SystemRootPath.Buffer) - 1);
		//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitSystemRootPath -> GetSymbolicLink SystemRootPath1 = %S \n", SystemRootNameTemp));

		if (*SystemRootNameTemp == L'\\') {
			*SystemRootNameTemp = 0;
			SystemRootPath.Length -= sizeof(wchar_t);
		}
		//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitSystemRootPath -> GetSymbolicLink SystemRootPath = %S \n", SystemRootPath.Buffer));

		SystemRootNameTemp = wcsrchr(SystemRootPath.Buffer, L'\\');
		if (!SystemRootNameTemp)
		{
			//DebugTrace(DEBUG_TRACE_ERROR, ("Data!InitSystemRootPath -> wcsrchr return null\n."));
			Status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (wcslen(SystemRootNameTemp) >= sizeof(SystemRootName) / sizeof(WCHAR))
		{
			//DebugTrace(DEBUG_TRACE_ERROR, ("Data!InitSystemRootPath -> length error\n."));
			Status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		RtlStringCbCopyW(SystemRootName, sizeof(SystemRootName), SystemRootNameTemp);

		//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitSystemRootPath -> SystemRootName = %S \n", SystemRootName));

		SystemRootPath.Length -= (wcslen(SystemRootName) * sizeof(WCHAR));

		while (TRUE)
		{
			Status = GetSymbolicLink(&SystemRootPath, &VolumeName);
			if (!NT_SUCCESS(Status))
			{
				break;
			}
			RtlZeroMemory(SystemRootPath.Buffer, SystemRootPath.MaximumLength);
			SystemRootPath.Length = 0;
			RtlAppendUnicodeStringToString(&SystemRootPath, &VolumeName);
			//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitSystemRootPath -> VolumeName = %S \n", VolumeName.Buffer));
		}


		if (!GetDriverLetter(&VolumeName, DriveLetter))
		{
			//DebugTrace(DEBUG_TRACE_ERROR, ("Data!InitSystemRootPath -> GetDriverLetter return FALSE.\n"));
			//      RtlStringCchPrintfW(DriveLetter, MAX_PATH, L"%c", 65);
			DriveLetter[0] = L'C';
			//      Status = STATUS_UNSUCCESSFUL;
			//      __leave;
		}

		//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitSystemRootPath -> DriveLetter = %S \n", DriveLetter));

		RtlStringCbCopyW(SystemRootDriveLetter, sizeof(SystemRootDriveLetter), L"\\??\\");
		RtlStringCbCatW(SystemRootDriveLetter, sizeof(SystemRootDriveLetter), DriveLetter);
		RtlStringCbCatW(SystemRootDriveLetter, sizeof(SystemRootDriveLetter), L":");
		RtlStringCbCatW(SystemRootPathName, sizeof(SystemRootPathName), SystemRootName);

		RtlStringCbCopyW(PolicyPath, sizeof(PolicyPath), L"\\??\\");
		RtlStringCbCatW(PolicyPath, sizeof(PolicyPath), DriveLetter);
		RtlStringCbCatW(PolicyPath, sizeof(PolicyPath), L":");
		RtlStringCbCatW(PolicyPath, sizeof(PolicyPath), SystemRootName);
		RtlStringCbCatW(PolicyPath, sizeof(PolicyPath), L"\\iSafe.dat");

		RtlStringCbCopyW(DriverPath, sizeof(DriverPath), L"\\??\\");
		RtlStringCbCatW(DriverPath, sizeof(DriverPath), DriveLetter);
		RtlStringCbCatW(DriverPath, sizeof(DriverPath), L":");
		RtlStringCbCatW(DriverPath, sizeof(DriverPath), SystemRootName);
		RtlStringCbCatW(DriverPath, sizeof(DriverPath), L"\\system32\\drivers\\FileSafe.sys");

		//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitSystemRootPath -> PolicyPath = %S \n", PolicyPath));
		//DebugTrace(DEBUG_TRACE_DEBUG, ("Data!InitSystemRootPath -> DriverPath = %S \n", DriverPath));


		Status = STATUS_SUCCESS;
	}
	__finally
	{
		if (SystemRootPathBuf)
		{
			FreePathLookasideList(SystemRootPathBuf);
		}

		if (VolumeNameBuf)
		{
			FreePathLookasideList(VolumeNameBuf);
		}
	}

	return Status;

}


// Process Name

ULONG EprocessNameOffset = 0;

BOOLEAN GetEProcessNameOffset()
{
	ULONG i;
	UCHAR *Eprocess;

	Eprocess = (UCHAR *) IoGetCurrentProcess();

	for (i = 0; i < 0x3000; i++)
	{
		if (0 == strncmp("System", (const char*) (Eprocess + i), 6))
		{
			EprocessNameOffset = i;
			return TRUE;
		}
	}

	return FALSE;
}

PCHAR GetCurrentProcessName()
{
	PCHAR Eprocess;

	if (!EprocessNameOffset)
	{
		return NULL;
	}

	Eprocess = (PCHAR) IoGetCurrentProcess();
	return(Eprocess + EprocessNameOffset);
}

BOOLEAN CheckProcess(PCHAR ProcessName)
{
	PCHAR CurrentProcessName;
	CurrentProcessName = GetCurrentProcessName();
	if (0 == _stricmp(CurrentProcessName, ProcessName))
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN CheckProcessW(PWCHAR ProcessName)
{
	PAGED_CODE();

	BOOLEAN Result = FALSE;
	ANSI_STRING AnsiString;
	UNICODE_STRING UnicodeString;
	UNICODE_STRING NewUnicodeString;
	PWCHAR ProcessNameBuf;

	PCHAR CurrentProcessName;

	RtlInitUnicodeString(&UnicodeString, ProcessName);

	CurrentProcessName = GetCurrentProcessName();

	RtlInitAnsiString(&AnsiString, CurrentProcessName);

	ProcessNameBuf = (PWCHAR) ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'pnam');
	if (!ProcessNameBuf)
	{
		return FALSE;
	}
	RtlZeroMemory(ProcessNameBuf, MAX_PATH_SIZE);
	RtlInitEmptyUnicodeString(&NewUnicodeString, ProcessNameBuf, MAX_PATH_SIZE);
	RtlAnsiStringToUnicodeString(&NewUnicodeString, &AnsiString, FALSE);

	if (RtlCompareUnicodeString(&NewUnicodeString, &UnicodeString, TRUE) == 0)
	{
		Result = TRUE;
	}

	ExFreePool(ProcessNameBuf);
	return Result;
}


NPAGED_LOOKASIDE_LIST PathNameBufferPagedList;

VOID InitPathLookasideList()
{
	ExInitializeNPagedLookasideList(&PathNameBufferPagedList, NULL, NULL, 0, MAX_PATH_SIZE, 'PNAM', 0);
}

VOID DeletePathLookasideList()
{
	ExDeleteNPagedLookasideList(&PathNameBufferPagedList);
}

PWCHAR AllocPathLookasideList()
{
	PWCHAR PathName;
	PathName = (PWCHAR) ExAllocateFromNPagedLookasideList(&PathNameBufferPagedList);
	if (!PathName)
	{
		return NULL;
	}
	RtlZeroMemory(PathName, MAX_PATH_SIZE);
	return PathName;
}

VOID FreePathLookasideList(PVOID Path)
{
	ExFreeToNPagedLookasideList(&PathNameBufferPagedList, Path);
}

PWCHAR AllocBufferNonPagedPool()
{
	PWCHAR Buffer;
	Buffer = (PWCHAR) ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'BUFF');
	if (!Buffer)
	{
		return NULL;
	}
	RtlZeroMemory(Buffer, MAX_PATH_SIZE);
	return Buffer;
}


