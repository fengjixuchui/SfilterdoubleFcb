#include "Common.h"

//#include "Log.h"
#include "Struct.h"
#include <ntstrsafe.h>
#include "Utils.h"

BOOLEAN
GetDriverLetter(
	IN PUNICODE_STRING VolumeName,
	OUT PWCHAR DriveLetter
	)
{
	BOOLEAN				Result = FALSE;
	NTSTATUS			Status;
	PWCHAR				TempDriveLetterBuf = NULL;
	PWCHAR				LinkValueBuf = NULL;
	UNICODE_STRING		TempDriveLetter;
	UNICODE_STRING		LinkValue;

	__try
	{
		TempDriveLetterBuf = (PWCHAR) ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'DRIV');
		if (!TempDriveLetterBuf)
		{
			//DebugTrace(DEBUG_TRACE_DEBUG, ("GetDriverLetter!TempDriveLetterBuf ExAllocatePoolWithTag Fail.\n"));
			__leave;
		}

		LinkValueBuf = (PWCHAR) ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'ttag');
		if (!LinkValueBuf)
		{
			//DebugTrace(DEBUG_TRACE_DEBUG, ("GetDriverLetter!LinkValueBuf ExAllocatePoolWithTag Fail.\n"));
			__leave;
		}

		for (UCHAR i = 'A'; i <= 'Z'; i++)
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

		for (UCHAR i = 'a'; i <= 'z'; i++)
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
			ExFreePool(TempDriveLetterBuf);
		}

		if (LinkValueBuf)
		{
			ExFreePool(LinkValueBuf);
		}
	}

	return Result;
}

BOOLEAN
GetDosPathName(
	IN PFLT_FILE_NAME_INFORMATION FileNameInfo,
	OUT PWCHAR *DosPathName
	)
{
	PWCHAR					DosPathNameBuf = NULL;
	WCHAR					DriveLetter[2] = { 0 };
	UNICODE_STRING			DosPathNameTemp;

	if (!DosPathName)
	{
		//		DebugTrace(DEBUG_TRACE_DEBUG, ("GetDosPathName!DosPathName = null\n"));
		return FALSE;
	}

	if (!FileNameInfo || !FileNameInfo->Volume.Buffer || !FileNameInfo->FinalComponent.Buffer || !FileNameInfo->ParentDir.Buffer)
	{
		//		DebugTrace(DEBUG_TRACE_DEBUG, ("GetDosPathName!FileNameInfo = null\n"));
		return FALSE;
	}

	if (GetDriverLetter(&FileNameInfo->Volume, DriveLetter))
	{
		DosPathNameBuf = (PWCHAR) ExAllocatePoolWithTag(NonPagedPool, MAX_PATH_SIZE, 'NDPN');
		if (!DosPathNameBuf)
		{
			//DebugTrace(DEBUG_TRACE_DEBUG, ("GetDosPathName!DosPathNameBuf ExAllocatePoolWithTag Fail.\n"));
			return FALSE;
		}
		RtlZeroMemory(DosPathNameBuf, MAX_PATH_SIZE);

		RtlStringCchPrintfW(DosPathNameBuf, MAX_PATH, L"%S:", DriveLetter);
		DosPathNameTemp.Buffer = DosPathNameBuf;
		DosPathNameTemp.Length = wcslen(DosPathNameBuf) * sizeof(WCHAR);
		DosPathNameTemp.MaximumLength = MAX_PATH_SIZE;

		RtlUnicodeStringCat(&DosPathNameTemp, &FileNameInfo->ParentDir);
		FileNameInfo->FinalComponent.Length -= FileNameInfo->Stream.Length;
		RtlUnicodeStringCat(&DosPathNameTemp, &FileNameInfo->FinalComponent);

		*DosPathName = DosPathNameBuf;

		return TRUE;
	}
	return FALSE;
}

VOID
DumpFileInfo(
	PFLT_FILE_NAME_INFORMATION FileNameInfo
	)
{
	//DebugTrace(DEBUG_TRACE_DEBUG, ("----DumpFileInfo Begin----\n"));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.Extension = %S\n", FileNameInfo->Extension.Buffer));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.FinalComponent = %S\n", FileNameInfo->FinalComponent.Buffer));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.Name = %S\n", FileNameInfo->Name.Buffer));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.ParentDir = %S\n", FileNameInfo->ParentDir.Buffer));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.Share = %S\n", FileNameInfo->Share.Buffer));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.Size = %d\n", FileNameInfo->Size));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.Stream = %S\n", FileNameInfo->Stream.Buffer));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("	FileNameInfo.Volume = %S\n", FileNameInfo->Volume.Buffer));
	//DebugTrace(DEBUG_TRACE_DEBUG, ("----DumpFileInfo End----\n"));
}

BOOLEAN
GetRegValue(
	IN PWCHAR RegPath,
	IN PWCHAR RegKeyName,
	OUT PWCHAR RegValueBuffer,
	IN INT RegValueSize
	)
{
	NTSTATUS						Status;
	BOOLEAN							Result = FALSE;
	HANDLE							KeyHandle = NULL;
	OBJECT_ATTRIBUTES				ObjectAttributes;
	PKEY_VALUE_PARTIAL_INFORMATION	ValueInfo = NULL;
	ULONG							ReturnLength;
	UNICODE_STRING					UnicodeRegPath;
	UNICODE_STRING					UnicodeKeyName;

	RtlInitUnicodeString(&UnicodeRegPath, RegPath);
	RtlInitUnicodeString(&UnicodeKeyName, RegKeyName);

	InitializeObjectAttributes(
		&ObjectAttributes,
		&UnicodeRegPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
		);

	Status = ZwOpenKey(&KeyHandle, GENERIC_READ, &ObjectAttributes);
	if (!NT_SUCCESS(Status))
	{
		//DebugTrace(DEBUG_TRACE_DEBUG, ("GetRegValue!ZwOpenKey Fail. Status = %08x %S\n", Status, RegPath));
		return FALSE;
	}

	__try
	{
		Status = ZwQueryValueKey(KeyHandle, &UnicodeKeyName, KeyValuePartialInformation, ValueInfo, 0, &ReturnLength);
		if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW)
		{
			ValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, ReturnLength, 'NREG');
			if (!ValueInfo)
			{
				//DebugTrace(DEBUG_TRACE_DEBUG, ("GetRegValue!ExAllocatePoolWithTag Fail. ValueInfo is null\n"));
				__leave;
			}

			Status = ZwQueryValueKey(KeyHandle, &UnicodeKeyName, KeyValuePartialInformation, ValueInfo, ReturnLength, &ReturnLength);
			if (!NT_SUCCESS(Status))
			{
				//DebugTrace(DEBUG_TRACE_DEBUG, ("GetRegValue!ZwQueryValueKey Fail. %S\n", RegKeyName));
				__leave;
			}

			if (ValueInfo->DataLength > (ULONG) RegValueSize)
			{
				//DebugTrace(DEBUG_TRACE_DEBUG, ("GetRegValue!Buffer Too Small. BufferSize = %d DataLen = %d\n", RegValueSize, ValueInfo->DataLength));
				__leave;
			}

			RtlCopyMemory(RegValueBuffer, ValueInfo->Data, ValueInfo->DataLength);
			//DebugTrace(DEBUG_TRACE_DEBUG, ("GetRegValue!%S %S = %S\n", RegPath, RegKeyName, RegValueBuffer));
			Result = TRUE;
		}
	}
	__finally
	{
		if (ValueInfo)
		{
			ExFreePool(ValueInfo);
		}

		if (KeyHandle)
		{
			ZwClose(KeyHandle);
		}
	}
	return Result;
}

BOOLEAN
RegPathMatch(
	IN PUNICODE_STRING RegPath,
	IN PUNICODE_STRING RegProtectPath
	)
{
	NTSTATUS					Status;
	BOOLEAN						Result = FALSE;
	HANDLE						KeyHandle = NULL;
	OBJECT_ATTRIBUTES			ObjectAttributes;
	ULONG						ReturnLength;
	PKEY_NAME_INFORMATION		KeyName = NULL;

	__try
	{
		InitializeObjectAttributes(
			&ObjectAttributes,
			RegProtectPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL
			);


		//  DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> RegProtectPath = %S\n", RegProtectPath->Buffer));
		Status = ZwOpenKey(&KeyHandle, GENERIC_READ, &ObjectAttributes);
		//  DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> IRQL END\n"));
		if (!NT_SUCCESS(Status))
		{
			//		DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> ZwOpenKey Fail. RegPath = %S\n", RegPath->Buffer));
			//		DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> ZwOpenKey Fail. RegProtectPath = %S\n", RegProtectPath->Buffer));
			//		DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> ZwOpenKey Fail. Status = 0x%x\n", Status));
			__leave;
		}

		Status = ZwQueryKey(KeyHandle, KeyNameInformation, NULL, 0, &ReturnLength);
		if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW)
		{
			KeyName = (PKEY_NAME_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, ReturnLength, 'NREG');
			if (!KeyName)
			{
				//DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> ExAllocatePoolWithTag Fail. KeyName is null\n"));
				__leave;
			}

			Status = ZwQueryKey(KeyHandle, KeyNameInformation, KeyName, ReturnLength, &ReturnLength);
			if (!NT_SUCCESS(Status))
			{
				//DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> ZwQueryKey Fail. Status = %08x\n", Status));
				__leave;
			}

			if (RegPath->Length < KeyName->NameLength)
			{
				__leave;
			}

			if (_wcsnicmp(RegPath->Buffer, KeyName->Name, KeyName->NameLength / sizeof(WCHAR)) == 0)
			{
				//DebugTrace(DEBUG_TRACE_DEBUG, ("Common!RegPathMatch -> Match. KeyName = %S\n", KeyName->Name));
				Result = TRUE;
				__leave;
			}
		}
	}
	__finally
	{
		if (KeyName)
		{
			ExFreePool(KeyName);
		}

		if (KeyHandle)
		{
			ZwClose(KeyHandle);
		}
	}

	return Result;
}

wchar_t* wcsistr(const wchar_t *s1, const wchar_t *s2)
{
	int n;
	if (*s2)
	{
		while (*s1)
		{
			for (n = 0; tolower(*(s1 + n)) == tolower(*(s2 + n)); n++)
			{
				if (!*(s2 + n + 1))
					return (wchar_t *) s1;
			}
			s1++;
		}
		return NULL;
	}
	else
		return (wchar_t *) s1;
}

//////////////////////////////////////////////////////------------------------------------------------------------

//初始化链表
BOOLEAN
InitializeList(OUT LIST_ENTRY &linkListHead , IN OUT KSPIN_LOCK & my_spin_lock)
{
	// 初始化
	InitializeListHead(&linkListHead);

	KeInitializeSpinLock(&my_spin_lock);

	return TRUE;
}
//插入我自己的链表 
VOID Insertlist(IN HANDLE pid, ULONG cout, IN OUT LIST_ENTRY &linkListHead ,IN KSPIN_LOCK &my_spin_lock) {

	// 中断级别
	ULONG i = 0; // 计数
	PGloballinklist  pData;
	KIRQL irql = NULL;


	KdPrint(("[Wrench] Begin insert to link list"));


	KeAcquireSpinLock(&my_spin_lock, &irql);

	pData = (PGloballinklist)ExAllocatePoolWithTag(PagedPool, sizeof(Globallinklist), 'jpmw');

	pData->pid = pid;

	pData->count = cout;

	linkListHead.Flink = NULL;

	linkListHead.Blink = NULL;

	InsertHeadList(&linkListHead, &pData->ListEntry);

	KeReleaseSpinLock(&my_spin_lock, irql);


}



VOID Removelist(IN  LIST_ENTRY &linklist , IN KSPIN_LOCK &my_spin_lock)
{

	PGloballinklist pData;
	KIRQL irql = NULL;
	KdPrint(("[Wrench] 开始移除链接链表\n"));

	KeAcquireSpinLock(&my_spin_lock, &irql);

	while (!IsListEmpty(&linklist))

	{

		PLIST_ENTRY pEntry = RemoveTailList(&linklist); //
		pData = CONTAINING_RECORD(pEntry, Globallinklist, ListEntry);
		KdPrint(("[Wrench]正在删除此pid为:%d这个链表块的数据\n", pData->pid));
		ExFreePool(pData);
	}
	KeReleaseSpinLock(&my_spin_lock, irql);


}

//根据pid查询列表

BOOLEAN Querylist(IN HANDLE Pid, IN PGloballinklist pData, OUT LIST_ENTRY &ListEntry, IN KSPIN_LOCK &my_spin_lock) {
	KIRQL irql = NULL;
	if (Pid == pData->pid) {
		ListEntry = pData->ListEntry;
		KdPrint(("[Wrench]The Pid is opend\n"));
		return TRUE;
	}
	else {
		while (1) {
			if (pData->ListEntry.Flink != NULL)
			{
				pData = (PGloballinklist)pData->ListEntry.Flink;
			}
			else {
				KdPrint(("no get...\n"));
				return FALSE;
			}
			if (Pid == pData->pid) {
				ListEntry = pData->ListEntry;
				KdPrint(("[Wrench] Find process is opend\n"));
				return TRUE;
			}
		}

	}
}
