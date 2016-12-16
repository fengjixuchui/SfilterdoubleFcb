#ifndef _COMMON_
#define _COMMON_

#include <fltKernel.h>


BOOLEAN
GetDriverLetter(
	IN PUNICODE_STRING VolumeName,
	OUT PWCHAR DriveLetter
	);

BOOLEAN
GetDosPathName(
	IN PFLT_FILE_NAME_INFORMATION FileNameInfo,
	OUT PWCHAR *DosPathName
	);



VOID
DumpFileInfo(
	PFLT_FILE_NAME_INFORMATION FileNameInfo
	);

BOOLEAN
GetRegValue(
	IN PWCHAR RegPath,
	IN PWCHAR KeyName,
	OUT PWCHAR RegValueBuffer,
	IN INT RegValueSize
	);

BOOLEAN
RegPathMatch(
	IN PUNICODE_STRING RegPath,
	IN PUNICODE_STRING RegProtectPath
	);

wchar_t* wcsistr(const wchar_t *s1, const wchar_t *s2);

typedef struct _Globalcountlist
{
	LIST_ENTRY ListEntry;
	HANDLE pid; //进程PID
	ULONG  count;//创建计数
	BOOLEAN PidisExist;
}Globallinklist, *PGloballinklist;

BOOLEAN
InitializeList(OUT LIST_ENTRY &linkListHead, IN OUT KSPIN_LOCK & my_spin_lock);

VOID Insertlist(IN HANDLE pid, ULONG cout, IN OUT LIST_ENTRY &linkListHead, IN KSPIN_LOCK &my_spin_lock);

VOID Removelist(IN  LIST_ENTRY &linklist, IN KSPIN_LOCK &my_spin_lock);

BOOLEAN Querylist(IN HANDLE Pid, IN PGloballinklist pData, OUT LIST_ENTRY &ListEntry, IN KSPIN_LOCK &my_spin_lock);

#endif// _LOG_