#pragma once
#ifndef __GLOBAL_H_INCLUDED
#define __GLOBAL_H_INCLUDED

#define FUNCTION_COM_DEFENCE
#define FUNCTION_NETWORK_DEFENCE
#define FUNCTION_DEFENCE_SELF


#include "WDK.h"
//#include "Inject.h"
//#include "ProcCallback.h"
//#include "Communication.h"
#include "FileUtils.h"
//#include "Config.h"
//#include "Ctx.h"
/*************************************************************************
Debug tracing information
*************************************************************************/

//
//  Definitions to display log messages.  The registry DWORD entry:
//  "hklm\system\CurrentControlSet\Services\Swapbuffers\DebugFlags" defines
//  the default state of these logging flags
//

#define LOGFL_ERRORS    0x00000001  // if set, display error messages
#define LOGFL_READ      0x00000002  // if set, display READ operation info
#define LOGFL_WRITE     0x00000004  // if set, display WRITE operation info
#define LOGFL_DIRCTRL   0x00000008  // if set, display DIRCTRL operation info
#define LOGFL_VOLCTX    0x00000010  // if set, display VOLCTX operation info

/*************************************************************************
Pool Tags
*************************************************************************/

#define BUFFER_SWAP_TAG     'bdBS'
#define CONTEXT_TAG         'xcBS'
#define NAME_TAG            'mnBS'
#define PRE_2_POST_TAG      'ppBS'

/*************************************************************************
Local structures
*************************************************************************/

//
//  This is a volume context, one of these are attached to each volume
//  we monitor.  This is used to get a "DOS" name for debug display.
//

typedef struct _VOLUME_CONTEXT {

	//
	//  Holds the name to display
	//

	UNICODE_STRING Name;

	//
	//  Holds the sector size for this volume.
	//

	ULONG SectorSize;

} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

#define MIN_SECTOR_SIZE 0x200

//
//  This is a lookAside list used to allocate our pre-2-post structure.
//

// extern NPAGED_LOOKASIDE_LIST gPre2PostContextList;

// /*
// * 全局配置
// */
// extern tagConfig g_Config;


// extern  PHANDLE Ppid;

// extern PULONG Pi;

// extern LONG my_Spin_Lock;

// extern  PBOOLEAN IsExistProcess1;

// extern WCHAR * procName;//进程名


// extern WCHAR * procwpsName;
// extern WCHAR * procEtName;//
// extern WCHAR * procwppName;


// extern WCHAR * procPOWName;//officePOW进程名
// extern WCHAR * procExcelName;//officeExcel进程名



// extern WCHAR *  notepadName;




// extern WCHAR * txtExt;




// extern WCHAR * FileExt;//文件后缀名


// extern WCHAR * docxExt;//DOCX文件后缀名
// extern CHAR  * wpsName;
// extern CHAR * EtName;//
// extern CHAR * wppName;


// extern WCHAR * PdfExt;//Pdf文件后缀名
// extern WCHAR * xlsxExt;
// extern WCHAR * DocExt;
// extern WCHAR * PPTXExt;
// extern WCHAR * PPTExt;

// extern int PTESize;
// extern UINT_PTR PAGE_SIZE_LARGE;
// extern UINT_PTR MAX_PDE_POS;
// extern UINT_PTR MAX_PTE_POS;

// extern ERESOURCE m_processResouce;

// extern "C" void InitMemSafe();

// extern "C"  bool IsAddressSafe(UINT_PTR StartAddress);

// extern "C" NTSTATUS ExAllocateWNamebuffterW(IN PUNICODE_STRING src, IN OUT WCHAR* &dev);
// //extern "C" NTSTATUS ExAllocateWNamebuffterA(IN PUNICODE_STRING src, IN OUT CHAR* &dev);


// extern "C" NTSTATUS InitializechatW(WCHAR* &dest, const WCHAR * src);
// extern "C" NTSTATUS InitializechatA(CHAR* &dest, const CHAR * src);


// extern "C"  
// VOID
// CtxReleaseResource(
	// PERESOURCE Resource
// );
// extern "C"
// VOID
// CtxAcquireResourceShared(
	// PERESOURCE Resource
// );


#endif