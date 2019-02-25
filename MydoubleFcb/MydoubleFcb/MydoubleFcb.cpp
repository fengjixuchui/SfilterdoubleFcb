// MydoubleFcb.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<stdlib.h>
#include <windows.h>
#include "Head.h"




//#define MAX_PATH 512

#pragma warning(disable:4100)

typedef struct _CONFIGDATA
{
	ULONG	nNextOffset;
	BOOLEAN bBackup;
	WCHAR	szEXEPath [512];
	UCHAR	EXEHashValue[512];
	LONG	bAllowInherent;
	LONG	bEnableEncrypt;
	LONG	bForceEncryption;
	LONG	szBytesOfFileTypes;
	LONG	bAbone;
	LONG    bCreateExeFile;
	LONG    bBrowser;
	ULONG	BrowserEncryptTypeValue;
	WCHAR	szFileTypes[1];
}ConfigData,*PConfigData;

typedef enum _TAGPROTECTTYPE
{
	NOACCESS_INVISIBLE =0,
	NOACCESS_VISABLE
}PROTECTTYPE;
typedef struct _tagFodlerProtectorInfo
{
	PROTECTTYPE Type;	
	ULONG		bEncryptRealTime;
	ULONG		EncryptForFileTypes;
	ULONG		bBackup;	
	ULONG       State;	
	WCHAR		szDisplayName[50];
}FODLERPROTECTORINFO,*PFODLERPROTECTORINFO;
typedef struct _tagAddProtectedFolder
{
	WCHAR		szFolderPath[1024];
	FODLERPROTECTORINFO FolderProtectInfo;
}ADDPROTECTEDFOLDER,*PADDPROTECTEDFOLDER,*PFolderWithProtectorInfo,FolderWithProtectorInfo;


VOID Funcerr(CHAR* str,INT ret0){
	//int LastError = GetLastError();
	CHAR szBuf[128];
	LPVOID lpMsgBuf;
	FormatMessageA (
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		ret0,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR) &lpMsgBuf,
		0, NULL );
	sprintf(szBuf,
		("%s 出错信息 (出错码=%d):%s"),
		str, ret0, lpMsgBuf);
	LocalFree(lpMsgBuf);
#ifdef _CONSOLE
	printf("%s",szBuf);
#else
	OutputDebugString(szBuf);
#endif

}
int _tmain(int argc, _TCHAR* argv[])
{
	//UNREFERENCED_PARAMETER(argc); 
	//UNREFERENCED_PARAMETER(argv);
	               char* BufferData = new char[16];
				   PConfigData promInfo = (PConfigData)malloc(sizeof(_CONFIGDATA));
				   PVOID outbuffter = malloc(sizeof(LONG));
				   PADDPROTECTEDFOLDER FoledrInfo = (PADDPROTECTEDFOLDER)malloc(sizeof(ADDPROTECTEDFOLDER));


	__try{

	HANDLE DeviceHandle = CreateFile(FILESPY_W32_DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (DeviceHandle==INVALID_HANDLE_VALUE)
	{
        printf("Communication failure\r\n");
		getchar();
		return 0;
	}
	char BufferDataP = NULL;
	DWORD ReturnLength = 0;
	BOOL IsOk = DeviceIoControl(DeviceHandle, PFPCOMMAND_StartDriver,
		0,
		0,
		(LPVOID)BufferDataP,
		0,
		&ReturnLength,
		NULL);
	if (IsOk == FALSE)
	{
		Funcerr("PFPCOMMAND_StartDriver",IsOk);
	}
	if (IsOk == TRUE)
			{
			  printf("Finish one  please Input AnyKey\r\n");
			  system("pause");
              CopyMemory(BufferData,"ABCDEFGHIJKLMNOP",16);
              LPVOID pOutBufferData;
                if (strlen(BufferData)==16)
                {
                     printf("BufferDatalength is ok\r\n");
                }
				IsOk = DeviceIoControl(DeviceHandle, PFPCOMMAND_SetEncryptKey,
					(LPVOID)BufferData,
					16,
					(LPVOID)pOutBufferData,
					NULL,
					&ReturnLength,
					NULL);
				delete BufferData;
				if (IsOk == TRUE)
				{
					printf("Finish double please Input AnyKey\r\n");
					system("pause");
                    ZeroMemory(promInfo,sizeof(ConfigData));
					UCHAR hashValue[513] = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111222222222222"; 
                    WCHAR szEXEPath []  = L"C:\\Windows\\System32\\notepad.exe";
                     promInfo->bAbone= 0;
                     promInfo->bAllowInherent = 0;
					 promInfo->bBackup = 0;
					 promInfo->bBrowser = 0;
					 promInfo->bCreateExeFile = 0;
					 promInfo->bEnableEncrypt = TRUE;
					 promInfo->bForceEncryption = TRUE;  //强制加密类型
					 promInfo->BrowserEncryptTypeValue = 0;
					 CopyMemory(promInfo->EXEHashValue,hashValue,512);
					 promInfo->nNextOffset = 0x1314;
					 promInfo->szBytesOfFileTypes = 3;
					 CopyMemory(promInfo->szEXEPath,szEXEPath,512);
                    // promInfo->szFileTypes = "1";
                  
					IsOk = DeviceIoControl(DeviceHandle, PFPCOMMAND_AddPrograms,
						(LPVOID)promInfo,
						sizeof(ConfigData),
						(LPVOID)outbuffter,
						sizeof(outbuffter),
						&ReturnLength,
						NULL);
					    free(promInfo) ;
					    free(outbuffter) ;
					if (IsOk == TRUE)
					{  
                       ZeroMemory(FoledrInfo->szFolderPath,1024);
					   ZeroMemory(FoledrInfo ->FolderProtectInfo.szDisplayName,50);
                       CopyMemory(FoledrInfo->szFolderPath,_T("C:\\1111"),1024);
                       FoledrInfo->FolderProtectInfo.bBackup = NULL;
                       FoledrInfo->FolderProtectInfo.bEncryptRealTime = NULL;
                       FoledrInfo ->FolderProtectInfo.EncryptForFileTypes = 0; //0是文件夹所有加密 1是指定加密对应的文件类型 2好像都不加密
					   FoledrInfo ->FolderProtectInfo.State = 1; //0是锁定文件夹禁止访问  1是解锁文件夹
					   CopyMemory(FoledrInfo ->FolderProtectInfo.szDisplayName,"1111",50);
                       FoledrInfo ->FolderProtectInfo.Type = NOACCESS_VISABLE;
					   IsOk = DeviceIoControl(DeviceHandle, PFPCOMMAND_AddFolderProtectionInfo,
						   (LPVOID)FoledrInfo,
						   sizeof(ADDPROTECTEDFOLDER),
						   (LPVOID)outbuffter,
						   sizeof(outbuffter),
						   &ReturnLength,
						   NULL);
					   free(FoledrInfo);
                      printf("DeviceIoControl is Finished\r\n");
					}else{
					  Funcerr("PFPCOMMAND_AddPrograms",IsOk);
					}
				}else{
					  Funcerr("PFPCOMMAND_SetEncryptKey",IsOk);
				}
			}		
	
	if (DeviceHandle != NULL)
	{
		CloseHandle(DeviceHandle);
		DeviceHandle = NULL;
	}
	}__except(1){

	if (BufferData!=NULL)
	{
		delete BufferData;
	}
	if (promInfo!=NULL)
	{
		free (promInfo);
	}if (outbuffter!=NULL)
	{
		free (outbuffter);
	}if(FoledrInfo !=NULL)
	{
         free(FoledrInfo);
	}
	  Funcerr("__except",GetLastError());
}
	printf("Input AnyKey To Exit\r\n");
	system("pause");
	return 0;
}



