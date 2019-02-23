#pragma once
#pragma pack(4)
#include <windows.h>

#define DLLTMP "C:\\Users\\Administrator\\AppData\\Local\\Temp\\copyDllHook.dll"
#define RARTMP "C:\\Users\\Administrator\\AppData\\Local\\Temp\\Rar.exe "
#define UNRARTMP "C:\\Users\\Administrator\\AppData\\Local\\Temp\\UnRAR.exe"
#define TMPDIR "C:\\Users\\Administrator\\AppData\\Local\\Temp\\RJUNCOMOUTGONINGFILETOOL__"
#define E_TMPDIR "E:\\XUJYALDSKFJLSKDFJKLSDFJALSDKFJLKSD"

#define EncryptHeader (LONGLONG)0xA1F0B4CF378EB4C8

typedef struct _Time {
	char startuserTime[20] ;
	char stopuserTime[20] ;
}Time,*PTime;

//这个是加密后的文件写在文件头里的information
typedef struct _RjFileSrtuct {
	char FileHeadName[20] ; //文件头的名字
	char FileSrcName [60];  //原本文件的名称
	Time Outgoingfiletime; //文件外发时间记录
	INT Count;//使用次数
	BOOLEAN forbidensaveas;//是否禁用另存为
	BOOLEAN onlyread;//是否只读
	ULONG length; //加密buffter的长度；
}RjFileSrtuct, *pRjFileSrtuct;

//目标加密文件所拥有的信息
typedef struct  _rjFileInfo {
	RjFileSrtuct encryptHead;
	char *  EncryptBuffer; //加密后的buffer  //这里也是四字节对齐晕
}rjFileInfo,*prjFileInfo;









