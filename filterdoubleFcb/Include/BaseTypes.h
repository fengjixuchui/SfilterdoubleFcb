#ifndef __BASETYPE_H__
#define __BASETYPE_H__
#include "../WDK.h"

#define		ISAFE_COMMON_VERSION	230

#define		SIZE_8				8
#define		SIZE_16				16
#define		SIZE_24				24
#define		SIZE_32				32
#define		SIZE_64				64
#define		SIZE_128			128
#define		SIZE_256			256
#define		SIZE_512			512
#define		SIZE_1024			1024
#define		SIZE_2048			2048
#define		SIZE_4096			4096

#define		SIGN_LENGTH			32

#define		DEFAULT_KEY_LEN		SIZE_16

#define		MD5_SIZE			SIZE_16

#define		KEY_NUMS			SIZE_64
#define		POLICY_NUMS			SIZE_32
#define		POLICY_SCRIPT_NUMS	SIZE_16
#define		POLICY_ITEM_NUMS	SIZE_16
#define		SIG_NUMS			SIZE_64

#define		FILE_HEAD_LEN		PAGE_SIZE

#define		DEFAULT_CONTENT_LEN	SIZE_256

#define		DEFAULT_BUFFER_LEN	65536

#ifndef		PATH_MAX
#define		PATH_MAX			260
#endif

#define		FILE_HEAD_SIG_LEN	10
#define		FILE_HEAD_SIG		"iSafeFile"

#define		SM_POLICY_NAME		_T("ISAFE_SM_POLICY")
#define		SM_AUTHCONTROL_NAME	_T("ISAFE_SM_AUTHCONTROL")
#define		SM_NETCONTROL_NAME	_T("ISAFE_SM_NETCONTROL")
#define		SM_BASECONFIG_NAME	_T("ISAFE_SM_BASECONFIG")

#define		WARDEN_EVENT_NAME	_T("ISAFE_WARDEN")

#define		DRIVER_LOCK_NAME	_T("ISAFE_LOCK")

#define		FILENAME_POLICY		_T("iSafe.dat")
#define		FILENAME_WATERMARK	_T("iWaterMark.png")

#define		ISAFE_SPLIT_STRING	_T("|")

#define		UUID_LEN	20
enum SecretDegree
{
	SECRET_DEGREE_PUBLIC = 0,	// 普通	
	SECRET_DEGREE_NORMAL,		// 秘密
	SECRET_DEGREE_CONFIDENTIAL,	// 机密
	SECRET_DEGREE_TOP,			// 绝密

	SECRET_DEGREE_END,
};

enum ProductLevel
{
	PRODUCT_LEVEL_1 = 1,
	PRODUCT_LEVEL_2,
	PRODUCT_LEVEL_3,

	PRODUCT_LEVEL_END,
};

enum SigType
{
	SIG_TYPE_EXE = 0,
	SIG_TYPE_DLL,
	SIG_TYPE_SYS,

	SIG_TYPE_END,
};

enum UserStatus
{
	USER_STATUS_ONLINE = 0,
	USER_STATUS_OFFLINE = 1,
	USER_STATUS_DISCONNECT = 2,

	USER_STATUS_END,
};

enum iSafeStatus
{
	ISAFE_STATUS_FAIL				= 0,
	ISAFE_STATUS_SUCCESS			= 1,

	// Basic
	ISAFE_UNKNOWN_CMD				= 50,
	ISAFE_EXCEPTION					= 51,
	ISAFE_CRYPT_FAIL				= 52,
	ISAFE_KEY_NULL					= 53,
	ISAFE_KEY_LENGTH				= 54,
	ISAFE_BLOCK_LENGTH				= 55,
	ISAFE_INIT_FAIL					= 56,
	ISAFE_BUFFER_NULL				= 57,
	ISAFE_BUFFER_ERROR_LEN			= 58,
	ISAFE_BUFFER_OVERFLOW			= 59,
	ISAFE_CRC_FAIL					= 60,
	ISAFE_ERROR_VERSION				= 61,
	ISAFE_MINILZO					= 62,
	ISAFE_JSON_PRASE_ERROR			= 63,
	// Key
	ISAFE_NO_KEY					= 100,
	ISAFE_KEY_BANNED,
	ISAFE_KEY_ZERO,

	// File Encrypt
	ISAFE_FILE_NOT_ENCRYPT			= 150,
	ISAFE_FILE_ALREADY_ENCRYPT,
	ISAFE_FILE_HEAD_OVERFLOW,
	ISAFE_FILE_DATA_TOO_SMALL,

	// Hook
	ISAFE_HOOK_NO_MEMORY			= 200,
	ISAFE_HOOK_NOT_SUPPORTED,
	ISAFE_HOOK_INSUFFICIENT_RESOURCES,
	ISAFE_HOOK_UNKNOWS,
	ISAFE_HOOK_STATUS_INVALID_PARAMETER_1,
	ISAFE_HOOK_STATUS_INVALID_PARAMETER_2,
	ISAFE_HOOK_STATUS_INVALID_PARAMETER_3,
	ISAFE_HOOK_UNINSTALLHOOK,
	ISAFE_HOOK_WAITFORPENDING,
	ISAFE_HOOK_FAIL,

	// ShareMemory
	ISAFE_SM_CREATE_FAIL			= 250,
	ISAFE_SM_OPEN_FAIL,
	ISAFE_SM_MAP_FAIL,

	// File
	ISAFE_NAME_NULL					= 300,
	ISAFE_GETPATH_FAIL,
	ISAFE_CREATEFILE_FAIL,
	ISAFE_READFILE_FAIL,
	ISAFE_READFILEHEAD_FAIL,
	ISAFE_WRITEFILE_FAIL,
	ISAFE_WRITEFILEHEAD_FAIL,
	ISAFE_DELETEFILE_FAIL,
	ISAFE_MOVEFILE_FAIL,
	ISAFE_SETFILEPOINTER_FAIL,
	ISAFE_AUTH_MODIFY_DENY,

	// Driver
	ISAFE_MESSAGE_DRIVER_FAIL		= 350,
	ISAFE_RETURN_ERROR_DATA_LEN,
	ISAFE_IS_RELATED_PROCESS,
	ISAFE_NOT_RELATED_PROCESS,
	ISAFE_DRIVER_RETURN_YES,
	ISAFE_DRIVER_RETURN_NO,

	ISAFE_STATUS_END,
};

#ifndef VOID
#define VOID			void			//标准空
typedef unsigned char	UCHAR;			//标准无符号CHAR
typedef char			CHAR;			//标准CHAR
typedef unsigned int	uint;			//标准无符号INT
typedef int				INT;			//标准INT
typedef unsigned short	USHORT;			//标准无符号short
typedef short			SHORT;			//标准short
typedef unsigned long	ULONG;			//标准无符号LONG(不推荐使用)
typedef long			LONG;			//标准LONG(不推荐使用)
typedef float			FLOAT;			//标准float
#endif

#ifndef _WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif

#ifndef MAX_PATH
#define MAX_PATH          260
#endif

#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif


#define ALIGN_TO_SIZE_DOWN(len, size) (len & (~(size - 1)) )
#define ALIGN_TO_SIZE_UP(len, size) ((len + size - 1) & (~ (size - 1)))

// Hook
typedef struct _LOCAL_HOOK_INFO_* PLOCAL_HOOK_INFO;
typedef struct _HOOK_TRACE_INFO_
{
	PLOCAL_HOOK_INFO        Link;
}HOOK_TRACE_INFO, *TRACED_HOOK_HANDLE;


#endif