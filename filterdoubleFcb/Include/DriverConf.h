#pragma once

#define ISAFE_DRIVER_VERSION			14
#define ISAFE_DRIVER_NAME				_T("RJ-iSafe")
#define	ISAFE_DRIVER_DISPLAY			_T("RJ-iSafe(c) Data Protection System.")
#define	ISAFE_DRIVER_DESC				_T("RJ-iSafe(c) Protect Your Data & Keep Your Data Safe.")
#define ISAFE_DRIVER_ALTITUDE			_T("140010")

#define ISAFE_DRIVER_PORT				L"\\iSafePort"
#define ISAFE_DRIVER_SCAN_PORT			L"\\iSafeScanPort"

#define DRIVER_FILE						L"FileSafe.sys"
#define REG_RUN_PATH					L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RJ-iSafe"
#define REG_INSTALL_PATH				L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\RJ-iSafe"

#define REG_FIREWALL_PATH				L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\SharedAccess"
#define REG_NET_CONTROL_PATH			L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"


enum DRIVER_CMD
{
	DRIVER_CMD_NONE = 0,
	DRIVER_CMD_GET_VERSION,
	DRIVER_CMD_POLICY_UPDATE,

	DRIVER_CMD_DEBUG_TRACE_LEVEL,

	DRIVER_CMD_CHECK_RELATED_PROCESS,
	DRIVER_CMD_CHECK_RELATED_PROCESS_EXIST,
	DRIVER_CMD_CHECK_READONLYFILE_EXIST,

	DRIVER_CMD_RESTORE_DLL_DATA,

	DRIVER_CMD_CHECK_FILE_COPY,
	DRIVER_CMD_CHECK_FILE_PRINT,

	DRIVER_CMD_CHECK_SAVEAS_FLAG,

	DRIVER_CMD_WORKMODEFLAG_SET,
	DRIVER_CMD_WORKMODEFLAG_QUERY,

	DRIVER_CMD_ONLINEFLAG_SET,
	DRIVER_CMD_ONLINEFLAG_QUERY,

	DRIVER_CMD_GUARD_START,

	DRIVER_CMD_SYNC_TIME,

	DRIVER_CMD_DEFENCE_START = 50,
	DRIVER_CMD_DEFENCE_STOP,
	DRIVER_CMD_DEFENCE_QUERY,

	DRIVER_CMD_REG_PROTECT_ADD,
	DRIVER_CMD_REG_PROTECT_REMOVE,
	DRIVER_CMD_REG_PROTECT_CLEAR,
	DRIVER_CMD_REG_PROTECT_QUERY,

	DRIVER_CMD_DIR_PROTECT_ADD,
	DRIVER_CMD_DIR_PROTECT_REMOVE,
	DRIVER_CMD_DIR_PROTECT_CLEAR,
	DRIVER_CMD_DIR_PROTECT_QUERY,

	DRIVER_CMD_PROCESS_PROTECT_ADD,
	DRIVER_CMD_PROCESS_PROTECT_REMOVE,
	DRIVER_CMD_PROCESS_PROTECT_CLEAR,
	DRIVER_CMD_PROCESS_PROTECT_QUERY,
	DRIVER_CMD_PROCESS_PROTECT_QUERYID,

	DRIVER_CMD_CRYPT_XOR = 100,
	DRIVER_CMD_CRYPT_RC4,
	DRIVER_CMD_CRYPT_AES,
	DRIVER_CMD_CRYPT_HARDWARE,
	DRIVER_CMD_CRYPT_CRC,
	DRIVER_CMD_CRYPT_MD5,
	DRIVER_CMD_CRYPT_COMPRESS,

	DRIVER_CMD_LOG_AUDIT = 150,
	DRIVER_CMD_LOG_MONITOR,
	DRIVER_CMD_SHOW_INFO,
	DRIVER_CMD_ASK_YESNO,
	DRIVER_CMD_ASK_PASSWORD,
	DRIVER_CMD_LOG_FILE_OPEN,
	DRIVER_CMD_LOG_UNKNOWN_SIGN,

	DRIVER_PROC_GET = 200,

	DRIVER_CMD_END,
};

#pragma pack(push,1)
#pragma warning(push)
#pragma warning(disable:4200)

struct OperHead
{
	unsigned short	nCommand;
	unsigned short	nStatus;
	unsigned int	nCode;
	unsigned int	nCrcCode;
	unsigned short	nBufferSize;
	char			szBuffer[0];

	static int GetHeadSize()
	{
		return sizeof(unsigned short) + sizeof(unsigned short) + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned short);
	}
};

#pragma warning(pop)
#pragma pack(pop)
