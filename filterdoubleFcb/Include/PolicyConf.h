#include "MySTL.h"
#if 0
#pragma once
#ifndef __POLICYCONF_H__
#define __POLICYCONF_H__

#include "BaseTypes.h"

#define	ISAFE_POLICY_VERSION		0x0001

#define PRODUCT_TYPE_SAFEFILE			0x00000001
#define PRODUCT_TYPE_SAFEFILE_CONTROL	0x00000002
#define PRODUCT_TYPE_SAFEFILE_FLOW		0x00000004
#define PRODUCT_TYPE_DEVICE				0x00000100
#define PRODUCT_TYPE_NET				0x00000200
#define PRODUCT_TYPE_AUDIT				0x00001000
#define PRODUCT_TYPE_MONITOR			0x00010000
#define PRODUCT_TYPE_DEFENCE			0x00100000
#define PRODUCT_TYPE_PATCHER			0x00200000
#define PRODUCT_TYPE_VIRUS				0x00400000
#define PRODUCT_TYPE_FIREWALL			0x00800000
#define PRODUCT_TYPE_ACCESSGATE			0x01000000
#define PRODUCT_TYPE_SAFEGATE			0x02000000

#define OPER_TYPE_CREATE			0x00000001
#define OPER_TYPE_OPEN				0x00000002
#define OPER_TYPE_DELETE			0x00000004
#define OPER_TYPE_ZIP				0x00000008
#define OPER_TYPE_COPY				0x00000010
#define OPER_TYPE_HTTP				0x00000020
#define OPER_TYPE_HTTPFILE			0x00000040
#define OPER_TYPE_FTP				0x00000080
#define OPER_TYPE_EXECUTE			0x00000100
#define OPER_TYPE_SCREENSHOT        0x00000200
#define OPER_TYPE_MAIL		        0x00000400
#define OPER_TYPE_QQ				0x00000800
#define OPER_TYPE_MSN				0x00001000
#define OPER_TYPE_WANGWANG			0x00002000
#define OPER_TYPE_YY				0x00004000
#define OPER_TYPE_SKYPE				0x00008000

#define DEVICE_AUTH_OPEN			0x00000001
#define DEVICE_AUTH_READ			0x00000002
#define DEVICE_AUTH_WRITE			0x00000004
#define DEVICE_AUTH_EXECUTE			0x00000008

enum PolicyScriptType
{
	POLICY_NONE = 0,

	// 基本加密策略
	POLICY_ENCRYPT,					// 加密策略
	POLICY_GLOBAL_ENCRYPT,			// 落地加密

	// 白名单
	POLICY_PASS_PATH,				// 路径白名单
	POLICY_PASS_FILE,				// 文件白名单
	POLICY_PASS_PROCESS,			// 进程白名单
	POLICY_PASS_DLL,				// 模块白名单

	// 网络
	POLICY_NET_OPEN_PORTS,			// 允许网络端口
	POLICY_NET_ACCESS_GATE,			// 准入网关

	POLICY_END,
};

#pragma pack(push,1)
#pragma warning(push)
#pragma warning(disable:4200)

struct tagPolicyHead
{
	unsigned short	nVersion;							// 版本号
	unsigned short	nSubVersion;						// 子版本号
	bool			bEncryptFlag;						// 是否加密
	unsigned int	nCrc32;								// CRC校验
	int				nKey;								// 解密Key
};

struct tagProductInfo
{
	unsigned char	nLicenseType;						// 授权类型 账户授权 机器授权
	unsigned int	nProductType;						// 产品类型 支持32个模块
	unsigned char	nProductLevel;						// 安保等级
	unsigned int	nBeginTime;							// 授权开始时间
	unsigned int	nEndTime;							// 授权截止时间

	unsigned short	nPolicyUpdateInterval;				// 策略更新间隔（分钟）

	unsigned int	nHeartBeatInterval;					// 心跳包时间间隔（分钟）
	unsigned int	nOfflineAddTime;					// 离线补时（小时）
};

struct tagBaseAuth
{
	// 设备管控 x7 x6 x5 x4 x3 (设备可执行) x2（设备可写） x1（设备可读） x0（设备开启）
	unsigned char	bUDiskFlag;							// U盘设备 
	unsigned char	bCDROMFlag;							// 光驱设备
	unsigned char	bFloppyFlag;						// 软驱设备

	unsigned char	bComFlag;							// 串口设备
	unsigned char	bInfraredFlag;						// 红外设备

	unsigned char	bBluetoothFlag;						// 蓝牙设备	
	unsigned char	bWifiFlag;							// Wifi设备

	unsigned char	bDevice1Flag;						// 设备预留
	unsigned char	bDevice2Flag;						// 设备预留
	unsigned char	bDevice3Flag;						// 设备预留
	unsigned char	bDevice4Flag;						// 设备预留
	unsigned char	bDevice5Flag;						// 设备预留

	bool			bPrinterFlag;						// 打印机设备
	bool			bWatermarkFlag;						// 打印水印
	unsigned char	nWatermarkLevel;					// 水印颜色深浅 0-10 越大越深
	bool			bWatermarkPicFlag;					// 是否打印图片
	wchar_t			wszWatermarkText[SIZE_256];			// 水印内容
	wchar_t			wszWatermarkURL[SIZE_256];			// 水印图片地址

	// 主动防御
	bool			bSelfProtectFlag;					// 自身保护 进程防杀 目录防拷贝防删除
	bool			bProcessSigFlag;					// 进程签名
	bool			bModuleSigFlag;						// 模块签名
	bool			bDriverSigFlag;						// 驱动签名

	// 行为审计 数据监控
	bool			bAuditFlag;							// 行为审计
	unsigned int	nAuditType;							// 行为审计种类
	bool			bMonitorFlag;						// 数据监控
	unsigned int	nMonitorType;						// 数据监控种类

	bool			bScreenShotUploadFlag;				// 截屏开启
	unsigned int	nScreenShotUploadInterval;			// 截屏间隔
};

struct tagUserAuth
{
	tagBaseAuth		BaseAuth;

	wchar_t			wszUserName[SIZE_32];
	unsigned int	nUserID;
	unsigned char	nNodeID1;							// 组ID 0-255
	unsigned char	nNodeID2;
	unsigned char	nNodeID3;
	unsigned char	nNodeID4;

	bool			bModeModifyFlag;					// 是否允许用户改变模式
	unsigned char	nSecretDegree;						// 密级	0-15  0 普通  1 秘密 2 机密 3 绝密

	unsigned short	nCryptIndex;						// 加密算法索引
	bool			bCrc32Flag;							// 是否做CRC完整性校验

	bool			bGroupOnlyFlag;						// 默认组权限
	bool			bGroupKeyFlag;						// 组密钥

	bool			bTrayFlag;							// 托盘图标显示
	bool			bMainFormFlag;						// 主窗体显示
	bool			bQuitFlag;							// 是否可以退出
	bool			bSyncServerTimeFlag;				// 是否同步服务器时间

	bool			bBackupFlag;						// 是否备份
	bool			bBackupAskFlag;						// 是否询问用户是否备份
	unsigned char	nBackupInterval;					// 备份间隔（小时）
	wchar_t			wszBackupPath[SIZE_256];			// 备份路径

	bool			bBackupDeleteFlag;					// 是否备份删除文件
	wchar_t			wszBackupDeletePath[SIZE_256];		// 删除文件备份路径

	bool			bPopWindowFlag;						// 是否弹窗
	bool			bScreenShotFlag;					// 截屏控制

	bool			bLockScreenFlag;					// 是否自动锁屏
	unsigned int	nLockScreenValue;					// 自动锁屏无动作时间（分钟）

	bool			bOfflineFlowFlag;					// 离线申请
	bool			bOutFlowFlag;						// 外发申请
	bool			bDecryptFlowFlag;					// 解密申请
	bool			bUninstallFlowFlag;					// 卸载申请

	bool			bDecryptManageFlag;					// 离线审批
	bool			bOutManageFlag;						// 外发审批
	bool			bOfflineManageFlag;					// 解密审批
	bool			bUninstallManageFlag;				// 卸载审批

	bool			bPublisherToolFlag;					// 外发制作工具
	bool			bProcessSignatureToolFlag;			// 进程签名工具
	bool			bModuleSignatureToolFlag;			// 模块签名工具
	bool			bDriverSignatureToolFlag;			// 驱动签名工具
	bool			bDecryptToolFlag;					// 文档解密工具
	bool			bOfflineToolFlag;					// 离线授权工具
	bool			bUninstallToolFlag;					// 卸载授权工具	

	bool			bReservedToolFlag2;
	bool			bReservedToolFlag3;
	bool			bReservedToolFlag4;
	bool			bReservedToolFlag5;
	bool			bReservedToolFlag6;
};

struct tagKeyItem
{
	unsigned char	nKeyIndex;
	unsigned int	nNodeID;
	unsigned int	nKey;
	unsigned short	nKeyLen;
	unsigned short	nKeyDegree;
	bool			IsActiveFlag;
};

struct tagKeyList
{
	unsigned char	nKeyNums;							// 密钥数目
	tagKeyItem		KeyItem[KEY_NUMS];
};

struct tagScriptItem
{
	unsigned char	nItemNums;							// 脚本数目
	wchar_t			wszContent[POLICY_ITEM_NUMS][SIZE_256];
};

struct tagPolicyScriptItem
{
	unsigned char	nScriptType;						// 策略类型ID
	tagScriptItem	ContentList;						// 策略内容
	tagScriptItem	ProcessList;						// 策略关联进程
};

struct tagPolicyScriptList
{
	unsigned char	nPolicyNums;						// 策略数目
	tagPolicyScriptItem	PolicyItem[POLICY_NUMS];
};

struct tagSigItem
{
	wchar_t			wszName[SIZE_32];					// 名称
	unsigned int	nSize;								// 文件大小
	unsigned char	szSignature[SIZE_16];				// MD5签名
};

struct tagSigList
{
	unsigned char	nSigNums;							// 签名数目
	tagSigItem		SigItem[SIG_NUMS];
};

struct tagPolicy
{
	tagPolicyHead		PolicyHead;
	tagProductInfo		ProductInfo;
	tagBaseAuth			GlobalAuth;
	tagUserAuth			UserAuth;
	tagKeyList			KeyList;
	tagPolicyScriptList	PolicyScriptList;
	tagSigList			ProcessSigList;
};

#pragma warning(pop)
#pragma pack(pop)

#endif //__POLICYCONF_H__

#endif
#pragma once
#ifndef __POLICYCONF_H__
#define __POLICYCONF_H__

#include "BaseTypes.h"

#define	ISAFE_POLICY_VERSION			0x0001		//策略版本
#define	ISAFE_TEMP_POLICY_VERSION		0x0000		//策略版本

#define PRODUCT_TYPE_SAFEFILE			0x00000001	//文件加密
#define PRODUCT_TYPE_SAFEFILE_CONTROL	0x00000002	//权限控制
#define PRODUCT_TYPE_SAFEFILE_FLOW		0x00000004	//流程审批
#define PRODUCT_TYPE_DEVICE				0x00000100	//设备管控
#define PRODUCT_TYPE_NET				0x00000200	//上网管控
#define PRODUCT_TYPE_AUDIT				0x00001000	//行为审计
#define PRODUCT_TYPE_MONITOR			0x00010000	//数据监控
#define PRODUCT_TYPE_DEFENCE			0x00100000	//主动防御
#define PRODUCT_TYPE_PATCHER			0x00200000	//补丁管理
#define PRODUCT_TYPE_VIRUS				0x00400000	//杀毒
#define PRODUCT_TYPE_FIREWALL			0x00800000	//防火墙
#define PRODUCT_TYPE_ACCESSGATE			0x01000000	//准入网关
#define PRODUCT_TYPE_SAFEGATE			0x02000000	//安全网关

#define OPER_TYPE_CREATE			0x00000001
#define OPER_TYPE_OPEN				0x00000002
#define OPER_TYPE_DELETE			0x00000004
#define OPER_TYPE_ZIP				0x00000008
#define OPER_TYPE_COPY				0x00000010
#define OPER_TYPE_HTTP				0x00000020
#define OPER_TYPE_HTTPFILE			0x00000040
#define OPER_TYPE_FTP				0x00000080
#define OPER_TYPE_EXECUTE			0x00000100
#define OPER_TYPE_SCREENSHOT        0x00000200
#define OPER_TYPE_MAIL		        0x00000400
#define OPER_TYPE_QQ				0x00000800
#define OPER_TYPE_MSN				0x00001000
#define OPER_TYPE_WANGWANG			0x00002000
#define OPER_TYPE_YY				0x00004000
#define OPER_TYPE_SKYPE				0x00008000

#define DEVICE_AUTH_OPEN			0x00000001
#define DEVICE_AUTH_READ			0x00000002
#define DEVICE_AUTH_WRITE			0x00000004
#define DEVICE_AUTH_EXECUTE			0x00000008

enum PolicyScriptType
{
	POLICY_NONE = 0,

	// 基本加密策略
	POLICY_ENCRYPT,					// 加密策略
	POLICY_GLOBAL_ENCRYPT,			// 落地加密

	// 白名单
	POLICY_PASS_PATH,				// 路径白名单
	POLICY_PASS_FILE,				// 文件白名单
	POLICY_PASS_PROCESS,			// 进程白名单
	POLICY_PASS_DLL,				// 模块白名单

	// 网络
	POLICY_NET_OPEN_PORTS,			// 允许网络端口
	POLICY_NET_ACCESS_GATE,			// 准入网关

	POLICY_END,
};

#pragma pack(push,1)
#pragma warning(push)
#pragma warning(disable:4200)

struct tagPolicyHead
{
	unsigned short	nVersion;							// 版本号
	unsigned short	nSubVersion;						// 子版本号
	bool			bEncryptFlag;						// 是否加密
	unsigned int	nCrc32;								// CRC校验
	int				nKey;								// 解密Key
};

struct tagProductInfo
{
	unsigned char	nLicenseType;						// 授权类型 账户授权 机器授权
	unsigned int	nProductType;						// 产品类型 支持32个模块
	unsigned char	nProductLevel;						// 安保等级
	unsigned int	nBeginTime;							// 授权开始时间
	unsigned int	nEndTime;							// 授权截止时间

	unsigned short	nPolicyUpdateInterval;				// 策略更新间隔（分钟）

	unsigned int	nHeartBeatInterval;					// 心跳包时间间隔（分钟）
	unsigned int	nOfflineAddTime;					// 离线补时（小时）
};

struct tagBaseAuth
{
	// 设备管控 x7 x6 x5 x4 x3 (设备可执行) x2（设备可写） x1（设备可读） x0（设备开启）
	unsigned char	bUDiskFlag;							// U盘设备 
	unsigned char	bCDROMFlag;							// 光驱设备
	unsigned char	bFloppyFlag;						// 软驱设备

	unsigned char	bComFlag;							// 串口设备
	unsigned char	bInfraredFlag;						// 红外设备

	unsigned char	bBluetoothFlag;						// 蓝牙设备	
	unsigned char	bWifiFlag;							// Wifi设备

	unsigned char	bDevice1Flag;						// 设备预留
	unsigned char	bDevice2Flag;						// 设备预留
	unsigned char	bDevice3Flag;						// 设备预留
	unsigned char	bDevice4Flag;						// 设备预留
	unsigned char	bDevice5Flag;						// 设备预留

	bool			bPrinterFlag;						// 打印机设备
	bool			bWatermarkFlag;						// 打印水印
	unsigned char	nWatermarkLevel;					// 水印颜色深浅 0-10 越大越深
	bool			bWatermarkPicFlag;					// 是否打印图片
	wchar_t			wszWatermarkText[SIZE_256];			// 水印内容
	wchar_t			wszWatermarkURL[SIZE_256];			// 水印图片地址

	// 主动防御
	bool			bSelfProtectFlag;					// 自身保护 进程防杀 目录防拷贝防删除
	bool			bProcessSigFlag;					// 进程签名
	bool			bModuleSigFlag;						// 模块签名
	bool			bDriverSigFlag;						// 驱动签名

	// 行为审计 数据监控
	bool			bAuditFlag;							// 行为审计
	unsigned int	nAuditType;							// 行为审计种类
	bool			bMonitorFlag;						// 数据监控
	unsigned int	nMonitorType;						// 数据监控种类

	bool			bScreenShotUploadFlag;				// 截屏开启
	unsigned int	nScreenShotUploadInterval;			// 截屏间隔
};

struct tagUserAuth
{
	tagBaseAuth		BaseAuth;

	wchar_t			wszUserName[SIZE_32];
	unsigned int	nUserID;
	unsigned char	nNodeID1;							// 组ID 0-255
	unsigned char	nNodeID2;
	unsigned char	nNodeID3;
	unsigned char	nNodeID4;

	bool			bModeModifyFlag;					// 是否允许用户改变模式
	unsigned char	nSecretDegree;						// 密级	0-15  0 普通  1 秘密 2 机密 3 绝密

	unsigned short	nCryptIndex;						// 加密算法索引
	bool			bCrc32Flag;							// 是否做CRC完整性校验

	bool			bGroupOnlyFlag;						// 默认组权限
	bool			bGroupKeyFlag;						// 组密钥

	bool			bTrayFlag;							// 托盘图标显示
	bool			bMainFormFlag;						// 主窗体显示
	bool			bQuitFlag;							// 是否可以退出
	bool			bSyncServerTimeFlag;				// 是否同步服务器时间

	bool			bBackupFlag;						// 是否备份
	bool			bBackupAskFlag;						// 是否询问用户是否备份
	unsigned char	nBackupInterval;					// 备份间隔（小时）
	wchar_t			wszBackupPath[SIZE_256];			// 备份路径

	bool			bBackupDeleteFlag;					// 是否备份删除文件
	wchar_t			wszBackupDeletePath[SIZE_256];		// 删除文件备份路径

	bool			bPopWindowFlag;						// 是否弹窗
	bool			bScreenShotFlag;					// 截屏控制

	bool			bLockScreenFlag;					// 是否自动锁屏
	unsigned int	nLockScreenValue;					// 自动锁屏无动作时间（分钟）

	bool			bOfflineFlowFlag;					// 离线申请
	bool			bOutFlowFlag;						// 外发申请
	bool			bDecryptFlowFlag;					// 解密申请
	bool			bUninstallFlowFlag;					// 卸载申请

	bool			bDecryptManageFlag;					// 离线审批
	bool			bOutManageFlag;						// 外发审批
	bool			bOfflineManageFlag;					// 解密审批
	bool			bUninstallManageFlag;				// 卸载审批

	bool			bPublisherToolFlag;					// 外发制作工具
	bool			bProcessSignatureToolFlag;			// 进程签名工具
	bool			bModuleSignatureToolFlag;			// 模块签名工具
	bool			bDriverSignatureToolFlag;			// 驱动签名工具
	bool			bDecryptToolFlag;					// 文档解密工具
	bool			bOfflineToolFlag;					// 离线授权工具
	bool			bUninstallToolFlag;					// 卸载授权工具	

	bool			bReservedToolFlag2;
	bool			bReservedToolFlag3;
	bool			bReservedToolFlag4;
	bool			bReservedToolFlag5;
	bool			bReservedToolFlag6;
};

struct tagKeyItem
{
	unsigned char	nKeyIndex;			//密钥类型
	unsigned int	nNodeID;			//组id
	unsigned int	nKey;				//密钥索引
	unsigned short	nKeyLen;			//密钥长度
	unsigned short	nKeyDegree;
	bool			IsActiveFlag;
};

struct tagKeyList
{
	unsigned char	nKeyNums;							// 密钥数目
	tagKeyItem		KeyItem[KEY_NUMS];
};

struct tagScriptItem
{
	unsigned char	nItemNums;							// 脚本数目
	wchar_t			wszContent[POLICY_ITEM_NUMS][SIZE_256];
};

struct tagPolicyScriptItem
{
	unsigned char	nScriptType;						// 策略类型ID
	tagScriptItem	ContentList;						// 策略内容
	tagScriptItem	ProcessList;						// 策略关联进程
};

struct tagPolicyScriptList
{
	unsigned char	nPolicyNums;						// 策略数目
	tagPolicyScriptItem	PolicyItem[POLICY_NUMS];
};

struct tagSigItem
{
	wchar_t			wszName[SIZE_32];					// 名称
	unsigned int	nSize;								// 文件大小
	unsigned char	szSignature[SIZE_16];				// MD5签名
};

struct tagSigList
{
	unsigned char	nSigNums;							// 签名数目
	tagSigItem		SigItem[SIG_NUMS];
};

struct tagPolicy
{
	tagPolicyHead		PolicyHead;
	tagProductInfo		ProductInfo;
	tagBaseAuth			GlobalAuth;
	tagUserAuth			UserAuth;
	tagKeyList			KeyList;
	tagPolicyScriptList	PolicyScriptList;
	tagSigList			ProcessSigList;
};

/************************************
 * Temp Policy start
 *************************************/

class tagFileTempPolicyItem {
public:
	int nodeID;								//节点ID
	int fileKey;							//文件key
	char UUID[UUID_LEN];					//UUID
};

class tagProcessPolicyBlacklistItem {
public:
	CArray<int> processList;				//进程列表 存放签名ID
	PWCHAR alert;							//提示信息
};

class tagNetPolicyBlacklistItem {
public:
	CArray<USHORT> port;					//端口列表
	CArray<int> processList;				//进程列表 存放签名ID
	CArray<unsigned char[4]> ip;			//ip列表  转为Hex形式
	int protocal;							//协议类型 0、ALL 1、UDP 2、TCP
};

class tagProcessPolicy {
public:
	CArray<tagProcessPolicyBlacklistItem> blacklist;	//进程黑名单
};

class tagNetPolicy {
public:
	CArray<tagNetPolicyBlacklistItem> blacklist;		//网络黑名单
	CArray<tagNetPolicyBlacklistItem> whitelist;		//网络白名单
};

class tagEncryptPolicyItem
{
public:
	CArray<PWCHAR>	wszContent;
	CArray<int> processList;
};

class tagAuth {
public:
	int blockingNetWhenRelated;
};

class tagUserPolicy {
public:
	CArray<tagFileTempPolicyItem> fileTempPolicy;		//文件临时策略
	tagProcessPolicy	processPolicy;					//进程策略
	tagNetPolicy		netPolicy;						//网络策略
	CArray<tagEncryptPolicyItem>	encryptPolicy;
	tagAuth	auth;
};


class tagSignItem
{
public:
	int				id;							// 签名ID
	PWCHAR			fileName;					// 名称
	unsigned int	fileSize;					// 文件大小
	UCHAR			hash[SIZE_16];				// MD5签名
};

class tagSignature {
public:
	CArray<tagSignItem> processSignList;		//进程签名列表
};

class tagTempPolicyHead {
public:
	unsigned short	nVersion;							// 版本号
	unsigned short	nSubVersion;						// 子版本号
	bool			bEncryptFlag;						// 是否加密
	unsigned int	nCrc32;								// CRC校验
	int				nKey;								// 解密Key
	int				bodyLen;
};

class tagNodesItem {
public:
	int nodeId;										//节点ID
	int isAdmin;									//是否管理 1、是 0、否
};

class tagKeyItemNew
{
public:
	unsigned int	nKeyIndex;
	unsigned int	nNodeID;
	unsigned int	nKey;
	unsigned short	nKeyLen;
	unsigned short	nKeyDegree;
	bool			IsActiveFlag;
};

class tagUserConfig {
public:
	CArray<tagNodesItem>		nodeList;		//节点信息
	CArray<tagKeyItemNew>		keyList;
};

class tagTempPolicy {
public:
	tagTempPolicyHead		PolicyHead;
	tagUserPolicy			userPolicy;			//用户策略
	tagUserConfig			userConfig;			//用户信息
	tagSignature			signature;			//签名
};

#pragma warning(pop)
#pragma pack(pop)

#endif //__POLICYCONF_H__
