#pragma once
#ifndef __FILECONF_INCLUDED
#define __FILECONF_INCLUDED

#include "BaseTypes.h"

#define	ISAFE_FILE_VERSION				0x0001

#pragma pack(push,1)
#pragma warning(push)
#pragma warning(disable:4200)

enum FILE_STATUS {
	FILE_STATUS_BROKEN,
	FILE_STATUS_NORMAL,
	FILE_STATUS_PENDING,
	FILE_STATUS_DELETED,
	FILE_STATUS_TEMP
};

#define FILE_STATUS_SIGN_NORMAL		"v2Tgz69Ef8l4p[1"
#define FILE_STATUS_SIGN_DELETED	"H5Z.Wz8Fr8W4b7Q"
#define FILE_STATUS_SIGN_PENDING	"uIe6Dhv5^Yh3kLB"
#define FILE_STATUS_SIGN_TEMP		"4e[Wg*jo4R68^1;"
#define FILE_STATUS_SIGN_LEN 16
#define HEAD_WARNING "警告！这是榕基数据安全系统加密的文件，若直接修改内容将造成文件损坏！！！"

#define FILE_CRYPT_BLOCK_SIZE  512 //文件加密块大小

#define	PEER_KEY_LEN	32

struct tagFileHead
{
	char			szHeadSig[10];				// 文件标志
	char			szStatusSig[16];			// 类型标识
	char			szWarning[80];				// 文件标志
	unsigned short	nVersion;					// 版本

	unsigned int	nHeadCrc32;					// 文件头CRC

	unsigned char	bHeadEncryptFlag;			// 加密标志
	unsigned int	nHeadKey;					// 文件头密钥
};

struct tagFileInfo
{
	tagFileHead		FileHead;

	unsigned short	nHeadLen;					// 文件头原长度
	unsigned short	nHeadDataLen;				// 文件头压缩后长度

	unsigned long long llFileSize;				// 文件大小
	unsigned int	nFileCrc32;					// 文件CRC校验码

	unsigned char	nSecretDegree : 3;			// 密级	0-15  0 普通  1 秘密 2 机密 3 绝密

	unsigned char   bCryptIndex : 4;			// 加密算法索引 0-15
	unsigned char	bKeyFlag : 1;				// 0:密钥索引 1:真实密钥
	unsigned int	nKeyIndex;					// 密钥索引

	unsigned char	bTagFlag;					// 是否使用标签文件

	unsigned int    nKey;						// 真实密钥
	unsigned short	nKeyLen;					// 密钥长度

	unsigned int	nUserID;					// 创建者ID

	unsigned char	bFileControlFlag;		// 文件权限控制标志

	unsigned char   bGroupOnlyFlag : 1;			// 仅组内成员
	unsigned char	bModifyFlag : 1;			// 修改权限
	unsigned char	bCopyFlag : 1;				// 复制权限
	unsigned char	bPrintFlag : 1;				// 打印权限
	unsigned char	bPrintTimesFlag : 1;		// 打印次数控制
	unsigned char	bReadTimesFlag : 1;			// 解密次数
	unsigned char	bLifeCycleFlag : 1;			// 生命周期控制

	unsigned char	bFileCrcFlag : 1;			// 开启文件完整性校验
	unsigned char	bModifyAuthFlag : 1;		// 是否允许修改权限
	unsigned char	bSelfDestoryFlag : 1;		// 是否自动销毁
	unsigned char	bPasswordFlag : 1;			// 开启密码访问内容复制权限

	unsigned char	bGroupID_1_InheritFlag : 1;	// 组织结构继承关系
	unsigned char	bGroupID_2_InheritFlag : 1;	// 组织结构继承关系
	unsigned char	bGroupID_3_InheritFlag : 1;	// 组织结构继承关系
	unsigned char	bGroupID_4_InheritFlag : 1;	// 组织结构继承关系

	unsigned char	nNodeID_1;					// 用户组ID 0-255
	unsigned char	nNodeID_2;					// 用户组ID 0-255
	unsigned char	nNodeID_3;					// 用户组ID 0-255
	unsigned char	nNodeID_4;					// 用户组ID 0-255

	unsigned char	nPrintTimes;				// 允许打印次数 0-255
	unsigned char	nReadTimes;					// 允许解密次数	0-255

	unsigned int	nBeginTime;					// 开始时间
	unsigned int	nEndTime;					// 截止时间

	unsigned int	nPassword;					// 密码

	unsigned char	uuid[UUID_LEN];				// 文件UUID

	unsigned int	publicKeyId;				// 安全密钥序号

	unsigned char	peerKey[PEER_KEY_LEN];		// 安全密钥
	
	unsigned char	shareKeyType;				// 0、未加密 1、已加密

	unsigned char	shareKey[PEER_KEY_LEN];		// 仅用于传递数据，不记录到文件数据
};
typedef struct tagFileInfo *pTagFileInfo;

#pragma warning(pop)
#pragma pack(pop)

#define FILEHEAD_HEAD_LEN	sizeof(tagFileHead)
#define FILEHEAD_INFO_LEN	sizeof(tagFileInfo)
#define FILEHEAD_BODY_LEN	(FILEHEAD_INFO_LEN - FILEHEAD_HEAD_LEN)

#endif