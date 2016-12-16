#pragma once
#ifndef __NETCONF_INCLUDED
#define __NETCONF_INCLUDED

#include "BaseTypes.h"

/*
 * 数据监控配置结构
 */
enum PROTOCAL
{
	PROTOCAL_ALL = 0,
	PROTOCAL_UDP = 1,
	PROTOCAL_TCP = 2
};

struct tagNetPolicyOld
{
	char			szAccessGateAddr[SIZE_512];			// 准入访问地址列表（分隔符|）
	unsigned short	nPortList[SIZE_32];
	WCHAR			process[SIZE_512];
	PROTOCAL		protocal;
};

struct tagNetControl
{
	int				NetPolicySize;
	tagNetPolicyOld (*NetPolicy);
	bool			bNetFlag;							// 是否允许网络
	unsigned int	nPortList[SIZE_32];					// 允许端口列表

	bool			bAccessGateFlag;					// 准入网关
	char			szAccessGateAddr[SIZE_512];			// 准入访问地址列表（分隔符|）
};

#endif //__NETCONF_H__
