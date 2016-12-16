#pragma once
#ifndef __POLICY_INCLUDED
#define __POLICY_INCLUDED

#include "PolicyConf.h"

//extern BOOLEAN InitPolicy;

int ImportPolicy(OUT tagPolicy* Policy);

int ImportPolicy(OUT tagPolicy* Policy, IN unsigned char* szInBuffer, unsigned int nInBufferLen);

int GetKeyByKeyIndex(IN CArray<tagKeyItemNew>& keyList, unsigned int nKeyIndex, tagKeyItemNew& Key);

int GetKey(CArray<tagKeyItemNew>& keyList, tagKeyItemNew& Key);

BOOLEAN Check_Process_Ext_Parse_Policy(PWCHAR content, PWCHAR NameBuff);
BOOLEAN Get_File_Ext(IN PWCHAR dev, OUT PWCHAR Str, OUT size_t  length);

/*
 * 导入临时策略
 */
int ImportTempPolicy(OUT tagTempPolicy *tempPolicy, IN unsigned char* szBuffer, IN int size);

#endif