#pragma once
#ifndef __SAFEFILE_H__
#define __SAFEFILE_H__

#include "FileConf.h"
#include "Struct.h"
#include "PolicyConf.h"

bool IsEncryptBuffer(IN unsigned char* szInBuffer, IN unsigned int nInBufferLen);

int GetFileHeadInfo(OUT tagFileInfo* FileInfo, IN unsigned char* szInBuffer, IN unsigned int nInBufferLen);

//int DecryptFileHead(IN PENCRYPT_IO EncryptIo, IN unsigned char* szInBuffer, IN unsigned int nInBufferLen/*, OUT unsigned char* szOutBuffer, IN unsigned int nOutBufferLen, OUT unsigned int& nOutDataLen*/);
int DecryptFileHead(IN PENCRYPT_IO EncryptIo, OUT tagFileInfo* FileInfo, IN unsigned char* szInBuffer, IN unsigned int nInBufferLen/*, OUT unsigned char* szOutBuffer, IN unsigned int nOutBufferLen, OUT unsigned int& nOutDataLen*/);
int EncryptFileHead(IN PENCRYPT_IO EncryptIo, IN tagFileInfo* FileInfo, /*IN unsigned char* szInBuffer, IN unsigned int nInBufferLen, */OUT unsigned char* szOutBuffer, IN unsigned int nOutBufferLen, OUT unsigned int& nOutDataLen);

int DecryptFileHeadSelf(IN PENCRYPT_IO EncryptIo, IN unsigned char* szBuffer, IN unsigned int nBufferLen, OUT unsigned int& nDataLen);
int DecryptFileHeadSelf(IN PENCRYPT_IO EncryptIo, IN tagFileInfo* FileInfo, IN unsigned char* szBuffer, IN unsigned int nBufferLen, OUT unsigned int& nDataLen);
int EncryptFileHeadSelf(IN PENCRYPT_IO EncryptIo, IN tagFileInfo* FileInfo, IN unsigned char* szBuffer, IN unsigned int nBufferLen, OUT unsigned int& nDataLen);

int PolicyToFileInfo(IN tagPolicy* Policy, IN OUT tagFileInfo* FileInfo);
int PolicyToTempFileInfo(IN tagPolicy* Policy, IN OUT tagFileInfo* FileInfo);

#endif