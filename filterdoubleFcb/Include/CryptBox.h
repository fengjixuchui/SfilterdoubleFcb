#pragma once
#ifndef __CRYPTBOX_H__
#define __CRYPTBOX_H__

#include "BaseTypes.h"

int InitKeys(int nSeeds, unsigned char* szKeyBuffer, unsigned int nKeyBufferLen, unsigned int nKeyLen = DEFAULT_KEY_LEN);

int CrcMemory(const unsigned char* szInBuffer, unsigned int nBufferLen, unsigned int& dwCrc32);

int EncryptXor(unsigned char* szKey, unsigned int nKeyLen, unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen);

int DecryptXor(unsigned char* szKey, unsigned int nKeyLen, unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen);

int EasyEncrypt(unsigned int nKey, unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen);

int EasyDecrypt(unsigned int nKey, unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen);

int EasyEncryptSelf(unsigned int nKey, unsigned char* szBuffer, unsigned int nBufferLen, unsigned int& nDataLen);

int EasyDecryptSelf(unsigned int nKey, unsigned char* szBuffer, unsigned int nBufferLen, unsigned int& nDataLen);

int Compress(unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen);

int Decompress(unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen);

unsigned int GenerateRandom(unsigned int nSeeds);

#endif