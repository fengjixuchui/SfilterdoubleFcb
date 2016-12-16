#include "WDK.h"
#include "Include/Crc32.h"
#include "BaseTypes.h"


int InitKeys(int nSeeds, unsigned char* szKeyBuffer, unsigned int nKeyBufferLen, unsigned int nKeyLen)
{
	if(szKeyBuffer == NULL)
	{
		return ISAFE_BUFFER_NULL;
	}

	if(nKeyBufferLen < nKeyLen)
	{
		return ISAFE_BUFFER_OVERFLOW;
	}
    
    RtlZeroMemory(szKeyBuffer, nKeyBufferLen);

	unsigned int temp = nSeeds;
	for (unsigned int i = 0; i < nKeyLen; ++i)
	{
		unsigned int n, bit;
		for (n = 0; n < 32; n++)
		{
			bit = ((temp >> 0) ^ (temp >> 1) ^ (temp >> 2) ^ (temp >> 3) ^ (temp >> 5) ^ (temp >> 7)) & 1;
			temp = (((temp >> 1) | (temp << 31)) & ~1) | bit;
		}
		szKeyBuffer[i] = (unsigned char)temp;
	}

	return ISAFE_STATUS_SUCCESS;
}

int CrcMemory(const unsigned char* szInBuffer, unsigned int nBufferLen, unsigned int& dwCrc32)
{
	if(szInBuffer == NULL)
	{
		return ISAFE_BUFFER_NULL;
	}

    dwCrc32 = 0xFFFFFFFF;

	if(!CalcCrc32(szInBuffer, nBufferLen, dwCrc32))
	{
		return ISAFE_CRYPT_FAIL;
	}


	return ISAFE_STATUS_SUCCESS;
}


unsigned int GenerateRandom(unsigned int nSeeds)
{
	unsigned int n, bit, temp;
	temp = nSeeds;

	for (n = 0; n < 32; n++)
	{
		bit = ((temp >> 0) ^ (temp >> 1) ^ (temp >> 2) ^ (temp >> 3) ^ (temp >> 5) ^ (temp >> 7)) & 1;
		temp = (((temp >> 1) | (temp << 31)) & ~1) | bit;
	}

	return temp;
}


int EncryptXor(unsigned char* szKey, unsigned int nKeyLen, unsigned char* szInBuffer, unsigned int nInBufferLen,unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen)
{
	if(szInBuffer == NULL || szOutBuffer == NULL)
	{
		return ISAFE_BUFFER_NULL;
	}

	if(szKey == NULL)
	{
		return ISAFE_KEY_NULL;
	}

	if(nOutBufferLen < nInBufferLen)
	{
		return ISAFE_BUFFER_OVERFLOW;
	}

	for(unsigned int i = 0; i < nInBufferLen; ++i)
	{
		int key_pos = i % nKeyLen;
		szOutBuffer[i] = (szInBuffer[i] + szKey[key_pos]) ^ szKey[key_pos];
	}

	nOutDataLen = nInBufferLen;

	return ISAFE_STATUS_SUCCESS;
}


int DecryptXor(unsigned char* szKey, unsigned int nKeyLen, unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen)
{
	if(szInBuffer == NULL || szOutBuffer == NULL)
	{
		return ISAFE_BUFFER_NULL;
	}

	if(szKey == NULL)
	{
		return ISAFE_KEY_NULL;
	}

	if(nOutBufferLen < nInBufferLen)
	{
		return ISAFE_BUFFER_OVERFLOW;
	}

	for(unsigned int i = 0; i < nInBufferLen; ++i)
	{
		int key_pos = i % nKeyLen;
		szOutBuffer[i] = (szInBuffer[i] ^ szKey[key_pos]) - szKey[key_pos];
	}

	nOutDataLen = nInBufferLen;

	return ISAFE_STATUS_SUCCESS;
}


int EasyEncrypt(unsigned int nKey, unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen)
{
	unsigned char key[DEFAULT_KEY_LEN] = {0};

	int nRet = InitKeys(nKey, key, DEFAULT_KEY_LEN, DEFAULT_KEY_LEN);
	if( nRet != ISAFE_STATUS_SUCCESS)
	{
		return nRet;
	}

	return EncryptXor(key, DEFAULT_KEY_LEN, szInBuffer, nInBufferLen, szOutBuffer, nOutBufferLen, nOutDataLen);
}

int EasyDecrypt(unsigned int nKey, unsigned char* szInBuffer, unsigned int nInBufferLen, unsigned char* szOutBuffer, unsigned int nOutBufferLen, unsigned int& nOutDataLen)
{
	unsigned char key[DEFAULT_KEY_LEN] = {0};

	int nRet = InitKeys(nKey, key, DEFAULT_KEY_LEN, DEFAULT_KEY_LEN);
	if( nRet != ISAFE_STATUS_SUCCESS)
	{
		return nRet;
	}

	return DecryptXor(key, DEFAULT_KEY_LEN, szInBuffer, nInBufferLen, szOutBuffer, nOutBufferLen, nOutDataLen);
}

int EasyEncryptSelf(unsigned int nKey, unsigned char* szBuffer, unsigned int nBufferLen, unsigned int& nDataLen)
{
	return EasyEncrypt(nKey, szBuffer, nBufferLen, szBuffer, nBufferLen, nDataLen);
}

int EasyDecryptSelf(unsigned int nKey, unsigned char* szBuffer, unsigned int nBufferLen, unsigned int& nDataLen)
{
	return EasyDecrypt(nKey, szBuffer, nBufferLen, szBuffer, nBufferLen, nDataLen);
}



