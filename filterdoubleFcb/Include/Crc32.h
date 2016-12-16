#pragma once
#ifndef __CRC32_H__
#define __CRC32_H__

#define  CRC_MAX_SIZE	(4096)



void Crc32(const unsigned char bVal, unsigned int &dwCrc32);

bool CalcCrc32(const void* pMemory, unsigned int dwBfferSize, unsigned int& dwCrc32);


#endif