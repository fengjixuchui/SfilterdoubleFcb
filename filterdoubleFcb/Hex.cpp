#include "Hex.h"

char HexCharToBinChar(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

char Hex2Bin(const char *p) {
	char temp = 0;
	temp = HexCharToBinChar(p[0]);
	temp <<= 4;
	temp |= HexCharToBinChar(p[1]);
	return temp;
}

bool Hex2Bin(const char *p, char * outBuf, int sizeOfBuf) {
	int i = 0;
	while (*p)
	{
		if (*p == ' ') {
			p++;
			continue;
		}
		if (!*(p + 1)) {
			return false;
		}
		if (sizeOfBuf < i) {
			return false;
		}
		outBuf[i] = Hex2Bin(p);
		i++;
		p += 2;
	}
	return true;
}