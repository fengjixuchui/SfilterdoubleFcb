#pragma once

VOID BlockEncrypt(PUCHAR Buffer, ULONG Length, PUCHAR Key, ULONG KeyLength, struct rc4_state *State, INT BlockSize);
