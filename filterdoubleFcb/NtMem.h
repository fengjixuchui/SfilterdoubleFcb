// ÷ÿ‘ÿnew°¢delete  µœ÷malloc°¢free°¢calloc°¢realloc
#pragma once
#ifndef __NTMEM_INCLUDED
#define __NTMEM_INCLUDED

#include "WDK.h"

#ifdef new
#undef new
#endif

#ifdef delete
#undef delete
#endif

#pragma push_macro("calloc")
#pragma push_macro("free")
#pragma push_macro("malloc")
#pragma push_macro("realloc")
#ifdef calloc
#undef calloc
#endif
#ifdef free
#undef free
#endif
#ifdef malloc
#undef malloc
#endif
#ifdef realloc
#undef realloc
#endif

//#define calloc(_NumOfElements,_SizeOfElements)		__calloc(_NumOfElements,_SizeOfElements)
//#define free(_Memory)								__free(_Memory)
//#define malloc(_Size)								__malloc(_Size)
//#define realloc(_Memory,_NewSize)					__realloc(_Memory,_NewSize)
//#define calloc										__calloc
//#define free										__free
//#define malloc										__malloc
//#define realloc										NULL

void * __malloc(__in size_t _Size);
void * __calloc(__in size_t _NumOfElements, __in size_t _SizeOfElements);
void  __free(__inout_opt void * _Memory);
void * mallocp(__in size_t _Size);
void * callocp(__in size_t _NumOfElements, __in size_t _SizeOfElements);


//void * reallocp(__in_opt void * _Memory, __in size_t _NewSize) {
//	free(_Memory);
//	return mallocp(_NewSize);
//}
#ifdef __cplusplus

inline void* __cdecl operator new (size_t _Size){
	return ExAllocatePoolWithTag(NonPagedPool,_Size,'nmem');
}

inline void __cdecl operator delete (void* _P){
	if (_P) {
		ExFreePool(_P);
	}
}

inline void* __cdecl operator new[] (size_t _Size){
	return ExAllocatePoolWithTag(NonPagedPool,_Size,'nmem');
}

inline void* __cdecl operator new[](size_t _Size, bool zero) {
	PVOID addr = ExAllocatePoolWithTag(NonPagedPool, _Size, 'nmem');
	if (zero) {
		memset(addr, 0, _Size);
	}
	return addr;
}

inline void __cdecl operator delete[] (void* _P) {
	if (_P) {
		ExFreePool(_P);
	}
}
#endif
#endif