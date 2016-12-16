#include "NtMem.h"

//void * calloc(__in size_t _NumOfElements, __in size_t _SizeOfElements);
//void   free(__inout_opt void * _Memory);
//void * malloc(__in size_t _Size);
//void * realloc(__in_opt void * _Memory, __in size_t _NewSize);

void * __malloc(__in size_t _Size) {
	return ExAllocatePoolWithTag(NonPagedPool, _Size, 'nmem');
}

void * __calloc(__in size_t _NumOfElements, __in size_t _SizeOfElements) {
	return __malloc(_NumOfElements * _SizeOfElements);
}

void  __free(__inout_opt void * _Memory) {
	if (_Memory)
		ExFreePool(_Memory);
}

//void * __realloc(__in_opt void * _Memory, __in size_t _NewSize) {
//
//	size_t ysize = ExQueryPoolBlockSize(_Memory, NULL);
//
//	void* newMem = malloc(_NewSize);
//
//	if (ysize > _NewSize) {
//		memcpy(newMem, _Memory, _NewSize);
//	} else {
//		memcpy(newMem, _Memory, ysize);
//	}
//	free(_Memory);
//	return newMem;
//}

void * mallocp(__in size_t _Size) {
	return ExAllocatePoolWithTag(PagedPool, _Size, 'nmem');
}

void * callocp(__in size_t _NumOfElements, __in size_t _SizeOfElements) {
	return mallocp(_NumOfElements * _SizeOfElements);
}