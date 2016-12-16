#pragma once
#ifndef _ENV_
#define _ENV_

#include "../WDK.h"

// Include the following declaration in each C++ class in order to
// prevent the compiler from inadvertently putting a default destructor
// into the INIT segment (cf. Numega's white paper on C++ support)

#define DESTRUCTOR_HACK void Destruct(){delete this;}

typedef void(__cdecl *EXITFUNCTION)();
typedef void(__cdecl *INITFUNCTION)();

typedef struct _ATEXIT_LIST_ENTRY {
	LIST_ENTRY link;      // linking fields
	EXITFUNCTION f;        // function to call during exit processing
} ATEXIT_LIST_ENTRY, *PATEXIT_LIST_ENTRY;

static KSPIN_LOCK exitlock;      // spin lock to protect atexit list
static LIST_ENTRY exitlist;      // anchor of atexit list
PDRIVER_OBJECT theDriver;  // the address of our driver object

///////////////////////////////////////////////////////////////////////////////
// Declare dummy symbols to bound the pointers emitted by the compiler for
// static initialization functions.

#pragma data_seg(".CRT$XCA")
static INITFUNCTION BeginInitFunctions[1] = { 0 };

#pragma data_seg(".CRT$XCZ")
static INITFUNCTION EndInitFunctions[1] = { 0 };

#pragma data_seg()

///////////////////////////////////////////////////////////////////////////////
// ATEXIT records a function address to be called during C++ shutdown.
// Compiled code uses this to setup static destructors

extern "C" int __cdecl atexit(EXITFUNCTION f)
{              // atexit
	PATEXIT_LIST_ENTRY p = (PATEXIT_LIST_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(ATEXIT_LIST_ENTRY), 'exit');
	if (!p)
		return 0;

	p->f = f;
	ExInterlockedInsertTailList(&exitlist, &p->link, &exitlock);

	return 1;
}              // atexit

			   ///////////////////////////////////////////////////////////////////////////////
			   // CppInit initializes static objects

VOID CppInit(PDRIVER_OBJECT DriverObject)
{              // CppInit

	theDriver = DriverObject;

	// Initialize the list of atexit processing functions

	InitializeListHead(&exitlist);
	KeInitializeSpinLock(&exitlock);

	// Execute static initialization routines

	for (INITFUNCTION* p = BeginInitFunctions + 1; p < EndInitFunctions; ++p)
		(*p)();
}              // CppInit

			   ///////////////////////////////////////////////////////////////////////////////
			   // CppShutdown executes the atexit functions, which includes destructors for
			   // static objects

VOID CppShutdown()
{              // CppShutdown
	PATEXIT_LIST_ENTRY p;
	while ((p = (PATEXIT_LIST_ENTRY)
		ExInterlockedRemoveHeadList(&exitlist, &exitlock)))
	{            // for each item on list
		(*p->f)();
		ExFreePool(p);
	}            // for each item on list
}              // CppShutdown

#endif// _STRUCT_