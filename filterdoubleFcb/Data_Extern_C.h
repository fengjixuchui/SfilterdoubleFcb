#pragma once
#include <ntddk.h>
#ifdef __cplusplus
extern "C" {
#endif
	VOID	 InitData(PDRIVER_OBJECT DriverObject);
	NTSTATUS InitSystemRootPath();
#ifdef __cplusplus
}
#endif