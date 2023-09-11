#include "SysCallHandler.h"

sSysCallData SysCallData;

#ifndef XorString
#define XorString
#endif

#define LOAD_SYSCALL(x) pSysCallData->x = GetSyscallIndex(XorString(#x)); if(pSysCallData->x == NULL) {return FALSE;}

DWORD GetSyscallIndex(const char* Function)
{
	DWORD* pFunction = (DWORD*)GetProcAddress(GetModuleHandleA("ntdll.dll"), (Function));

	if (!pFunction)
		return NULL;

	return *(DWORD*)((uintptr_t)pFunction + 0x4);
}

BOOL InitSyscalls(sSysCallData* pSysCallData)
{
	//VMProtectBeginMutation("InitSyscalls");

	LOAD_SYSCALL(NtDeviceIoControlFile);
	LOAD_SYSCALL(NtQueryInformationProcess);
	LOAD_SYSCALL(NtTerminateProcess);
	LOAD_SYSCALL(NtSetInformationThread);
	LOAD_SYSCALL(NtGetContextThread);
	LOAD_SYSCALL(NtQueryPerformanceCounter);
	LOAD_SYSCALL(NtQuerySystemInformation);
	LOAD_SYSCALL(NtQueryVirtualMemory);
	LOAD_SYSCALL(NtProtectVirtualMemory);
	LOAD_SYSCALL(NtLoadDriver);
	LOAD_SYSCALL(NtUnloadDriver);
	LOAD_SYSCALL(NtShutdownSystem);
	LOAD_SYSCALL(NtAllocateVirtualMemory);
	LOAD_SYSCALL(NtFreeVirtualMemory);
	LOAD_SYSCALL(NtPlugPlayControl);

	//VMProtectEnd();

	return true;
}
