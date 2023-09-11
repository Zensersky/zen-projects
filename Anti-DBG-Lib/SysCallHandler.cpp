#include "SysCallHandler.h"

sSysCallData SysCallData;

#define LOAD_SYSCALL(x) pSysCallData->x = GetSyscallIndex(XorString(#x)); if(pSysCallData->x == NULL) {return FALSE;} MessageBoxA(NULL, std::to_string(pSysCallData->x).c_str(), ###x, MB_OK)

DWORD GetSyscallIndex(const char * Function)
{
	DWORD * pFunction = (DWORD*)SafeNT::GetProcAddress(SafeNT::GetModule(sha256((L"ntdll.dll"), 18)), sha256(Function));

	if (!pFunction)
		return NULL;

	return *(DWORD*)((uintptr_t)pFunction + 0x4);
}

BOOL InitSyscalls(sSysCallData * pSysCallData)
{
	LOAD_SYSCALL(NtWriteVirtualMemory);
	LOAD_SYSCALL(NtReadVirtualMemory);
	LOAD_SYSCALL(NtAllocateVirtualMemory);
	LOAD_SYSCALL(NtFreeVirtualMemory);
	LOAD_SYSCALL(NtDeviceIoControlFile);
	LOAD_SYSCALL(NtCreateProcess);
	LOAD_SYSCALL(NtCreateUserProcess);
	LOAD_SYSCALL(NtQueryInformationProcess);
	LOAD_SYSCALL(NtTerminateProcess);
	LOAD_SYSCALL(NtSetInformationThread);
	LOAD_SYSCALL(NtGetContextThread);
	LOAD_SYSCALL(NtQueryPerformanceCounter);
	LOAD_SYSCALL(NtQuerySystemInformation);

	return true;
}
