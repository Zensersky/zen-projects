#pragma once
#ifndef LAUNCHER3_WINAPI_H
#define LAUNCHER3_WINAPI_H

#include <Windows.h>
#include <tlhelp32.h>
#include "ImportSafeNT.h"
#include "StrEncrypt.h"
#include "sha256.h"

class WinAPI {
#define CREATE_FUNC(Name, Typedef) using t##Name = Typedef; t##Name Name = nullptr
#define LOAD_FUNC(Function, Module) Function = reinterpret_cast<t##Function>(SafeNT::GetProcAddress(Module, sha256(XorString(#Function)))); \
if (Function == nullptr) { return false; }
public:
	//KERNEL32
	/*CREATE_FUNC(ReadProcessMemory, BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*));
	CREATE_FUNC(WriteProcessMemory, BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*));
	CREATE_FUNC(VirtualAllocEx, LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD));
	CREATE_FUNC(VirtualAlloc, LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD));
	CREATE_FUNC(VirtualFree, BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD));
	CREATE_FUNC(VirtualFreeEx, BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD));*/
	CREATE_FUNC(OpenProcess, HANDLE(WINAPI*)(DWORD, BOOL, DWORD));
	CREATE_FUNC(DeviceIoControl, BOOL(WINAPI*)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED));
	CREATE_FUNC(AddVectoredExceptionHandler, PVOID(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER));
	CREATE_FUNC(OpenThread, HANDLE(WINAPI*)(DWORD, BOOL, DWORD));
//For Window title detection
	CREATE_FUNC(EnumWindows, BOOL(WINAPI*)(WNDENUMPROC, LPARAM));
	CREATE_FUNC(GetWindowTextA, int(WINAPI*)(HWND, LPSTR, int));
	CREATE_FUNC(GetConsoleWindow, HWND(WINAPI*)(void));
	CREATE_FUNC(ShowWindow, BOOL(WINAPI*)(HWND, int));
	CREATE_FUNC(FindWindowA, HWND(WINAPI*)(LPCSTR, LPCSTR));

	CREATE_FUNC(CreateToolhelp32Snapshot, HANDLE(WINAPI*)(DWORD, DWORD));
	CREATE_FUNC(Process32First, BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32));
	CREATE_FUNC(Process32Next, BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32));

	CREATE_FUNC(CreateThread, HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD));
	CREATE_FUNC(GetThreadContext, BOOL(WINAPI*)(HANDLE, LPCONTEXT));
	CREATE_FUNC(SetThreadContext, BOOL(WINAPI*)(HANDLE, CONTEXT*));
	CREATE_FUNC(ResumeThread, DWORD(WINAPI*)(HANDLE));
	CREATE_FUNC(SuspendThread, DWORD(WINAPI*)(HANDLE));
	CREATE_FUNC(CloseHandle, BOOL(WINAPI*)(HANDLE));
	CREATE_FUNC(GetModuleHandleA, HMODULE(WINAPI*)(LPCSTR));
	CREATE_FUNC(WaitForSingleObject, DWORD(WINAPI*)(HANDLE, DWORD));
	CREATE_FUNC(CreateProcessA, BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION));
	CREATE_FUNC(ExitProcess, void(WINAPI*)(LONG));
	/*CREATE_FUNC(K32EnumDeviceDrivers, BOOL(WINAPI*)(LPVOID*, DWORD, LPDWORD));
	CREATE_FUNC(K32GetDeviceDriverBaseNameA, DWORD(WINAPI*)(LPVOID, LPSTR, DWORD));*/
	CREATE_FUNC(TerminateProcess, BOOL(WINAPI*)(HANDLE, UINT));
	CREATE_FUNC(GetExitCodeProcess, BOOL(WINAPI*)(HANDLE, LPDWORD));
	CREATE_FUNC(TerminateThread, BOOL(WINAPI*)(HANDLE, DWORD));
	CREATE_FUNC(GetTickCount, DWORD(WINAPI*)());
//NTDLL

	/*CREATE_FUNC(RtlInitializeResource, VOID(WINAPI*)(void*));
	CREATE_FUNC(NtAllocateVirtualMemory, NTSTATUS(WINAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG));
	CREATE_FUNC(RtlInitUnicodeString, NTSTATUS(WINAPI*)(void*, PCWSTR));*/
	CREATE_FUNC(RtlAddVectoredExceptionHandler, NTSTATUS(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER));

public:

	bool Init() {
		const auto kernel32 = SafeNT::GetModule(sha256((L"KERNEL32.DLL"), 24));
		if (kernel32) {
			/*LOAD_FUNC(ReadProcessMemory, kernel32);
			LOAD_FUNC(WriteProcessMemory, kernel32);
			LOAD_FUNC(VirtualAllocEx, kernel32);
			LOAD_FUNC(VirtualAlloc, kernel32);
			LOAD_FUNC(VirtualFree, kernel32);
			LOAD_FUNC(VirtualFreeEx, kernel32);*/
			LOAD_FUNC(CloseHandle, kernel32);
			LOAD_FUNC(OpenProcess, kernel32);
			LOAD_FUNC(DeviceIoControl, kernel32);
			LOAD_FUNC(AddVectoredExceptionHandler, kernel32);
			LOAD_FUNC(GetConsoleWindow, kernel32);

			LOAD_FUNC(CreateToolhelp32Snapshot, kernel32);
			LOAD_FUNC(Process32First, kernel32);
			LOAD_FUNC(Process32Next, kernel32);

			LOAD_FUNC(CreateThread, kernel32);
			LOAD_FUNC(GetThreadContext, kernel32);
			LOAD_FUNC(SetThreadContext, kernel32);
			LOAD_FUNC(ResumeThread, kernel32);
			LOAD_FUNC(SuspendThread, kernel32);
			LOAD_FUNC(CloseHandle, kernel32);
			LOAD_FUNC(GetModuleHandleA, kernel32);
			LOAD_FUNC(WaitForSingleObject, kernel32);
			LOAD_FUNC(CreateProcessA, kernel32);
			LOAD_FUNC(OpenThread, kernel32);
			LOAD_FUNC(ExitProcess, kernel32);
			/*LOAD_FUNC(K32EnumDeviceDrivers, kernel32);
			LOAD_FUNC(K32GetDeviceDriverBaseNameA, kernel32);*/
			LOAD_FUNC(TerminateProcess, kernel32);
			LOAD_FUNC(GetExitCodeProcess, kernel32);
			LOAD_FUNC(TerminateThread, kernel32);
			LOAD_FUNC(GetTickCount, kernel32);

		}
		const auto ntdll = SafeNT::GetModule(sha256((L"ntdll.dll"),18));
		if (ntdll)
		{
			/*LOAD_FUNC(RtlInitializeResource, ntdll);
			LOAD_FUNC(NtAllocateVirtualMemory, ntdll);
			LOAD_FUNC(RtlInitUnicodeString, ntdll);*/
			LOAD_FUNC(RtlAddVectoredExceptionHandler, ntdll);
		}

		const auto user32 = SafeNT::GetModule(sha256((L"USER32.dll"), 20));
		if (user32)
		{
			LOAD_FUNC(EnumWindows, user32);
			LOAD_FUNC(GetWindowTextA, user32);
			LOAD_FUNC(ShowWindow, user32);
			LOAD_FUNC(FindWindowA, user32);
		}

		return true;
	}
};

inline WinAPI WinApi;

#endif //LAUNCHER3_WINAPI_H