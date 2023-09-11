#pragma once
#include <cstdlib>
#include <type_traits>
#include <cstdint>
#include <Windows.h>
//#include "ImportHiderWinAPI.h"

namespace detail
{
	extern "C" void* _syscaller_stub();

	template <typename... Args>
	static inline auto syscall_stub_helper(
		Args... args
	) -> void*
	{
		auto fn = reinterpret_cast<void* (*)(Args...)>(&_syscaller_stub);
		return fn(args...);
	}

	template <std::size_t argc, typename>
	struct argument_remapper
	{
		// At least 5 params
		template<
			typename First,
			typename Second,
			typename Third,
			typename Fourth,
			typename... Pack
		>
		static auto do_call(
			std::uint32_t idx,
			First first,
			Second second,
			Third third,
			Fourth fourth,
			Pack... pack
		) -> void*
		{
			return syscall_stub_helper(first, second, third, fourth, idx, nullptr, pack...);
		}
	};

	template <std::size_t Argc>
	struct argument_remapper<Argc, std::enable_if_t<Argc <= 4>>
	{
		// 4 or less params
		template<
			typename First = void*,
			typename Second = void*,
			typename Third = void*,
			typename Fourth = void*
		>
		static auto do_call(
			std::uint32_t idx,
			First first = First{},
			Second second = Second{},
			Third third = Third{},
			Fourth fourth = Fourth{}
		) -> void*
		{
			return syscall_stub_helper(first, second, third, fourth, idx, nullptr);
		}
	};
}

template<typename Return, typename... Args>
static inline auto do_syscall(
	std::uint32_t idx,
	Args... args
) -> Return
{
	using mapper = detail::argument_remapper<sizeof...(Args), void>;
	return (Return)mapper::do_call(idx, args...);
}

struct sSysCallData
{
	DWORD NtDeviceIoControlFile;
	DWORD NtQueryInformationProcess;
	DWORD NtTerminateProcess;
	DWORD NtSetInformationThread;
	DWORD NtGetContextThread;
	DWORD NtQueryPerformanceCounter;
	DWORD NtQuerySystemInformation;
	DWORD NtQueryVirtualMemory;
	DWORD NtProtectVirtualMemory;
	DWORD NtAllocateVirtualMemory;
	DWORD NtFreeVirtualMemory;

	DWORD NtLoadDriver;
	DWORD NtUnloadDriver;

	DWORD NtShutdownSystem;
	DWORD NtPlugPlayControl;
};

DWORD GetSyscallIndex(const char* Function);

extern sSysCallData SysCallData;
BOOL InitSyscalls(sSysCallData* pSysCallData);

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  

__forceinline PVOID sNtAllocateVirtualMemory(HANDLE handle, PVOID address, SIZE_T size, ULONG type, ULONG protect)
{
	//VMProtectBeginVirtualization("Security.sNtAllocateVirtualMemory");

	PVOID Buffer = address; SIZE_T SizeBuffer = size;
	if (do_syscall<NTSTATUS>(SysCallData.NtAllocateVirtualMemory, handle, &Buffer, NULL, &SizeBuffer, type, protect) != 0x0)
		return nullptr;

	//VMProtectEnd();

	return Buffer;
}

__forceinline BOOL sNtFreeVirtualMemory(HANDLE handle, LPVOID address, SIZE_T size, DWORD type)
{
	//VMProtectBeginVirtualization("Security.sNtFreeVirtualMemory");

	LPVOID Buffer = address; SIZE_T SizeBuffer = size;
	if (do_syscall<NTSTATUS>(SysCallData.NtFreeVirtualMemory, handle, &Buffer, &SizeBuffer, type) != 0x0)
		return FALSE;

	//VMProtectEnd();

	return TRUE;
}

__forceinline BOOL sDeviceIoControl(HANDLE hdevice, DWORD code, LPVOID InBuff, DWORD InBuffSize, LPVOID OutBuff, DWORD OutBuffSize, LPDWORD BytesReturned, LPOVERLAPPED overlapped)
{
	//VMProtectBeginVirtualization("Security.sDeviceIOControl");
	typedef struct _IO_STATUS_BLOCK {
		union {
			NTSTATUS Status;
			PVOID    Pointer;
		} DUMMYUNIONNAME;
		ULONG_PTR Information;
	} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

	IO_STATUS_BLOCK StatusBlock = { 0 };
	NTSTATUS status = do_syscall<NTSTATUS>(SysCallData.NtDeviceIoControlFile, hdevice, NULL, NULL, NULL, &StatusBlock, code, InBuff, InBuffSize, OutBuff, OutBuffSize);

	if (status != 0x0)
		return false;

	if (BytesReturned)
		*BytesReturned = StatusBlock.Information;

	//VMProtectEnd();

	return (StatusBlock.Status == 0x0);
}
