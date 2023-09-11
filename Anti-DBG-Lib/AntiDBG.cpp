#include <Windows.h>
#include "AntiDBG.h"
#include "SysCallHandler.h"

//#include "VMProtectSDK.h"

#define VMProtectBeginVirtualization(x);
#define VMProtectBeginMutation(x);
#define VMProtectBeginUltra(x);
#define VMProtectEnd();

#define DEBUG_MODE 1

#define GetCurrentProcess(x) ((HANDLE)-1)
#define GetCurrentThread(x) ((HANDLE)-2)

//Structs
typedef struct timeKeeper {
	uint64_t timeUpperA;
	uint64_t timeLowerA;
	uint64_t timeUpperB;
	uint64_t timeLowerB;
} TimeKeeper;

//ASSEMBLY FUNCTIONS
extern "C" int _NtGlobalFlagPEBx64();
extern "C" void _RDTSCx64(TimeKeeper*);
extern "C" void _QueryPerformanceCounterx64();
extern "C" void _IntException();

//EXTERN DEFINITIONS
// Main
bool AntiDebug::SecurityThreadCheck1();
bool AntiDebug::SecurityCheck1();
bool AntiDebug::SecurityCheck2();
//	Memory
bool AntiDebug::Interals::CheckNtQueryInformationProcess();
bool AntiDebug::Interals::CheckWindowClassName();
bool AntiDebug::Interals::CheckNtGlobalFlagPEB();
bool AntiDebug::Interals::CheckIsDebuggerPresent();
bool AntiDebug::Interals::CheckZwQuerySystemInformation();
bool AntiDebug::Interals::CheckSetInformationThread();
bool AntiDebug::Interals::CheckDebugActiveProcess(); // Not Finished
// CPU
bool AntiDebug::Interals::CheckHardwareDebugRegisters(HANDLE handle);
// Timing
bool AntiDebug::Interals::CheckRDTSC();
bool AntiDebug::Interals::CheckQueryPerformanceCounter();
bool AntiDebug::Interals::CheckGetTickCount();
// VEH
bool AntiDebug::Interals::CheckVectoredExceptionHandler();
// Others
std::vector<DWORD> AntiDebug::Interals::m_ProtectedThread;
AntiDebug::Interals::_ExitCallback AntiDebug::Interals::pExitCallBack = nullptr;

__forceinline bool AntiDebug::SecurityCheck1()
{
	//VMProtectBeginVirtualization("SecurityGate01");

	//Memory
	/*DBG_ASSERT(AntiDebug::Interals::CheckWindowClassName);

	DBG_ASSERT(AntiDebug::Interals::CheckNtGlobalFlagPEB);

	DBG_ASSERT(AntiDebug::Interals::CheckIsDebuggerPresent);

	DBG_ASSERT(AntiDebug::Interals::CheckNtQueryInformationProcess);

	DBG_ASSERT(AntiDebug::Interals::CheckDebugActiveProcess);*/

	//Kernel Debugger
	/*DBG_ASSERT(AntiDebug::Interals::CheckZwQuerySystemInformation);*/

	//Thread Specific
	/*DBG_ASSERT(AntiDebug::Interals::CheckSetInformationThread);*/

	//CPU
	/*DBG_ASSERT(AntiDebug::Interals::CheckHardwareDebugRegisters);*/

	//Timing
	DBG_ASSERT(AntiDebug::Interals::CheckRDTSC);

	DBG_ASSERT(AntiDebug::Interals::CheckQueryPerformanceCounter);

	DBG_ASSERT(AntiDebug::Interals::CheckGetTickCount);

	//VEH
	//DBG_ASSERT(AntiDebug::Interals::CheckVectoredExceptionHandler);

	//VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::SecurityCheck2()
{
	//VMProtectBeginVirtualization("SecurityGate02");

	//Kernel Debugger
	DBG_ASSERT(AntiDebug::Interals::CheckZwQuerySystemInformation);

	//CPU
	DBG_ASSERT(AntiDebug::Interals::CheckHardwareDebugRegisters);

	//Memory
	DBG_ASSERT(AntiDebug::Interals::CheckNtGlobalFlagPEB);

	DBG_ASSERT(AntiDebug::Interals::CheckNtQueryInformationProcess);

	DBG_ASSERT(AntiDebug::Interals::CheckDebugActiveProcess);

	DBG_ASSERT(AntiDebug::Interals::CheckWindowClassName);

	DBG_ASSERT(AntiDebug::Interals::CheckIsDebuggerPresent);

	//VEH
	//DBG_ASSERT(AntiDebug::Interals::CheckVectoredExceptionHandler);

	//Thread Specific
	DBG_ASSERT(AntiDebug::Interals::CheckSetInformationThread);

	//Timing
	DBG_ASSERT(AntiDebug::Interals::CheckGetTickCount);

	DBG_ASSERT(AntiDebug::Interals::CheckRDTSC);

	DBG_ASSERT(AntiDebug::Interals::CheckQueryPerformanceCounter);

	//VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::SecurityThreadCheck1()
{
	//VMProtectBeginVirtualization("ThreadCheck01");
	for (auto & entry : AntiDebug::Interals::m_ProtectedThread)
	{
		HANDLE hThread = WinApi.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, false, entry);
		if (!hThread)
		{
			return false;
		}
		AntiDebug::Interals::CheckHardwareDebugRegisters(hThread);
		WinApi.CloseHandle(hThread);
	}
	//VMProtectEnd();
	return true;
}


__forceinline bool AntiDebug::Interals::CheckWindowClassName()
{
	VMProtectBeginVirtualization(("CheckWindowClassName"));

	BOOL found = FALSE;
	HANDLE hWindow = NULL;

	static std::vector<IAString> WindowClassNames = {
		XorString("OLLYDBG"), XorString("ID"), XorString("ProcessHacker"),
		XorString("WindowsForms10.Window.8.app.0.13965fa_r6_ad1")
	};

	for (auto & str : WindowClassNames)
	{
		hWindow = WinApi.FindWindowA(str.GetValue().c_str(), 0);
		if (hWindow != NULL)
		{
			found = true;
			break;
		}
	}

	if (found)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_WindowClassName);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckNtGlobalFlagPEB()
{
	VMProtectBeginVirtualization(("CheckNtGlobalFlagPEB"));

	int result = _NtGlobalFlagPEBx64();

	if (result)
	{
		//DBG_MSG(DBG_NTQUERYINFORMATIONPROCESS, "Caught by NtQueryInformationProcess, (ProcessDebugFlags)!");
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_NtGlobalFlagPEB);
#if(DEBUG_MODE == 0)

		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckIsDebuggerPresent()
{
	VMProtectBeginVirtualization(("CheckIsDebuggerPresent"));

	BYTE IsPresent = *(BYTE*)(__readgsqword(0x60u) + 2);

	if (IsPresent)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_IsDebuggerPresent);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckNtQueryInformationProcess()
{
	VMProtectBeginVirtualization(("CheckNtQueryInformationProcess"));

	HANDLE hProcess = INVALID_HANDLE_VALUE;
	DWORD found = FALSE;
	const DWORD ProcessDebugPort = 0x07;	// 1st method; See MSDN for details
	const DWORD ProcessDebugFlags = 0x1F;	// 2nd method; See MSDN for details
	const DWORD ProcessDebugObjectHandle = 0x1E; // 3st method; See MSDN for details

	// Method 1: Query ProcessDebugPort
	hProcess = GetCurrentProcess();
	//NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessDebugPort, &found, sizeof(DWORD), NULL);
	NTSTATUS status = do_syscall<NTSTATUS>(SysCallData.NtQueryInformationProcess, hProcess, ProcessDebugPort, &found, sizeof(DWORD), NULL);

	if (!status && found)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_NtQueryInformationProcess);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s(ProcessDebugPort)...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	// Method 2: Query ProcessDebugFlags
	//status = NtQueryInformationProcess(hProcess, ProcessDebugFlags, &found, sizeof(DWORD), NULL);
	found = FALSE;
	status = do_syscall<NTSTATUS>(SysCallData.NtQueryInformationProcess, hProcess, ProcessDebugFlags, &found, sizeof(DWORD), NULL);

	// The ProcessDebugFlags caused 'found' to be 1 if no debugger is found, so we check !found.
	if (!status && found == 0)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_NtQueryInformationProcess);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s(ProcessDebugFlags)...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	// Method 3: Query ProcessDebugObjectHandle
	HANDLE hDebugHandle = NULL; found = FALSE;
	status = do_syscall<NTSTATUS>(SysCallData.NtQueryInformationProcess, hProcess, ProcessDebugObjectHandle, &hDebugHandle, sizeof(HANDLE), NULL);

	// The ProcessDebugFlags caused 'found' to be 1 if no debugger is found, so we check !found.
	if (!status && hDebugHandle != NULL)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_NtQueryInformationProcess);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s(ProcessDebugObjectHandle)...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckZwQuerySystemInformation()
{
	VMProtectBeginVirtualization(("CheckZwQuerySystemInformation"));

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
		BOOLEAN DebuggerEnabled;
		BOOLEAN DebuggerNotPresent;
	} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
	enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };

	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;

	NTSTATUS status = do_syscall<NTSTATUS>(SysCallData.NtQuerySystemInformation, SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL);

	if (status != 0x0)
		return false;

	if (Info.DebuggerEnabled && !Info.DebuggerNotPresent)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_ZwQuerySystemInformation);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckSetInformationThread()
{
	VMProtectBeginVirtualization("CheckSetInformationThread");
	THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;

	// There is nothing to check here after this call.
	bool ret = (do_syscall<NTSTATUS>(SysCallData.NtSetInformationThread, GetCurrentThread(), ThreadHideFromDebugger, 0, 0) == 0x0);

	VMProtectEnd();

	return ret;
}

__forceinline bool AntiDebug::Interals::CheckDebugActiveProcess()
{
	return true;
}

__forceinline bool AntiDebug::Interals::CheckHardwareDebugRegisters(HANDLE handle)
{
	VMProtectBeginVirtualization("CheckHardwareDebugRegisters");

	BOOL found = FALSE;
	CONTEXT ctx = { 0 };
	HANDLE hThread = NULL;

	if (!handle)
		hThread = GetCurrentThread();
	else
		hThread = handle;

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (do_syscall<NTSTATUS>(SysCallData.NtGetContextThread, hThread, &ctx) == 0x0)
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			if (AntiDebug::Interals::pExitCallBack)
				AntiDebug::Interals::pExitCallBack(AntiDBGCheck_HardwareDebugRegisters);
#if(DEBUG_MODE == 0)
			do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
			printf("Caught by %s...\n", __FUNCTION__);
			system("pause");
#endif
			return false;
		}
	}
	else
	{
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckRDTSC()
{
	VMProtectBeginMutation("CheckRDTSC");

	BOOL found = FALSE;

	uint64_t timeA = 0;
	uint64_t timeB = 0;
	TimeKeeper timeKeeper = { 0 };
	_RDTSCx64(&timeKeeper);

	timeA = timeKeeper.timeUpperA;
	timeA = (timeA << 32) | timeKeeper.timeLowerA;

	timeB = timeKeeper.timeUpperB;
	timeB = (timeB << 32) | timeKeeper.timeLowerB;

	// 0x100000 is purely empirical and is based on the CPU clock speed
	// This value should be change depending on the length and complexity of 
	// code between each RDTSC operation.

	if (timeB - timeA > 0x100000)
	{
		found = TRUE;
	}

//	printf("[RDTSC] timeB(0x%llX) - timeA(0x%llX) = 0x%llX\n", timeB, timeA, (timeB - timeA));

	if (found)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_RDTSC);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckQueryPerformanceCounter()
{
	VMProtectBeginMutation("CheckQueryPerformanceCounter");

	BOOL found = FALSE;
	LARGE_INTEGER t1;
	LARGE_INTEGER t2;

	//QueryPerformanceCounter(&t1);
	if (do_syscall<NTSTATUS>(SysCallData.NtQueryPerformanceCounter, &t1, NULL) != 0x0)
		return false;

//Assembly Trash
	_QueryPerformanceCounterx64();

	//QueryPerformanceCounter(&t2);
	if (do_syscall<NTSTATUS>(SysCallData.NtQueryPerformanceCounter, &t2, NULL) != 0x0)
		return false;

	// 30 is an empirical value
	if ((t2.QuadPart - t1.QuadPart) > 30)
	{
		found = TRUE;
	}

	//printf("[QueryPerformanceCounter] t2.QuadPart(0x%llX) - t1.QuadPart(0x%llX) = 0x%llX\n", t2.QuadPart, t1.QuadPart, (t2.QuadPart - t1.QuadPart));

	if (found)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_QueryPerformanceCounter);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckGetTickCount()
{
	VMProtectBeginMutation("CheckGetTickCount");

	BOOL found = FALSE;
	DWORD t1;
	DWORD t2;

	t1 = WinApi.GetTickCount();

//Junk instructions
	_QueryPerformanceCounterx64();

	t2 = WinApi.GetTickCount();

	// 30 milliseconds is an empirical value
	if ((t2 - t1) > 30)
	{
		found = TRUE;
	}

	//printf("[CheckGetTickCount] t2(0x%lX) - t1(0x%lX) = 0x%lX\n", t2, t1, (t2 - t1));

	if (found)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_GetTickCount);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return false;
	}

	VMProtectEnd();

	return true;
}

__forceinline bool AntiDebug::Interals::CheckVectoredExceptionHandler()
{
	VMProtectBeginVirtualization("CheckVectoredExceptionHandler");

	static bool VEHInit = false;

	if (!VEHInit)
	{
		if (WinApi.RtlAddVectoredExceptionHandler(0, AntiDebug::Interals::CallBacks::ExceptionHandler) == NULL)
			return false;
		VEHInit = true;
	}

	_IntException();

	VMProtectEnd();

	return true;
}

bool AntiDebug::Initialize(void* ExitCallback)
{
	VMProtectBeginUltra("AntiDBG::Init()");

	if (!WinApi.Init())
		return false;

	if (!InitSyscalls(&SysCallData))
		return false;

	AntiDebug::Interals::pExitCallBack = (AntiDebug::Interals::_ExitCallback)ExitCallback;

	VMProtectEnd();

	return true;
}

bool AntiDebug::AddProtectedThread(DWORD ThreadID)
{
	VMProtectBeginVirtualization("AddProtectedThread");

	THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;

	// There is nothing to check here after this call.
	if (do_syscall<NTSTATUS>(SysCallData.NtSetInformationThread, GetCurrentThread(), ThreadHideFromDebugger, 0, 0) != 0x0)
		return false;

	for (auto & entry : AntiDebug::Interals::m_ProtectedThread)
	{
		if (entry == ThreadID)
			return true;
	}

	AntiDebug::Interals::m_ProtectedThread.push_back(ThreadID);

	VMProtectEnd();

	return true;
}

LONG AntiDebug::Interals::CallBacks::ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	VMProtectBeginVirtualization("CallBack::ExceptionHandler");

	PCONTEXT ctx = ExceptionInfo->ContextRecord;
	if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0 || ctx->Dr6 != 0 || ctx->Dr7 != 0)
	{
		if (AntiDebug::Interals::pExitCallBack)
			AntiDebug::Interals::pExitCallBack(AntiDBGCheck_VectoredExceptionHandler);
#if(DEBUG_MODE == 0)
		do_syscall<NTSTATUS>(SysCallData.NtTerminateProcess, GetCurrentProcess(), 0);
#else
		printf("Caught by %s...\n", __FUNCTION__);
		system("pause");
#endif
		return NULL;
	}
	ctx->Rip += 2;

	VMProtectEnd();

	return EXCEPTION_CONTINUE_EXECUTION;
}
