#pragma once
#include <vector>

#ifdef ANTIDBG_EXPORTS
#define ANTIDBG_API __declspec(dllexport)
#else
#define ANTIDBG_API __declspec(dllimport)
#endif

#define DBG_ASSERT(x) if(!x()) {printf("%s failed...\n", ###x); return false;}

namespace AntiDebug  
{
	bool Initialize(void* ExitCallback);
//Security Gates
	extern bool SecurityCheck1();
	extern bool SecurityCheck2();
//Protected Threads
	extern bool SecurityThreadCheck1();
//Utils
	bool AddProtectedThread(DWORD ThreadID);
	namespace Interals
	{
	//FeatureList
		enum eAntiDBGCheck : const int
		{
			AntiDBGCheck_WindowClassName = 1,
			AntiDBGCheck_NtGlobalFlagPEB,
			AntiDBGCheck_IsDebuggerPresent,
			AntiDBGCheck_NtQueryInformationProcess,
			AntiDBGCheck_ZwQuerySystemInformation,
			AntiDBGCheck_SetInformationThread,
			AntiDBGCheck_HardwareDebugRegisters,
			AntiDBGCheck_RDTSC,
			AntiDBGCheck_QueryPerformanceCounter,
			AntiDBGCheck_GetTickCount,
			AntiDBGCheck_VectoredExceptionHandler
		};
	//Memory
		bool CheckBeingDebuggedPEB();
		extern bool CheckWindowClassName();
		extern bool CheckNtGlobalFlagPEB();
		extern bool CheckIsDebuggerPresent();
		extern bool CheckNtQueryInformationProcess();
		extern bool CheckZwQuerySystemInformation();
		extern bool CheckSetInformationThread();
		extern bool CheckDebugActiveProcess(); // Not Finished
	//CPU
		extern bool CheckHardwareDebugRegisters(HANDLE handle = NULL);
		//bool CheckMovSS(); // x32 only
	//Timing
		extern bool CheckRDTSC();
		extern bool CheckQueryPerformanceCounter();
		extern bool CheckGetTickCount();
	//Threads
		extern std::vector<DWORD> m_ProtectedThread;
	//Execution Callbacks
		typedef bool(__stdcall * _ExitCallback)(int);
		extern _ExitCallback pExitCallBack;
	//Exceptions
		//ADD LATER DUE TO MANUAL MAP DLL SUPPORT
	//VEH
		extern bool CheckVectoredExceptionHandler();

		namespace CallBacks
		{
			LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
		}

	}
}


