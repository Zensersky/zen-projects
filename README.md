# Anti-DBG (Library & Test Project)
**Projekta mērķis** : Palīdz sargāt programmas intelektuālo vērtību no uzbrucējiem. (x64dbg, cheat-engine, ollydbg)  
**Kur tiek pielietots** : Video Spēlēs, Anti Vīrusos, Licenzētās Programmās.  

<sub>Viens no vispopulārākajiem debugging rīkiem. (x64dbg)</sub>
![alt text](https://x64dbg.com/img/slide2.png)

### Izmantojam syscall (system-call) priekšrocības, lai izvairītos no uzbrucēju modifikācijām.
```cpp

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
```
```cpp
NTSTATUS status = do_syscall<NTSTATUS>(SysCallData.NtQueryInformationProcess, hProcess, ProcessDebugPort, &found, sizeof(DWORD), NULL);
```

### Izmantojam VMProtect, lai apmulsinātu un sarežģitu darbu uzbrucējiem
```cpp
__forceinline bool AntiDebug::Interals::CheckWindowClassName()
{
	VMProtectBeginVirtualization(("CheckWindowClassName"));

  //CODE HERE

	VMProtectEnd();

	return true;
}
```

### Izmantojam dažādus paņemienus, lai noteiktu vai programmu cenšās uzlauzt uzbrucējs
**RDTSC(Read Time-Stamp Counter) - Processora cikla skaita balstīts paņēmiens**  
<sub>Nav efektīvākais un precīzākais paņēmiens, tomēr bieži sastopams.</sub>
```cpp
__forceinline bool AntiDebug::Interals::CheckRDTSC()
{
	VMProtectBeginMutation("CheckRDTSC");
  //CODE HERE
	TimeKeeper timeKeeper = { 0 };
	_RDTSCx64(&timeKeeper);

	timeA = timeKeeper.timeUpperA;
	timeA = (timeA << 32) | timeKeeper.timeLowerA;

	timeB = timeKeeper.timeUpperB;
	timeB = (timeB << 32) | timeKeeper.timeLowerB;

	// 0x100000 is purely based on the CPU clock speed
	if (timeB - timeA > 0x100000)
		found = TRUE;

	if (found)
	{
		// MORE CODE HERE
	}

	VMProtectEnd();

	return true;
}
```

**NtSetInformationThread(ThreadHideFromDebugger) - Paņemiens**  
<sub>Bieži sastopmas, DRM vai Anti Vīrusu programmās.</sub>
```cpp
bool AntiDebug::AddProtectedThread(DWORD ThreadID)
{
	VMProtectBeginVirtualization("AddProtectedThread");

	auto ThreadHideFromDebugger = static_cast<(THREAD_INFORMATION_CLASS)>(0x11);

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
```  

**FindWindowA - Paņemiens**  
<sub>Dažreiz pietiek ar vienkāršiem risinājumiem, lai uzbrucējs padotos.</sub>
```cpp
__forceinline bool AntiDebug::Interals::CheckWindowClassName()
{
	VMProtectBeginVirtualization(("CheckWindowClassName"));

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
    //CODE HERE
	}

	VMProtectEnd();

	return true;
}
```
<sub>Pārējie paņēmieni aplūkojami projektā.</sub>



# New Title hey
