#pragma once
#include <Windows.h>
#include <string>

#include <vector>
#include <atomic>

#include "SysCallHandler.h"

class asio3_interface;
extern asio3_interface _driver_asio3;

namespace asio3_info
{
	namespace io_control_code
	{
		constexpr ULONG IOCTL_MAP_PHYS_MEMORY = 0xA040A480;
		constexpr ULONG IOCTL_UNMAP_PHYS_MEMORY = 0xA0402450;
	}
	namespace structures
	{
		struct _IOCTL_MAP_UNMAP_PHYS_MEMORY_X64
		{
			ULONG64 section_size;
			LARGE_INTEGER phys_address;
			HANDLE out_handle;
			ULONG64 out_mapped_address;
			PVOID out_object;
		};

		struct __declspec(align(8)) _IOCTL_MAP_PHYS_MEM_X32
		{
			ULONG HalInterfaceType;
			unsigned int HalBusType;
			LARGE_INTEGER physical_address;
			ULONG hal_reserved;
			ULONG size;
		};

	}
}

/*
* Add syscall mapping functionallity
* Add code calling functionallity
*/

#ifndef XorString
#define XorString
#endif

class asio3_interface
{
private:
	//Asusgio3 service namae
	std::string symbolic_link = XorString("\\\\.\\Asusgio3");
	
	std::string driver_name = "";
	bool driver_load_performed = false;
public:
	HANDLE device_handle = NULL;

	std::atomic<PVOID> syscall_mapping = nullptr;
	std::atomic<bool> syscall_located = false;
	ULONG syscall_page_offset = 0x0;
	std::vector<BYTE> syscall_bytes;
private:
	std::vector<std::pair<ULONG64, ULONG>> get_physical_mem_ranges();
	static void physmeme_map_syscall(ULONG64 begin, ULONG64 end);

	bool hook_syscall(PVOID function, std::vector<BYTE>* out_original_bytes);
	bool unhook_syscall(std::vector<BYTE>* in_original_bytes);

	bool bypass_handle_protection();
	bool map_syscall();
public:
	static asio3_interface* get_instance() { return &_driver_asio3; }
	static PVOID get_kernel_export(const char* module_name, const char* export_name, bool rva = false);
	bool verify_syscall();
	~asio3_interface() { this->on_exit(); }

	bool initialize_interface();
	
	bool load_driver(std::string* out_driver_name);
	bool unload_driver(std::string& driver_name);

	bool on_exit();

	//IOCTLS
	PVOID map_phys_memory_x64(const ULONG64& start, const ULONG64& size, asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64* out_info);
	BOOL unmap_phys_memory_x64(asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64* p_info);

	ULONG64 map_phys_memory_x32(const ULONG64& start, const ULONG& size);
	BOOL unmap_phys_memory_x32(const ULONG64& mapped_address);

	template<typename T, typename ...A>
	BOOL __stdcall call_function(PVOID func_addr, T* out_return, const A ...arguments);
};

template<typename T, typename ...A>
inline BOOL asio3_interface::call_function(PVOID func_addr, T* out_return, const A ...arguments)
{
	if (!this->syscall_located.load())
		return FALSE;

	//using FunctionFn = T(__stdcall*)(A...);
	//static auto syscall_function = (FunctionFn)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtShutdownSystem"));

	std::vector<BYTE> original_bytes = { 0 };

	if (!this->hook_syscall(func_addr, &original_bytes))
		return FALSE;

	if (out_return)
		*out_return = do_syscall<T>(SysCallData.NtShutdownSystem, arguments...);
	else
		do_syscall<T>(SysCallData.NtShutdownSystem, arguments...);
	//T buffer = do_syscall<T>(SysCallData.NtShutdownSystem, arguments...);

	this->unhook_syscall(&original_bytes);
		
	return TRUE;
}

class asio3_utils
{
public:
	static bool acquire_privilege(DWORD privlage);
	static std::string get_sys_driver_path();
	static bool create_file_from_mem(const std::string& desired_file_path, const char* address, size_t size);
	static std::string gen_random_str(size_t len);
	//Registry stuff
	static bool registry_add_service(const std::wstring& driver_name);
	static bool registry_remove_service(const std::wstring& driver_name);
	static void InitUnicodeString(PVOID pString, const wchar_t* pwszSource);
};