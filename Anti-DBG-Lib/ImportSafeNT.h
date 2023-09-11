#pragma once
#include <Windows.h>
#include <string>
#include "sha256.h"

namespace SafeNT {
	enum class Module : std::uint32_t
	{
		
	};

	namespace Proc {
		enum KERNEL32 : std::uint32_t {
			
		};
	}

	typedef struct _UNICODE_STRING
	{
		WORD Length;
		WORD MaximumLength;
		WORD* Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;

		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};

		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};

		_ACTIVATION_CONTEXT* EntryPointActivationContext;
		PVOID PatchInformation;
		LIST_ENTRY ForwarderLinks;
		LIST_ENTRY ServiceTagLinks;
		LIST_ENTRY StaticLinks;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	static _LDR_DATA_TABLE_ENTRY* GetModule(const std::string & modulehash)
	{
#if defined( _WIN64 )
#define PEBOffset 0x60
#define LdrOffset 0x18
#define ListOffset 0x10
		unsigned long long pPeb = __readgsqword(PEBOffset);
#elif defined( _WIN32 )
#define PEBOffset 0x30
#define LdrOffset 0x0C
#define ListOffset 0x0C
		unsigned long pPeb = __readfsdword(PEBOffset);
#endif
		pPeb = *reinterpret_cast<decltype(pPeb)*>(pPeb + LdrOffset);
		PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pPeb + ListOffset);
		while (pModuleList->DllBase)
		{
			SHA256 sha256;

			const auto moduleHash = sha256(pModuleList->BaseDllName.Buffer, pModuleList->BaseDllName.Length);
			//printf("%ls %u\n", pModuleList->BaseDllName.Buffer, moduleHash);

			if (strcmp(modulehash.c_str(), moduleHash.c_str()) == 0)
				return pModuleList;

			pModuleList = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pModuleList->InLoadOrderLinks.Flink);
		}
		return nullptr;
	}

	static uintptr_t GetProcAddress(_LDR_DATA_TABLE_ENTRY* hModule, const std::string& proc) {
		unsigned char *lpBase = reinterpret_cast<unsigned char *>(hModule->DllBase);
		IMAGE_DOS_HEADER *idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(lpBase);
		if (idhDosHeader->e_magic == 0x5A4D) {
#if defined( _M_IX86 )
			IMAGE_NT_HEADERS32 *inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32 *>(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )
			IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif

			SHA256 sha256;
			if (inhNtHeader->Signature == 0x4550) {
				IMAGE_EXPORT_DIRECTORY *iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				for (unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter) {
					const std::string szNames = reinterpret_cast<char *>(lpBase + reinterpret_cast<unsigned long *>(lpBase + iedExportDirectory->AddressOfNames)[uiIter]);
					const auto hash = sha256(szNames.c_str(), szNames.size());
					//CONSOLE("%s %u", szNames.c_str(), hash);

					if (strcmp(hash.c_str(), proc.c_str()) == 0) {
						unsigned short usOrdinal = reinterpret_cast<unsigned short *>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
						return reinterpret_cast<uintptr_t>(lpBase + reinterpret_cast<unsigned long *>(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
					}
				}
			}
		}
		return 0;
	}
};