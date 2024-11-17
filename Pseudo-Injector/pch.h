#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <codecvt>
#include <locale>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include <Shobjidl.h>
#include <Shlwapi.h>
#include <Psapi.h>
#include <ctime>
#include <map>

// Basic type definitions first
typedef struct _MEMORY_RANGE_ENTRY {
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_REGION_INFORMATION {
    PVOID AllocationBase;
    ULONG AllocationProtect;
    union {
        ULONG RegionType;
        struct {
            ULONG Private : 1;
            ULONG MappedDataFile : 1;
            ULONG MappedImage : 1;
            ULONG MappedPageFile : 1;
            ULONG MappedPhysical : 1;
            ULONG DirectMapped : 1;
            ULONG Reserved : 26;
        };
    };
    SIZE_T RegionSize;
    SIZE_T CommitSize;
} MEMORY_REGION_INFORMATION, *PMEMORY_REGION_INFORMATION;

// NT API function types that use the above structures
typedef NTSTATUS(NTAPI* NtSetInformationVirtualMemory_t)(
    HANDLE ProcessHandle,
    MEMORY_INFORMATION_CLASS VirtualMemoryInformationClass,
    ULONG_PTR NumberOfEntries,
    PMEMORY_RANGE_ENTRY VirtualAddresses,
    PVOID VirtualMemoryInformation,
    ULONG VirtualMemoryInformationLength
);

typedef struct _PEB_LDR_DATA_FULL {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
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
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// Include project headers after all type definitions
#include "inject.hpp"
#include "hijack.hpp"
#include "hollow.hpp"
#include "obfuscate.hpp"
#include "shellcode.hpp"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

// Ensure we don't have conflicting definitions
#ifdef KPRIORITY
#undef KPRIORITY
#endif

typedef LONG KPRIORITY;