#pragma once
#include "pch.h"

class ImportObfuscator {
public:
    static bool ObfuscateImports(HANDLE hProc, LPVOID moduleBase) {
        BYTE headers[0x1000];
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProc, moduleBase, headers, sizeof(headers), &bytesRead))
            return false;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headers;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(headers + dosHeader->e_lfanew);
        
        // Get import directory
        IMAGE_DATA_DIRECTORY& importDir = 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        // Allocate memory for obfuscated imports
        LPVOID newImportTable = VirtualAllocEx(hProc,
            NULL, importDir.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (!newImportTable) return false;

        // Read original import table
        std::vector<BYTE> importTable(importDir.Size);
        if (!ReadProcessMemory(hProc,
            (LPVOID)((DWORD_PTR)moduleBase + importDir.VirtualAddress),
            importTable.data(), importDir.Size, &bytesRead)) {
            VirtualFreeEx(hProc, newImportTable, 0, MEM_RELEASE);
            return false;
        }

        // Encrypt and write new import table
        for (size_t i = 0; i < importTable.size(); i++) {
            importTable[i] ^= 0xFF; // Simple XOR encryption
        }

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(hProc, newImportTable,
            importTable.data(), importDir.Size, &bytesWritten)) {
            VirtualFreeEx(hProc, newImportTable, 0, MEM_RELEASE);
            return false;
        }

        // Update import directory to point to new table
        DWORD oldProtect;
        if (!VirtualProtectEx(hProc,
            (LPVOID)((DWORD_PTR)moduleBase + 
                dosHeader->e_lfanew + 
                offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT])),
            sizeof(IMAGE_DATA_DIRECTORY),
            PAGE_READWRITE,
            &oldProtect)) {
            VirtualFreeEx(hProc, newImportTable, 0, MEM_RELEASE);
            return false;
        }

        IMAGE_DATA_DIRECTORY newImportDir = {
            (DWORD)((DWORD_PTR)newImportTable - (DWORD_PTR)moduleBase),
            importDir.Size
        };

        if (!WriteProcessMemory(hProc,
            (LPVOID)((DWORD_PTR)moduleBase + 
                dosHeader->e_lfanew + 
                offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT])),
            &newImportDir,
            sizeof(IMAGE_DATA_DIRECTORY),
            &bytesWritten)) {
            VirtualFreeEx(hProc, newImportTable, 0, MEM_RELEASE);
            return false;
        }

        VirtualProtectEx(hProc,
            (LPVOID)((DWORD_PTR)moduleBase + 
                dosHeader->e_lfanew + 
                offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT])),
            sizeof(IMAGE_DATA_DIRECTORY),
            oldProtect,
            &oldProtect);

        return true;
    }

    static bool CloakMemoryRegion(HANDLE hProc, LPVOID address, SIZE_T size) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        auto pNtSetInformationVirtualMemory = reinterpret_cast<NtSetInformationVirtualMemory_t>(
            GetProcAddress(hNtdll, "NtSetInformationVirtualMemory"));
            
        if (!pNtSetInformationVirtualMemory) return false;

        MEMORY_RANGE_ENTRY range = { 0 };
        range.VirtualAddress = address;
        range.NumberOfBytes = size;

        MEMORY_REGION_INFORMATION memInfo = { 0 };
        memInfo.AllocationProtect = PAGE_NOACCESS;

        return NT_SUCCESS(pNtSetInformationVirtualMemory(
            hProc,
            MemoryRegionInformation,
            1,
            &range,
            &memInfo,
            sizeof(memInfo)
        ));
    }

    static bool PreventIATHooking(HANDLE hProc, LPVOID moduleBase) {
        BYTE headers[0x1000];
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProc, moduleBase, headers, sizeof(headers), &bytesRead))
            return false;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headers;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(headers + dosHeader->e_lfanew);
        
        // Get IAT directory
        IMAGE_DATA_DIRECTORY& iatDir = 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

        // Protect IAT
        DWORD oldProtect;
        if (!VirtualProtectEx(hProc,
            (LPVOID)((DWORD_PTR)moduleBase + iatDir.VirtualAddress),
            iatDir.Size,
            PAGE_READONLY,
            &oldProtect))
            return false;

        return true;
    }
};
