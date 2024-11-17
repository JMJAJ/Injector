#pragma once
#include "pch.h"

class DllUnlinking {
public:
    static bool UnlinkFromPEB(HANDLE hProcess, HMODULE hDll) {
        PROCESS_BASIC_INFORMATION pbi;
        PPEB peb;
        PPEB_LDR_DATA ldr;
        PLDR_DATA_TABLE_ENTRY module;

        // Get process information
        NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
            &pbi, sizeof(pbi), NULL);
        
        if (!NT_SUCCESS(status)) return false;

        // Read PEB
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL))
            return false;

        // Read loader data
        if (!ReadProcessMemory(hProcess, &peb->Ldr, &ldr, sizeof(ldr), NULL))
            return false;

        // Get module list head
        LIST_ENTRY head;
        if (!ReadProcessMemory(hProcess, &ldr->InMemoryOrderModuleList,
            &head, sizeof(head), NULL))
            return false;

        // Walk module list
        LIST_ENTRY current = head;
        do {
            if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current.Flink,
                LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
                &module, sizeof(module), NULL))
                break;

            if (module->DllBase == hDll) {
                // Unlink from all three lists
                UnlinkListEntry(hProcess, &module->InLoadOrderLinks);
                UnlinkListEntry(hProcess, &module->InMemoryOrderLinks);
                UnlinkListEntry(hProcess, &module->InInitializationOrderLinks);
                return true;
            }

            if (!ReadProcessMemory(hProcess, current.Flink,
                &current, sizeof(current), NULL))
                break;

        } while (current.Flink != head.Flink);

        return false;
    }

private:
    static void UnlinkListEntry(HANDLE hProcess, PLIST_ENTRY entry) {
        LIST_ENTRY le;
        if (ReadProcessMemory(hProcess, entry, &le, sizeof(le), NULL)) {
            // Fix forward link
            WriteProcessMemory(hProcess, le.Blink,
                &le.Flink, sizeof(PVOID), NULL);
            // Fix backward link
            WriteProcessMemory(hProcess, le.Flink,
                &le.Blink, sizeof(PVOID), NULL);
        }
    }

    static bool RemapSections(HANDLE hProcess, LPVOID moduleBase) {
        BYTE headers[0x1000];
        if (!ReadProcessMemory(hProcess, moduleBase, headers, sizeof(headers), NULL))
            return false;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headers;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(headers + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                LPVOID sectionBase = (LPVOID)((DWORD_PTR)moduleBase + sections[i].VirtualAddress);
                DWORD oldProtect;

                // Remap with new protection
                if (VirtualProtectEx(hProcess, sectionBase, sections[i].Misc.VirtualSize,
                    PAGE_EXECUTE_READ, &oldProtect)) {
                    // Optional: Modify section contents or checksums here
                }
            }
        }
        return true;
    }
};
