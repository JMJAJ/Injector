#pragma once
#include "pch.h"

class StealthHelper {
public:
    // Hide thread from debugger
    static bool HideThread(HANDLE hThread) {
        typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
        NTSTATUS Status;

        // Get NtSetInformationThread
        pNtSetInformationThread NtSIT = (pNtSetInformationThread)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
        
        if (NtSIT == nullptr)
            return false;

        // Hide thread from debugger
        if (hThread == nullptr)
            Status = NtSIT(GetCurrentThread(),
                0x11, // ThreadHideFromDebugger
                0, 0);
        else
            Status = NtSIT(hThread, 0x11, 0, 0);

        if (Status != STATUS_SUCCESS)
            return false;

        return true;
    }

    // Remove PE headers
    static void RemovePeHeader(HANDLE hProcess, DWORD_PTR moduleBase) {
        DWORD oldProtect = 0;
        DWORD_PTR size = 0x1000;

        if (VirtualProtectEx(hProcess, (LPVOID)moduleBase, size, PAGE_READWRITE, &oldProtect)) {
            SecureZeroMemory((PVOID)moduleBase, size);
            VirtualProtectEx(hProcess, (LPVOID)moduleBase, size, oldProtect, &oldProtect);
        }
    }

    // Clean up PE traces
    static void CleanPeHeaders(HANDLE hProcess, void* dllBase) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + pDosHeader->e_lfanew);
        
        // Zero out headers
        SIZE_T bytesWritten;
        WriteProcessMemory(hProcess, dllBase, "\0\0\0\0", 4, &bytesWritten);
        WriteProcessMemory(hProcess, (PVOID)((DWORD_PTR)dllBase + pDosHeader->e_lfanew), "\0\0\0\0", 4, &bytesWritten);
    }

    // Spoof thread call stack
    static bool SpoofCallStack(HANDLE hThread) {
        typedef NTSTATUS(NTAPI* pNtSetContextThread)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(hThread, &ctx))
            return false;

        // Modify stack frame to look legitimate
        ctx.Rsp = (ctx.Rsp & 0xFFFFFFFFFFFFFFF0) - 8;
        ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");

        pNtSetContextThread NtSCT = (pNtSetContextThread)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetContextThread");
        
        if (NtSCT == nullptr)
            return false;

        NTSTATUS status = NtSCT(hThread, &ctx);
        return NT_SUCCESS(status);
    }

    // Erase PE header after injection
    static void ErasePEHeader(HANDLE hProcess, LPVOID baseAddress) {
        DWORD oldProtect;
        VirtualProtectEx(hProcess, baseAddress, 0x1000, PAGE_READWRITE, &oldProtect);
        
        BYTE emptyHeader[0x1000];
        ZeroMemory(emptyHeader, 0x1000);
        
        WriteProcessMemory(hProcess, baseAddress, emptyHeader, 0x1000, nullptr);
        VirtualProtectEx(hProcess, baseAddress, 0x1000, oldProtect, &oldProtect);
    }

    // Randomize PE header timestamps
    static void RandomizeTimestamp(HANDLE hProcess, LPVOID baseAddress) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddress + dosHeader->e_lfanew);
        
        srand((unsigned)time(nullptr));
        DWORD randomTimestamp = rand();
        
        WriteProcessMemory(hProcess, &ntHeaders->FileHeader.TimeDateStamp, &randomTimestamp, sizeof(DWORD), nullptr);
    }
};
