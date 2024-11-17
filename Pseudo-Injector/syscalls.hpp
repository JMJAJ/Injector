#pragma once
#include "pch.h"

// Direct syscall definitions
#define SYSCALL_STUB_SIZE 23

// Function pointer types for direct syscalls
using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PVOID AttributeList OPTIONAL
    );

class SyscallHelper {
public:
    static PVOID GetSyscallStub(const char* functionName) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return nullptr;

        PVOID functionAddress = GetProcAddress(ntdll, functionName);
        if (!functionAddress) return nullptr;

        // Allocate memory for syscall stub
        PVOID stub = VirtualAlloc(nullptr, SYSCALL_STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stub) return nullptr;

        // Copy original syscall stub
        memcpy(stub, functionAddress, SYSCALL_STUB_SIZE);

        return stub;
    }

    static bool InitializeSyscalls() {
        // Get syscall stubs for required functions
        PVOID ntCreateThreadExStub = GetSyscallStub("NtCreateThreadEx");
        if (!ntCreateThreadExStub) return false;

        // Store function pointers
        NtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_t>(ntCreateThreadExStub);

        return true;
    }

    static HANDLE CreateRemoteThreadEx(
        HANDLE hProcess,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter
    ) {
        HANDLE hThread = nullptr;
        
        if (!NtCreateThreadEx) return nullptr;

        NTSTATUS status = NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            hProcess,
            lpStartAddress,
            lpParameter,
            0,
            0,
            0,
            0,
            nullptr
        );

        return NT_SUCCESS(status) ? hThread : nullptr;
    }

private:
    static inline NtCreateThreadEx_t NtCreateThreadEx = nullptr;
};
