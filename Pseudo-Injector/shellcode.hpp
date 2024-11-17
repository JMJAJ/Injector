#pragma once
#include "pch.h"
#include <vector>

// Structure to hold shellcode and its allocated memory
struct ShellcodeData {
    std::vector<BYTE> code;
    LPVOID stringPtr;
    
    ShellcodeData() : stringPtr(nullptr) {}
    ~ShellcodeData() {
        if (stringPtr) {
            VirtualFree(stringPtr, 0, MEM_RELEASE);
        }
    }
};

inline ShellcodeData CreateLoadLibraryShellcode(const std::wstring& dllPath) {
    ShellcodeData result;
    
    // Convert wide string to ASCII for shellcode
    std::string dllPathA(dllPath.begin(), dllPath.end());
    
    // Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return result;
    
    LPVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) return result;
    
    // x64 shellcode template for calling LoadLibraryA
    result.code = {
        // Save registers and align stack
        0x48, 0x83, 0xEC, 0x28,                                   // sub rsp, 0x28
        0x48, 0x89, 0x5C, 0x24, 0x20,                            // mov [rsp+20h], rbx
        
        // Load DLL path and function address
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rcx, dllPath
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, LoadLibraryA
        
        // Call LoadLibraryA
        0xFF, 0xD0,                                               // call rax
        0x48, 0x89, 0xC3,                                         // mov rbx, rax
        
        // Restore registers and clean up stack
        0x48, 0x8B, 0x5C, 0x24, 0x20,                            // mov rbx, [rsp+20h]
        0x48, 0x83, 0xC4, 0x28,                                   // add rsp, 0x28
        0xC3                                                      // ret
    };
    
    // Allocate memory for DLL path string (this will be freed by the destructor)
    result.stringPtr = VirtualAlloc(NULL, dllPathA.size() + 1, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!result.stringPtr) {
        result.code.clear();
        return result;
    }
    
    // Copy DLL path to allocated memory
    memcpy(result.stringPtr, dllPathA.c_str(), dllPathA.size() + 1);
    
    // Update shellcode with addresses
    *(LPVOID*)(&result.code[12]) = result.stringPtr;
    *(LPVOID*)(&result.code[22]) = pLoadLibraryA;
    
    return result;
}

// Helper function to create shellcode for thread hijacking
inline std::vector<BYTE> CreateThreadHijackShellcode(LPVOID originalEip, LPVOID injectedCode) {
    std::vector<BYTE> shellcode = {
        // Save all volatile registers
        0x50,                                           // push rax
        0x51,                                           // push rcx
        0x52,                                           // push rdx
        0x53,                                           // push rbx
        0x55,                                           // push rbp
        0x56,                                           // push rsi
        0x57,                                           // push rdi
        0x41, 0x50,                                     // push r8
        0x41, 0x51,                                     // push r9
        0x41, 0x52,                                     // push r10
        0x41, 0x53,                                     // push r11
        
        // Call injected code
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, injectedCode
        0xFF, 0xD0,                                     // call rax
        
        // Restore all registers
        0x41, 0x5B,                                     // pop r11
        0x41, 0x5A,                                     // pop r10
        0x41, 0x59,                                     // pop r9
        0x41, 0x58,                                     // pop r8
        0x5F,                                           // pop rdi
        0x5E,                                           // pop rsi
        0x5D,                                           // pop rbp
        0x5B,                                           // pop rbx
        0x5A,                                           // pop rdx
        0x59,                                           // pop rcx
        0x58,                                           // pop rax
        
        // Jump to original code
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, originalEip
        0xFF, 0xE0                                      // jmp rax
    };
    
    // Update addresses in shellcode
    *(LPVOID*)(&shellcode[18]) = injectedCode;
    *(LPVOID*)(&shellcode[47]) = originalEip;
    
    return shellcode;
}
