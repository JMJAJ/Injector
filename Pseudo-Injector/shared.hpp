#pragma once
#include "pch.h"

// Function declarations
bool InjectDll(void* hProcess, const wchar_t* dllPath);

bool SR_SetWindowsHookEx(
    void* hTargetProc,
    unsigned __int64 (__cdecl** pCallbackFn)(void*),
    void* pParam,
    unsigned long& LastWin32Error,
    unsigned __int64& Out
);

void* GetProcAddressEx(void* hProc, const wchar_t* moduleName, const char* funcName);

HMODULE GetModuleHandleExW(void* hProc, const wchar_t* moduleName);
