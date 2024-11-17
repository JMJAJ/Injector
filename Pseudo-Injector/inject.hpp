#pragma once
#include "pch.h"
#include <tchar.h>
#include "config.hpp"

namespace Stealth {
    class Helper {
    public:
        static void ErasePEHeader(HANDLE hProc, LPVOID moduleBase) {
            DWORD oldProtect;
            VirtualProtectEx(hProc, moduleBase, 0x1000, PAGE_READWRITE, &oldProtect);
            
            BYTE emptyHeader[0x1000] = { 0 };
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(hProc, moduleBase, emptyHeader, 0x1000, &bytesWritten);
            
            VirtualProtectEx(hProc, moduleBase, 0x1000, oldProtect, &oldProtect);
        }

        static void RandomizeTimestamp(HANDLE hProc, LPVOID moduleBase) {
            BYTE headers[0x1000];
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProc, moduleBase, headers, sizeof(headers), &bytesRead))
                return;

            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headers;
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(headers + dosHeader->e_lfanew);
            
            srand((unsigned)time(nullptr));
            DWORD randomTimestamp = rand();
            
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(hProc, (LPVOID)((BYTE*)moduleBase + dosHeader->e_lfanew + 
                offsetof(IMAGE_NT_HEADERS, FileHeader.TimeDateStamp)), 
                &randomTimestamp, sizeof(DWORD), &bytesWritten);
        }
    };

    class DllUnlink {
    public:
        static bool UnlinkFromPEB(HANDLE hProc, HMODULE hDll) {
            PROCESS_BASIC_INFORMATION pbi;
            NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation,
                &pbi, sizeof(pbi), NULL);
            
            if (!NT_SUCCESS(status)) return false;

            // Read PEB
            PEB peb;
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
                return false;

            // Read loader data
            PEB_LDR_DATA_FULL ldrData = { 0 };
            bytesRead = 0;
            if (!ReadProcessMemory(hProc, peb.Ldr, &ldrData, sizeof(ldrData), &bytesRead))
                return false;

            // Unlink module from all three lists
            PVOID firstEntry = ldrData.InLoadOrderModuleList.Flink;
            PVOID currentEntry = firstEntry;
            
            do {
                LDR_DATA_TABLE_ENTRY_FULL currentModule = { 0 };
                bytesRead = 0;
                if (!ReadProcessMemory(hProc, currentEntry, &currentModule, sizeof(currentModule), &bytesRead)) {
                    break;
                }

                if (currentModule.DllBase == hDll) {
                    // Unlink from all three lists
                    const size_t offsetsToUnlink[] = {
                        offsetof(LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks),
                        offsetof(LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks),
                        offsetof(LDR_DATA_TABLE_ENTRY_FULL, InInitializationOrderLinks)
                    };

                    for (const auto& offset : offsetsToUnlink) {
                        SIZE_T bytesWritten = 0;
                        
                        // Update Flink's Blink
                        WriteProcessMemory(hProc,
                            (PVOID)((ULONG_PTR)currentModule.InLoadOrderLinks.Flink + offset + offsetof(LIST_ENTRY, Blink)),
                            &currentModule.InLoadOrderLinks.Blink,
                            sizeof(PVOID),
                            &bytesWritten);

                        // Update Blink's Flink
                        WriteProcessMemory(hProc,
                            (PVOID)((ULONG_PTR)currentModule.InLoadOrderLinks.Blink + offset + offsetof(LIST_ENTRY, Flink)),
                            &currentModule.InLoadOrderLinks.Flink,
                            sizeof(PVOID),
                            &bytesWritten);
                    }

                    return true;
                }

                currentEntry = currentModule.InLoadOrderLinks.Flink;
            } while (currentEntry != firstEntry);

            return false;
        }
    };

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
            LPVOID newImportTable = VirtualAllocEx(hProc, NULL,
                importDir.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
            if (!newImportTable) return false;

            // Copy and obfuscate import table
            BYTE* importData = new BYTE[importDir.Size];
            bytesRead = 0;
            if (!ReadProcessMemory(hProc, (LPVOID)((BYTE*)moduleBase + importDir.VirtualAddress),
                importData, importDir.Size, &bytesRead)) {
                delete[] importData;
                return false;
            }

            // Simple XOR obfuscation
            for (DWORD i = 0; i < importDir.Size; i++)
                importData[i] ^= 0xFF;

            // Write obfuscated table
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(hProc, newImportTable, importData, importDir.Size, &bytesWritten);
            delete[] importData;

            // Update import directory
            IMAGE_DATA_DIRECTORY newImportDir = importDir;
            newImportDir.VirtualAddress = (DWORD)((BYTE*)newImportTable - (BYTE*)moduleBase);
            
            bytesWritten = 0;
            WriteProcessMemory(hProc, (LPVOID)((BYTE*)moduleBase + 
                offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT])),
                &newImportDir, sizeof(IMAGE_DATA_DIRECTORY), &bytesWritten);

            return true;
        }

        static bool PreventIATHooking(HANDLE hProc, LPVOID moduleBase) {
            BYTE headers[0x1000];
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProc, moduleBase, headers, sizeof(headers), &bytesRead))
                return false;

            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headers;
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(headers + dosHeader->e_lfanew);
            
            IMAGE_DATA_DIRECTORY& iatDir = 
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

            DWORD oldProtect;
            return VirtualProtectEx(hProc,
                (LPVOID)((BYTE*)moduleBase + iatDir.VirtualAddress),
                iatDir.Size, PAGE_READONLY, &oldProtect);
        }

        static bool CloakMemoryRegion(HANDLE hProc, LPVOID address, SIZE_T size) {
            DWORD oldProtect;
            return VirtualProtectEx(hProc, address, size, PAGE_NOACCESS, &oldProtect);
        }
    };
}

#ifdef _WIN64
using f_Routine = UINT_PTR(__fastcall*)(void* pArg);
#else
using f_Routine = UINT_PTR(__stdcall*)(void* pArg);
#endif

#ifdef UNICODE
#define LOAD_LIBRARY_NAME "LoadLibraryW"
#else
#define LOAD_LIBRARY_NAME "LoadLibraryA"
#endif

struct HookData {
    HHOOK m_hHook;
    HWND m_hWnd;
};

struct EnumWindowsCallback_Data {
    std::vector<HookData> m_HookData;
    DWORD m_PID;
    HOOKPROC m_pHook;
    HINSTANCE m_hModule;
};

inline HMODULE GetModuleHandleEx(HANDLE hTargetProc, const TCHAR* lpModuleName) {
    MODULEENTRY32 ME32{ 0 };
    ME32.dwSize = sizeof(MODULEENTRY32);  

    DWORD processId = GetProcessId(hTargetProc);
    if (processId == 0) {
        return NULL;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnap == INVALID_HANDLE_VALUE) {
        while (GetLastError() == ERROR_BAD_LENGTH) {
            hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
            if (hSnap != INVALID_HANDLE_VALUE)
                break;
        }
    }

    if (hSnap == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    BOOL bRet = Module32First(hSnap, &ME32);
    if (bRet) {
        do {
            if (!_tcsicmp(lpModuleName, ME32.szModule)) {
                CloseHandle(hSnap);
                return (HINSTANCE)ME32.modBaseAddr;
            }
        } while (Module32Next(hSnap, &ME32));
    }

    CloseHandle(hSnap);
    return NULL;
}

inline void* GetProcAddressEx(HANDLE hTargetProc, const TCHAR* lpModuleName, const char* lpProcName) {
    BYTE* modBase = reinterpret_cast<BYTE*>(GetModuleHandleEx(hTargetProc, lpModuleName));
    if (!modBase)
        return nullptr;

    BYTE* pe_header = new BYTE[0x1000];
    if (!pe_header)
        return nullptr;

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hTargetProc, modBase, pe_header, 0x1000, &bytesRead)) {
        delete[] pe_header;

        return nullptr;
    }

    auto* pNT =
        reinterpret_cast<IMAGE_NT_HEADERS*>(pe_header + reinterpret_cast<IMAGE_DOS_HEADER*>(pe_header)->e_lfanew);
    auto* pExportEntry = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!pExportEntry->Size) {
        delete[] pe_header;

        return nullptr;
    }

    BYTE* export_data = new BYTE[pExportEntry->Size];
    if (!export_data) {
        delete[] pe_header;

        return nullptr;
    }

    bytesRead = 0;
    if (!ReadProcessMemory(hTargetProc, modBase + pExportEntry->VirtualAddress, export_data, pExportEntry->Size,
        &bytesRead)) {
        delete[] export_data;
        delete[] pe_header;

        return nullptr;
    }

    BYTE* localBase = export_data - pExportEntry->VirtualAddress;
    auto* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(export_data);

    auto Forward = [&](DWORD FuncRVA) -> void* {
        char pFullExport[MAX_PATH + 1]{ 0 };
        auto Len = strlen(reinterpret_cast<char*>(localBase + FuncRVA));
        if (!Len)
            return nullptr;

        memcpy(pFullExport, reinterpret_cast<char*>(localBase + FuncRVA), Len);

        char* pFuncName = strchr(pFullExport, '.');
        *(pFuncName++) = 0;
        if (*pFuncName == '#')
            pFuncName = reinterpret_cast<char*>(LOWORD(atoi(++pFuncName)));

#ifdef UNICODE
        TCHAR ModNameW[MAX_PATH + 1]{ 0 };
        size_t SizeOut = 0;
        mbstowcs_s(&SizeOut, ModNameW, pFullExport, MAX_PATH);

        return GetProcAddressEx(hTargetProc, ModNameW, pFuncName);
#else

        return GetProcAddressEx(hTargetProc, pFullExport, pFuncName);
#endif
    };

    if ((reinterpret_cast<UINT_PTR>(lpProcName) & 0xFFFFFF) <= MAXWORD) {
        WORD Base = LOWORD(pExportDir->Base - 1);
        WORD Ordinal = LOWORD(lpProcName) - Base;
        DWORD FuncRVA = reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];

        delete[] export_data;
        delete[] pe_header;

        if (FuncRVA >= pExportEntry->VirtualAddress && FuncRVA < pExportEntry->VirtualAddress + pExportEntry->Size) {
            return Forward(FuncRVA);
        }

        return modBase + FuncRVA;
    }

    DWORD max = pExportDir->NumberOfNames - 1;
    DWORD min = 0;
    DWORD FuncRVA = 0;

    while (min <= max) {
        DWORD mid = (min + max) / 2;

        DWORD CurrNameRVA = reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfNames)[mid];
        char* szName = reinterpret_cast<char*>(localBase + CurrNameRVA);

        int cmp = strcmp(szName, lpProcName);
        if (cmp < 0)
            min = mid + 1;
        else if (cmp > 0)
            max = mid - 1;
        else {
            WORD Ordinal = reinterpret_cast<WORD*>(localBase + pExportDir->AddressOfNameOrdinals)[mid];
            FuncRVA = reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];

            break;
        }
    }

    delete[] export_data;
    delete[] pe_header;

    if (!FuncRVA)
        return nullptr;

    if (FuncRVA >= pExportEntry->VirtualAddress && FuncRVA < pExportEntry->VirtualAddress + pExportEntry->Size) {
        return Forward(FuncRVA);
    }

    return modBase + FuncRVA;
}

inline bool SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& LastWin32Error, UINT_PTR& Out) {
    void* pCodecave = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pCodecave) {
        LastWin32Error = GetLastError();

        return false;
    }

    void* pCallNextHookEx = GetProcAddressEx(hTargetProc, TEXT("user32.dll"), "CallNextHookEx");
    if (!pCallNextHookEx) {
        VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

        return false;
    }

#ifdef _WIN64

    BYTE Shellcode[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x18	-> pArg / returned value / rax
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x10	-> pRoutine
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x08	-> CallNextHookEx

        0x55, // + 0x00	-> push rbp
        0x54, // + 0x01	-> push rsp
        0x53, // + 0x02	-> push rbx

        0x48, 0x8D, 0x1D, 0xDE, 0xFF, 0xFF, 0xFF, // + 0x03	-> lea rbx, [pArg]

        0x48, 0x83, 0xEC, 0x20, // + 0x0A	-> sub rsp, 0x20
        0x4D, 0x8B, 0xC8,       // + 0x0E	-> mov r9,r8
        0x4C, 0x8B, 0xC2,       // + 0x11	-> mov r8, rdx
        0x48, 0x8B, 0xD1,       // + 0x14	-> mov rdx,rcx
        0xFF, 0x53, 0x10,       // + 0x17	-> call [rbx + 0x10]
        0x48, 0x83, 0xC4, 0x20, // + 0x1A	-> add rsp, 0x20

        0x48, 0x8B, 0xC8, // + 0x1E	-> mov rcx, rax

        0xEB, 0x00,                               // + 0x21	-> jmp $ + 0x02
        0xC6, 0x05, 0xF8, 0xFF, 0xFF, 0xFF, 0x18, // + 0x23	-> mov byte ptr[$ - 0x01], 0x1A

        0x48, 0x87, 0x0B,       // + 0x2A	-> xchg [rbx], rcx
        0x48, 0x83, 0xEC, 0x20, // + 0x2D	-> sub rsp, 0x20
        0xFF, 0x53, 0x08,       // + 0x31	-> call [rbx + 0x08]
        0x48, 0x83, 0xC4, 0x20, // + 0x34	-> add rsp, 0x20

        0x48, 0x87, 0x03, // + 0x38	-> xchg [rbx], rax

        0x5B, // + 0x3B	-> pop rbx
        0x5C, // + 0x3C	-> pop rsp
        0x5D, // + 0x3D	-> pop rbp

        0xC3 // + 0x3E	-> ret
    }; // SIZE = 0x3F (+ 0x18)

    DWORD CodeOffset = 0x18;
    DWORD CheckByteOffset = 0x22 + CodeOffset;

    *reinterpret_cast<void**>(Shellcode + 0x00) = pArg;
    *reinterpret_cast<void**>(Shellcode + 0x08) = pRoutine;
    *reinterpret_cast<void**>(Shellcode + 0x10) = pCallNextHookEx;

#else

    BYTE Shellcode[] = {
        0x00, 0x00, 0x00, 0x00, // - 0x08				-> pArg
        0x00, 0x00, 0x00, 0x00, // - 0x04				-> pRoutine

        0x55,       // + 0x00				-> push ebp
        0x8B, 0xEC, // + 0x01				-> mov ebp, esp

        0xFF, 0x75, 0x10,             // + 0x03				-> push [ebp + 0x10]
        0xFF, 0x75, 0x0C,             // + 0x06				-> push [ebp + 0x0C]
        0xFF, 0x75, 0x08,             // + 0x09				-> push [ebp + 0x08]
        0x6A, 0x00,                   // + 0x0C				-> push 0x00
        0xE8, 0x00, 0x00, 0x00, 0x00, // + 0x0E (+ 0x0F)		-> call CallNextHookEx

        0xEB, 0x00, // + 0x13				-> jmp $ + 0x02

        0x50, // + 0x15				-> push eax
        0x53, // + 0x16				-> push ebx

        0xBB, 0x00, 0x00, 0x00, 0x00, // + 0x17 (+ 0x18)		-> mov ebx, pArg
        0xC6, 0x43, 0x1C, 0x14,       // + 0x1C				-> mov [ebx + 0x1C], 0x17

        0xFF, 0x33, // + 0x20				-> push [ebx]

        0xFF, 0x53, 0x04, // + 0x22				-> call [ebx + 0x04]

        0x89, 0x03, // + 0x25				-> mov [ebx], eax

        0x5B, // + 0x27				-> pop ebx
        0x58, // + 0x28				-> pop eax

        0x5D,            // + 0x29				-> pop ebp
        0xC2, 0x0C, 0x00 // + 0x2A				-> ret 0x000C
    }; // SIZE = 0x3D (+ 0x08)

    DWORD CodeOffset = 0x08;
    DWORD CheckByteOffset = 0x14 + CodeOffset;

    *reinterpret_cast<void**>(Shellcode + 0x00) = pArg;
    *reinterpret_cast<void**>(Shellcode + 0x04) = pRoutine;

    *reinterpret_cast<DWORD*>(Shellcode + 0x0F + CodeOffset) =
        reinterpret_cast<DWORD>(pCallNextHookEx) - (reinterpret_cast<DWORD>(pCodecave) + 0x0E + CodeOffset) - 5;
    *reinterpret_cast<void**>(Shellcode + 0x18 + CodeOffset) = pCodecave;

#endif

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hTargetProc, pCodecave, Shellcode, sizeof(Shellcode), &bytesWritten)) {
        LastWin32Error = GetLastError();

        VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

        return false;
    }

    static EnumWindowsCallback_Data data;
    data.m_HookData.clear();

    data.m_pHook = reinterpret_cast<HOOKPROC>(reinterpret_cast<BYTE*>(pCodecave) + CodeOffset);
    data.m_PID = GetProcessId(hTargetProc);
    data.m_hModule = GetModuleHandle(TEXT("user32.dll"));

    WNDENUMPROC EnumWindowsCallback = [](HWND hWnd, LPARAM) -> BOOL {
        DWORD winPID = 0;
        DWORD winTID = GetWindowThreadProcessId(hWnd, &winPID);
        if (winPID == data.m_PID) {
            TCHAR szWindow[MAX_PATH]{ 0 };
            if (IsWindowVisible(hWnd) && GetWindowText(hWnd, szWindow, MAX_PATH)) {
                if (GetClassName(hWnd, szWindow, MAX_PATH) && _tcscmp(szWindow, TEXT("ConsoleWindowClass"))) {
                    HHOOK hHook = SetWindowsHookEx(WH_CALLWNDPROC, data.m_pHook, data.m_hModule, winTID);
                    if (hHook) {
                        data.m_HookData.push_back({ hHook, hWnd });
                    }
                }
            }
        }

        return TRUE;
    };

    if (!EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&data))) {
        LastWin32Error = GetLastError();

        VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

        return false;
    }

    if (data.m_HookData.empty()) {
        VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

        return false;
    }

    HWND hForegroundWnd = GetForegroundWindow();
    for (auto i : data.m_HookData) {
        SetForegroundWindow(i.m_hWnd);
        SendMessageA(i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0);
        Sleep(10);
        SendMessageA(i.m_hWnd, WM_KEYUP, VK_SPACE, 0);
        UnhookWindowsHookEx(i.m_hHook);
    }
    SetForegroundWindow(hForegroundWnd);

    DWORD Timer = GetTickCount();
    BYTE CheckByte = 0;

    do {
        SIZE_T bytesRead = 0;
        ReadProcessMemory(hTargetProc, reinterpret_cast<BYTE*>(pCodecave) + CheckByteOffset, &CheckByte, 1, &bytesRead);

        if (GetTickCount() - Timer > 5000) {
            return false;
        }

        Sleep(10);

    } while (!CheckByte);

    SIZE_T bytesRead = 0;
    ReadProcessMemory(hTargetProc, pCodecave, &Out, sizeof(Out), &bytesRead);

    VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

    return true;
}

inline bool InjectDll(HANDLE hProc, const TCHAR* szPath) {
    if (!hProc) {
        DWORD dwErr = GetLastError();
        printf("OpenProcess failed: 0x%08X\n", dwErr);

        return false;
    }

    auto len = _tcslen(szPath) * sizeof(TCHAR);
    void* pArg = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pArg) {
        DWORD dwErr = GetLastError();
        printf("VirtualAllocEx failed: 0x%08X\n", dwErr);

        CloseHandle(hProc);

        return false;
    }

    SIZE_T bytesWritten = 0;
    BOOL bRet = WriteProcessMemory(hProc, pArg, szPath, len, &bytesWritten);
    if (!bRet) {
        DWORD dwErr = GetLastError();
        printf("WriteProcessMemory failed: 0x%08X\n", dwErr);

        VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
        CloseHandle(hProc);

        return false;
    }

    f_Routine* p_LoadLibrary =
        reinterpret_cast<f_Routine*>(GetProcAddressEx(hProc, TEXT("kernel32.dll"), LOAD_LIBRARY_NAME));
    if (!p_LoadLibrary) {
        printf("Can't find LoadLibrary\n");

        VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
        CloseHandle(hProc);

        return false;
    }

    UINT_PTR hDllOut = 0;
    DWORD last_error = 0;
    bool dwErr = SR_SetWindowsHookEx(hProc, p_LoadLibrary, pArg, last_error, hDllOut);

    CloseHandle(hProc);

    if (!dwErr) {
        printf("StartRoutine failed\n");
        printf("LastWin32Error: 0x%08X\n", last_error);

        return false;
    }

    printf("Success! LoadLibrary returned 0x%p\n", reinterpret_cast<void*>(hDllOut));

    // Get base address of injected DLL
    HMODULE hModule = GetModuleHandleEx(hProc, PathFindFileName(szPath));
    if (hModule) {
        // Apply advanced stealth techniques
        Stealth::Helper::ErasePEHeader(hProc, hModule);
        Stealth::Helper::RandomizeTimestamp(hProc, hModule);
        
        // Unlink DLL from PEB
        if (!Stealth::DllUnlink::UnlinkFromPEB(hProc, hModule)) {
            return false;
        }
        
        // Obfuscate imports and protect IAT
        Stealth::ImportObfuscator::ObfuscateImports(hProc, hModule);
        Stealth::ImportObfuscator::PreventIATHooking(hProc, hModule);
        
        // Cloak critical memory regions
        Stealth::ImportObfuscator::CloakMemoryRegion(hProc, hModule, 0x1000);
    }

    return true;
}

inline bool LoadLibraryInject(HANDLE hProcess, const std::wstring& dllPath, bool obfuscateImports = false) {
    // Allocate memory for the DLL path in the target process
    SIZE_T pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remotePath) {
        return false;
    }

    // Write the DLL path to the allocated memory
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathSize, &bytesWritten)) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    // Get the address of LoadLibraryW in kernel32.dll
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr = 
        (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryW");
    if (!loadLibraryAddr) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    // Create a remote thread to call LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        loadLibraryAddr, remotePath, 0, NULL);

    if (!hThread) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    // Wait for the thread to complete
    WaitForSingleObject(hThread, INFINITE);

    // Get the thread exit code (handle to the loaded module)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    // Get module base address
    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(me32.szModule, PathFindFileNameW(dllPath.c_str())) == 0) {
                    // Apply stealth techniques
                    Stealth::Helper::ErasePEHeader(hProcess, me32.modBaseAddr);
                    Stealth::Helper::RandomizeTimestamp(hProcess, me32.modBaseAddr);
                    
                    // Apply import table obfuscation if enabled
                    if (obfuscateImports) {
                        Stealth::ImportObfuscator::ObfuscateImports(hProcess, me32.modBaseAddr);
                    }
                    
                    // Unlink from PEB
                    Stealth::DllUnlink::UnlinkFromPEB(hProcess, (HMODULE)me32.modBaseAddr);
                    break;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);

    return exitCode != 0;
}
