#include "config.hpp"
#include "inject.hpp"
#include "manual.hpp"
#include "pch.h"
#include "version.h"
#include "hijack.hpp"
#include "hollow.hpp"
#include "obfuscate.hpp"
#include "shellcode.hpp"
#include <TlHelp32.h>
#include "stealth.hpp"
#include "syscalls.hpp"
#include "shared.hpp"

#pragma warning (disable : 4996)

typedef void (*setDirectory)(std::wstring directory);
typedef int (*init)(HINSTANCE hInstDLL);

// Logger for actions taken by the injector
class Logger {
public:
    static Logger& getInstance() {
        static Logger instance("injector.log");
        return instance;
    }

    Logger(const std::string& filename) {
        logFile.open(filename, std::ios::out | std::ios::app);
        if (!logFile.is_open()) {
            MessageBoxA(NULL, "Failed to open log file!", "Error", MB_OK | MB_ICONERROR);
            std::cerr << "Failed to open log file: " << filename << std::endl;
        } else {
            log("=== Injector Started ===");
        }
    }

    ~Logger() {
        if (logFile.is_open()) {
            log("=== Injector Shutdown ===");
            logFile.close();
        }
    }

    void log(const std::string& message) {
        if (logFile.is_open()) {
            std::string timestamp = getCurrentTime();
            std::string fullMessage = timestamp + " - " + message;
            
            // Write to file
            logFile << fullMessage << std::endl;
            logFile.flush(); // Ensure it's written immediately
            
            // Also output to console for immediate feedback
            std::cout << fullMessage << std::endl;
        }
    }

private:
    std::ofstream logFile;

    std::string getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %X");
        return oss.str();
    }
};

// Global logger accessor
#define LOG(msg) Logger::getInstance().log(msg)

// Function to ask for the launcher path using a FileOpenDialog
PWSTR askForLauncherPath() {
    PWSTR pszFilePath = nullptr;
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    if (SUCCEEDED(hr)) {
        IFileOpenDialog* pFileOpen = nullptr;
        hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));

        if (SUCCEEDED(hr)) {
            const COMDLG_FILTERSPEC filter[] = { {L"Launcher", L"tof_launcher.exe"} };
            pFileOpen->SetFileTypes(ARRAYSIZE(filter), filter);
            hr = pFileOpen->Show(NULL);

            if (SUCCEEDED(hr)) {
                IShellItem* pItem = nullptr;
                hr = pFileOpen->GetResult(&pItem);
                if (SUCCEEDED(hr)) {
                    hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                    pItem->Release();
                }
            }
            pFileOpen->Release();
        }
        CoUninitialize();
    }

    return pszFilePath;
}

// Function to start the launcher process
bool startLauncher(const wchar_t* launcherPath, Logger& logger) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    SetEnvironmentVariable(L"__COMPAT_LAYER", L"RUNASINVOKER");

    if (!CreateProcess(launcherPath, nullptr, nullptr, nullptr, false, 0, nullptr, nullptr, &si, &pi)) {
        logger.log("Failed to start the launcher. Error: " + std::to_string(GetLastError()));
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// Function to retrieve the process ID of the specified executable
DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE handleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (handleSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry = { sizeof(procEntry) };
        while (Process32Next(handleSnapshot, &procEntry)) {
            if (_wcsicmp(procEntry.szExeFile, procName) == 0) {
                procId = procEntry.th32ProcessID;
                break;
            }
        }
        CloseHandle(handleSnapshot);
    }

    return procId;
}

// Function to construct the DLL path
std::wstring getDllPath(const std::wstring& directory, const std::wstring& dllName) {
    return directory + dllName;
}

// Function to resolve API functions dynamically
using FuncPtr = FARPROC;

class ApiResolver {
public:
    ApiResolver() {
        hKernel32 = LoadLibraryA("kernel32.dll");
        hPsapi = LoadLibraryA("Psapi.dll");
        // Add more libraries as needed
    }

    ~ApiResolver() {
        if (hKernel32) FreeLibrary(hKernel32);
        if (hPsapi) FreeLibrary(hPsapi);
    }

    FuncPtr GetProc(const std::string& functionName) {
        if (hKernel32) {
            return GetProcAddress(hKernel32, functionName.c_str());
        }
        return nullptr;
    }

private:
    HMODULE hKernel32;
    HMODULE hPsapi;
};

bool injectDll(HANDLE proc, const std::wstring& dllPath, const std::string& injectionMethod, const std::wstring& directory, Logger& logger, ApiResolver& apiResolver) {
    bool result = false;

    if (injectionMethod == "manual") {
        LOG("Attempting manual map injection with enhanced stealth");
        std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
        if (!dllFile.is_open()) {
            LOG("Failed to open DLL file: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));
            return false;
        }
        
        auto dllSize = dllFile.tellg();
        dllFile.seekg(0, std::ios::beg);
        
        LOG("DLL size: " + std::to_string(dllSize) + " bytes");
        
        std::vector<BYTE> pSrcData(dllSize);
        dllFile.read(reinterpret_cast<char*>(pSrcData.data()), dllSize);
        dllFile.close();
        
        // Initialize direct syscalls
        if (!SyscallHelper::InitializeSyscalls()) {
            LOG("Failed to initialize syscalls");
            return false;
        }
        
        result = ManualMapDll<const wchar_t*>(proc, pSrcData.data(), dllSize, "preMain", directory.c_str(), directory.size() * 2);
        
        if (result) {
            // Apply stealth techniques
            DWORD_PTR moduleBase = 0; // You need to get this from ManualMapDll
            if (moduleBase) {
                StealthHelper::RemovePeHeader(proc, moduleBase);
                StealthHelper::RandomizeTimestamp(proc, (LPVOID)moduleBase);
            }
        } else {
            LOG("Manual mapping failed");
            DWORD error = GetLastError();
            LOG("Last error code: " + std::to_string(error));
        }
    }
    else if (injectionMethod == "loadLibrary") {
        LOG("Attempting LoadLibrary injection");
        bool obfuscateImports = Config::config.contains("obfuscateImports") && Config::config["obfuscateImports"].get<bool>();
        result = LoadLibraryInject(proc, dllPath, obfuscateImports);
        if (!result) {
            LOG("LoadLibrary injection failed");
            DWORD error = GetLastError();
            LOG("Last error code: " + std::to_string(error));
        }
    }
    else if (injectionMethod == "threadHijack") {
        LOG("Attempting Thread Hijacking injection");
        // Find a suitable thread to hijack
        HANDLE hThread = nullptr;
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == GetProcessId(proc)) {
                        hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                        if (hThread) break;
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }
            CloseHandle(hSnapshot);
        }
        
        if (hThread) {
            // Create shellcode for LoadLibrary injection
            ShellcodeData shellcode = CreateLoadLibraryShellcode(dllPath);
            if (shellcode.code.empty()) {
                std::cerr << "Failed to create shellcode" << std::endl;
                CloseHandle(hThread);
                return false;
            }
            result = ThreadHijacking::HijackThread(proc, hThread, shellcode.code.data(), shellcode.code.size());
            CloseHandle(hThread);
        }
    }
    else if (injectionMethod == "hollow") {
        LOG("Attempting Process Hollowing injection");
        std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
        if (!dllFile.is_open()) {
            LOG("Failed to open DLL file: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));
            return false;
        }
        
        auto dllSize = dllFile.tellg();
        dllFile.seekg(0, std::ios::beg);
        
        LOG("DLL size: " + std::to_string(dllSize) + " bytes");
        
        std::vector<BYTE> pSrcData(dllSize);
        dllFile.read(reinterpret_cast<char*>(pSrcData.data()), dllSize);
        dllFile.close();
        
        result = ProcessHollowing::HollowProcess(proc, pSrcData.data(), dllSize);
    }
    else {
        LOG("Unknown injection method: " + injectionMethod);
        return false;
    }

    if (result) {
        // Apply additional stealth techniques
        DWORD_PTR moduleBase = 0; // You need to get this from the injection method
        if (moduleBase) {
            StealthHelper::RemovePeHeader(proc, moduleBase);
            StealthHelper::RandomizeTimestamp(proc, (LPVOID)moduleBase);
            
            // Apply import table obfuscation if requested
            if (Config::config["obfuscateImports"]) {
                ImportObfuscator::ObfuscateImports(proc, (LPVOID)moduleBase);
            }
        }
        
        LOG("Injection successful");
    } else {
        LOG("Injection failed");
    }

    return result;
}

bool IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

HANDLE OpenGameProcess(DWORD processId) {
    if (!IsElevated()) {
        LOG("ERROR: Administrator privileges required for process access");
        return nullptr;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ |
        PROCESS_TERMINATE |
        SYNCHRONIZE,
        FALSE,
        processId
    );

    if (!hProcess) {
        DWORD error = GetLastError();
        LOG("Failed to open process. Error code: " + std::to_string(error));
        if (error == ERROR_ACCESS_DENIED) {
            LOG("Access denied. Make sure you're running as administrator");
        }
        return nullptr;
    }

    return hProcess;
}

void convertUtf8ToWchar(const char* utf8, wchar_t*& wide) {
    int length = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    wide = new wchar_t[length];
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, length);
}

int main() {
    std::cout << VERSION_INFO << std::endl;
    LOG("Starting injector process");

    const wchar_t* launcherExe = L"tof_launcher.exe";
    const wchar_t* gameExe = L"QRSL.exe";
    
    // Check if the injector is running with admin privileges
    if (!IsElevated()) {
        LOG("WARNING: Injector is not running with administrator privileges!");
        MessageBoxA(NULL, "Running without admin privileges may cause injection to fail!", "Warning", MB_OK | MB_ICONWARNING);
    }

    // Check if the launcher is already running
    if (GetProcId(launcherExe) != 0) {
        LOG("Launcher is already running. Please close it and relaunch the injector.");
        MessageBoxA(NULL, "Launcher is already running. Please close it and relaunch the injector.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    wchar_t path[2048];
    GetModuleFileName(nullptr, path, sizeof(path) / sizeof(wchar_t));
    std::wstring directory = std::wstring(path).substr(0, std::wstring(path).find_last_of(L"\\") + 1);

    Config::setDirectory(directory);
    Config::init();

    auto launcherPath = Config::get<std::string>("/launcherPath", "");

    if (launcherPath->empty()) {
        LOG("Launcher path not found. Please select the launcher path.");
        PWSTR selectedPath = askForLauncherPath();
        if (selectedPath) {
            launcherPath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(selectedPath);
            CoTaskMemFree(selectedPath);
            LOG("Selected launcher path: " + *launcherPath);
        }
        else {
            LOG("Launcher path not given. Exiting...");
            return 1;
        }
    }

    LOG("Starting launcher process...");
    if (!startLauncher(std::wstring(launcherPath->begin(), launcherPath->end()).c_str(), Logger::getInstance())) {
        return 1;
    }

    // Reload config to get latest injection method
    Config::reload();
    auto configuredInjectionMethod = Config::get<std::string>("/injectionMethod", "manual");
    std::string injectionMethodStr = configuredInjectionMethod->c_str();
    LOG("Using injection method: " + injectionMethodStr);

    LOG("Waiting for game process (QRSL.exe)...");
    DWORD qrslPid = 0;
    while ((qrslPid = GetProcId(gameExe)) == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    LOG("Game process found. PID: " + std::to_string(qrslPid));

    std::wstring dllPath = getDllPath(directory, L"SDK_cheat_menu.dll");
    LOG("DLL path: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));

    // Verify DLL exists
    if (!std::filesystem::exists(dllPath)) {
        LOG("ERROR: DLL file not found at: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));
        return 1;
    }

    LOG("Opening game process...");
    HANDLE proc = OpenGameProcess(qrslPid);
    if (!proc) {
        LOG("Failed to open game process with required permissions");
        LOG("Please run the injector as administrator");
        return 1;
    }

    ApiResolver apiResolver;
    bool injected = false;
    LOG("Ready for injection. Press F1 to inject...");
    
    while (!injected) {
        if (GetAsyncKeyState(VK_F1) & 0x8000) {
            LOG("F1 pressed - attempting injection...");
            
            // Small delay to prevent multiple injections
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            bool injectionResult = injectDll(proc, dllPath, injectionMethodStr, directory, Logger::getInstance(), apiResolver);
            
            if (injectionResult) {
                LOG("DLL injection successful!");
                injected = true;
            } else {
                LOG("DLL injection failed - press F1 to retry or ESC to exit");
                if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
                    break;
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    if (!injected) {
        LOG("Injection process terminated without successful injection.");
    }

    CloseHandle(proc);
    Config::shutdown();
    LOG("Injector shutting down...");
    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}
