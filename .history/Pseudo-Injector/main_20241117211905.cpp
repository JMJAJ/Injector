#include "config.hpp"
#include "inject.hpp"
#include "manual.hpp"
#include "pch.h"
#include "version.h"
#include "stealth.hpp"
#include "syscalls.hpp"

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
    if (injectionMethod == "manual") {
        LOG("Using manual mapping injection method");
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
        
        LOG("Attempting manual map injection with enhanced stealth");
        bool result = ManualMapDll<const wchar_t*>(proc, pSrcData.data(), dllSize, "preMain", directory.c_str(), directory.size() * 2);
        
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
        
        return result;
    }
    else if (injectionMethod == "loadLibrary") {
        LOG("Using LoadLibrary injection method with enhanced stealth");
        
        // Convert wide string DLL path to TCHAR
        #ifdef UNICODE
        std::wstring tcharPath = dllPath;
        #else
        std::string tcharPath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath);
        #endif
        
        LOG("Attempting LoadLibrary injection with path: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));
        
        // Initialize direct syscalls
        if (!SyscallHelper::InitializeSyscalls()) {
            LOG("Failed to initialize syscalls");
            return false;
        }
        
        // Use our enhanced SetWindowsHookEx injection with stealth measures
        bool result = InjectDll(proc, tcharPath.c_str());
        
        if (result) {
            // Get the base address of the injected DLL
            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(proc));
            
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                if (Module32First(hSnapshot, &me32)) {
                    do {
                        if (_wcsicmp(me32.szModule, PathFindFileName(tcharPath.c_str())) == 0) {
                            // Apply stealth techniques
                            StealthHelper::ErasePEHeader(proc, me32.modBaseAddr);
                            StealthHelper::RandomizeTimestamp(proc, me32.modBaseAddr);
                            break;
                        }
                    } while (Module32Next(hSnapshot, &me32));
                }
                CloseHandle(hSnapshot);
            }
        } else {
            LOG("LoadLibrary injection failed");
            DWORD error = GetLastError();
            LOG("Last error code: " + std::to_string(error));
            return false;
        }
        
        LOG("LoadLibrary injection completed successfully");
        return true;
    }
    else {
        LOG("Invalid injection method: " + injectionMethod);
        return false;
    }
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
    BOOL isAdmin = FALSE;
    HANDLE tokenHandle;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(tokenHandle, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(tokenHandle);
    }

    if (!isAdmin) {
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
        std::wstring errorMsg = L"DLL file not found at: " + dllPath;
        MessageBoxW(NULL, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
        LOG("ERROR: DLL file not found at: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));
        return 1;
    }

    LOG("Opening game process...");
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, qrslPid);
    if (!proc) {
        DWORD error = GetLastError();
        LOG("Failed to open process. Error code: " + std::to_string(error));
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
