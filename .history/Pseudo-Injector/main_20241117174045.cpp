#include "config.hpp"
#include "inject.hpp"
#include "manual.hpp"
#include "pch.h"

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
        logger.log("Using manual mapping injection method");
        std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
        if (!dllFile.is_open()) {
            logger.log("Failed to open DLL file: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));
            return false;
        }
        auto dllSize = dllFile.tellg();
        dllFile.seekg(0, std::ios::beg);
        std::unique_ptr<BYTE[]> pSrcData(new BYTE[dllSize]);
        dllFile.read(reinterpret_cast<char*>(pSrcData.get()), dllSize);
        
        logger.log("Attempting manual map injection with DLL size: " + std::to_string(dllSize));
        bool result = ManualMapDll<const wchar_t*>(proc, pSrcData.get(), dllSize, "preMain", directory.c_str(), directory.size() * 2);
        if (!result) {
            logger.log("Manual mapping failed");
        }
        return result;
    }
    else if (injectionMethod == "loadLibrary") {
        logger.log("Using LoadLibrary injection method");
        auto LoadLibraryA = reinterpret_cast<FuncPtr>(apiResolver.GetProc("LoadLibraryA"));
        if (!LoadLibraryA) {
            logger.log("Failed to resolve LoadLibraryA function");
            return false;
        }

        // Convert wide string DLL path to ASCII
        std::string dllPathA = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath);
        logger.log("Attempting LoadLibrary injection with path: " + dllPathA);
        
        // Allocate memory in target process
        LPVOID pDllPath = VirtualAllocEx(proc, nullptr, dllPathA.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pDllPath) {
            logger.log("Failed to allocate memory in target process. Error: " + std::to_string(GetLastError()));
            return false;
        }

        // Write DLL path to target process
        if (!WriteProcessMemory(proc, pDllPath, dllPathA.c_str(), dllPathA.size() + 1, nullptr)) {
            logger.log("Failed to write to process memory. Error: " + std::to_string(GetLastError()));
            VirtualFreeEx(proc, pDllPath, 0, MEM_RELEASE);
            return false;
        }

        // Create remote thread to load DLL
        HANDLE hThread = CreateRemoteThread(proc, nullptr, 0, 
            reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), 
            pDllPath, 0, nullptr);
        
        if (!hThread) {
            logger.log("Failed to create remote thread. Error: " + std::to_string(GetLastError()));
            VirtualFreeEx(proc, pDllPath, 0, MEM_RELEASE);
            return false;
        }

        // Wait for thread completion
        WaitForSingleObject(hThread, INFINITE);
        
        // Get thread exit code
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        
        // Cleanup
        CloseHandle(hThread);
        VirtualFreeEx(proc, pDllPath, 0, MEM_RELEASE);
        
        if (exitCode == 0) {
            logger.log("LoadLibrary injection failed - DLL load returned 0");
            return false;
        }
        
        logger.log("LoadLibrary injection completed successfully");
        return true;
    }
    else {
        logger.log("Invalid injection method: " + injectionMethod);
        return false;
    }
}

int main() {
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
        LOG("ERROR: DLL file not found at: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath));
        MessageBoxA(NULL, "SDK_cheat_menu.dll not found!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    LOG("Opening game process...");
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, qrslPid);
    if (!proc) {
        DWORD error = GetLastError();
        LOG("Failed to open process. Error code: " + std::to_string(error));
        MessageBoxA(NULL, "Failed to open game process! Try running as administrator.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ApiResolver apiResolver;
    bool injected = false;
    LOG("Ready for injection. Press F1 to inject...");
    
    // Create a window to receive keyboard input
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, DefWindowProc, 0, 0, 
                      GetModuleHandle(NULL), NULL, NULL, NULL, NULL, L"InjectorWindow", NULL };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName, NULL, WS_OVERLAPPED, 
                            0, 0, 1, 1, NULL, NULL, wc.hInstance, NULL);
    
    if (hwnd) {
        ShowWindow(hwnd, SW_HIDE);
        MSG msg;
        
        while (!injected) {
            // Process any pending messages
            while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
                if (msg.message == WM_QUIT)
                    break;
            }

            if (GetAsyncKeyState(VK_F1) & 0x8000) {
                LOG("F1 pressed - attempting injection...");
                
                // Small delay to prevent multiple injections
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                
                bool injectionResult = injectDll(proc, dllPath, injectionMethodStr, directory, Logger::getInstance(), apiResolver);
                
                if (injectionResult) {
                    LOG("DLL injection successful!");
                    MessageBoxA(NULL, "Injection successful!", "Success", MB_OK | MB_ICONINFORMATION);
                    injected = true;
                } else {
                    LOG("DLL injection failed!");
                    if (MessageBoxA(NULL, "Injection failed! Try again?", "Error", 
                                  MB_RETRYCANCEL | MB_ICONERROR) != IDRETRY) {
                        break;
                    }
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        DestroyWindow(hwnd);
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
