#include "config.hpp"
#include <iostream>
#include <format>

namespace Config {
    nlohmann::json config;
    std::wstring directory = L"";
    std::wstring filePath = L"";
    std::ofstream output;
    bool shuttingDown = false;

    void setDirectory(std::wstring directory) { 
        std::wcout << L"[DEBUG] Setting directory to: " << directory << std::endl;
        Config::directory = directory; 
    }

    void actualSave(bool dontWriteLastSave) {
        std::cout << "[DEBUG] Saving configuration to file: " << std::string(filePath.begin(), filePath.end()) << std::endl;
        output = std::ofstream(filePath);
        output << config;
        output.close();
    }

    void actualSave() {
        actualSave(false);
    }

    void init(HMODULE handle) {
        std::cout << "[DEBUG] Initializing configuration" << std::endl;
        
        if (directory.empty()) {
            std::cout << "[DEBUG] Directory not set, getting module path" << std::endl;
            const uint16_t pathSize = 2048;
            wchar_t path[pathSize];
            GetModuleFileName((HMODULE)handle, (LPWSTR)path, sizeof(path));
            std::wstring dir = std::wstring(path);
            dir = dir.substr(0, dir.find_last_of(L"\\") + 1);
            setDirectory(dir);
        }

        filePath = directory + L"\\config.json";
        std::wcout << L"[DEBUG] Config file path: " << filePath << std::endl;

        if (!std::filesystem::exists(filePath)) {
            std::cout << "[DEBUG] Config file doesn't exist, creating new file" << std::endl;
            std::ofstream file(filePath);
            file.close();
        }

        const auto size = std::filesystem::file_size(std::filesystem::path(filePath));
        std::cout << "[DEBUG] Config file size: " << size << " bytes" << std::endl;

        if (size == 0) {
            std::cout << "[DEBUG] Empty config file, initializing with empty JSON object" << std::endl;
            config = nlohmann::json::object();
            config["injectionMethod"] = "loadLibrary";
            config["launcherPath"] = "";
            actualSave(true);
        } else {
            std::cout << "[DEBUG] Loading existing config file" << std::endl;
            std::ifstream file(filePath);
            config = nlohmann::json::parse(file);
            file.close();
        }

        shuttingDown = false;
        std::cout << "[DEBUG] Configuration initialization complete" << std::endl;
    }

    void save() {
        actualSave(false);
    }

    void shutdown() { 
        std::cout << "[DEBUG] Shutting down configuration system" << std::endl;
        shuttingDown = true;
        actualSave(false);
    }
} // namespace Config
