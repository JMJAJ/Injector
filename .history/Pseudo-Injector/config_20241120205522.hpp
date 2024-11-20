#pragma once
#include <string>
#include <memory>
#include <nlohmann/json.hpp>

struct LoggingConfig {
    std::string logFilePath;
    std::string logLevel;
    bool enableFileLogging;
    bool enableConsoleOutput;
    int maxLogSizeMB;
    int keepLogFiles;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(LoggingConfig, logFilePath, logLevel, enableFileLogging, enableConsoleOutput, maxLogSizeMB, keepLogFiles)
};

struct InjectionConfig {
    std::string defaultMethod;
    int timeoutSeconds;
    int retryAttempts;
    int retryDelayMs;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(InjectionConfig, defaultMethod, timeoutSeconds, retryAttempts, retryDelayMs)
};

struct SecurityConfig {
    bool verifySignatures;
    bool enableAslr;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(SecurityConfig, verifySignatures, enableAslr)
};

struct DebugConfig {
    bool verboseOutput;
    bool collectSystemInfo;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DebugConfig, verboseOutput, collectSystemInfo)
};

class ConfigManager {
public:
    static ConfigManager& getInstance();
    void initialize(const std::string& configPath = "config.json");
    void shutdown();
    void setDirectory(const std::wstring& directory);
    void init(HMODULE handle = nullptr);

    template<typename T>
    static std::shared_ptr<T> get(const std::string& key, const T& defaultValue = T()) {
        return getInstance().getValue<T>(key, defaultValue);
    }

    std::string launcherPath;
    LoggingConfig logging;
    InjectionConfig injection;
    SecurityConfig security;
    DebugConfig debug;

private:
    ConfigManager();
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    void loadConfig();
    void setDefaults();
    void saveConfig();

    template<typename T>
    std::shared_ptr<T> getValue(const std::string& key, const T& defaultValue) {
        try {
            nlohmann::json j;
            {
                std::ifstream file(m_configPath);
                if (file.is_open()) {
                    file >> j;
                }
            }
            return std::make_shared<T>(j.value(key, defaultValue));
        } catch (...) {
            return std::make_shared<T>(defaultValue);
        }
    }

    std::string m_configPath;
    std::wstring m_directory;
    HMODULE m_handle;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ConfigManager, launcherPath, logging, injection, security, debug)
};
