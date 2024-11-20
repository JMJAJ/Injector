#pragma once
#include <string>
#include <memory>
#include <windows.h>
#include <iostream>
#include <format>
#include <fstream>
#include <future>
#include <queue>
#include <mutex>
#include <chrono>
#include <thread>
#include "json.hpp"

// Forward declarations
class ConfigManager;

struct LoggingConfig {
    std::string logFilePath = "injector.log";
    std::string logLevel = "INFO";
    bool enableFileLogging = true;
    bool enableConsoleOutput = true;
    int maxLogSizeMB = 10;
    int keepLogFiles = 3;

    friend void to_json(nlohmann::json& j, const LoggingConfig& c) {
        j = nlohmann::json{
            {"logFilePath", c.logFilePath},
            {"logLevel", c.logLevel},
            {"enableFileLogging", c.enableFileLogging},
            {"enableConsoleOutput", c.enableConsoleOutput},
            {"maxLogSizeMB", c.maxLogSizeMB},
            {"keepLogFiles", c.keepLogFiles}
        };
    }

    friend void from_json(const nlohmann::json& j, LoggingConfig& c) {
        j.at("logFilePath").get_to(c.logFilePath);
        j.at("logLevel").get_to(c.logLevel);
        j.at("enableFileLogging").get_to(c.enableFileLogging);
        j.at("enableConsoleOutput").get_to(c.enableConsoleOutput);
        j.at("maxLogSizeMB").get_to(c.maxLogSizeMB);
        j.at("keepLogFiles").get_to(c.keepLogFiles);
    }
};

struct InjectionConfig {
    std::string defaultMethod = "manual";
    int timeoutSeconds = 30;
    int retryAttempts = 3;
    int retryDelayMs = 1000;

    friend void to_json(nlohmann::json& j, const InjectionConfig& c) {
        j = nlohmann::json{
            {"defaultMethod", c.defaultMethod},
            {"timeoutSeconds", c.timeoutSeconds},
            {"retryAttempts", c.retryAttempts},
            {"retryDelayMs", c.retryDelayMs}
        };
    }

    friend void from_json(const nlohmann::json& j, InjectionConfig& c) {
        j.at("defaultMethod").get_to(c.defaultMethod);
        j.at("timeoutSeconds").get_to(c.timeoutSeconds);
        j.at("retryAttempts").get_to(c.retryAttempts);
        j.at("retryDelayMs").get_to(c.retryDelayMs);
    }
};

struct SecurityConfig {
    bool verifySignatures = true;
    bool enableAslr = true;

    friend void to_json(nlohmann::json& j, const SecurityConfig& c) {
        j = nlohmann::json{
            {"verifySignatures", c.verifySignatures},
            {"enableAslr", c.enableAslr}
        };
    }

    friend void from_json(const nlohmann::json& j, SecurityConfig& c) {
        j.at("verifySignatures").get_to(c.verifySignatures);
        j.at("enableAslr").get_to(c.enableAslr);
    }
};

struct DebugConfig {
    bool verboseOutput = false;
    bool collectSystemInfo = true;

    friend void to_json(nlohmann::json& j, const DebugConfig& c) {
        j = nlohmann::json{
            {"verboseOutput", c.verboseOutput},
            {"collectSystemInfo", c.collectSystemInfo}
        };
    }

    friend void from_json(const nlohmann::json& j, DebugConfig& c) {
        j.at("verboseOutput").get_to(c.verboseOutput);
        j.at("collectSystemInfo").get_to(c.collectSystemInfo);
    }
};

class ConfigManager {
public:
    static ConfigManager& getInstance();
    void initialize(const std::string& configPath = "config.json");
    void shutdown();
    void setDirectory(const std::wstring& directory);
    void init(HMODULE handle = nullptr);
    void save();

    // Public methods for accessing config values
    nlohmann::json& getConfig() { return config; }
    const nlohmann::json& getConfig() const { return config; }

    template<typename T>
    static std::shared_ptr<T> get(const std::string& key, const T& defaultValue = T()) {
        return getInstance().getValue<T>(key, defaultValue);
    }

    // Configuration members
    std::string launcherPath;
    LoggingConfig logging;
    InjectionConfig injection;
    SecurityConfig security;
    DebugConfig debug;

    friend void to_json(nlohmann::json& j, const ConfigManager& c) {
        j = nlohmann::json{
            {"launcherPath", c.launcherPath},
            {"logging", c.logging},
            {"injection", c.injection},
            {"security", c.security},
            {"debug", c.debug}
        };
    }

    friend void from_json(const nlohmann::json& j, ConfigManager& c) {
        j.at("launcherPath").get_to(c.launcherPath);
        j.at("logging").get_to(c.logging);
        j.at("injection").get_to(c.injection);
        j.at("security").get_to(c.security);
        j.at("debug").get_to(c.debug);
    }

private:
    ConfigManager();
    ~ConfigManager();
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    void loadConfig();
    void setDefaults();
    void actualSave(bool dontUpdateLastSave = false);
    void saveLoop();

    template<typename T>
    std::shared_ptr<T> getValue(const std::string& key, const T& defaultValue) {
        try {
            if (config.contains(key)) {
                return std::make_shared<T>(config[key].get<T>());
            }
        } catch (...) {}
        return std::make_shared<T>(defaultValue);
    }

    std::string m_configPath;
    std::wstring m_directory;
    HMODULE m_handle;
    nlohmann::json config;
    
    bool m_saveThreadStarted;
    bool m_shuttingDown;
    std::chrono::time_point<std::chrono::system_clock> m_lastSave;
};
