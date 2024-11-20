#include "config.hpp"

namespace Config {
    nlohmann::json config;
    std::wstring directory = L"";
    std::wstring filePath = L"";
    bool shuttingDown = false;
    HMODULE handle = nullptr;

    void setDirectory(std::wstring dir) {
        directory = dir;
        filePath = directory + L"config.json";
    }

    void init(HMODULE h) {
        handle = h;
        try {
            std::ifstream file(filePath);
            if (file.is_open()) {
                file >> config;
            }
        } catch (...) {
            std::cout << "[ERROR] Failed to load configuration file" << std::endl;
        }
    }

    void actualSave(bool checkShutdown) {
        if (checkShutdown && shuttingDown) return;

        try {
            std::ofstream file(filePath);
            file << config.dump(4);
        } catch (...) {
            std::cout << "[ERROR] Failed to save configuration file" << std::endl;
        }
    }

    void save() {
        actualSave(true);
    }

    void shutdown() {
        std::cout << "[DEBUG] Shutting down configuration system" << std::endl;
        shuttingDown = true;
        actualSave(false);
    }
}

// ConfigManager implementation
ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

ConfigManager::ConfigManager() 
    : m_saveThreadStarted(false)
    , m_shuttingDown(false)
    , m_lastSave(std::chrono::system_clock::now() - std::chrono::seconds(5))
{
    setDefaults();
}

ConfigManager::~ConfigManager() {
    shutdown();
}

void ConfigManager::initialize(const std::string& configPath) {
    m_configPath = configPath;
    loadConfig();
}

void ConfigManager::shutdown() {
    actualSave();
    m_shuttingDown = true;
}

void ConfigManager::setDirectory(const std::wstring& directory) {
    m_directory = directory;
}

void ConfigManager::init(HMODULE handle) {
    m_handle = handle;
    
    if (m_directory.empty()) {
        wchar_t path[2048];
        GetModuleFileName(handle, path, sizeof(path) / sizeof(wchar_t));
        m_directory = std::wstring(path).substr(0, std::wstring(path).find_last_of(L"\\") + 1);
    }

    if (!std::filesystem::exists(m_configPath)) {
        std::ofstream file(m_configPath);
        file.close();
    }

    const auto size = std::filesystem::file_size(m_configPath);
    if (size == 0) {
        config = nlohmann::json::object();
        actualSave(true);
    } else {
        loadConfig();
    }

    m_shuttingDown = false;
    m_saveThreadStarted = false;
    save();
}

void ConfigManager::loadConfig() {
    try {
        std::ifstream file(m_configPath);
        if (file.is_open()) {
            config = nlohmann::json::parse(file);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error loading config: " << e.what() << std::endl;
        setDefaults();
        actualSave(true);
    }
}

void ConfigManager::setDefaults() {
    launcherPath = "";
    logging = LoggingConfig();
    injection = InjectionConfig();
    security = SecurityConfig();
    debug = DebugConfig();
}

void ConfigManager::actualSave(bool dontUpdateLastSave) {
    try {
        std::ofstream output(m_configPath);
        output << config.dump(4);
        output.close();
        
        if (!dontUpdateLastSave) {
            m_lastSave = std::chrono::system_clock::now();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error saving config: " << e.what() << std::endl;
    }
}

void ConfigManager::saveLoop() {
    while (true) {
        if (m_shuttingDown) {
            return;
        }

        actualSave();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void ConfigManager::save() {
    if (m_saveThreadStarted) {
        return;
    }

    std::thread loop(&ConfigManager::saveLoop, this);
    loop.detach();

    m_saveThreadStarted = true;
}
