#pragma once

#include <concepts>
#include <iostream>
#include "json.hpp"
#include <set>
#include <string>
#include "pch.h"

namespace Config {
    extern nlohmann::json config;

    void setDirectory(std::wstring directory);
    void init(HMODULE handle = nullptr);
    void shutdown();
    void save();
    void actualSave(); // Added function declaration

    template <typename T>
    concept isVectorOrSet =
        std::is_same_v<T, std::vector<typename T::value_type>> || std::is_same_v<T, std::set<typename T::value_type>>;

    template <typename T> struct field {
        field() = default;
        template <isVectorOrSet T> field(std::string k, T val) : k(k) { ptr = new T(val); }
        field(std::string k, T* ptr) : k(k), ptr(ptr) {}

        T* operator->() const { return ptr; }

        T& operator*() const {
            config[k] = *ptr;
            actualSave(); // Save immediately when value is accessed/modified
            return *ptr;
        }

        T* operator&() const { return ptr; }

        std::string operator=(const std::string& val) {
            *ptr = val;
            config[k] = *ptr;
            actualSave(); // Save immediately when value is set
            return val;
        }

    private:
        std::string k;
        T* ptr;
    };

    template <isVectorOrSet T> Config::field<T> get(const std::string key, T def) {
        if (!config.contains(key)) {
            config[key] = def;
        }

        auto realPtr = config[key].get<T>();
        field<T> ret = { key, realPtr };
        return ret;
    }

    template <typename T> Config::field<T> get(const std::string key, T def) {
        if (!config.contains(key)) {
            config[key] = def;
        }

        auto realPtr = config[key].get_ptr<T*>();
        field<T> ret = { key, realPtr };
        return ret;
    }
} // namespace Config
