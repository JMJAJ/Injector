#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <codecvt>
#include <locale>
#include <vector>
#include <memory>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include <Shlwapi.h>
#include <Shobjidl.h>

// Link required libraries
#pragma comment(lib, "Shlwapi.lib")

// Windows NT definitions
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef LONG NTSTATUS;
typedef DWORD KPRIORITY;

// Windows-specific definitions
#ifdef UNICODE
#define PathFindFileName PathFindFileNameW
#else
#define PathFindFileName PathFindFileNameA
#endif