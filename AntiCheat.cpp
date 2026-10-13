// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan,
//           self-integrity (CRC32 build-time and/or SHA-256 of the running executable)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cctype>
#include <cstdlib>

#include "sha256.hpp"

static const char* kTag = "[Javelin AntiCheat] ";

// Exit codes
static const int kExitDebugger = 0xDEB;
static const int kExitSuspicious = 0xBAD;
static const int kExitCrcMismatch = 0xC2C;
static const int kExitShaMismatch = 3;  // matches Python integrity.py

// --- Configurable lists ---
static std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
};

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Simple CRC32 (polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    // Use c_str() so MinGW's ifstream accepts a wide path.
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(out.data()), size)) return false;
    return true;
}

static bool getSelfPath(std::wstring& out) {
    wchar_t path[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    out.assign(path, n);
    return true;
}

static bool constantTimeEqualHex(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (MSVC only)
#if defined(_MSC_VER) && defined(_M_IX86)
    __try {
        BYTE* peb = *(BYTE**)_readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_MSC_VER) && defined(_M_X64)
    __try {
        BYTE* peb = *(BYTE**)_readgsqword(0x60);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    return false;
}

static bool checkSuspiciousProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
#ifdef UNICODE
        // Convert wide process name to narrow UTF-8-ish for comparison.
        char narrow[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, narrow, MAX_PATH, nullptr, nullptr);
        std::string name = toLower(narrow);
#else
        std::string name = toLower(pe.szExeFile);
#endif
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
}

static bool checkSelfIntegrityCrc(uint32_t expectedCrc) {
    std::wstring path;
    if (!getSelfPath(path)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

// Returns true if check passes or is disabled. False on mismatch / I/O error.
static bool checkSelfIntegritySha256(const std::string& expectedHex) {
    if (expectedHex.empty()) return true;

    std::wstring path;
    if (!getSelfPath(path)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    std::string actual = javelin::Sha256::hashHex(bytes);
    return constantTimeEqualHex(actual, toLower(expectedHex));
}

static std::string resolveExpectedSha256() {
    // Prefer runtime env (matches Python JAVELIN_EXPECTED_SHA256), else build-time constant.
    if (const char* env = std::getenv("JAVELIN_EXPECTED_SHA256")) {
        if (env[0] != '\0') return env;
    }
#ifdef JAVELIN_EXPECTED_SHA256_STR
    return JAVELIN_EXPECTED_SHA256_STR;
#else
    return "";
#endif
}

// --- Entry helper (embed a baseline CRC once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time, e.g. -DJAVELIN_EXPECTED_CRC32=0x12345678
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebugger;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitSuspicious;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return kExitCrcMismatch;
        }
    }

    const std::string expectedSha = resolveExpectedSha256();
    if (!expectedSha.empty()) {
        if (!checkSelfIntegritySha256(expectedSha)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return kExitShaMismatch;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
