// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan,
//           self-integrity (CRC32 build-time and/or SHA-256 of the running executable)

// Avoid min/max macros from windows.h breaking the C++ standard library.
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#if defined(_MSC_VER)
#include <intrin.h>  // __readfsdword / __readgsqword
#endif
#include <iostream>
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

// Python integrity.py uses str.strip() before comparing. Match the ASCII
// whitespace it strips so both sides accept the same env value.
static bool isAsciiSpace(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static std::string trimAscii(const std::string& s) {
    size_t begin = 0;
    size_t end = s.size();
    while (begin < end && isAsciiSpace(static_cast<unsigned char>(s[begin]))) ++begin;
    while (end > begin && isAsciiSpace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(begin, end - begin);
}

// Simple CRC32 (polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            // (crc & 1) ? 0xFFFFFFFF : 0, without negating an unsigned value.
            const uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    // Win32 read (not ifstream) so MSVC and MinGW both open a wide path in
    // binary mode, including the image the loader already has mapped.
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) {
        CloseHandle(file);
        return false;
    }
    const unsigned long long nbytes = static_cast<unsigned long long>(size.QuadPart);
    if (nbytes > static_cast<unsigned long long>(static_cast<size_t>(-1))) {
        CloseHandle(file);
        return false;
    }

    out.resize(static_cast<size_t>(nbytes));
    unsigned long long offset = 0;
    while (offset < nbytes) {
        const unsigned long long remain = nbytes - offset;
        const DWORD chunk = remain > 0x100000ull ? 0x100000u : static_cast<DWORD>(remain);
        DWORD got = 0;
        if (!ReadFile(file, out.data() + offset, chunk, &got, nullptr) || got == 0) {
            CloseHandle(file);
            return false;
        }
        offset += got;
    }
    CloseHandle(file);
    return true;
}

static bool getSelfPath(std::wstring& out) {
    // Grow past MAX_PATH. A truncated path would fail the integrity check closed.
    DWORD cap = MAX_PATH;
    for (;;) {
        out.resize(cap);
        DWORD n = GetModuleFileNameW(nullptr, &out[0], cap);
        if (n == 0) return false;
        if (n < cap) {
            out.resize(n);
            return true;
        }
        if (cap >= 32768) return false;
        cap *= 2;
    }
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
// SEH must live in a function the compiler will not inline into main().
// main() has C++ locals, and MSVC rejects __try there (C2712).
#if defined(_MSC_VER)
__declspec(noinline)
#endif
static bool pebBeingDebugged() {
#if defined(_MSC_VER) && defined(_M_IX86)
    __try {
        // fs:[0x30] is already the PEB address; do not dereference it again.
        BYTE* peb = reinterpret_cast<BYTE*>(static_cast<uintptr_t>(__readfsdword(0x30)));
        return peb && peb[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#elif defined(_MSC_VER) && defined(_M_X64)
    __try {
        // gs:[0x60] is already the PEB address; do not dereference it again.
        BYTE* peb = reinterpret_cast<BYTE*>(static_cast<uintptr_t>(__readgsqword(0x60)));
        return peb && peb[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    return false;
#endif
}

static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;
    return pebBeingDebugged();
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

    // Same contract as integrity.py: strip surrounding whitespace, then
    // compare case-insensitively. A whitespace-only value is a mismatch.
    const std::string expected = toLower(trimAscii(expectedHex));

    std::wstring path;
    if (!getSelfPath(path)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    std::string actual = javelin::Sha256::hashHex(bytes);
    return constantTimeEqualHex(actual, expected);
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
