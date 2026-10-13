// Portable SHA-256 (FIPS 180-4). Header-only, no OS deps.
// Used by AntiCheat.cpp and by tests/test_sha256.cpp.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace javelin {

class Sha256 {
public:
    Sha256() { reset(); }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            m_block[m_blockLen++] = data[i];
            if (m_blockLen == 64) {
                transform(m_block.data());
                m_bitLen += 512;
                m_blockLen = 0;
            }
        }
    }

    void update(const std::vector<uint8_t>& data) {
        update(data.data(), data.size());
    }

    std::array<uint8_t, 32> digest() {
        uint64_t bitLen = m_bitLen + static_cast<uint64_t>(m_blockLen) * 8;
        m_block[m_blockLen++] = 0x80;
        if (m_blockLen > 56) {
            while (m_blockLen < 64) m_block[m_blockLen++] = 0;
            transform(m_block.data());
            m_blockLen = 0;
        }
        while (m_blockLen < 56) m_block[m_blockLen++] = 0;
        for (int i = 7; i >= 0; --i) {
            m_block[m_blockLen++] = static_cast<uint8_t>((bitLen >> (i * 8)) & 0xff);
        }
        transform(m_block.data());

        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            out[i * 4 + 0] = static_cast<uint8_t>((m_state[i] >> 24) & 0xff);
            out[i * 4 + 1] = static_cast<uint8_t>((m_state[i] >> 16) & 0xff);
            out[i * 4 + 2] = static_cast<uint8_t>((m_state[i] >> 8) & 0xff);
            out[i * 4 + 3] = static_cast<uint8_t>(m_state[i] & 0xff);
        }
        return out;
    }

    std::string hexDigest() {
        static const char* hex = "0123456789abcdef";
        auto d = digest();
        std::string s;
        s.resize(64);
        for (int i = 0; i < 32; ++i) {
            s[i * 2] = hex[(d[i] >> 4) & 0xf];
            s[i * 2 + 1] = hex[d[i] & 0xf];
        }
        return s;
    }

    static std::string hashHex(const uint8_t* data, size_t len) {
        Sha256 h;
        h.update(data, len);
        return h.hexDigest();
    }

    static std::string hashHex(const std::vector<uint8_t>& data) {
        return hashHex(data.data(), data.size());
    }

private:
    void reset() {
        m_state = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                   0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        m_bitLen = 0;
        m_blockLen = 0;
        m_block.fill(0);
    }

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void transform(const uint8_t* chunk) {
        static const uint32_t k[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
            0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
            0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
            0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
            0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
            0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

        uint32_t m[64];
        for (int i = 0; i < 16; ++i) {
            m[i] = (static_cast<uint32_t>(chunk[i * 4]) << 24) |
                   (static_cast<uint32_t>(chunk[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(chunk[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(chunk[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
        uint32_t e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + k[i] + m[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }

    std::array<uint32_t, 8> m_state{};
    std::array<uint8_t, 64> m_block{};
    uint64_t m_bitLen = 0;
    size_t m_blockLen = 0;
};

}  // namespace javelin
