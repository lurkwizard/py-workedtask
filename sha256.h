// sha256.h
// Javelin Project - small portable SHA-256 (FIPS 180-4), header-only.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace javelin {

class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        static const uint32_t init
