// Native (Linux/g++) unit test for portable SHA-256 against FIPS 180-4 vectors.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../sha256.hpp"

static int failures = 0;

static void expect(const char* name, const std::string& got, const char* want) {
    if (got == want) {
        std::printf("PASS  %s\n", name);
    } else {
        std::printf("FAIL  %s\n  got:  %s\n  want: %s\n", name, got.c_str(), want);
        ++failures;
    }
}

int main() {
    // FIPS 180-4 / NIST examples
    expect("empty",
           javelin::Sha256::hashHex(nullptr, 0),
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    {
        const char* msg = "abc";
        expect("abc",
               javelin::Sha256::hashHex(reinterpret_cast<const uint8_t*>(msg), 3),
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    {
        const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        expect("56-byte",
               javelin::Sha256::hashHex(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg)),
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    {
        // One million 'a's
        std::vector<uint8_t> ones(1000000, static_cast<uint8_t>('a'));
        expect("1e6 a's",
               javelin::Sha256::hashHex(ones),
               "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    if (failures) {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }
    std::printf("All SHA-256 vectors OK\n");
    return 0;
}
