// hex_conversion.cpp
#include "hex_conversion.h"

std::string hex_conversion::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    static const char* hexChars = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);

    for (uint8_t byte : bytes) {
        hex.push_back(hexChars[(byte & 0xF0) >> 4]);
        hex.push_back(hexChars[byte & 0x0F]);
    }

    return hex;
}

std::string hex_conversion::bytes_to_hex(const std::string& str_data) {
    const std::vector<uint8_t> bytes(str_data.begin(), str_data.end());
    static const char* hexChars = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);

    for (uint8_t byte : bytes) {
        hex.push_back(hexChars[(byte & 0xF0) >> 4]);
        hex.push_back(hexChars[byte & 0x0F]);
    }

    return hex;
}

std::vector<uint8_t> hex_conversion::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.size() % 2 != 0) {
        return bytes; // Invalid hex string
    }

    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; j++) {
            char ch = hex[i + j];
            if ('0' <= ch && ch <= '9') {
                byte = (byte << 4) | (ch - '0');
            } else if ('a' <= ch && ch <= 'f') {
                byte = (byte << 4) | (ch - 'a' + 10);
            } else if ('A' <= ch && ch <= 'F') {
                byte = (byte << 4) | (ch - 'A' + 10);
            } else {
                return std::vector<uint8_t>(); // Invalid hex char
            }
        }
        bytes.push_back(byte);
    }

    return bytes;
}