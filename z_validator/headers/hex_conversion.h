#ifndef HEX_CONVERSION_H
#define HEX_CONVERSION_H

#include <string>
#include <vector>

class hex_conversion {
public:
    // Convert bytes to hexadecimal string
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    static std::string bytes_to_hex(const std::string& str_data);

    // Convert hexadecimal string to bytes
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};

#endif // HEX_CONVERSION_H