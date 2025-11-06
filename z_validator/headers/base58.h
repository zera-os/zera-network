#pragma once

#include <string>
#include <vector>

std::string base58_encode(const std::vector<uint8_t>& data);
std::string base58_encode(const std::string& data_str);
std::vector<uint8_t> base58_decode(const std::string& encoded);
std::vector<uint8_t> base58_decode(const std::vector<uint8_t>& encoded_vec);
std::string base58_encode_public_key(const std::string& public_key);
std::string base58_encode_public_key(const std::vector<uint8_t>& public_key);
std::vector<uint8_t> base58_decode_public_key(const std::string& public_key);
std::vector<uint8_t> base58_decode_public_key(const std::vector<uint8_t>& public_key);