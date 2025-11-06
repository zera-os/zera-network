#pragma once

#include <cstdint>
#include <sodium.h>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "../blake3/blake3.h"
#include <iostream>

enum class Blake3HashLength
{
    Bits_256 = 32,   // 256 bits = 32 bytes
    Bits_512 = 64,   // 512 bits = 64 bytes
    Bits_1024 = 128, // 1024 bits = 128 bytes
    Bits_2048 = 256, // 2048 bits = 256 bytes
    Bits_4096 = 512, // 4096 bits = 512 bytes
    Bits_9001 = 1126 // 9001 bits ≈ 1126 bytes
};

enum class SHAKEHashLength
{
    Bits_1024 = 128, // 1024 bits = 128 bytes
    Bits_2048 = 256, // 2048 bits = 256 bytes
    Bits_4096 = 512  // 4096 bits = 512 bytes
};

namespace Hashing
{

    static std::vector<uint8_t> blake3_hash(const std::vector<uint8_t> &input, Blake3HashLength length = Blake3HashLength::Bits_256)
    {
        size_t output_length_bytes = static_cast<size_t>(length);
        std::vector<uint8_t> hash(output_length_bytes);
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, input.data(), input.size());
        blake3_hasher_finalize(&hasher, hash.data(), hash.size());

        // Handle special case for 9001 bits
        if (length == Blake3HashLength::Bits_9001)
        {
            // Truncate the hash to 9001 bits (1125 bytes + 1 bit)
            hash.resize(1126);  // 1126 bytes = 9008 bits
            hash[1125] &= 0x80; // Truncate the last byte to keep only the most significant bit (7 bits cleared)
        }

        return hash;
    }

    static std::vector<uint8_t> shake_hash(const std::vector<uint8_t> &input, SHAKEHashLength length)
    {
        size_t output_length_bytes = static_cast<size_t>(length);
        std::vector<uint8_t> hash(output_length_bytes);

        // Select SHAKE-256 or SHAKE-128 based on required security
        const EVP_MD *md = EVP_shake256(); // Use EVP_shake128() for lower security
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

        if (mdctx == nullptr)
        {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }

        if (1 != EVP_DigestInit_ex(mdctx, md, nullptr))
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to initialize EVP_Digest");
        }

        if (1 != EVP_DigestUpdate(mdctx, input.data(), input.size()))
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to update EVP_Digest");
        }

        if (1 != EVP_DigestFinalXOF(mdctx, hash.data(), output_length_bytes))
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to finalize EVP_Digest");
        }

        EVP_MD_CTX_free(mdctx);
        return hash;
    }

    static std::vector<uint8_t> sha256_hash(const std::vector<uint8_t> &input)
    {
        // Buffer for the hash result
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        // Create a context for the hashing operation
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr)
        {
            std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
            return {};
        }

        // Initialize the context with the SHA-3-256 algorithm
        if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), nullptr) != 1)
        {
            std::cerr << "Failed to initialize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Hash the data
        if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1)
        {
            std::cerr << "Failed to update digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Finalize the hash and retrieve the result
        if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
        {
            std::cerr << "Failed to finalize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Cleanup
        EVP_MD_CTX_free(mdctx);

        // Convert the hash to a vector<uint8_t> and return it
        return std::vector<uint8_t>(hash, hash + hash_len);
    }

    static std::vector<uint8_t> sha256_hash(const std::string &input_str)
    {
        std::vector<uint8_t> input(input_str.begin(), input_str.end());
        return sha256_hash(input);
    }

    static std::vector<uint8_t> sha512_hash(const std::vector<uint8_t> &input)
    {
        // Buffer for the hash result
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        // Create a context for the hashing operation
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr)
        {
            std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
            return {};
        }

        // Initialize the context with the SHA-3-512 algorithm
        if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), nullptr) != 1)
        {
            std::cerr << "Failed to initialize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Hash the data
        if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1)
        {
            std::cerr << "Failed to update digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Finalize the hash and retrieve the result
        if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
        {
            std::cerr << "Failed to finalize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Cleanup
        EVP_MD_CTX_free(mdctx);

        // Convert the hash to a vector<uint8_t> and return it
        return std::vector<uint8_t>(hash, hash + hash_len);
    }
    static bool compare_hash(const std::vector<uint8_t> &hash_1, const std::vector<uint8_t> &hash_2)
    {
        if (hash_1.size() != hash_2.size())
        {
            return false;
        }

        int hash_size = static_cast<int>(hash_1.size());

        for (int x = 0; x < hash_size; x++)
        {
            if (hash_1.at(x) != hash_2.at(x))
            {
                return false;
            }
        }
        return true;
    }

};