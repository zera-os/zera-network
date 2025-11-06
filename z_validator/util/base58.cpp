#include "base58.h"
#include "wallets.h"
#include "signatures.h"

namespace
{
    std::string encode_public_key(const std::vector<uint8_t> &public_key)
    {
        std::string pub_key_str(public_key.begin(), public_key.end());
        KeyType key_typ = signatures::get_key_type(pub_key_str);
        int key_size = signatures::get_key_size(key_typ);

        int prefix_length = pub_key_str.length() - key_size;

        // Extract the prefix and the actual key
        std::string prefix = pub_key_str.substr(0, prefix_length);
        std::string extracted_pub_key = pub_key_str.substr(prefix_length);

        // Encode the extracted key using Base58
        std::string encoded_key = base58_encode(extracted_pub_key);

        // Combine the prefix with the encoded key
        encoded_key = prefix + encoded_key;

        return encoded_key;
    }
    std::vector<uint8_t> decode_public_key(const std::string &public_key)
    {
        size_t pos = public_key.find_last_of('_');
        std::string prefix;
        std::string extracted_pub_key;
        if (pos != std::string::npos)
        {
            prefix = public_key.substr(0, pos + 1); // +1 to include the last underscore
            extracted_pub_key = public_key.substr(pos + 1);
            // Use letters and publicKey
        }

        std::vector<uint8_t> decoded_key_vec = base58_decode(extracted_pub_key);

        std::string decoded_key(decoded_key_vec.begin(), decoded_key_vec.end());

        decoded_key = prefix + decoded_key;

        std::vector<uint8_t> decoded_key_vec1(decoded_key.begin(), decoded_key.end());

        return decoded_key_vec1;
    }
}

static const std::string base58_chars =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58_encode(const std::vector<uint8_t> &data)
{
    std::string encoded;
    int size = static_cast<int>(data.size());
    // Count leading zeros
    int zeros = 0;
    while (zeros < size && data[zeros] == 0)
    {
        zeros++;
    }

    // Allocate enough space in the encoded string
    int encodedSize = (size - zeros) * 138 / 100 + 1;
    std::vector<uint8_t> encodedData(encodedSize, 0);

    // Process the number
    for (int i = zeros; i < size; ++i)
    {
        int carry = data[i];
        for (int j = encodedSize - 1; j >= 0; --j)
        {
            carry += encodedData[j] * 256;
            encodedData[j] = carry % 58;
            carry /= 58;
        }
    }

    // Skip leading zeros in the encoded data
    int leadingZeros = 0;
    while (leadingZeros < encodedSize && encodedData[leadingZeros] == 0)
    {
        leadingZeros++;
    }

    // Append the base58 characters to the encoded string
    encoded.reserve(zeros + encodedSize - leadingZeros);
    for (int k = 0; k < zeros; ++k)
    {
        encoded += '1';
    }
    for (int k = leadingZeros; k < encodedSize; ++k)
    {
        encoded += base58_chars[encodedData[k]];
    }

    return encoded;
}

std::string base58_encode(const std::string &data_str)
{
    std::string encoded;
    std::vector<uint8_t> data(data_str.begin(), data_str.end());
    int size = static_cast<int>(data.size());
    // Count leading zeros
    int zeros = 0;
    while (zeros < size && data[zeros] == 0)
    {
        zeros++;
    }

    // Allocate enough space in the encoded string
    int encodedSize = (size - zeros) * 138 / 100 + 1;
    std::vector<uint8_t> encodedData(encodedSize, 0);

    // Process the number
    for (int i = zeros; i < size; ++i)
    {
        int carry = data[i];
        for (int j = encodedSize - 1; j >= 0; --j)
        {
            carry += encodedData[j] * 256;
            encodedData[j] = carry % 58;
            carry /= 58;
        }
    }

    // Skip leading zeros in the encoded data
    int leadingZeros = 0;
    while (leadingZeros < encodedSize && encodedData[leadingZeros] == 0)
    {
        leadingZeros++;
    }

    // Append the base58 characters to the encoded string
    encoded.reserve(zeros + encodedSize - leadingZeros);
    for (int k = 0; k < zeros; ++k)
    {
        encoded += '1';
    }
    for (int k = leadingZeros; k < encodedSize; ++k)
    {
        encoded += base58_chars[encodedData[k]];
    }

    return encoded;
}

std::vector<uint8_t> base58_decode(const std::string &encoded)
{
    std::vector<uint8_t> decoded;

    int size = static_cast<int>(encoded.size());

    // Skip leading zeros in the encoded string
    int zeros = 0;
    while (zeros < size && encoded[zeros] == '1')
    {
        zeros++;
    }

    // Allocate enough space in the decoded vector
    int decodedSize = (size - zeros) * 733 / 1000 + 1;
    std::vector<uint8_t> decodedData(decodedSize, 0);

    // Process the base58 string
    for (int i = zeros; i < size; ++i)
    {
        int carry = base58_chars.find(encoded[i]);
        for (int j = decodedSize - 1; j >= 0; --j)
        {
            carry += decodedData[j] * 58;
            decodedData[j] = carry % 256;
            carry /= 256;
        }
    }

    // Skip leading zeros in the decoded data
    int leadingZeros = 0;
    while (leadingZeros < decodedSize && decodedData[leadingZeros] == 0)
    {
        leadingZeros++;
    }

    // Append the decoded data to the vector
    decoded.reserve(zeros + decodedSize - leadingZeros);
    for (int k = 0; k < zeros; ++k)
    {
        decoded.push_back(0);
    }
    for (int k = leadingZeros; k < decodedSize; ++k)
    {
        decoded.push_back(decodedData[k]);
    }

    return decoded;
}

std::vector<uint8_t> base58_decode(const std::vector<uint8_t> &encoded_vec)
{
    std::vector<uint8_t> decoded;
    std::string encoded(encoded_vec.begin(), encoded_vec.end());
    int size = static_cast<int>(encoded.size());

    // Skip leading zeros in the encoded string
    int zeros = 0;
    while (zeros < size && encoded[zeros] == '1')
    {
        zeros++;
    }

    // Allocate enough space in the decoded vector
    int decodedSize = (size - zeros) * 733 / 1000 + 1;
    std::vector<uint8_t> decodedData(decodedSize, 0);

    // Process the base58 string
    for (int i = zeros; i < size; ++i)
    {
        int carry = base58_chars.find(encoded[i]);
        for (int j = decodedSize - 1; j >= 0; --j)
        {
            carry += decodedData[j] * 58;
            decodedData[j] = carry % 256;
            carry /= 256;
        }
    }

    // Skip leading zeros in the decoded data
    int leadingZeros = 0;
    while (leadingZeros < decodedSize && decodedData[leadingZeros] == 0)
    {
        leadingZeros++;
    }

    // Append the decoded data to the vector
    decoded.reserve(zeros + decodedSize - leadingZeros);
    for (int k = 0; k < zeros; ++k)
    {
        decoded.push_back(0);
    }
    for (int k = leadingZeros; k < decodedSize; ++k)
    {
        decoded.push_back(decodedData[k]);
    }

    return decoded;
}

std::string base58_encode_public_key(const std::string &public_key)
{
    std::vector<uint8_t> pub_key(public_key.begin(), public_key.end());
    return encode_public_key(pub_key);
}

std::string base58_encode_public_key(const std::vector<uint8_t> &public_key)
{
    return encode_public_key(public_key);
}

std::vector<uint8_t> base58_decode_public_key(const std::string &public_key)
{
    return decode_public_key(public_key);
}

std::vector<uint8_t> base58_decode_public_key(const std::vector<uint8_t> &public_key)
{
    std::string pub_key_str(public_key.begin(), public_key.end());
    return decode_public_key(pub_key_str);
}
