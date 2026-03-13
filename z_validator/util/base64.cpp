#include "base64.h"
#include <vector>

std::string base64_decode(const std::string &encoded)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string decoded;
    std::vector<int> T(256, -1);

    for (int i = 0; i < 64; i++)
        T[base64_chars[i]] = i;

    int val = 0;
    int valb = -8;
    bool padding_started = false;

    for (unsigned char c : encoded)
    {
        if (c == '=')
        {
            padding_started = true;
            continue;
        }

        if (padding_started)
        {
            return "";
        }

        if (T[c] == -1)
        {
            return "";
        }

        val = (val << 6) + T[c];
        valb += 6;

        if (valb >= 0)
        {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return decoded;
}

std::string base64_encode(const std::string &data)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded;
    int val = 0;
    int valb = -6;

    for (unsigned char c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6)
    {
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (encoded.size() % 4)
    {
        encoded.push_back('=');
    }

    return encoded;
}
