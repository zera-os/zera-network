#include "base64.h"

namespace
{
    // Helper: Read varint (postcard uses LEB128 encoding)
    size_t read_varint(const std::string &data, size_t &pos)
    {
        size_t result = 0;
        size_t shift = 0;

        while (pos < data.size())
        {
            uint8_t byte = static_cast<uint8_t>(data[pos++]);
            result |= static_cast<size_t>(byte & 0x7F) << shift;

            if ((byte & 0x80) == 0)
                break;

            shift += 7;
        }

        return result;
    }

    // Helper: Read string from postcard format
    std::string read_postcard_string(const std::string &data, size_t &pos)
    {
        size_t len = read_varint(data, pos);

        if (pos + len > data.size())
            return ""; // Invalid data

        std::string result = data.substr(pos, len);
        pos += len;
        return result;
    }

    // Helper: Read u64 from postcard format (encoded as varint)
    uint64_t read_u64(const std::string &data, size_t &pos)
    {
        uint64_t result = 0;
        size_t shift = 0;

        while (pos < data.size())
        {
            uint8_t byte = static_cast<uint8_t>(data[pos++]);
            result |= static_cast<uint64_t>(byte & 0x7F) << shift;

            if ((byte & 0x80) == 0)
                break;

            shift += 7;
        }

        return result;
    }

    // Helper: Read WalletStake from postcard format
    WalletStake read_wallet_stake(const std::string &data, size_t &pos)
    {
        WalletStake stake;
        stake.principle = read_u64(data, pos);
        stake.total_reward = read_u64(data, pos);
        stake.daily_release = read_u64(data, pos);
        stake.total_released = read_u64(data, pos);
        stake.last_reward_day = read_u64(data, pos);
        stake.term = read_postcard_string(data, pos);
        return stake;
    }

    // Helper: Read LiquidStake from postcard format
    LiquidStake read_liquid_stake(const std::string &data, size_t &pos)
    {
        LiquidStake liquid;
        liquid.bump_id = read_u64(data, pos);
        liquid.principle = read_u64(data, pos);
        liquid.last_reward_day = read_u64(data, pos);
        liquid.daily_release = read_u64(data, pos);
        liquid.unstake_day = read_u64(data, pos);
        return liquid;
    }

    // Helper: Read InstantStake from postcard format
    InstantStake read_instant_stake(const std::string &data, size_t &pos)
    {
        InstantStake stake;
        stake.principle = read_u64(data, pos);
        stake.total_reward = read_u64(data, pos);
        stake.release_day = read_u64(data, pos);
        stake.term = read_postcard_string(data, pos);
        return stake;
    }

    // Helper: Read bool from postcard format
    bool read_bool(const std::string &data, size_t &pos)
    {
        if (pos >= data.size())
            return false;
        
        uint8_t byte = static_cast<uint8_t>(data[pos++]);
        return byte != 0;
    }

    // Helper: Write varint (LEB128 encoding for postcard)
    void write_varint(std::string &output, size_t value)
    {
        while (value >= 0x80)
        {
            output.push_back(static_cast<char>((value & 0x7F) | 0x80));
            value >>= 7;
        }
        output.push_back(static_cast<char>(value & 0x7F));
    }

    // Helper: Write string in postcard format (length prefix + data)
    void write_postcard_string(std::string &output, const std::string &str)
    {
        write_varint(output, str.size());
        output.append(str);
    }

}

// Decode the full state from base64 + postcard format
SmartContractState decode_smart_contract_state(const std::string &b64_encoded)
{
    SmartContractState state;

    // Step 1: Base64 decode
    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return state; // Decode failed

    // Step 2: Deserialize postcard format
    size_t pos = 0;
    state.smart_contract = read_postcard_string(postcard_bytes, pos);
    state.instance = read_postcard_string(postcard_bytes, pos);

    return state;
}

// Decode AllStakers from base64 + postcard format
AllStakers decode_all_stakers(const std::string &b64_encoded)
{
    AllStakers stakers;

    // Step 1: Base64 decode
    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return stakers; // Decode failed

    // Step 2: Deserialize postcard format
    size_t pos = 0;

    // Read the number of entries in the HashMap
    size_t num_entries = read_varint(postcard_bytes, pos);

    // Read each key-value pair
    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        // Read the key (string)
        std::string key = read_postcard_string(postcard_bytes, pos);

        // Read the value (u8)
        if (pos >= postcard_bytes.size())
            break; // Invalid data

        uint8_t value = static_cast<uint8_t>(postcard_bytes[pos++]);

        // Add to map
        stakers.staker_states[key] = value;
    }

    return stakers;
}

// Decode AllWalletStakes from base64 + postcard format
AllWalletStakes decode_all_wallet_stakes(const std::string &b64_encoded)
{
    AllWalletStakes all_stakes;

    // Step 1: Base64 decode
    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return all_stakes; // Decode failed

    // Step 2: Deserialize postcard format
    size_t pos = 0;

    // Read the HashMap (staker_states)
    size_t num_entries = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        // Read the key (string)
        std::string key = read_postcard_string(postcard_bytes, pos);

        // Read the value (WalletStake)
        WalletStake stake = read_wallet_stake(postcard_bytes, pos);

        // Add to map
        all_stakes.staker_states[key] = stake;
    }

    // Read the LiquidStake
    all_stakes.liquid_stake = read_liquid_stake(postcard_bytes, pos);

    return all_stakes;
}

// Decode LiquidityPool from base64 + postcard format
LiquidityPool decode_liquidity_pool(const std::string &b64_encoded)
{
    LiquidityPool pool;

    // Step 1: Base64 decode
    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return pool; // Decode failed

    // Step 2: Deserialize postcard format
    size_t pos = 0;

    // Read fields in order matching Rust struct
    pool.token1 = read_postcard_string(postcard_bytes, pos);
    pool.token2 = read_postcard_string(postcard_bytes, pos);
    pool.lp_token_id = read_postcard_string(postcard_bytes, pos);
    pool.token1_volume = read_postcard_string(postcard_bytes, pos);
    pool.token2_volume = read_postcard_string(postcard_bytes, pos);
    pool.circulating_lp_tokens = read_postcard_string(postcard_bytes, pos);
    pool.active = read_bool(postcard_bytes, pos);
    pool.derived_wallet = read_postcard_string(postcard_bytes, pos);
    pool.redeemed_lp_tokens = read_postcard_string(postcard_bytes, pos);
    pool.fee_percent = read_u64(postcard_bytes, pos);

    return pool;
}

// Decode NetworkValues from base64 + postcard format
NetworkValues decode_network_values(const std::string &b64_encoded)
{
    NetworkValues network_values;

    // Step 1: Base64 decode
    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return network_values; // Decode failed

    // Step 2: Deserialize postcard format
    size_t pos = 0;

    // Read the Vec<String> - first read the length
    size_t num_values = read_varint(postcard_bytes, pos);

    // Read each string in the vector
    for (size_t i = 0; i < num_values && pos < postcard_bytes.size(); ++i)
    {
        std::string value = read_postcard_string(postcard_bytes, pos);
        network_values.values.push_back(value);
    }

    return network_values;
}

// Decode AllInstantStakers from base64 + postcard format
AllInstantStakers decode_all_instant_stakers(const std::string &b64_encoded)
{
    AllInstantStakers stakers;

    // Step 1: Base64 decode
    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return stakers; // Decode failed

    // Step 2: Deserialize postcard format
    size_t pos = 0;

    // Read the HashMap (staker_states)
    size_t num_entries = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        // Read the key (string)
        std::string key = read_postcard_string(postcard_bytes, pos);

        // Read the value (u8)
        if (pos >= postcard_bytes.size())
            break; // Invalid data

        uint8_t value = static_cast<uint8_t>(postcard_bytes[pos++]);

        // Add to map
        stakers.staker_states[key] = value;
    }

    // Read the earliest_release_day (u64)
    stakers.earliest_release_day = read_u64(postcard_bytes, pos);

    return stakers;
}

// Decode AllWalletInstantStakes from base64 + postcard format
AllWalletInstantStakes decode_all_wallet_instant_stakes(const std::string &b64_encoded)
{
    AllWalletInstantStakes all_stakes;

    // Step 1: Base64 decode
    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return all_stakes; // Decode failed

    // Step 2: Deserialize postcard format
    size_t pos = 0;

    // Read the HashMap (staker_states)
    size_t num_entries = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        // Read the key (string)
        std::string key = read_postcard_string(postcard_bytes, pos);

        // Read the value (InstantStake)
        InstantStake stake = read_instant_stake(postcard_bytes, pos);

        // Add to map
        all_stakes.staker_states[key] = stake;
    }

    return all_stakes;
}

// Encode SmartContractState to base64 + postcard format
std::string encode_smart_contract_state(const SmartContractState &state)
{
    std::string postcard_bytes;

    // Serialize fields in order matching Rust struct
    write_postcard_string(postcard_bytes, state.smart_contract);
    write_postcard_string(postcard_bytes, state.instance);

    // Base64 encode
    return base64_encode(postcard_bytes);
}

std::string base64_decode(const std::string &encoded)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string decoded;
    std::vector<int> T(256, -1);

    // Build lookup table
    for (int i = 0; i < 64; i++)
        T[base64_chars[i]] = i;

    int val = 0;
    int valb = -8;
    bool padding_started = false;

    for (unsigned char c : encoded)
    {
        // Handle padding
        if (c == '=')
        {
            padding_started = true;
            continue;
        }

        // If we already started padding, any non-padding character is invalid
        if (padding_started)
        {
            return ""; // Invalid: characters after padding
        }

        // Check if character is valid base64
        if (T[c] == -1)
        {
            return ""; // Invalid character found
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