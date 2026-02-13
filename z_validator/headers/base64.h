#pragma once

#include <string>
#include <vector>
#include <map>

std::string base64_decode(const std::string& encoded);
std::string base64_encode(const std::string& data);

// Postcard deserialization helpers
struct SmartContractState {
    std::string smart_contract;
    std::string instance;
};

struct AllStakers {
    std::map<std::string, uint8_t> staker_states;
};

struct WalletStake {
    uint64_t principle;
    uint64_t total_reward;
    uint64_t daily_release;
    uint64_t total_released;
    uint64_t last_reward_day;
    std::string term;
};

struct LiquidStake {
    uint64_t bump_id;
    uint64_t principle;
    uint64_t last_reward_day;
    uint64_t daily_release;
    uint64_t unstake_day;
};

struct AllWalletStakes {
    std::map<std::string, WalletStake> staker_states;
    LiquidStake liquid_stake;
};

struct LiquidityPool {
    std::string token1;
    std::string token2;
    std::string lp_token_id;
    std::string token1_volume;
    std::string token2_volume;
    std::string circulating_lp_tokens;
    bool active;
    std::string derived_wallet;
    std::string redeemed_lp_tokens;
    uint64_t fee_percent;
};

struct NetworkValues {
    std::vector<std::string> values;
};

struct InstantStake {
    uint64_t principle;
    uint64_t total_reward;
    uint64_t release_day;
    std::string term;
};

struct AllInstantStakers {
    std::map<std::string, uint8_t> staker_states;
    uint64_t earliest_release_day;
};

struct AllWalletInstantStakes {
    std::map<std::string, InstantStake> staker_states;
};

SmartContractState decode_smart_contract_state(const std::string& b64_encoded);
AllStakers decode_all_stakers(const std::string& b64_encoded);
AllWalletStakes decode_all_wallet_stakes(const std::string& b64_encoded);
LiquidityPool decode_liquidity_pool(const std::string& b64_encoded);
NetworkValues decode_network_values(const std::string& b64_encoded);
AllInstantStakers decode_all_instant_stakers(const std::string& b64_encoded);
AllWalletInstantStakes decode_all_wallet_instant_stakes(const std::string& b64_encoded);

std::string encode_smart_contract_state(const SmartContractState& state);
std::string base64_encode(const std::string& data);