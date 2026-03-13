#pragma once

#include "sc_base64_types.h"

// Existing decode/encode
SmartContractState decode_smart_contract_state(const std::string &b64_encoded);
AllStakers decode_all_stakers(const std::string &b64_encoded);
AllWalletStakes decode_all_wallet_stakes(const std::string &b64_encoded);
LiquidityPool decode_liquidity_pool(const std::string &b64_encoded);
NetworkValues decode_network_values(const std::string &b64_encoded);
AllInstantStakers decode_all_instant_stakers(const std::string &b64_encoded);
AllWalletInstantStakes decode_all_wallet_instant_stakes(const std::string &b64_encoded);
std::string encode_smart_contract_state(const SmartContractState &state);

// New decode
NetworkTXN decode_network_txn(const std::string &b64_encoded);
ContractUpdateTXN decode_contract_update_txn(const std::string &b64_encoded);
