#include "temp_data.h"
#include "db_base.h"
#include "sc_base64.h"

std::mutex fee_token_tracker::mtx;

bool fee_token_tracker::add_temp_fee_token(const std::string &contract_id, const uint256_t &amount, const uint256_t &denomination)
{
    std::lock_guard<std::mutex> lock(mtx);

    if(!db_contracts::exist(contract_id))
    {
        return false;
    }

    std::string fee_token_data;
    zera_validator::FeeToken fee_token;
    std::string fee_token_key = FEE_TOKENS + contract_id;
    
    if((!db_fee_tokens_temp::get_single(fee_token_key, fee_token_data) && !db_fee_tokens::get_single(fee_token_key, fee_token_data)) || !fee_token.ParseFromString(fee_token_data))
    {
        return false;
    }

    std::string token_whitelist_data;
    NetworkValues network_values;
    std::string stable_coin_contract;
    if (db_smart_contract_states::get_single(TOKEN_WHITELIST, token_whitelist_data) && token_whitelist_data != "")
    {
        network_values = decode_network_values(token_whitelist_data);
    }
    if (db_smart_contract_states::get_single(STABLE_COIN_SC, stable_coin_contract) && stable_coin_contract != "")
    {
        stable_coin_contract = STABLE_COIN_CONTRACT;
    }
    else
    {
        stable_coin_contract = STABLE_COIN_CONTRACT;
    }
    

    if(std::find(network_values.values.begin(), network_values.values.end(), contract_id) != network_values.values.end() || contract_id == NETWORK_CONTRACT || contract_id == stable_coin_contract)
    {
        return true;
    }

    uint256_t rate(fee_token.rate());
    uint256_t value_used(fee_token.value_used());
    uint256_t allowed_amount(fee_token.stable_value_allowed());
    uint256_t amount_value = (amount * rate) / denomination;
    uint256_t used_amount = value_used + amount_value;

    if(used_amount > allowed_amount)
    {
        return false;
    }

    fee_token.set_value_used(used_amount.str());
    db_fee_tokens_temp::store_single(fee_token_key, fee_token.SerializeAsString());

    return true;
}