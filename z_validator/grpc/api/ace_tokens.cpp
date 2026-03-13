#include "validator_api_service.h"
#include "fees.h"
#include "sc_base64.h"
#include <unordered_set>

grpc::Status APIImpl::RecieveGetTokenFeeInfo(grpc::ServerContext *context, const zera_api::TokenFeeInfoRequest *request, zera_api::TokenFeeInfoResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    std::vector<std::string> keys;
    std::vector<std::string> values;
    std::unordered_set<std::string> authorized_contracts;

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

    for (auto contract_id : request->contract_ids())
    {

        zera_api::TokenFeeInfo token_fee_info;

        std::string contract_data;
        uint256_t currency_equiv_data;
        if (!db_contracts::get_single(contract_id, contract_data))
        {
            continue;
        }

        zera_txn::InstrumentContract contract;
        contract.ParseFromString(contract_data);

        zera_validator::FeeToken fee_token;
        std::string fee_token_data;
        if (!db_fee_tokens::get_single(FEE_TOKENS + contract_id, fee_token_data) || !fee_token.ParseFromString(fee_token_data))
        {
            token_fee_info.set_authorized(false);
            token_fee_info.set_allowed_fees("0");
            token_fee_info.set_used_fees("0");
        }
        else
        {
            token_fee_info.set_authorized(fee_token.authorized());
            token_fee_info.set_allowed_fees(fee_token.stable_value_allowed());
            token_fee_info.set_used_fees(fee_token.value_used());
        }

        if (std::find(network_values.values.begin(), network_values.values.end(), contract_id) != network_values.values.end() || contract_id == NETWORK_CONTRACT || contract_id == stable_coin_contract)
        {
            token_fee_info.set_authorized(true);
            token_fee_info.set_allowed_fees("MAX");
            token_fee_info.set_used_fees("0");
        }

        token_fee_info.set_contract_id(contract_id);
        if (contract_id == stable_coin_contract)
        {
            token_fee_info.set_rate(std::to_string(ONE_DOLLAR));
        }
        else
        {
            zera_fees::get_cur_equiv(contract_id, currency_equiv_data);
            token_fee_info.set_rate(currency_equiv_data.str());
        }

        token_fee_info.set_denomination(contract.coin_denomination().amount());
        token_fee_info.mutable_contract_fees()->CopyFrom(contract.contract_fees());
        response->add_tokens()->CopyFrom(token_fee_info);
        authorized_contracts.insert(contract_id);
    }

    if (response->tokens_size() == 0)
    {
        return grpc::Status(grpc::NOT_FOUND, "No tokens found");
    }

    return grpc::Status::OK;
}
