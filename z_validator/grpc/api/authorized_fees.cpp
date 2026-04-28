#include "validator_api_service.h"
#include "fees.h"
#include "sc_base64.h"

#include <unordered_set>

grpc::Status APIImpl::RecieveGetAllAuthorizedFees(grpc::ServerContext *context, const google::protobuf::Empty *request, zera_api::GetAllAuthorizedFeesResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    std::vector<std::string> authorized_data;
    std::vector<std::string> authorized_keys;

    db_fee_tokens::get_all_data(authorized_keys, authorized_data);
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

    for (size_t i = 0; i < authorized_keys.size(); i++)
    {

        zera_validator::FeeToken fee_token;
        if (!fee_token.ParseFromString(authorized_data[i]))
        {
            continue;
        }

        if (!fee_token.authorized())
        {
            continue;
        }

        if (std::find(network_values.values.begin(), network_values.values.end(), fee_token.contract_id()) != network_values.values.end() || fee_token.contract_id() == NETWORK_CONTRACT || fee_token.contract_id() == stable_coin_contract)
        {
            continue;
        }

        zera_api::AuthorizedFee authorized_fee;
        authorized_fee.set_contract_id(fee_token.contract_id());
        authorized_fee.set_allowed_fees(fee_token.stable_value_allowed());
        authorized_fee.set_used_fees(fee_token.value_used());
        response->add_authorized_fees()->CopyFrom(authorized_fee);

        authorized_contracts.insert(fee_token.contract_id());
    }

    for (auto contract_id : network_values.values)
    {
        if (authorized_contracts.find(contract_id) == authorized_contracts.end())
        {
            zera_api::AuthorizedFee authorized_fee;
            authorized_fee.set_contract_id(contract_id);
            authorized_fee.set_allowed_fees("MAX");
            authorized_fee.set_used_fees("0");
            response->add_authorized_fees()->CopyFrom(authorized_fee);
        }
    }
    
    if (authorized_contracts.find(stable_coin_contract) == authorized_contracts.end())
    {
        zera_api::AuthorizedFee authorized_fee;
        authorized_fee.set_contract_id(stable_coin_contract);
        authorized_fee.set_allowed_fees("MAX");
        authorized_fee.set_used_fees("0");
        response->add_authorized_fees()->CopyFrom(authorized_fee);
    }

    if (authorized_contracts.find(NETWORK_CONTRACT) == authorized_contracts.end())
    {
        zera_api::AuthorizedFee authorized_fee;
        authorized_fee.set_contract_id(NETWORK_CONTRACT);
        authorized_fee.set_allowed_fees("MAX");
        authorized_fee.set_used_fees("0");
        response->add_authorized_fees()->CopyFrom(authorized_fee);
    }

    return grpc::Status::OK;
}