#include "validator_api_service.h"
#include "fees.h"

grpc::Status APIImpl::RecieveGetTokenFeeInfo(grpc::ServerContext *context, const zera_api::TokenFeeInfoRequest *request, zera_api::TokenFeeInfoResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }
    
    std::vector<std::string> keys;
    std::vector<std::string> values;

    for(auto contract_id : request->contract_ids())
    {

        zera_api::TokenFeeInfo token_fee_info;

        std::string contract_data;
        uint256_t currency_equiv_data;
        if(!db_contracts::get_single(contract_id, contract_data))
        {
            continue;
        }
        if(!zera_fees::get_cur_equiv(contract_id, currency_equiv_data))
        {
            continue;
        }

        zera_txn::InstrumentContract contract;
        contract.ParseFromString(contract_data);

        token_fee_info.set_contract_id(contract_id);
        token_fee_info.set_rate(currency_equiv_data.str());
        token_fee_info.set_authorized(true);
        token_fee_info.set_denomination(contract.coin_denomination().amount());
        token_fee_info.mutable_contract_fees()->CopyFrom(contract.contract_fees());
        response->add_tokens()->CopyFrom(token_fee_info);
    
    }

    if(response->tokens_size() == 0)
    {
        return grpc::Status(grpc::NOT_FOUND, "No tokens found");
    }

    return grpc::Status::OK;
}