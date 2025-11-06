#include "validator_api_service.h"

grpc::Status APIImpl::RecieveRequestDenomination(grpc::ServerContext *context, const zera_api::DenominationRequest *request, zera_api::DenominationResponse *response)
{

    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }
    
    std::string contract_data;
    if(!db_contracts::get_single(request->contract_id(), contract_data))
    {
        return grpc::Status(grpc::NOT_FOUND, "Invalid Contract ID");
    }

    zera_txn::InstrumentContract contract;
    contract.ParseFromString(contract_data);

    if(!contract.has_coin_denomination())
    {
        return grpc::Status(grpc::NOT_FOUND, "Contract does not have denomination");
    }

    response->set_denomination(contract.coin_denomination().amount());

    return grpc::Status::OK;
}