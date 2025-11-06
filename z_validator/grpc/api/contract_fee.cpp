#include "validator_api_service.h"

grpc::Status APIImpl::RecieveRequestContractFee(grpc::ServerContext *context, const zera_api::ContractFeeRequest *request, zera_api::ContractFeeResponse *response)
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

    if(!contract.has_contract_fees())
    {
        return grpc::Status(grpc::NOT_FOUND, "Contract does not have contract fees");
    }
    
    response->set_contract_fee_type(contract.contract_fees().contract_fee_type());

    response->set_fee(contract.contract_fees().fee());

    for(auto id : contract.contract_fees().allowed_fee_instrument())
    {
        response->add_allowed_fee_instrument(id);
    }
    
    return grpc::Status::OK;
}