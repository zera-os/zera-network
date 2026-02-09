#include "validator_api_service.h"
#include "fees.h"

grpc::Status APIImpl::RecieveGetAllAuthorizedFees(grpc::ServerContext *context, const google::protobuf::Empty *request, zera_api::GetAllAuthorizedFeesResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }
    
    std::vector<std::string> authorized_data;
    std::vector<std::string> authorized_keys;

    db_fee_tokens::get_all_data(authorized_keys, authorized_data);

    for(size_t i = 0; i < authorized_keys.size(); i++)
    {
        zera_validator::FeeToken fee_token;
        if(!fee_token.ParseFromString(authorized_data[i]))
        {
            continue;
        }

        if(!fee_token.authorized() || fee_token.contract_id() == NETWORK_CONTRACT)
        {
            continue;
        }

        zera_api::AuthorizedFee authorized_fee;
        authorized_fee.set_contract_id(fee_token.contract_id());
        authorized_fee.set_allowed_fees(fee_token.stable_value_allowed());
        authorized_fee.set_used_fees(fee_token.value_used());
        response->add_authorized_fees()->CopyFrom(authorized_fee);
    }

    return grpc::Status::OK;
}