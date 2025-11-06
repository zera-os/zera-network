#include "validator_api_service.h"

#include "validators.h"
#include "signatures.h"
#include "google/protobuf/util/time_util.h"
#include "wallets.h"
#include "db_base.h"

grpc::Status APIImpl::RecieveRequestContract(grpc::ServerContext *context, const zera_api::ContractRequest *request, zera_api::ContractResponse *response)
{
    std::string contract_data;
    if(db_contracts::get_single(request->contract_id(), contract_data))
    {
        response->mutable_contract()->ParseFromString(contract_data);
    }
    else
    {
        return grpc::Status(grpc::NOT_FOUND, "Invalid Contract ID");
    }


    KeyPair key_pair = ValidatorConfig::get_key_pair();

    std::string public_key(key_pair.public_key.begin(), key_pair.public_key.end());

    response->mutable_public_key()->set_single(public_key);

    response->mutable_timestamp()->CopyFrom(google::protobuf::util::TimeUtil::GetCurrentTime());

    signatures::sign_response(response, key_pair);

    return grpc::Status::OK;
}