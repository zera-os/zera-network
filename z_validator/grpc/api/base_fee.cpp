#include "validator_api_service.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

#include "utils.h"

grpc::Status APIImpl::RecieveRequestBaseFee(grpc::ServerContext *context, const zera_api::BaseFeeRequest *request, zera_api::BaseFeeResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }
    
    uint256_t byte_fee = get_txn_fee(request->txn_type());

    uint256_t key_fee = get_key_fee(request->public_key());

    response->set_byte_fee(byte_fee.str());
    response->set_key_fee(key_fee.str());

    return grpc::Status::OK;
}
