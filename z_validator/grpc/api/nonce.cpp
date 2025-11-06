#include "validator_api_service.h"

grpc::Status APIImpl::RecieveRequestNonce(grpc::ServerContext *context, const zera_api::NonceRequest *request, zera_api::NonceResponse *response)
{

    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }
    
    std::string wallet;

    if (request->encoded())
    {
        auto wallet_vec = base58_decode(request->wallet_address());
        wallet.assign(wallet_vec.begin(), wallet_vec.end());

    }
    else
    {
        wallet.assign(request->wallet_address().begin(), request->wallet_address().end());
    }

    std::string nonce_data;

    uint64_t nonce;

    if (db_wallet_nonce::get_single(wallet, nonce_data))
    {
        try
        {
            nonce = std::stoull(nonce_data);
        }
        catch (std::exception &e)
        {
            return grpc::Status(grpc::StatusCode::CANCELLED, "Failed to parse nonce. (this should never happen)");
        }
    }
    else
    {
        nonce = 0;
    }

    response->set_nonce(nonce);

    return grpc::Status::OK;
}