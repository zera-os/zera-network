// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"
#include "validator_network_service_grpc.h"

// Project-specific headers (from the current directory)
#include "db_base.h"

grpc::Status ValidatorServiceImpl::Nonce(grpc::ServerContext *context, const zera_validator::NonceRequest *request, zera_validator::NonceResponse *response)
{
    // Get the client's IP address
    std::string peer_info = context->peer();
    std::string client_ip;

    // Extract the IP address from the peer info
    size_t pos = peer_info.find(":");
    if (pos != std::string::npos)
    {
        client_ip = peer_info.substr(0, pos); // Extract everything before the first colon
    }
    else
    {
        client_ip = peer_info; // Fallback if no colon is found
    }

    if (!rate_limiter.canProceed(client_ip))
    {
        std::cerr << "Rate limit exceeded for IP: " << client_ip << std::endl;
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    rate_limiter.processUpdate(client_ip, false);
    
    std::string nonce_data;

    if(!db_wallet_nonce::get_single(request->wallet_address(), nonce_data)){
        return grpc::Status(grpc::StatusCode::CANCELLED, "Wallet address does not exist.");
    }

    uint64_t nonce;

    try
    {
        nonce = std::stoull(nonce_data);
    } 
    catch (std::exception& e)
    {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Failed to parse nonce. (this should never happen)");
    }

    response->set_nonce(nonce);

    return grpc::Status::OK;
}