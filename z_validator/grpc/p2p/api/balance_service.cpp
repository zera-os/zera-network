// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"
#include "validator_network_service_grpc.h"

// Project-specific headers (from the current directory)
#include "db_base.h"

grpc::Status ValidatorServiceImpl::Balance(grpc::ServerContext *context, const zera_validator::BalanceRequest *request, zera_validator::BalanceResponse *response)
{
    std::string balance_data;
    std::string wallet_key;

    if(request->encoded())
    {
        auto wallet_temp = base58_decode(request->wallet_address());
        wallet_key = std::string(wallet_temp.begin(), wallet_temp.end()) + request->contract_id();
        
    }
    else
    {
        wallet_key = request->wallet_address() + request->contract_id();
    }

    std::string balance = "0";
    if(db_wallets::get_single(wallet_key, balance_data))
    {
        balance = balance_data;
    }

    response->set_balance(balance);

    return grpc::Status::OK;
}