#include "validator_api_service.h"
#include "fees.h"

grpc::Status APIImpl::RecieveRequestBalance(grpc::ServerContext *context, const zera_api::BalanceRequest *request, zera_api::BalanceResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }
    
    std::string wallet;

    if(request->encoded())
    {
        auto wallet_vec = base58_decode(request->wallet_address());
        wallet.assign(wallet_vec.begin(), wallet_vec.end());
    }
    else
    {
        wallet.assign(request->wallet_address().begin(), request->wallet_address().end());
    }

    std::string contract_data;
    if(db_contracts::get_single(request->contract_id(), contract_data))
    {
        zera_txn::InstrumentContract contract;
        contract.ParseFromString(contract_data);
        response->set_denomination(contract.coin_denomination().amount());

        uint256_t cur_data;

        if(!zera_fees::get_cur_equiv(request->contract_id(), cur_data))
        {
            response->set_rate("0");
        }
        else
        {
            response->set_rate(cur_data.str());
        }
    }
    else
    {
        return grpc::Status(grpc::NOT_FOUND, "Invalid Contract ID");
    }

    std::string balance;

    if(db_wallets::get_single(wallet + request->contract_id(), balance))
    {
        response->set_balance(balance);

        return grpc::Status::OK;
    }
    else
    {
        return grpc::Status(grpc::NOT_FOUND, "Invalid Wallet");
    }

    return grpc::Status::OK;
}