#include "validator_api_service.h"

grpc::Status APIImpl::RecieveRequestItems(grpc::ServerContext *context, const zera_api::ItemRequest *request, zera_api::ItemResponse *response)
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


    std::string wallet_data;
    zera_validator::WalletItems wallet_items;
    if(!db_contract_items::get_single(wallet, wallet_data))
    {
        return grpc::Status(grpc::NOT_FOUND, "Invalid Wallet");
    }

    wallet_items.ParseFromString(wallet_data);

    if(wallet_items.items_size() == 0)
    {
        return grpc::Status(grpc::NOT_FOUND, "No items found for this wallet");
    }

    for (auto item : wallet_items.items())
    {
        auto *new_item = response->add_items();
        new_item->set_item_id(item.item_id());
        new_item->set_contract_id(item.contract_id());
    }

    return grpc::Status::OK;
}