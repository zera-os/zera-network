#include "validator_api_service.h"

#include "const.h"
#include "validators.h"
#include "base58.h"
#include "signatures.h"
#include "wallets.h"
#include "../../logging/logging.h"

grpc::Status APIImpl::RecieveSmartContractActivityRequest(grpc::ServerContext *context, const zera_api::ActivityRequest *request, google::protobuf::Empty *response)
{
    std::ifstream activity_config(ACTIVITY_WHITELIST);
    std::string line;
    bool whitelist = false;
    std::string wallet_address;
	while (std::getline(activity_config, line))
	{
        std::string wallet_decoded = wallets::generate_wallet(request->public_key(), "");
        wallet_address = base58_encode(wallet_decoded);
        if(line == wallet_address)
        {
            whitelist = true;
            break;
        }
    }
    if(!whitelist)
    {
        return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Public key not whitelisted");
    }
    uint64_t old_nonce = 0;  
    std::string old_nonce_str;
    if(db_sc_subscriber::get_single(wallet_address, old_nonce_str))
    {
        old_nonce = std::stoull(old_nonce_str);
    }
    if(old_nonce >= request->nonce())
    {
        return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Nonce must be greater than the old nonce: " + std::to_string(old_nonce) + " new nonce: " + std::to_string(request->nonce()));
    }
    if(!signatures::verify_activity_request(*request))
    {
        return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Signature verification failed");
    }
    std::string sc_key = request->smart_contract_id() + "_" + std::to_string(request->instance());
    std::string data;
    zera_api::SmartContractSubscription subscription;
    if(db_sc_subscriber::get_single(sc_key, data))
    {
        subscription.ParseFromString(data);
    }
    else if(!request->subscribe())
    {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Subscription not found");
    }

    db_sc_subscriber::store_single(wallet_address, std::to_string(request->nonce()));
    if(request->subscribe())
    {
        subscription.mutable_subscibers()->erase(wallet_address);
        zera_api::Subscriber subscriber;
        subscriber.set_level(request->level());
        subscriber.set_host(request->host());
        subscriber.set_port(request->port());
        subscription.mutable_subscibers()->insert({wallet_address, subscriber});
    }
    else
    {
        subscription.mutable_subscibers()->erase(wallet_address);
    }
    if(subscription.subscibers().empty())
    {
        db_sc_subscriber::remove_single(sc_key);
    }
    else
    {
        db_sc_subscriber::store_single(sc_key, subscription.SerializeAsString());
    }
    return grpc::Status::OK;
}


grpc::Status APIImpl::RecieveSmartContractEventsSearch(grpc::ServerContext *context, const zera_api::SmartContractEventsSearchRequest *request, zera_api::SmartContractEventsSearchResponse *response)
{
    std::string event_data;
    db_event_management::get_single(request->smart_contract_id(), event_data);
    zera_api::SmartContractEventManagement event_management;
    event_management.ParseFromString(event_data);

    for(auto event : event_management.events())
    {
        if(event.second.seconds() >= request->search_start().seconds())
        {
            std::string event_data;
            db_event_management::get_single(event.first, event_data);
            zera_api::SmartContractEventsResponse *event_response = response->add_events();
            event_response->ParseFromString(event_data);
        }
    }

    KeyPair key_pair = ValidatorConfig::get_key_pair();
    std::string public_key(key_pair.public_key.begin(), key_pair.public_key.end());
    response->mutable_public_key()->set_single(public_key);
    signatures::sign_response(response, key_pair);

    return grpc::Status::OK;
}
