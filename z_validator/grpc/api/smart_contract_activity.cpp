#include "validator_api_service.h"

#include <algorithm>
#include <tuple>
#include <vector>

#include "const.h"
#include "validators.h"
#include "base58.h"
#include "signatures.h"
#include "wallets.h"
#include "../../logging/logging.h"

grpc::Status APIImpl::RecieveSmartContractActivityRequest(grpc::ServerContext *context, const zera_api::ActivityRequest *request, google::protobuf::Empty *response)
{
    // Rate limit before the whitelist file read and signature verification so
    // unauthenticated callers can't burn disk/crypto work for free.
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

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
    if(request->subscribe())
    {
        if(request->host().empty())
        {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Subscriber host cannot be empty");
        }
        if(request->port() <= 0 || request->port() > 65535)
        {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Subscriber port must be between 1 and 65535");
        }
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
        logging::info("Smart contract event subscription registered - wallet: " + wallet_address +
                      " contract: " + sc_key +
                      " callback: " + request->host() + ":" + std::to_string(request->port()));
    }
    else
    {
        subscription.mutable_subscibers()->erase(wallet_address);
        logging::info("Smart contract event subscription removed - wallet: " + wallet_address +
                      " contract: " + sc_key);
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
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    std::string event_data;
    db_event_management::get_single(request->smart_contract_id(), event_data);
    zera_api::SmartContractEventManagement event_management;
    event_management.ParseFromString(event_data);

    // Collect matches and sort oldest-first before applying the result cap.
    // Proto map iteration order is unspecified, so truncating without sorting
    // would drop arbitrary events; sorted-ascending truncation lets clients
    // page by re-querying with search_start advanced past the newest event
    // they received.
    struct EventRef
    {
        int64_t seconds;
        int32_t nanos;
        std::string key;
    };
    std::vector<EventRef> matches;

    for (const auto &event : event_management.events())
    {
        if (event.second.seconds() >= request->search_start().seconds())
        {
            matches.push_back({event.second.seconds(), event.second.nanos(), event.first});
        }
    }

    std::sort(matches.begin(), matches.end(), [](const EventRef &a, const EventRef &b)
              { return std::tie(a.seconds, a.nanos, a.key) < std::tie(b.seconds, b.nanos, b.key); });

    if (matches.size() > MAX_EVENT_SEARCH_RESULTS)
    {
        matches.resize(MAX_EVENT_SEARCH_RESULTS);
    }

    for (const auto &match : matches)
    {
        std::string single_event_data;
        if (!db_event_management::get_single(match.key, single_event_data))
        {
            continue;
        }
        zera_api::SmartContractEventsResponse *event_response = response->add_events();
        event_response->ParseFromString(single_event_data);
    }

    KeyPair key_pair = ValidatorConfig::get_key_pair();
    std::string public_key(key_pair.public_key.begin(), key_pair.public_key.end());
    response->mutable_public_key()->set_single(public_key);
    signatures::sign_response(response, key_pair);

    return grpc::Status::OK;
}
