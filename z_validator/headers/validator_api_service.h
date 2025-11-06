#pragma once

// Standard Library
#include <random>
#include <thread>

// Third-party Libraries
#include <google/protobuf/empty.pb.h>
#include <google/protobuf/timestamp.pb.h>
#include <grpcpp/grpcpp.h>

// Project Headers
#include "db_base.h"
// #include "db_validators.h"
#include "txn.pb.h"
#include "zera_api.pb.h"
#include "zera_api.grpc.pb.h"
#include "verify_process_txn.h"
#include "zera_status.h"
#include "../logging/logging.h"
#include "rate_limiter.h"

class APIImpl final : public zera_api::APIService::Service
{
public:
    grpc::Status Balance(grpc::ServerContext *context, const zera_api::BalanceRequest *request, zera_api::BalanceResponse *response) override;
    grpc::Status Nonce(grpc::ServerContext *context, const zera_api::NonceRequest *request, zera_api::NonceResponse *response) override;
    grpc::Status ContractFee(grpc::ServerContext *context, const zera_api::ContractFeeRequest *request, zera_api::ContractFeeResponse *response) override;
    grpc::Status BaseFee(grpc::ServerContext *context, const zera_api::BaseFeeRequest *request, zera_api::BaseFeeResponse *response) override;
    grpc::Status GetTokenFeeInfo(grpc::ServerContext *context, const zera_api::TokenFeeInfoRequest *request, zera_api::TokenFeeInfoResponse *response) override;
    grpc::Status Items(grpc::ServerContext *context, const zera_api::ItemRequest *request, zera_api::ItemResponse *response) override;
    grpc::Status Denomination(grpc::ServerContext *context, const zera_api::DenominationRequest *request, zera_api::DenominationResponse *response) override;
    grpc::Status Database(grpc::ServerContext *context, const zera_api::DatabaseRequest *request, zera_api::DatabaseResponse *response) override;
    grpc::Status Block(grpc::ServerContext *context, const zera_api::BlockRequest *request, zera_api::BlockResponse *response) override;
    grpc::Status ProposalLedger(grpc::ServerContext *context, const zera_api::ProposalLedgerRequest *request, zera_api::ProposalLedgerResponse *response) override;
    grpc::Status SmartContractActivityRequest(grpc::ServerContext *context, const zera_api::ActivityRequest *request, google::protobuf::Empty *response) override;
    grpc::Status Contract(grpc::ServerContext *context, const zera_api::ContractRequest *request, zera_api::ContractResponse *response) override;
    grpc::Status SmartContractEventsSearch(grpc::ServerContext *context, const zera_api::SmartContractEventsSearchRequest *request, zera_api::SmartContractEventsSearchResponse *response) override;

    void StartService(const std::string &port = "50053")
    {
        grpc::ServerBuilder builder;
        std::string listening = "0.0.0.0:" + port;

        logging::print("Starting API service on port:", listening, true);
        builder.AddListeningPort(listening, grpc::InsecureServerCredentials());
        builder.RegisterService(this);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        server->Wait();
    }

    static void RateLimitConfig(std::vector<std::string> whitelist)
    {
        RateLimiterConfig config;
        config.staticMode = true;      // Use static config
        config.staticRefillRate = 5.0; // Static refill rate
        config.staticCapacity = 100.0; // Static max tokens
        rate_limiter.configure(config);

        for (const auto &ip : whitelist)
        {
            rate_limiter.addToWhitelist(ip);
        }
    }
    static RateLimiter rate_limiter; // Token bucket for rate limiting

private:
    grpc::Status RecieveRequestBalance(grpc::ServerContext *context, const zera_api::BalanceRequest *request, zera_api::BalanceResponse *response);
    grpc::Status RecieveRequestNonce(grpc::ServerContext *context, const zera_api::NonceRequest *request, zera_api::NonceResponse *response);
    grpc::Status RecieveRequestContractFee(grpc::ServerContext *context, const zera_api::ContractFeeRequest *request, zera_api::ContractFeeResponse *response);
    grpc::Status RecieveRequestBaseFee(grpc::ServerContext *context, const zera_api::BaseFeeRequest *request, zera_api::BaseFeeResponse *response);
    grpc::Status RecieveGetTokenFeeInfo(grpc::ServerContext *context, const zera_api::TokenFeeInfoRequest *request, zera_api::TokenFeeInfoResponse *response);
    grpc::Status RecieveRequestItems(grpc::ServerContext *context, const zera_api::ItemRequest *request, zera_api::ItemResponse *response);
    grpc::Status RecieveRequestDenomination(grpc::ServerContext *context, const zera_api::DenominationRequest *request, zera_api::DenominationResponse *response);
    grpc::Status RecieveRequestDatabase(grpc::ServerContext *context, const zera_api::DatabaseRequest *request, zera_api::DatabaseResponse *response);
    grpc::Status RecieveRequestBlock(grpc::ServerContext *context, const zera_api::BlockRequest *request, zera_api::BlockResponse *response);
    grpc::Status RecieveRequestProposalLedger(grpc::ServerContext *context, const zera_api::ProposalLedgerRequest *request, zera_api::ProposalLedgerResponse *response);
    grpc::Status RecieveSmartContractActivityRequest(grpc::ServerContext *context, const zera_api::ActivityRequest *request, google::protobuf::Empty *response);
    grpc::Status RecieveRequestContract(grpc::ServerContext *context, const zera_api::ContractRequest *request, zera_api::ContractResponse *response);
    grpc::Status RecieveSmartContractEventsSearch(grpc::ServerContext *context, const zera_api::SmartContractEventsSearchRequest *request, zera_api::SmartContractEventsSearchResponse *response);

    static bool check_rate_limit(grpc::ServerContext *context)
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
            return false;
        }

        rate_limiter.processUpdate(client_ip, false);

        return true;
    };
};