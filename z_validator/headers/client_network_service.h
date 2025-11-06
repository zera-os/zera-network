#ifndef CLIENT_NETWORK_SERVICE_H
#define CLIENT_NETWORK_SERVICE_H

// Standard Library
#include <random>
#include <thread>

// Third-party Libraries
#include <google/protobuf/empty.pb.h>
#include <grpcpp/grpcpp.h>

// Project Headers
#include "txn.pb.h"
#include "txn.grpc.pb.h"
#include "validator_network_client.h"
#include "verify_process_txn.h"
#include "zera_status.h"
#include "../block_process/block_process.h"
#include "threadpool.h"
#include "../logging/logging.h"
#include "rate_limiter.h"

class ClientNetworkServiceImpl final : public zera_txn::TXNService::Service
{
public:
    grpc::Status Coin(grpc::ServerContext *context, const zera_txn::CoinTXN *request, google::protobuf::Empty *response) override;
    grpc::Status Mint(grpc::ServerContext *context, const zera_txn::MintTXN *request, google::protobuf::Empty *response) override;
    grpc::Status NFT(grpc::ServerContext *context, const zera_txn::NFTTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ItemMint(grpc::ServerContext *context, const zera_txn::ItemizedMintTXN *request, google::protobuf::Empty *response) override;
    grpc::Status Contract(grpc::ServerContext *context, const zera_txn::InstrumentContract *request, google::protobuf::Empty *response) override;
    grpc::Status GovernProposal(grpc::ServerContext *context, const zera_txn::GovernanceProposal *request, google::protobuf::Empty *response) override;
    grpc::Status GovernVote(grpc::ServerContext *context, const zera_txn::GovernanceVote *request, google::protobuf::Empty *response) override;
    grpc::Status SmartContract(grpc::ServerContext *context, const zera_txn::SmartContractTXN *request, google::protobuf::Empty *response) override;
    grpc::Status SmartContractExecute(grpc::ServerContext *context, const zera_txn::SmartContractExecuteTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ExpenseRatio(grpc::ServerContext *context, const zera_txn::ExpenseRatioTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ContractUpdate(grpc::ServerContext *context, const zera_txn::ContractUpdateTXN *request, google::protobuf::Empty *response) override;
    grpc::Status DelegatedVoting(grpc::ServerContext *context, const zera_txn::DelegatedTXN *request, google::protobuf::Empty *response) override;
    grpc::Status Quash(grpc::ServerContext *context, const zera_txn::QuashTXN *request, google::protobuf::Empty *response) override;
    grpc::Status Revoke(grpc::ServerContext *context, const zera_txn::RevokeTXN *request, google::protobuf::Empty *response) override;
    grpc::Status FastQuorum(grpc::ServerContext *context, const zera_txn::FastQuorumTXN *request, google::protobuf::Empty *response) override;
    grpc::Status Compliance(grpc::ServerContext *context, const zera_txn::ComplianceTXN *request, google::protobuf::Empty *response) override;
    grpc::Status BurnSBT(grpc::ServerContext *context, const zera_txn::BurnSBTTXN *request, google::protobuf::Empty *response) override;
    grpc::Status SmartContractInstantiate(grpc::ServerContext *context, const zera_txn::SmartContractInstantiateTXN *request, google::protobuf::Empty *response) override;
    grpc::Status Allowance(grpc::ServerContext *context, const zera_txn::AllowanceTXN *request, google::protobuf::Empty *response) override;

    void StartService(const std::string &port = "50052")
    {
        grpc::ServerBuilder builder;
        std::string listening = "0.0.0.0:" + port;

        builder.AddListeningPort(listening, grpc::InsecureServerCredentials());
        builder.RegisterService(this);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        server->Wait();
    }

    static void RateLimitConfig()
    {
        RateLimiterConfig config;
        config.baseRefillRate = 1.0;
        config.baseCapacity = 3.0;
        config.refillScale = 0.2;
        config.capacityScale = 0.5;
        rate_limiter.configure(config);
    }

    static RateLimiter rate_limiter; // Token bucket for rate limiting

private:

    template <typename TXType>
    grpc::Status RecieveRequest(grpc::ServerContext *context, const TXType *request, google::protobuf::Empty *response)
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

        if(!rate_limiter.canProceed(client_ip))
        {
            std::cerr << "Rate limit exceeded for IP: " << client_ip << std::endl;
            return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
        }

        TXType *txn = new TXType();
        txn->CopyFrom(*request);



        try
        {
            ThreadPool::enqueueTask([txn, client_ip](){ 
                ProcessRequest<TXType>(txn, client_ip); 
                delete txn; });
        }
        catch (const std::exception &e)
        {
            std::cerr << "Failed to enqueue task: " << e.what() << std::endl;
        }

        return grpc::Status::OK;
    }

    template <typename TXType>
    static void ProcessRequest(const TXType *request, std::string client_ip)
    {

        ZeraStatus status = verify_txns::verify_txn(request);

        std::string memo = request->base().memo();
        if (request->base().has_memo())
        {
            memo = request->base().memo();
        }

        if (!status.ok())
        {
            status.prepend_message("client_network_service: ProcessRequest: " + memo);

            if (status.code() != ZeraStatus::Code::DUPLICATE_TXN_ERROR)
            {
                logging::print(status.read_status());
            }
            rate_limiter.processUpdate(client_ip, true);
            return;
        }
        zera_txn::TRANSACTION_TYPE txn_type;
        status = verify_txns::store_txn(request, txn_type);
        // if txn was stored start gossip
        if (!status.ok())
        {
            status.prepend_message("client_network_service: ProcessRequest: " + memo);
            logging::print(status.read_status());
            rate_limiter.processUpdate(client_ip, true);
            return;
        }
        if (!request || !request->IsInitialized())
        {
            rate_limiter.processUpdate(client_ip, true);
            logging::print("Error: Protobuf object is null or not initialized in ProcessRequest");
            return;
        }
        TXType *txn = new TXType();
        txn->CopyFrom(*request);

        std::string ip = client_ip;
        pre_process::process_txn(txn, txn_type, ip);
        
        delete txn;
    }
};
#endif
