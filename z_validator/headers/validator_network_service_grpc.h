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
#include "validator.pb.h"
#include "validator.grpc.pb.h"
#include "verify_process_txn.h"
#include "zera_status.h"
#include "validator_network_client.h"
#include "../block_process/block_process.h"
#include "../temp_data/temp_data.h"
#include "threadpool.h"
#include "../logging/logging.h"
#include "rate_limiter.h"
#include "wallets.h"

using google::protobuf::Empty;
using google::protobuf::Timestamp;
using zera_txn::InstrumentContract;
using zera_txn::MintTXN;
using zera_txn::ValidatorRegistration;
using zera_validator::Block;
using zera_validator::BlockBatch;
using zera_validator::BlockSync;
using zera_validator::ValidatorSync;
using zera_validator::ValidatorSyncRequest;


class ValidatorServiceImpl final : public zera_validator::ValidatorService::Service
{
public:
    // streams
    grpc::Status StreamBroadcast(grpc::ServerContext *context, grpc::ServerReader<zera_validator::DataChunk> *reader, google::protobuf::Empty *response) override;
    grpc::Status SyncBlockchain(grpc::ServerContext *context, const BlockSync *request, grpc::ServerWriter<zera_validator::DataChunk> *writer) override;
    grpc::Status StreamBlockAttestation(grpc::ServerContext *context, grpc::ServerReaderWriter<zera_validator::DataChunk, zera_validator::DataChunk> *stream) override;
    grpc::Status StreamGossip(grpc::ServerContext *context, grpc::ServerReader<zera_validator::DataChunk> *reader, google::protobuf::Empty *response) override;

    grpc::Status Broadcast(grpc::ServerContext *context, const Block *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorRegistration(grpc::ServerContext *context, const zera_txn::ValidatorRegistration *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorMint(grpc::ServerContext *context, const MintTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorNFT(grpc::ServerContext *context, const zera_txn::NFTTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorItemMint(grpc::ServerContext *context, const zera_txn::ItemizedMintTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorContract(grpc::ServerContext *context, const InstrumentContract *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorGovernProposal(grpc::ServerContext *context, const zera_txn::GovernanceProposal *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorGovernVote(grpc::ServerContext *context, const zera_txn::GovernanceVote *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorSmartContract(grpc::ServerContext *context, const zera_txn::SmartContractTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorSmartContractExecute(grpc::ServerContext *context, const zera_txn::SmartContractExecuteTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorExpenseRatio(grpc::ServerContext *context, const zera_txn::ExpenseRatioTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorContractUpdate(grpc::ServerContext *context, const zera_txn::ContractUpdateTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorHeartbeat(grpc::ServerContext *context, const zera_txn::ValidatorHeartbeat *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorDelegatedVoting(grpc::ServerContext *context, const zera_txn::DelegatedTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorQuash(grpc::ServerContext *context, const zera_txn::QuashTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorRevoke(grpc::ServerContext *context, const zera_txn::RevokeTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorFastQuorum(grpc::ServerContext *context, const zera_txn::FastQuorumTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorCompliance(grpc::ServerContext *context, const zera_txn::ComplianceTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorBurnSBT(grpc::ServerContext *context, const zera_txn::BurnSBTTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorCoin(grpc::ServerContext *context, const zera_txn::CoinTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorSmartContractInstantiate(grpc::ServerContext *context, const zera_txn::SmartContractInstantiateTXN *request, google::protobuf::Empty *response) override;
    grpc::Status ValidatorAllowance(grpc::ServerContext *context, const zera_txn::AllowanceTXN *request, google::protobuf::Empty *response) override;

    grpc::Status IndexerVoting(grpc::ServerContext *context, const zera_validator::IndexerVotingRequest *request, zera_validator::IndexerVotingResponse *response) override;
    grpc::Status Nonce(grpc::ServerContext *context, const zera_validator::NonceRequest *request, zera_validator::NonceResponse *response) override;
    grpc::Status Balance(grpc::ServerContext *context, const zera_validator::BalanceRequest *request, zera_validator::BalanceResponse *response) override;
    grpc::Status Gossip(grpc::ServerContext *context, const zera_validator::TXNGossip *request, google::protobuf::Empty *response) override;

    template <typename TXType>
    static void ProcessGossipTXN(const TXType *request, std::string client_ip);

    void StartService(const std::string &port = "50051")
    {
        grpc::ServerBuilder builder;
        std::string listening = "0.0.0.0:" + port;

        builder.AddListeningPort(listening, grpc::InsecureServerCredentials());
        builder.RegisterService(this);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        server->Wait();
    }

    static void chunkData(const std::string &data, std::vector<zera_validator::DataChunk> *responses)
    {
        size_t dataSize = data.size();
        int x = 0;
        for (size_t i = 0; i < dataSize; i += CHUNK_SIZE)
        {
            zera_validator::DataChunk chunk;
            chunk.set_chunk_data(data.substr(i, std::min(CHUNK_SIZE, dataSize - i)));
            chunk.set_chunk_number(x);
            responses->push_back(chunk);
            x++;
        }
        if (!responses->empty())
        {
            responses->at(0).set_total_chunks(static_cast<int>(responses->size()));
        }
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
    static void ProcessBroadcastAsync(const Block *request);
    static void ProcessValidatorRegistrationAsync(const zera_txn::ValidatorRegistration *request);
    static void ProcessBlockAttestationAsync(const zera_validator::BlockAttestation *request, const zera_validator::BlockAttestationResponse *response);
    static grpc::Status RecieveGossip(grpc::ServerContext *context, const zera_validator::TXNGossip *request, google::protobuf::Empty *response);

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

        if (!rate_limiter.canProceed(client_ip))
        {
            std::cerr << "Rate limit exceeded for IP: " << client_ip << std::endl;
            return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
        }

        // Start asynchronous processing of the request
        TXType *txn = new TXType();
        txn->CopyFrom(*request);
        if (recieved_txn_tracker::check_txn(txn->base().hash()))
        {
            logging::print("TXN already recieved");
            rate_limiter.processUpdate(client_ip, true);
            delete txn;
            return grpc::Status::CANCELLED;
        }

        recieved_txn_tracker::add_txn(txn->base().hash());

        try
        {
            // Enqueue the task into the thread pool
            ThreadPool::enqueueTask([txn, client_ip]()
                                    { 
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
        std::string memo = "";

        if (request->base().has_memo())
        {
            memo = request->base().memo();
        }

        if (!status.ok())
        {
            status.prepend_message("validator_network_service_grpc.h: ProcessRequestAsync: " + memo);

            if (status.code() != ZeraStatus::Code::DUPLICATE_TXN_ERROR)
            {
                rate_limiter.processUpdate(client_ip, true);
                logging::print(status.read_status());
            }

            return;
        }

        zera_txn::TRANSACTION_TYPE txn_type;
        status = verify_txns::store_txn(request, txn_type);

        // if (txn_type != zera_txn::TRANSACTION_TYPE::VALIDATOR_REGISTRATION_TYPE && txn_type != zera_txn::TRANSACTION_TYPE::VALIDATOR_HEARTBEAT_TYPE)
        // {
        //     auto public_key = wallets::get_public_key_string(request->base().public_key());
        //     db_validator_lookup::exist(public_key);

        //     // if sender is a validator remove txn. validators can only recieve coins
        //     if (db_validators::exist(public_key) || db_validator_lookup::exist(public_key) || db_validator_lookup::exist(public_key))
        //     {
        //         logging::print("Process request: validator not found", true);
        //         rate_limiter.processUpdate(client_ip, true);
        //         return;
        //     }
        // }

        // if txn was stored start gossip
        if (!status.ok())
        {
            rate_limiter.processUpdate(client_ip, true);
            status.prepend_message("validator_network_service_grpc.h: ProcessRequestAsync: " + memo);
            logging::print(status.read_status());
            return;
        }

        TXType *txn = new TXType();
        txn->CopyFrom(*request);

        // Enqueue the task into the thread pool
        ThreadPool::enqueueTask([txn, txn_type, client_ip]()
                                { 
            pre_process::process_txn(txn, txn_type, client_ip); 
            delete txn; });
    }
};
