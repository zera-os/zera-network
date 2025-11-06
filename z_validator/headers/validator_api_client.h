#pragma once

// Standard Library
#include <memory>
#include <future>
#include <random>
#include <thread>
#include <mutex>
#include <map>
#include <fstream>
#include <string>

// Third-party Libraries
#include <grpcpp/grpcpp.h>
#include <google/protobuf/empty.pb.h>
#include <google/protobuf/timestamp.pb.h>

// Project Headers
#include "txn.pb.h"
#include "zera_api.pb.h"
#include "zera_api.grpc.pb.h"
#include "db_base.h"
#include "const.h"
#include "validators.h"
#include "zera_status.h"
#include "wallets.h"
#include "../logging/logging.h"

// Struct to store pending smart contract events
struct PendingSmartContractEvent {
    zera_api::SmartContractEventsResponse event;
    std::string host;
    int32_t port;
    
    PendingSmartContractEvent(const zera_api::SmartContractEventsResponse& evt, 
                             const std::string& h, 
                             int32_t p) 
        : event(evt), host(h), port(p) {}
};

// Struct to store staged events (host/port added later during promotion)
struct StagedSmartContractEvent {
    zera_api::SmartContractEventsResponse event;
    
    StagedSmartContractEvent(const zera_api::SmartContractEventsResponse& evt) 
        : event(evt) {}
};

class ValidatorAPIClient
{
public:
    // Constructor for single channel
    ValidatorAPIClient(const std::string& server_address);
    
    // Constructor for multiple channels
    ValidatorAPIClient(const std::vector<std::string>& server_addresses);
    
    ~ValidatorAPIClient() = default;

    // SmartContractEvents methods - single channel
    bool SendSmartContractEvent(const zera_api::SmartContractEventsResponse& event);

    // SmartContractEvents methods - multiple channels
    void SendSmartContractEventToAll(const zera_api::SmartContractEventsResponse& event);

    // Connection management
    bool IsConnected() const;
    void Reconnect();
    void Disconnect();
    
    // Staging events management (before block info is known)
    static void StageEvent(const zera_api::SmartContractEventsResponse& event);
    static void PromoteStagedEventsToPending(const zera_validator::Block& block);
    static void ClearStagedEvents();
    static size_t GetStagedEventsCount();
    
    // Pending events management
    static void AddPendingEvent(const zera_api::SmartContractEventsResponse& event, 
                               const std::string& host, 
                               int32_t port,
                               uint64_t block_height);
    static void SendPendingEventsForBlock(uint64_t block_height);
    static void SendAllPendingEvents();
    static void ClearPendingEventsForBlock(uint64_t block_height);
    static size_t GetPendingEventsCount();
    static size_t GetPendingEventsCountForBlock(uint64_t block_height);
    

private:
    // Single channel members
    std::unique_ptr<zera_api::APIService::Stub> stub_;
    std::string server_address_;
    std::shared_ptr<grpc::Channel> channel_;
    
    // Multiple channels members
    std::vector<std::unique_ptr<zera_api::APIService::Stub>> stubs_;
    std::vector<std::shared_ptr<grpc::Channel>> channels_;
    std::vector<std::string> server_addresses_;
    
    // Async support
    grpc::CompletionQueue cq_;
    std::map<int, grpc::ClientContext*> contexts_;
    std::map<int, grpc::Status*> statuses_;
    std::map<int, google::protobuf::Empty*> responses_;
    
    // Staging area for events before block info is known
    static std::vector<StagedSmartContractEvent> staged_events_;
    static std::mutex staged_events_mutex_;
    
    // Pending events storage organized by block height
    static std::map<uint64_t, std::vector<PendingSmartContractEvent>> pending_events_by_block_;
    static std::mutex pending_events_mutex_;
    
    // Helper methods
    void InitializeSingleChannel();
    void InitializeMultipleChannels();
    void SendToChannel(const zera_api::SmartContractEventsResponse& event, int channel_index);
    void ProcessAsyncResponses();
    void CleanupAsyncCalls();
};