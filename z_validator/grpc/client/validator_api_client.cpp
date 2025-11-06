#include "validator_api_client.h"
#include <grpcpp/grpcpp.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <google/protobuf/empty.pb.h>
#include <google/protobuf/timestamp.pb.h>

#include <fstream>
#include "hex_conversion.h"
#include "db_base.h"

// Static member definitions
std::vector<StagedSmartContractEvent> ValidatorAPIClient::staged_events_;
std::mutex ValidatorAPIClient::staged_events_mutex_;
std::map<uint64_t, std::vector<PendingSmartContractEvent>> ValidatorAPIClient::pending_events_by_block_;
std::mutex ValidatorAPIClient::pending_events_mutex_;

// Single channel constructor
ValidatorAPIClient::ValidatorAPIClient(const std::string& server_address)
    : server_address_(server_address)
{
    InitializeSingleChannel();
}

// Multiple channels constructor
ValidatorAPIClient::ValidatorAPIClient(const std::vector<std::string>& server_addresses)
    : server_addresses_(server_addresses)
{
    InitializeMultipleChannels();
}

void ValidatorAPIClient::InitializeSingleChannel()
{
    try {
        // Create insecure channel for now - you can add SSL/TLS later if needed
        channel_ = grpc::CreateChannel(server_address_, grpc::InsecureChannelCredentials());
        stub_ = zera_api::APIService::NewStub(channel_);
        
        // Test connection by checking channel state
        grpc_connectivity_state state = channel_->GetState(true);
        if (state != GRPC_CHANNEL_READY && state != GRPC_CHANNEL_IDLE) {
            logging::print("Failed to connect to API server:", "Channel not ready", true);
        }
    }
    catch (const std::exception& e) {
        logging::log("Exception during channel initialization: " + std::string(e.what()));
    }
}

void ValidatorAPIClient::InitializeMultipleChannels()
{
    try {
        channels_.reserve(server_addresses_.size());
        stubs_.reserve(server_addresses_.size());
        
        for (const auto& address : server_addresses_) {
            auto channel = grpc::CreateChannel(address, grpc::InsecureChannelCredentials());
            channels_.push_back(channel);
            stubs_.push_back(zera_api::APIService::NewStub(channel));
        }
        
        logging::print("Initialized " + std::to_string(stubs_.size()) + " API client channels");
    }
    catch (const std::exception& e) {
        logging::log("Exception during multiple channel initialization: " + std::string(e.what()));
    }
}

bool ValidatorAPIClient::SendSmartContractEvent(const zera_api::SmartContractEventsResponse& event)
{
    if (!stub_) {
        logging::print("Stub not initialized");
        return false;
    }

    try {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
        
        google::protobuf::Empty response;
        grpc::Status status = stub_->SmartContractEvents(&context, event, &response);
        
        if (!status.ok()) {
            logging::print("Failed to send smart contract event:", status.error_message(), true);
            return false;
        }
        
        logging::print("Smart contract event sent successfully");
        return true;
    }
    catch (const std::exception& e) {
        logging::log("Exception while sending smart contract event: " + std::string(e.what()));
        return false;
    }
}


bool ValidatorAPIClient::IsConnected() const
{
    // Check single channel
    if (channel_) {
        grpc_connectivity_state state = channel_->GetState(true);
        return state == GRPC_CHANNEL_READY || state == GRPC_CHANNEL_IDLE;
    }
    
    // Check multiple channels - return true if at least one is connected
    if (!channels_.empty()) {
        for (const auto& channel : channels_) {
            grpc_connectivity_state state = channel->GetState(true);
            if (state == GRPC_CHANNEL_READY || state == GRPC_CHANNEL_IDLE) {
                return true;
            }
        }
    }
    
    return false;
}

void ValidatorAPIClient::Reconnect()
{
    Disconnect();
    
    if (!server_addresses_.empty()) {
        InitializeMultipleChannels();
    } else if (!server_address_.empty()) {
        InitializeSingleChannel();
    }
}

void ValidatorAPIClient::Disconnect()
{
    if (channel_) {
        channel_.reset();
    }
    stub_.reset();
    
    // Clean up multiple channels
    channels_.clear();
    stubs_.clear();
    server_addresses_.clear();
}

// Multiple channel methods
void ValidatorAPIClient::SendSmartContractEventToAll(const zera_api::SmartContractEventsResponse& event)
{
    if (stubs_.empty()) {
        logging::print("No stubs initialized for multiple channel sending");
        return;
    }

    CleanupAsyncCalls();

    // Send to all channels asynchronously
    for (size_t i = 0; i < stubs_.size(); ++i) {
        SendToChannel(event, i);
    }

    // Process responses
    ProcessAsyncResponses();
}


void ValidatorAPIClient::SendToChannel(const zera_api::SmartContractEventsResponse& event, int channel_index)
{
    if (channel_index >= static_cast<int>(stubs_.size())) {
        logging::print("Invalid channel index:", std::to_string(channel_index), true);
        return;
    }

    grpc::ClientContext* context = new grpc::ClientContext();
    grpc::Status* status = new grpc::Status();
    google::protobuf::Empty* response = new google::protobuf::Empty();
    
    std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
    context->set_deadline(deadline);

    try {
        auto async_call = stubs_[channel_index]->AsyncSmartContractEvents(context, event, &cq_);
        async_call->Finish(response, status, reinterpret_cast<void*>(channel_index));
        
        contexts_[channel_index] = context;
        statuses_[channel_index] = status;
        responses_[channel_index] = response;
    }
    catch (const std::exception& e) {
        delete context;
        delete status;
        delete response;
        logging::log("Error in SendToChannel: " + std::string(e.what()));
    }
}

void ValidatorAPIClient::ProcessAsyncResponses()
{
    size_t responses_received = 0;
    const size_t expected_responses = stubs_.size();

    while (responses_received < expected_responses) {
        void* got_tag;
        bool ok = false;

        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
        grpc::CompletionQueue::NextStatus status = cq_.AsyncNext(&got_tag, &ok, deadline);

        if (status == grpc::CompletionQueue::NextStatus::GOT_EVENT && ok) {
            int channel_index = static_cast<int>(reinterpret_cast<size_t>(got_tag));
            auto status_it = statuses_.find(channel_index);
            
            if (status_it == statuses_.end()) {
                logging::print("Received response for unknown channel", std::to_string(channel_index), true);
                continue;
            }

            if (!status_it->second->ok()) {
                if (status_it->second->error_code() == grpc::StatusCode::DEADLINE_EXCEEDED) {
                    logging::print("Call to channel", std::to_string(channel_index), "timed out", true);
                } else {
                    logging::print("Call to channel", std::to_string(channel_index), "failed:", status_it->second->error_message(), true);
                }
            } else {
                logging::print("Successfully sent event to channel", std::to_string(channel_index), true);
            }
        }
        else if (status == grpc::CompletionQueue::NextStatus::TIMEOUT) {
            logging::print("ProcessAsyncResponses: CompletionQueue timed out");
            break;
        }
        else {
            logging::print("ProcessAsyncResponses: CompletionQueue failed or returned false");
            break;
        }

        ++responses_received;
    }
}

void ValidatorAPIClient::CleanupAsyncCalls()
{
    for (auto& ctx : contexts_) {
        delete ctx.second;
    }
    for (auto& status : statuses_) {
        delete status.second;
    }
    for (auto& response : responses_) {
        delete response.second;
    }
    contexts_.clear();
    statuses_.clear();
    responses_.clear();
}


// Staging events management (before block info is known)
void ValidatorAPIClient::StageEvent(const zera_api::SmartContractEventsResponse& event)
{
    std::lock_guard<std::mutex> lock(staged_events_mutex_);
    staged_events_.emplace_back(event);
    logging::print("Staged event for smart contract:", event.smart_contract(), true);
}

void ValidatorAPIClient::PromoteStagedEventsToPending(const zera_validator::Block& block)
{
    std::lock_guard<std::mutex> staged_lock(staged_events_mutex_);
    
    if (staged_events_.empty()) {
        logging::print("No staged events to promote for block:", std::to_string(block.block_header().block_height()), true);
        return;
    }
    
    uint64_t block_height = block.block_header().block_height();
    std::string block_hash = block.block_header().hash();
    
    logging::print("Promoting", std::to_string(staged_events_.size()), "staged events to block:", std::to_string(block_height), true);
    
    // Update staged events with block info - you'll handle adding host/port manually
    for (auto& staged_event : staged_events_) {

        staged_event.event.set_block_height(block.block_header().block_height());
        std::string block_hash_hex = hex_conversion::bytes_to_hex(block.block_header().hash());
        staged_event.event.set_block_hash(block_hash_hex);
        staged_event.event.mutable_timestamp()->set_seconds(block.block_header().timestamp().seconds());
        
       
        std::string key = staged_event.event.smart_contract() + "_" + std::to_string(staged_event.event.instance());
        std::string value;

        if(db_sc_subscriber::get_single(key, value))
        {
            zera_api::SmartContractSubscription subscription;
            subscription.ParseFromString(value);

            for(const auto& subscriber : subscription.subscibers())
            {
                AddPendingEvent(staged_event.event, subscriber.second.host(), subscriber.second.port(), block_height);
            }
        }
    }
    
    // Clear staged events after promoting
    staged_events_.clear();
    logging::print("Cleared staged events after promotion", true);
}

void ValidatorAPIClient::ClearStagedEvents()
{
    std::lock_guard<std::mutex> lock(staged_events_mutex_);
    staged_events_.clear();
    logging::print("Cleared all staged events");
}

size_t ValidatorAPIClient::GetStagedEventsCount()
{
    std::lock_guard<std::mutex> lock(staged_events_mutex_);
    return staged_events_.size();
}

// Pending events management
void ValidatorAPIClient::AddPendingEvent(const zera_api::SmartContractEventsResponse& event, 
                                        const std::string& host, 
                                        int32_t port,
                                        uint64_t block_height)
{
    std::lock_guard<std::mutex> lock(pending_events_mutex_);
    pending_events_by_block_[block_height].emplace_back(event, host, port);
    logging::print("Added pending event for block:", std::to_string(block_height), "host:", host + " port:" + std::to_string(port), true);
}

void ValidatorAPIClient::SendPendingEventsForBlock(uint64_t block_height)
{
    std::lock_guard<std::mutex> lock(pending_events_mutex_);
    
    auto it = pending_events_by_block_.find(block_height);
    if (it == pending_events_by_block_.end() || it->second.empty()) {
        logging::print("No pending events for block:", std::to_string(block_height), true);
        return;
    }
    
    const auto& events = it->second;
    logging::print("Sending", std::to_string(events.size()), "pending events for block:", std::to_string(block_height), true);
    
    for (const auto& pending_event : events) {
        // Create a temporary client for this specific host:port
        std::string target_address = pending_event.host + ":" + std::to_string(pending_event.port);
        
        try {
            auto channel = grpc::CreateChannel(target_address, grpc::InsecureChannelCredentials());
            auto stub = zera_api::APIService::NewStub(channel);
            
            grpc::ClientContext context;
            zera_api::SmartContractEventsResponse event;
            event.CopyFrom(pending_event.event);
            event.mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
            signatures::sign_smart_contract_event(&event, ValidatorConfig::get_gen_key_pair());

            context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
            google::protobuf::Empty response;
            grpc::Status status = stub->SmartContractEvents(&context, event, &response);
            
            if (status.ok()) {
                logging::print("Successfully sent pending event to:", target_address, true);
            } else {
                logging::print("Failed to send pending event to:", target_address, "error:", status.error_message(), true);
            }
        }
        catch (const std::exception& e) {
            logging::log("Exception while sending pending event to " + target_address + ": " + std::string(e.what()));
        }
    }
    
    // Clear events for this block after sending
    pending_events_by_block_.erase(it);
    logging::print("Cleared pending events for block:", std::to_string(block_height), true);
}


void ValidatorAPIClient::ClearPendingEventsForBlock(uint64_t block_height)
{
    std::lock_guard<std::mutex> lock(pending_events_mutex_);
    auto it = pending_events_by_block_.find(block_height);
    if (it != pending_events_by_block_.end()) {
        pending_events_by_block_.erase(it);
        logging::print("Cleared pending events for block:", std::to_string(block_height), true);
    }
}

size_t ValidatorAPIClient::GetPendingEventsCount()
{
    std::lock_guard<std::mutex> lock(pending_events_mutex_);
    size_t total_count = 0;
    for (const auto& pair : pending_events_by_block_) {
        total_count += pair.second.size();
    }
    return total_count;
}

size_t ValidatorAPIClient::GetPendingEventsCountForBlock(uint64_t block_height)
{
    std::lock_guard<std::mutex> lock(pending_events_mutex_);
    auto it = pending_events_by_block_.find(block_height);
    if (it != pending_events_by_block_.end()) {
        return it->second.size();
    }
    return 0;
}
