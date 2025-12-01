#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>

#include "validator.pb.h"
#include "validator_network_client.h"

#include "db_base.h"
#include "signatures.h"
#include "validators.h"
#include "../../../logging/logging.h"
#include "../../../db/reorg.h"

namespace
{
    // Set timestamp and sign the checkpoint info request
    void set_checkpoint_info_request(zera_validator::CheckpointInfoRequest* request)
    {
        request->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
        
        auto now = std::chrono::system_clock::now();
        auto timestamp = request->mutable_timestamp();
        timestamp->set_seconds(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
        
        signatures::sign_request(request, ValidatorConfig::get_gen_key_pair());
    }

    // Set timestamp and sign the checkpoint request
    void set_checkpoint_request(zera_validator::CheckpointRequest* request, const std::string& version)
    {
        request->set_version(version);
        request->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
        
        auto now = std::chrono::system_clock::now();
        auto timestamp = request->mutable_timestamp();
        timestamp->set_seconds(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
        
        signatures::sign_request(request, ValidatorConfig::get_gen_key_pair());
    }

    // Extract the tar.gz file to the checkpoints directory
    bool extract_checkpoint(const std::string& tar_path, const std::string& version)
    {
        std::string extract_dir = DB_CHECKPOINTS;
        std::string cmd = "tar -xzf " + tar_path + " -C " + extract_dir;
        
        int result = system(cmd.c_str());
        if (result != 0)
        {
            logging::error("Failed to extract checkpoint: " + tar_path);
            return false;
        }
        
        logging::print("Checkpoint extracted successfully:", version);
        return true;
    }
}

// Get checkpoint info from a remote validator
grpc::Status ValidatorNetworkClient::GetCheckpointInfo(
    const zera_validator::CheckpointInfoRequest* request,
    zera_validator::CheckpointInfo* response)
{
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(30));
    
    return stub_->GetCheckpointInfo(&context, *request, response);
}

// Stream checkpoint from a remote validator
grpc::Status ValidatorNetworkClient::StreamCheckpoint(
    const zera_validator::CheckpointRequest* request,
    const std::string& output_path)
{
    grpc::ClientContext context;
    // Set a longer deadline for large file transfers (1 hour)
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::hours(1));
    
    std::unique_ptr<grpc::ClientReader<zera_validator::CheckpointChunk>> reader = 
        stub_->StreamCheckpoint(&context, *request);
    
    if (!reader)
    {
        logging::error("Failed to create checkpoint stream reader");
        return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to create reader");
    }
    
    // Open output file
    std::ofstream file(output_path, std::ios::binary | std::ios::trunc);
    if (!file.is_open())
    {
        logging::error("Failed to open output file: " + output_path);
        return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to open output file");
    }
    
    zera_validator::CheckpointChunk chunk;
    uint64_t bytes_received = 0;
    uint64_t total_size = 0;
    uint64_t chunks_received = 0;
    
    while (reader->Read(&chunk))
    {
        if (total_size == 0)
        {
            total_size = chunk.total_size();
            logging::print("Starting checkpoint download, total size:", std::to_string(total_size));
        }
        
        // Verify offset matches expected position
        if (chunk.offset() != bytes_received)
        {
            logging::error("Chunk offset mismatch: expected " + std::to_string(bytes_received) + 
                          " got " + std::to_string(chunk.offset()));
            file.close();
            std::filesystem::remove(output_path);
            return grpc::Status(grpc::StatusCode::DATA_LOSS, "Chunk offset mismatch");
        }
        
        // Write chunk data
        file.write(chunk.data().data(), chunk.data().size());
        bytes_received += chunk.data().size();
        chunks_received++;
        
        // Log progress every 100 chunks (~100MB)
        if (chunks_received % 100 == 0)
        {
            float progress = (float)bytes_received / total_size * 100;
            logging::print("Checkpoint download progress:", std::to_string((int)progress) + "%");
        }
        
        if (chunk.is_last())
        {
            break;
        }
    }
    
    file.close();
    
    grpc::Status status = reader->Finish();
    
    if (!status.ok())
    {
        logging::error("Checkpoint stream failed: " + status.error_message());
        std::filesystem::remove(output_path);
        return status;
    }
    
    // Verify we received all bytes
    if (bytes_received != total_size)
    {
        logging::error("Incomplete download: received " + std::to_string(bytes_received) + 
                      " of " + std::to_string(total_size) + " bytes");
        std::filesystem::remove(output_path);
        return grpc::Status(grpc::StatusCode::DATA_LOSS, "Incomplete download");
    }
    
    logging::print("Checkpoint download completed:", std::to_string(bytes_received), "bytes in", 
                   std::to_string(chunks_received), "chunks");
    return grpc::Status::OK;
}

// Main function to sync from checkpoint
bool ValidatorNetworkClient::SyncFromCheckpoint()
{
    logging::print("Starting checkpoint sync...");
    
    std::vector<zera_txn::Validator> validators;
    db_validators_tag::get_all_validators(validators);
    
    // Try seed validators first, then regular validators
    std::vector<std::string> hosts_to_try;
    
    // Add seed validators
    for (const auto& seed : ValidatorConfig::get_seed_validators())
    {
        hosts_to_try.push_back(seed);
    }
    
    // Add regular validators
    for (const auto& validator : validators)
    {
        if (validator.public_key().single() != ValidatorConfig::get_public_key())
        {
            hosts_to_try.push_back(validator.host() + ":" + validator.validator_port());
        }
    }
    
    if (hosts_to_try.empty())
    {
        logging::print("No validators available for checkpoint sync");
        return false;
    }
    
    // Randomize order
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(hosts_to_try.begin(), hosts_to_try.end(), gen);
    
    for (const auto& host : hosts_to_try)
    {
        logging::print("Trying checkpoint sync from:", host);
        
        std::shared_ptr<grpc::Channel> channel = 
            grpc::CreateChannel(host, grpc::InsecureChannelCredentials());
        ValidatorNetworkClient client(channel);
        
        // Get checkpoint info
        zera_validator::CheckpointInfoRequest info_request;
        zera_validator::CheckpointInfo info_response;
        set_checkpoint_info_request(&info_request);
        
        grpc::Status status = client.GetCheckpointInfo(&info_request, &info_response);
        
        if (!status.ok())
        {
            logging::print("Failed to get checkpoint info from", host, ":", status.error_message());
            continue;
        }
        
        logging::print("Checkpoint available:" + info_response.version(), 
                       "block height:" + std::to_string(info_response.block_height()),
                       "size:" + std::to_string(info_response.total_size()));


        std::string block_key;
        std::string block_header_data;
        zera_validator::BlockHeader block_header;
        if(db_hash_index::get_single(std::to_string(info_response.block_height()), block_key) && db_headers::get_single(block_key, block_header_data) && block_header.ParseFromString(block_header_data))
        {
            if(block_header.hash() == info_response.block_hash())
            {
                logging::print("Local blockchain is already at or beyond checkpoint block height:", std::to_string(info_response.block_height()));
                return true;
            }
        }
        
        // Create checkpoints directory if it doesn't exist
        std::filesystem::create_directories(DB_CHECKPOINTS);
        
        // Download checkpoint
        std::string tar_path = DB_CHECKPOINTS + info_response.version() + ".tar.gz";
        
        zera_validator::CheckpointRequest checkpoint_request;
        set_checkpoint_request(&checkpoint_request, info_response.version());
        
        status = client.StreamCheckpoint(&checkpoint_request, tar_path);
        
        if (!status.ok())
        {
            logging::error("Failed to download checkpoint from " + host + ": " + status.error_message());
            continue;
        }
        
        // Verify file size
        if (std::filesystem::file_size(tar_path) != info_response.total_size())
        {
            logging::error("Downloaded file size mismatch");
            std::filesystem::remove(tar_path);
            continue;
        }
        
        // Extract checkpoint
        if (!extract_checkpoint(tar_path, info_response.version()))
        {
            continue;
        }
        
        // Restore databases from checkpoint
        logging::print("Restoring databases from checkpoint...");
        Reorg::restore_database(info_response.version(), 2);
        logging::print("Checkpoint sync completed successfully from:", host);
        return true;
    }
    
    logging::error("Failed to sync from checkpoint from any validator");
    return false;
}
