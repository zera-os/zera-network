#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>

#include "validator.pb.h"
#include "validator_network_service_grpc.h"

#include "db_base.h"
#include "signatures.h"
#include "validators.h"
#include "../../../logging/logging.h"

namespace
{
    constexpr size_t CHECKPOINT_CHUNK_SIZE = 1024 * 1024; // 1MB chunks

    // Verify the request timestamp is within acceptable range (prevent replay attacks)
    bool verify_timestamp(const google::protobuf::Timestamp& timestamp)
    {
        auto now = std::chrono::system_clock::now();
        auto request_time = std::chrono::system_clock::from_time_t(timestamp.seconds());
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - request_time).count();
        
        // Allow 5 minute window for clock drift
        return std::abs(diff) < 300;
    }

}

grpc::Status ValidatorServiceImpl::GetCheckpointInfo(
    grpc::ServerContext* context,
    const zera_validator::CheckpointInfoRequest* request,
    zera_validator::CheckpointInfo* response)
{
    // Verify timestamp to prevent replay attacks
    if (!verify_timestamp(request->timestamp()))
    {
        logging::print("Checkpoint info request rejected: timestamp out of range");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Request timestamp out of range");
    }


    if (!signatures::verify_checkpoint_info_request(*request))
    {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid signature");
    }

    std::string checkpoint_info_key = CHECKPOINT_INFO + "latest";
    std::string checkpoint_data;
    if(!db_system::get_single(checkpoint_info_key, checkpoint_data))
    {
        logging::print("No checkpoint info found in database");
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "No checkpoint info found");
    }


    if(!response->ParseFromString(checkpoint_data))
    {
        logging::error("Failed to parse checkpoint info from database");
        return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to parse checkpoint info");
    }
     
    logging::print("Checkpoint info sent:", response->version(), "size:", std::to_string(response->total_size()));
    return grpc::Status::OK;
}

grpc::Status ValidatorServiceImpl::StreamCheckpoint(
    grpc::ServerContext* context,
    const zera_validator::CheckpointRequest* request,
    grpc::ServerWriter<zera_validator::CheckpointChunk>* writer)
{
    // Verify timestamp to prevent replay attacks
    if (!verify_timestamp(request->timestamp()))
    {
        logging::print("Checkpoint request rejected: timestamp out of range");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Request timestamp out of range");
    }


    if (!signatures::verify_checkpoint_request(*request))
    {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid signature");
    }

    std::string version = request->version();
    std::string tar_path = DB_CHECKPOINTS + version + ".tar.gz";

    if (!std::filesystem::exists(tar_path))
    {
        logging::print("Checkpoint not found:", tar_path);
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Checkpoint not found: " + version);
    }

    uint64_t file_size = std::filesystem::file_size(tar_path);
    std::ifstream file(tar_path, std::ios::binary);

    if (!file.is_open())
    {
        logging::error("Failed to open checkpoint file: " + tar_path);
        return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to open checkpoint file");
    }

    logging::print("Starting checkpoint stream:", version, "size:", std::to_string(file_size));

    std::vector<char> buffer(CHECKPOINT_CHUNK_SIZE);
    uint64_t offset = 0;
    uint64_t chunks_sent = 0;

    while (file && offset < file_size)
    {
        // Check if client cancelled
        if (context->IsCancelled())
        {
            logging::print("Checkpoint stream cancelled by client");
            file.close();
            return grpc::Status::CANCELLED;
        }

        file.read(buffer.data(), CHECKPOINT_CHUNK_SIZE);
        std::streamsize bytes_read = file.gcount();

        if (bytes_read > 0)
        {
            zera_validator::CheckpointChunk chunk;
            chunk.set_data(buffer.data(), bytes_read);
            chunk.set_offset(offset);
            chunk.set_total_size(file_size);
            chunk.set_is_last(offset + bytes_read >= file_size);

            if (!writer->Write(chunk))
            {
                logging::error("Failed to write checkpoint chunk at offset: " + std::to_string(offset));
                file.close();
                return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to write chunk");
            }

            offset += bytes_read;
            chunks_sent++;

            // Log progress every 100 chunks (~100MB)
            if (chunks_sent % 100 == 0)
            {
                float progress = (float)offset / file_size * 100;
                logging::print("Checkpoint stream progress:", std::to_string((int)progress) + "%");
            }
        }
    }

    file.close();
    logging::print("Checkpoint stream completed:", version, "chunks:", std::to_string(chunks_sent));
    return grpc::Status::OK;
}
