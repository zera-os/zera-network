#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <atomic>

#include "validator.pb.h"
#include "validator_network_service_grpc.h"

#include "db_base.h"
#include "signatures.h"
#include "validators.h"
#include "../../../logging/logging.h"

namespace
{
    constexpr size_t CHECKPOINT_CHUNK_SIZE = 1024 * 1024; // 1MB chunks

    // Checkpoint streams are large (multi-GB) and unauthenticated by design (new
    // validators bootstrapping are not in the validator set yet), so bound the I/O
    // and bandwidth a group of clients can consume at once.
    constexpr int MAX_CONCURRENT_CHECKPOINT_STREAMS = 3;
    std::atomic<int> active_checkpoint_streams{0};

    // RAII slot so every return path releases the stream slot.
    struct CheckpointStreamSlot
    {
        bool acquired = false;
        CheckpointStreamSlot()
        {
            if (active_checkpoint_streams.fetch_add(1) < MAX_CONCURRENT_CHECKPOINT_STREAMS)
            {
                acquired = true;
            }
            else
            {
                active_checkpoint_streams.fetch_sub(1);
            }
        }
        ~CheckpointStreamSlot()
        {
            if (acquired)
            {
                active_checkpoint_streams.fetch_sub(1);
            }
        }
    };

    // Verify the request timestamp is within acceptable range (prevent replay attacks)
    bool verify_timestamp(const google::protobuf::Timestamp& timestamp)
    {
        auto now = std::chrono::system_clock::now();
        auto request_time = std::chrono::system_clock::from_time_t(timestamp.seconds());
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - request_time).count();
        
        // Allow 5 minute window for clock drift
        return std::abs(diff) < 300;
    }

    // Checkpoint versions are always the numeric required-version (e.g. "100006").
    // Rejecting anything else kills path traversal via the version string.
    bool valid_version_format(const std::string& version)
    {
        if (version.empty() || version.size() > 20)
        {
            return false;
        }
        for (char c : version)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
        }
        return true;
    }

}

grpc::Status ValidatorServiceImpl::GetCheckpointInfo(
    grpc::ServerContext* context,
    const zera_validator::CheckpointInfoRequest* request,
    zera_validator::CheckpointInfo* response)
{
    std::string client_ip = extract_ip_from_peer(context->peer());
    if (!rate_limiter.canProceed(client_ip))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    // Verify timestamp to prevent replay attacks
    if (!verify_timestamp(request->timestamp()))
    {
        logging::print("Checkpoint info request rejected: timestamp out of range");
        rate_limiter.processUpdate(client_ip, true);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Request timestamp out of range");
    }


    if (!signatures::verify_checkpoint_info_request(*request))
    {
        rate_limiter.processUpdate(client_ip, true);
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
    std::string client_ip = extract_ip_from_peer(context->peer());
    if (!rate_limiter.canProceed(client_ip))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    // Verify timestamp to prevent replay attacks
    if (!verify_timestamp(request->timestamp()))
    {
        logging::print("Checkpoint request rejected: timestamp out of range");
        rate_limiter.processUpdate(client_ip, true);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Request timestamp out of range");
    }


    if (!signatures::verify_checkpoint_request(*request))
    {
        rate_limiter.processUpdate(client_ip, true);
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid signature");
    }

    std::string version = request->version();

    // The version string comes straight off the wire and is used to build a file
    // path, so allowlist it hard: numeric format only, and it must correspond to a
    // CheckpointInfo record this validator itself created. This makes it impossible
    // to reach any file other than a checkpoint archive we generated (CWE-22).
    if (!valid_version_format(version))
    {
        logging::print("Checkpoint request rejected: invalid version format");
        rate_limiter.processUpdate(client_ip, true);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid checkpoint version format");
    }

    std::string known_checkpoint_data;
    if (!db_system::get_single(CHECKPOINT_INFO + version, known_checkpoint_data))
    {
        logging::print("Checkpoint request rejected: unknown version", version);
        rate_limiter.processUpdate(client_ip, true);
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Unknown checkpoint version: " + version);
    }

    // Bound simultaneous multi-GB streams so checkpoint serving can't starve the
    // validator's disk I/O and bandwidth.
    CheckpointStreamSlot slot;
    if (!slot.acquired)
    {
        logging::print("Checkpoint request rejected: too many concurrent streams");
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Too many concurrent checkpoint streams, retry later");
    }

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
    rate_limiter.processUpdate(client_ip, false);
    return grpc::Status::OK;
}
