#include "validator_api_service.h"

#include "db_base.h"

grpc::Status APIImpl::RecieveRequestBlock(grpc::ServerContext *context, const zera_api::BlockRequest *request, zera_api::BlockResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    std::string hash_index_key;

    switch (request->payload_case())
    {
        case zera_api::BlockRequest::kBlockHeight:
        {
            google::protobuf::uint64 block_height = request->block_height();
            hash_index_key = std::to_string(block_height);
            break;
        }
        case zera_api::BlockRequest::kBlockHash:
        {
            std::string block_hash = request->block_hash();
            if (request->encoded())
            {
                std::vector<uint8_t> encoded_vec(block_hash.begin(), block_hash.end());
                auto key_vec = base58_decode(encoded_vec);
                hash_index_key = std::string(key_vec.begin(), key_vec.end());
            }
            else
            {
                hash_index_key = block_hash;
            }
            break;
        }
        case zera_api::BlockRequest::PAYLOAD_NOT_SET:
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "No payload provided");
        default:
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid payload type");
    }

    std::string block_key;
    if (!db_hash_index::get_single(hash_index_key, block_key))
    {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Block not found");
    }

    std::string block_data;
    std::string header_data;
    db_blocks::get_single(block_key, block_data);
    db_headers::get_single(block_key, header_data);

    zera_validator::Block block;
    block.ParseFromString(block_data);
    block.mutable_block_header()->ParseFromString(header_data);
    response->mutable_block()->CopyFrom(block);

    return grpc::Status::OK;
}
