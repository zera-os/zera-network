// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"

// Project-specific headers
#include "validator_network_client.h"
#include "db_base.h"
// #include "db_blocks.h"
// #include "db_headers.h"
// #include "db_wallets.h"
// #include "db_hash_index.h"
// #include "db_contracts.h"
#include "block.h"
#include "signatures.h"
#include "test.h"
#include "const.h"
#include "validators.h"
#include "base58.h"
#include "proposer.h"
#include "../../../crypto/merkle.h"
#include "../../../util/validate_block.h"
#include "../../../logging/logging.h"

namespace
{

    ZeraStatus compare_blocks(zera_validator::Block *block, const zera_validator::BlockHeader &original_header)
    {
        std::string block_write;
        std::string header_write;
        std::string key1 = block_utils::block_to_write(block, block_write, header_write);

        auto key_vec = Hashing::sha256_hash(key1);
        if (db_blocks::exist(key1))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "proposer.h: make_block: Block already exists.");
        }
        std::vector<uint8_t> hash(block->block_header().hash().begin(), block->block_header().hash().end());
        std::vector<uint8_t> hash2(original_header.hash().begin(), original_header.hash().end());

        if (!Hashing::compare_hash(hash, hash2))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "proposer.h: make_block: Block hash does not match.");
        }

        db_blocks::store_single(key1, block_write);
        db_headers::store_single(key1, header_write);
        db_hash_index::store_single(block->block_header().hash(), key1);
        db_hash_index::store_single(std::to_string(block->block_header().block_height()), key1);

        return ZeraStatus(ZeraStatus::Code::OK);
    }

    // Will need to have balances of every effected wallet from entire batch
    // incase of a failed block_batch... for now we are storing every individual blocks which is slower, but simplier...
    ZeraStatus BlockSyncProcessResponse(const BlockBatch *block_batch)
    {

        if (block_batch->blocks().size() > 0)
        {
            BlockBatch batch;
            batch.CopyFrom(*block_batch);

            ZeraStatus status = signatures::verify_block_batch(batch);
            if (!status.ok())
            {
                status.prepend_message("block_sync_client: BlockSyncProcessResponse");
                return status;
            }
            logging::print("Block batch size: " + std::to_string(block_batch->blocks().size()), true);
            for (auto block : block_batch->blocks())
            {
                logging::print("Processing block with height: " + std::to_string(block.block_header().block_height()), true);
                status = ValidateBlock::process_block_from_sync(block);
                if (!status.ok())
                {
                    if(status.code() == ZeraStatus::Code::BLOCKCHAIN_DUPLICATE_ERROR)
                    {
                        continue;
                    }
                    status.prepend_message("block_sync_client: BlockSyncProcessResponse");
                    return status;
                }
            }
        }
        return ZeraStatus(ZeraStatus::Code::OK);
    }
    void set_block_sync(BlockSync *block_sync)
    {
        block_sync->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
        signatures::sign_request(block_sync, ValidatorConfig::get_key_pair());
    }
    ZeraStatus unchunk_batch(std::vector<zera_validator::DataChunk> *responses, zera_validator::BlockBatch &batch)
    {

        if (responses->size() <= 0)
        {
            logging::print("No chunks received.");
            return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "No chunks received.");
        }

        // Step 1: Sort the chunks based on chunk_number
        std::sort(responses->begin(), responses->end(),
                  [](const zera_validator::DataChunk &a, const zera_validator::DataChunk &b)
                  {
                      return a.chunk_number() < b.chunk_number();
                  });

        // Step 2: Concatenate the chunk_data
        std::string concatenated_data;
        for (const auto &chunk : *responses)
        {
            concatenated_data += chunk.chunk_data();
        }

        // Step 3: Deserialize into BlockBatch
        if (!batch.ParseFromString(concatenated_data))
        {

            // Handle the error, if the data cannot be parsed
            return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "Failed to parse BlockBatch from concatenated chunks.");
        }

        return ZeraStatus();
    }
}

grpc::Status ValidatorNetworkClient::SyncBlockchain(const BlockSync *request, std::vector<zera_validator::DataChunk> *responses)
{
    grpc::ClientContext context;
    // Create a reader for the server-side streaming RPC
    std::unique_ptr<grpc::ClientReader<zera_validator::DataChunk>> reader = stub_->SyncBlockchain(&context, *request);

    if (reader == nullptr)
    {
        std::cerr << "Reader is not initialized." << std::endl;
        return grpc::Status::CANCELLED; // or handle error appropriately
    }
    zera_validator::DataChunk batch;
    while (reader->Read(&batch))
    {
        // Storing each received batch into the responses vector
        try
        {
            responses->push_back(batch);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception caught while pushing back into responses: " << e.what() << std::endl;
            return grpc::Status::CANCELLED; // Handle error appropriately
        }
    }

    grpc::Status status = reader->Finish();

    if (!status.ok())
    {
        // There was an error in the RPC
        std::cerr << "gRPC Error (" << status.error_code() << "): " << status.error_message() << std::endl;
    }

    return status;
}

bool ValidatorNetworkClient::StartSyncBlockchain(bool seed_sync)
{

    logging::print("ValidatorNetworkClient::StartSyncBlockchain!!!");
    bool final_block = false;
    std::string last_key = "";
    zera_validator::BlockHeader last_header;
    std::vector<zera_txn::Validator> validators;
    db_validators_tag::get_all_validators(validators);

    std::random_device rd;
    std::mt19937 gen(rd());
    
    int n = static_cast<int>(ValidatorConfig::get_seed_validators().size());
    int i = static_cast<int>(validators.size());

    if (validators.size() == 1 && validators[0].public_key().single() == ValidatorConfig::get_public_key())
    {
        logging::print("only myself as validator.");
        return true;
    }
    int failed_attempts = 0;

    while (!final_block && failed_attempts < 5)
    {
        std::string host;
        if (seed_sync)
        {
            std::uniform_int_distribution<> dis(0, n - 1);
            int randomIndex = dis(gen);
            host = ValidatorConfig::get_seed_validators()[randomIndex];
        }
        else
        {
            zera_txn::Validator validator;
            validator.mutable_public_key()->set_single(ValidatorConfig::get_public_key());

            while (validator.public_key().single() == ValidatorConfig::get_public_key())
            {
                std::uniform_int_distribution<> dis(0, i - 1);
                int randomIndex = dis(gen);
                validator.CopyFrom(validators.at(randomIndex));
            }

            host = validator.host() + ":" + validator.validator_port();
        }

        std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(host, grpc::InsecureChannelCredentials());

        ValidatorNetworkClient client(channel);
        db_headers_tag::get_last_data(last_header, last_key);
        std::vector<zera_validator::Block> blocks;
        db_blocks_tag::get_all_blocks(blocks);
        grpc::Status status;
        BlockBatch response;
        BlockSync request;
        std::vector<zera_validator::DataChunk> *responses = new std::vector<zera_validator::DataChunk>();

        request.set_last_key(last_header.hash());
        request.set_amount(BLOCK_SYNC);
        set_block_sync(&request);
        status = client.SyncBlockchain(&request, responses);
        ZeraStatus z_status = unchunk_batch(responses, response);
        if (!z_status.ok())
        {
            logging::print(z_status.read_status());
            final_block = false;
            failed_attempts++;
        }

        final_block = response.last_block();

        if (status.ok())
        {
            if(response.blocks().size() > 0)
            {
                logging::print("Received: " + std::to_string(response.blocks().size()), "blocks from:", host, "Block Height: " +  std::to_string(response.blocks(response.blocks().size() - 1).block_header().block_height()), false);
            }

            z_status = BlockSyncProcessResponse(&response);

            if (!z_status.ok())
            {
                final_block = false;
                failed_attempts++;
                logging::print("failed attempt #", std::to_string(failed_attempts), "\n", z_status.read_status(), false);
            }
        }
        else
        {
            final_block = false;
            // Handle the error
            logging::print(status.error_message());
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            failed_attempts++;
            logging::print("failed attempt #", std::to_string(failed_attempts), false);
        }
        delete responses;
    }

    if(failed_attempts >= 4)
    {
        logging::print("Failed to sync blockchain after 4 attempts.", false);
        return false;
    }

    return true;
}
