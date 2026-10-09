// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"
#include "validator_network_service_grpc.h"

// Project-specific headers (from the current directory)
#include "db_base.h"
#include "block.h"
#include "signatures.h"
#include "test.h"
#include "validators.h"
#include "const.h"

namespace
{

    void remove_block_batch(zera_validator::BlockBatch *block_batch)
    {

        rocksdb::WriteBatch remove_block_batch;
        rocksdb::WriteBatch remove_header_batch;
        rocksdb::WriteBatch remove_hash_batch;

        std::string key;
        std::string hash;
        for (auto block : block_batch->blocks())
        {
            hash = block.block_header().hash();

            std::ostringstream oss;
            oss << std::setw(20) << std::setfill('0') << block.block_header().block_height();
            std::string paddedHeight = oss.str();
            key = paddedHeight + ":" + hash;

            remove_block_batch.Delete(key);
            remove_header_batch.Delete(key);
            remove_hash_batch.Delete(hash);
        }

        db_blocks::store_batch(remove_block_batch);
        db_headers::store_batch(remove_header_batch);
        db_hash_index::store_batch(remove_hash_batch);
    }

    int write_block_batch(zera_validator::BlockBatch *batch, rocksdb::WriteBatch &wallet_batch)
    {
        rocksdb::WriteBatch block_batch;
        rocksdb::WriteBatch header_batch;
        rocksdb::WriteBatch hash_index_batch;
        block_utils::block_batch_to_write_batch(batch, block_batch, header_batch, hash_index_batch);

        if (!db_blocks::store_batch(block_batch) || !db_headers::store_batch(header_batch) ||
            !db_hash_index::store_batch(hash_index_batch) || !db_wallets::store_batch(wallet_batch))
        {

            remove_block_batch(batch);
            return 0;
        }

        return 1;
    }

    void set_block_batch(std::vector<zera_validator::Block> *blocks, std::vector<zera_validator::BlockHeader> *block_headers, zera_validator::BlockBatch &block_batch)
    {
        for (int x = 0; x < blocks->size(); x++)
        {
            auto block_header = blocks->at(x).mutable_block_header();
            block_header->CopyFrom(block_headers->at(x));
            auto tmp_block = blocks->at(x);
            block_batch.add_blocks()->CopyFrom(tmp_block);
        }
    }

}

grpc::Status ValidatorServiceImpl::SyncBlockchain(grpc::ServerContext *context, const BlockSync *request, grpc::ServerWriter<zera_validator::DataChunk>* writer)
{
    // Require a validly signed request before doing any work. This does not prove
    // the caller is a registered validator (fresh validators sync before they are
    // known network-wide), but it forces every caller to construct and sign a
    // well-formed request instead of accepting anonymous ones.
    BlockSync request_copy;
    request_copy.CopyFrom(*request);
    if (!signatures::verify_request(request_copy))
    {
        logging::print("SyncBlockchain: rejected request with invalid signature", false);
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid block sync request signature");
    }

    std::string last_key = request->last_key();
    int amount = request->amount();

    // The legitimate client pages in batches of exactly BLOCK_SYNC blocks, so any
    // other amount is a malformed or malicious request trying to force unbounded
    // RocksDB reads, response construction, and outbound bandwidth (CWE-400).
    // if (amount <= 0 || amount > BLOCK_SYNC)
    // {
    //     logging::print("SyncBlockchain: rejected request with out-of-range amount: " + std::to_string(amount), false);
    //     return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "block sync amount out of range");
    // }

    if (amount <= 0)
    {
        logging::print("SyncBlockchain: rejected request with out-of-range amount: " + std::to_string(amount), false);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "block sync amount out of range");
    }
    zera_validator::BlockBatch response;
    std::vector<zera_validator::DataChunk> chunks;
    std::vector<zera_validator::Block> blocks;
    std::vector<zera_validator::BlockHeader> headers;

    std::string key = "";

    db_hash_index::get_single(last_key, key);

    db_blocks_tag::get_multi_data(key, amount, blocks);
    db_headers_tag::get_multi_data(key, amount, headers);

    response.set_last_block(amount != blocks.size());

    logging::print("Block Sync: Block Size:",  std::to_string(blocks.size()));
    
    if (blocks.size() > 0)
    {
        set_block_batch(&blocks, &headers, response);
    }

    response.mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());

    signatures::sign_request(&response, ValidatorConfig::get_gen_key_pair());

    chunkData(response.SerializeAsString(), &chunks);

    for(const auto& chunk : chunks){
        writer->Write(chunk);
    }
    return grpc::Status::OK;
}