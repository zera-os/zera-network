// Standard library headers
#include <iomanip>

// Third-party library headers
#include <boost/lexical_cast.hpp>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

// Project-specific headers
#include "block.h"
#include "hashing.h"
#include "db_base.h"
#include "wallets.h"
#include "const.h"
#include "test.h"
#include "validators.h"
#include "zera_status.h"

namespace
{
    std::string get_block_key(uint64_t height, std::string hash)
    {
        std::ostringstream oss;
        oss << std::setw(20) << std::setfill('0') << height;
        std::string paddedHeight = oss.str();
        return paddedHeight + ":" + hash;
    }
}
void block_utils::set_block(zera_validator::Block *block)
{
    zera_validator::BlockHeader previous_block_header;
    std::string previous_block_header_key;

    db_headers_tag::get_last_data(previous_block_header, previous_block_header_key);
    zera_validator::BlockHeader *block_header = block->mutable_block_header();

    int height = 0;

    height = previous_block_header.block_height() + 1;

    block_header->set_previous_block_hash(previous_block_header.hash());
    block_header->set_version(ValidatorConfig::get_version());
    block_header->set_block_height(height);
    block_header->set_fee_address(ValidatorConfig::get_fee_address_string());
    signatures::sign_block_proposer(block, ValidatorConfig::get_gen_key_pair());
    hash_block(block);
}

void block_utils::set_block_sync(zera_validator::Block *block, const zera_validator::BlockHeader &original_header)
{
    zera_validator::BlockHeader previous_block_header;
    std::string previous_block_header_key;

    db_headers_tag::get_last_data(previous_block_header, previous_block_header_key);
    zera_validator::BlockHeader *block_header = block->mutable_block_header();

    int height = 0;

    height = previous_block_header.block_height() + 1;

    block_header->set_previous_block_hash(previous_block_header.hash());
    block_header->set_version(original_header.version());
    block_header->mutable_timestamp()->CopyFrom(original_header.timestamp());

    block_header->set_block_height(height);
    block_header->set_fee_address(original_header.fee_address());
    block_header->set_signature(original_header.signature());
    block_header->mutable_public_key()->CopyFrom(original_header.public_key());

    hash_block(block);
}


void block_utils::hash_block(zera_validator::Block *block)
{
    zera_validator::BlockHeader *block_header = block->mutable_block_header();
    std::string hash;
    std::vector<uint8_t> serialized_block;
    serialized_block.resize(block->ByteSizeLong());
    block->SerializeToArray(serialized_block.data(), serialized_block.size());
    std::vector<uint8_t> hash_vec = Hashing::sha256_hash(serialized_block);
    hash = std::string(hash_vec.begin(), hash_vec.end());
    block_header->set_hash(hash);
}

std::string block_utils::block_batch_to_write_batch(zera_validator::BlockBatch *block_batch, rocksdb::WriteBatch &write_block_batch, rocksdb::WriteBatch &write_header_batch, rocksdb::WriteBatch &hash_index_batch)
{
    std::string key;
    for (auto block : block_batch->blocks())
    {

        zera_validator::Block block_copy;
        block_copy.CopyFrom(block);
        zera_validator::BlockHeader *header = block_copy.release_block_header();
        

        key = get_block_key(header->block_height(), header->hash());

        write_block_batch.Put(key, block_copy.SerializeAsString());
        write_header_batch.Put(key, header->SerializeAsString());
        hash_index_batch.Put(header->hash(), key);
    }
    return key;
}

std::string block_utils::block_to_write(zera_validator::Block *block, std::string &write_block, std::string &write_header)
{

    zera_validator::Block block_copy;
    block_copy.CopyFrom(*block);

    zera_validator::BlockHeader *header = block_copy.release_block_header();

    std::string key = get_block_key(header->block_height(), header->hash());

    write_block = block_copy.SerializeAsString();
    write_header = header->SerializeAsString();

    return key;
}


bool block_utils::check_block(zera_validator::Block &block)
{
    if (!block.has_block_header() || !block.has_signature())
        return false;

    return true;
}
