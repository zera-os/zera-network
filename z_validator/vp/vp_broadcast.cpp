// Standard library headers
#include <vector>

// Third-party library headers
#include <rocksdb/write_batch.h>

// Project-specific headers
#include "verify_process_txn.h"
#include "validator.pb.h"
#include "txn.pb.h"
#include "signatures.h"
#include "hashing.h"
#include "db_base.h"
#include "../temp_data/temp_data.h"
#include "block.h"
#include "proposer.h"
#include "../util/validate_block.h"

namespace
{
    void get_proposers(std::vector<zera_txn::Validator>& proposers)
    {
        zera_validator::BlockHeader last_header; //get last block header
        std::string last_key;
        db_headers_tag::get_last_data(last_header, last_key);
        proposers = SelectValidatorsByWeight(last_header.hash(), last_header.block_height()); //select validators for the lottery

    }

    void remove_transactions(const zera_txn::TXNS txns)
    {
        rocksdb::WriteBatch txn_batch;

        for (auto txn : txns.mint_txns())
        {
            txn_batch.Delete(txn.base().hash());
        }
        for (auto txn : txns.contract_txns())
        {
            txn_batch.Delete(txn.base().hash());
        }
        db_transactions::store_batch(txn_batch);
    }

    void remove_block(std::string key, std::string hash, zera_validator::Block *block)
    {
        rocksdb::WriteBatch contract_batch;

        for (auto contract : block->transactions().contract_txns())
        {
            contract_batch.Delete(contract.contract_id());
        }
        db_contracts::store_batch(contract_batch);
        db_blocks::remove_single(key);
        db_headers::remove_single(key);
        db_hash_index::remove_single(hash);
    }

    ZeraStatus verify_proposer(zera_validator::Block &block)
    {

        std::vector<zera_txn::Validator> proposers;
        get_proposers(proposers);

        if(proposer_tracker::check_proposer(block.block_header().public_key()))
        {
            return ZeraStatus(ZeraStatus::Code::OK);
        }
        
        return ZeraStatus(ZeraStatus::Code::PROPOSAL_ERROR, "vp_broadcast.cpp: verify_proposer: proposer does not match");
    }

}

ZeraStatus vp_broadcast::verify_broadcast_block(const zera_validator::Block *block)
{
    zera_validator::Block block_copy;
    block_copy.CopyFrom(*block);
    ZeraStatus status = signatures::verify_block_validator(block_copy);
    if (!status.ok())
    {
        status.prepend_message("vp_broadcast.cpp: verify_broadcast_block 1");
        return status;
    }

    status = verify_proposer(block_copy);
    if (!status.ok())
    {
        status.prepend_message("vp_broadcast.cpp: verify_broadcast_block 2");
        return status;
    }

    status = ValidateBlock::process_block_from_broadcast(block_copy);

    if (!status.ok())
    {
        status.prepend_message("vp_broadcast.cpp: verify_broadcast_block 3");
        return status;
    }

    return ZeraStatus();
}