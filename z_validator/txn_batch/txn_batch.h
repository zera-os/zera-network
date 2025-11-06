#pragma once

#include <rocksdb/write_batch.h>

#include "txn.pb.h"
#include "zera_status.h"
#include "validator.pb.h"


class txn_batch{
    public:
    static void batch_item_mint(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_nft_transfer(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_proposals(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const uint64_t &block_time);
    static void batch_votes(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_contracts(const zera_txn::TXNS &txns, const std::map<std::string, bool> txn_passed);
    static void batch_contract_updates(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_proposal_results(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_delegated_voting(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_quash(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_compliance(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_revoke(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_validator_heartbeat(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const uint64_t& block_height);
    static void batch_validator_registration(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const zera_validator::BlockHeader &header);
    static void batch_required_version(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_smart_contract(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_instantiate(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed);
    static void batch_allowance_txns(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const uint64_t &block_time);


    // determine which transactions passed in block for storing data
    static void find_passed(std::map<std::string, bool> &txn_passed, const zera_txn::TXNS &txns)
    {
        for (auto status : txns.txn_fees_and_status())
        {
            if (status.status() == zera_txn::TXN_STATUS::OK)
            {
                txn_passed[status.txn_hash()] = true;
            }
            else
            {
                txn_passed[status.txn_hash()] = false;
            }
        }
    }
};