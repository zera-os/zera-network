#ifndef _VP_TXN_H_
#define _VP_TXN_H_

// Standard library headers
#include <chrono>
#include <thread>
#include <type_traits>

// Third-party library headers
#include <rocksdb/write_batch.h>
#include <chrono>

// Project-specific headers
#include "base58.h"
#include "const.h"
#include "db_base.h"
// #include "db_transactions.h"
#include "hashing.h"
#include "signatures.h"
#include "txn.pb.h"
#include "validator.pb.h"
#include "zera_status.h"
#include "base58.h"
#include "utils.h"
#include "../logging/logging.h"

namespace
{
    bool check_timestamp(int64_t txn_timestamp_in_seconds)
    {
        // Get the current timestamp
        auto now = std::chrono::system_clock::now();
        auto now_in_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        // Check if the transaction timestamp is within 2 minutes of the current time
        return (txn_timestamp_in_seconds - now_in_seconds <= 120);
    }

    template <typename TXType>
    void get_txn_nonce(TXType *txn, uint64_t &nonce)
    {
        nonce = txn->base().nonce();
    }

    template <>
    void get_txn_nonce<zera_txn::CoinTXN>(zera_txn::CoinTXN *txn, uint64_t &nonce)
    {
        for (auto input_nonce : txn->auth().nonce())
        {
            nonce += input_nonce;
        }
    }

}
class verify_txns
{
public:
    template <typename TXType>
    static ZeraStatus verify_txn(const TXType *txn)
    {
        TXType txn_copy;
        txn_copy.CopyFrom(*txn);
        
        if (!txn->base().has_hash() ||
            !txn->base().has_timestamp())
        {
            return ZeraStatus(ZeraStatus::Code::PARAMETER_ERROR, "verify_process.h: verify_txn: txn does not have required parameters. Hash or Timestamp.");
        }

        if(txn->base().public_key().has_smart_contract_auth() || txn->base().public_key().has_governance_auth())
        {
            return ZeraStatus(ZeraStatus::Code::PARAMETER_ERROR, "verify_process.h: verify_txn: txn has smart_contract_auth or governance_auth. These are not allowed in regular txns.");
        }
        std::string txn_hash = txn->base().hash();
        uint64_t txn_nonce = 0;

        get_txn_nonce(&txn_copy, txn_nonce);
        std::string txn_key = get_txn_key(txn_nonce, txn_hash);

        if (db_transactions::exist(txn_key) || db_processed_txns::exist(txn_key) || db_block_txns::exist(txn_hash))
        {
            return ZeraStatus(ZeraStatus::Code::DUPLICATE_TXN_ERROR, "verify_process.h: verify_txn: TXN is already queued for block.");
        }

        ZeraStatus status = verify_identity(&txn_copy);

        if (!status.ok())
        {
            return status;
        }

        return ZeraStatus(ZeraStatus::Code::OK);
    }


    template <typename TXType>
    static void store_wrapper(const TXType *txn, zera_txn::TXNWrapper &wrapper);

    template <typename TXType>
    static ZeraStatus store_txn(const TXType *txn, zera_txn::TRANSACTION_TYPE &txn_type)
    {
        zera_txn::TXNWrapper wrapper;
        store_wrapper(txn, wrapper);
        txn_type = wrapper.txn_type();

        return ZeraStatus(ZeraStatus::Code::OK);
    }

private:
    template <typename TXType>
    static ZeraStatus verify_identity(TXType *txn);
};

namespace vp_contract
{
    ZeraStatus verify_contract(const zera_txn::InstrumentContract *txn);
    void process_contract(const zera_txn::InstrumentContract &txn, rocksdb::WriteBatch *wallet_batch);
    ZeraStatus store_txn(const zera_txn::InstrumentContract *txn);
}

namespace vp_broadcast
{
    ZeraStatus verify_broadcast_block(const zera_validator::Block *block);
    int write_block(zera_validator::Block *block, rocksdb::WriteBatch &wallet_batch);
}


#endif