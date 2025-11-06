#pragma once

#include <google/protobuf/timestamp.pb.h>

#include "zera_status.h"
#include "txn.pb.h"
#include "validator.pb.h"


class restricted_keys_check
{
public:
    static void check_quash_ledger(const zera_validator::Block* block);

    template <typename TXType>
    static void make_quash_ledger(uint32_t time_delay, const TXType *txn);

    template <typename TXType>
    static void store_timed_txn(const TXType *txn);

    static bool get_timed_txns(std::vector<std::string>& keys, std::vector<std::string>& values);

    template <typename TXType>
    static ZeraStatus check_restricted_keys(const TXType *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed = false);

    template <typename TXType>
    static ZeraStatus check_restricted_keys(const TXType *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, zera_txn::RestrictedKey& restricted_key, uint32_t& key_weight);
};