#pragma once
#include "txn.pb.h"
#include "zera_status.h"
#include "validator.pb.h"

class gov_process{
    public:
    static ZeraStatus process_ledgers(zera_txn::TXNS* txns, zera_txn::TXNWrapper& wrapper, const std::string& fee_address = "");
    static void process_fast_quorum(zera_txn::TXNS *txns, const std::string& fee_address = "");
    static void process_fast_quorum_block_sync(zera_txn::TXNS *txns, const zera_validator::Block *original_block);
    static bool check_ledgers(const zera_validator::Block *block);
};

class gov_txn
{

};