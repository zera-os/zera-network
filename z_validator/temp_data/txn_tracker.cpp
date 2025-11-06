#include "temp_data.h"
#include "db_base.h"
#include "../governance/time_calc.h"

void txn_tracker::add_txn(const std::string& txn_id, google::protobuf::Timestamp& timestamp)
{
    std::string txn_key;

    time_calc::get_txn_duplicate_keys(timestamp, txn_key);

    zera_validator::TXNTracker txn_tracker;
    std::string txn_data;
    if(db_duplicate_txn::get_single(txn_key, txn_data))
    {
        txn_tracker.ParseFromString(txn_data);
    }

    txn_tracker.add_txn_ids(txn_id);

    db_duplicate_txn::store_single(txn_key, txn_tracker.SerializeAsString());
}

void txn_tracker::update_txn_ledger()
{
    std::string key = time_calc::get_key_hour();
    
    zera_validator::TXNTracker txn_tracker;
    std::string txn_data;

    if(db_duplicate_txn::get_single(key, txn_data))
    {
        txn_tracker.ParseFromString(txn_data);
    }
    else
    {
        return;
    }
    rocksdb::WriteBatch txn_remove_batch;

    for(auto txn : txn_tracker.txn_ids())
    {
        txn_remove_batch.Delete(txn);
    }

    db_block_txns::store_batch(txn_remove_batch);
    db_duplicate_txn::remove_single(key);
}