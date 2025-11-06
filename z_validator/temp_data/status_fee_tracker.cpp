#include "temp_data.h"
#include "base58.h"
#include "../logging/logging.h"
#include "db_base.h"


void status_fee_tracker::add_fee(const zera_txn::TXNStatusFees &status_fee)
{
    db_status_fee::store_single(status_fee.txn_hash(), status_fee.SerializeAsString());
}

bool status_fee_tracker::get_status(zera_txn::TXNStatusFees &status_fee, const std::string &key)
{

    std::string data;
    if (db_status_fee::get_single(key, data))
    {
        status_fee.ParseFromString(data);
        db_status_fee::remove_single(key);
        return true;
    }

    return false; // Key not found
}
