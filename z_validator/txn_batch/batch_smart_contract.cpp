#include "txn_batch.h"

#include "db_base.h"
#include "hashing.h"
#include "../logging/logging.h"
#include "base58.h"

void txn_batch::batch_smart_contract(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch contract_batch;

    for (auto txn : txns.smart_contracts())
    {
        if (txn_passed.at(txn.base().hash()))
        {
            contract_batch.Put(txn.smart_contract_name(), txn.SerializeAsString());
        }
    }

    db_smart_contracts::store_batch(contract_batch);
}

void txn_batch::batch_instantiate(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch contract_batch;

    for (auto txn : txns.smart_contract_instantiate_txns())
    {
        if (txn_passed.at(txn.base().hash()))
        {
            const std::string instance_string = std::to_string(txn.instance());
            std::string instance_name = txn.smart_contract_name() + "_" + instance_string;

            std::string raw_data;
            db_smart_contracts::get_single(txn.smart_contract_name(), raw_data);
            contract_batch.Put(instance_name, raw_data);

        }
    }
    db_smart_contracts::store_batch(contract_batch);
}
