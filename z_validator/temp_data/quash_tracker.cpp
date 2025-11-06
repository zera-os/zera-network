#include "temp_data.h"
#include "db_base.h"

std::vector<std::string> quash_tracker::quash_list;
std::map<std::string, std::vector<zera_txn::PublicKey>> quash_tracker::quash_keys;
std::mutex quash_tracker::mtx;

void quash_tracker::add_quash(const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (std::find(quash_list.begin(), quash_list.end(), txn_hash) != quash_list.end())
    {
        return;
    }
    quash_list.push_back(txn_hash);
}

void quash_tracker::add_quash_keys(const std::string &txn_hash, const zera_txn::PublicKey &public_key)
{
    std::lock_guard<std::mutex> lock(mtx);
    quash_keys[txn_hash].push_back(public_key);
}

void quash_tracker::quash_result(zera_txn::TXNS *txns)
{
    if (!quash_keys.empty())
    {
        for (auto &quash_item : quash_keys)
        {
            zera_validator::QuashLookup quash_lookup;
            std::string quash = quash_item.first;
            std::string quash_data;
            db_quash_lookup::get_single(quash, quash_data);
            quash_lookup.ParseFromString(quash_data);

            for (auto &keys : quash_item.second)
            {
                zera_txn::PublicKey *public_keys = quash_lookup.add_quash_keys();
                public_keys->CopyFrom(keys);
            }
            db_quash_lookup::store_single(quash, quash_lookup.SerializeAsString());
        }
        quash_keys.clear();
    }
    if (quash_list.empty())
    {
        return;
    }

    std::lock_guard<std::mutex> lock(mtx);
    rocksdb::WriteBatch quash_batch;
    rocksdb::WriteBatch timed_batch;

    std::string quash_data;
    for (auto quash : quash_list)
    {
        zera_validator::QuashLookup quash_lookup;
        db_quash_lookup::get_single(quash, quash_data);
        quash_lookup.ParseFromString(quash_data);

        zera_txn::QuashResult *quash_result = txns->add_quash_results();
        quash_result->set_txn_hash(quash);
        for (auto keys : quash_lookup.quash_keys())
        {
            zera_txn::PublicKey *public_keys = quash_result->add_public_keys();
            public_keys->CopyFrom(keys);
        }
        quash_batch.Delete(quash);
        timed_batch.Delete(quash);
    }
    db_quash_lookup::store_batch(quash_batch);
    db_timed_txns::store_batch(timed_batch);
    quash_list.clear();
}