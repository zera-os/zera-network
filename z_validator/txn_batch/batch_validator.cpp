#include "txn_batch.h"

#include "db_base.h"
#include "wallets.h"
#include "base58.h"
#include "validator.pb.h"
#include "../logging/logging.h"

//unbonding happens on registration txn
//if validator sends offline heartbeat, they are just offline not unbonded
void txn_batch::batch_validator_heartbeat(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const uint64_t& block_height)
{
    rocksdb::WriteBatch batch;
    rocksdb::WriteBatch unbond_batch;
    for (auto txn : txns.validator_heartbeat_txns())
    {
        if (txn_passed.at(txn.base().hash()))
        {
            std::string pub_str = wallets::get_public_key_string(txn.base().public_key());
            std::string validator_str;
            zera_txn::Validator validator;
            db_validators::get_single(pub_str, validator_str);
            

            validator.ParseFromString(validator_str);
            validator.set_online(txn.online());
            validator.set_version(txn.version());
            validator.set_last_heartbeat(block_height);
            std::string base58_pub = base58_encode_public_key(pub_str);
            batch.Put(pub_str, validator.SerializeAsString());
        }
    }

    db_validators::store_batch(batch);
}

void txn_batch::batch_validator_registration(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const zera_validator::BlockHeader &header)
{
    rocksdb::WriteBatch batch;
    rocksdb::WriteBatch batch_lookup;
    rocksdb::WriteBatch unbond_batch;
    rocksdb::WriteBatch archive_batch;
    for (auto txn : txns.validator_registration_txns())
    {
        
        if (txn_passed.at(txn.base().hash()))
        {
            zera_txn::Validator validator;
            validator.CopyFrom(txn.validator());
            validator.set_online(false);

            std::string pub_str = wallets::get_public_key_string(validator.public_key());         //original key
            std::string old_gen_key;
            std::string new_gen_key = wallets::get_public_key_string(txn.generated_public_key()); //generated key

            if (db_validator_lookup::get_single(pub_str, old_gen_key))
            {
                batch.Delete(old_gen_key);
            }

            if (txn.register_())
            {
                batch_lookup.Put(pub_str, new_gen_key);
                batch.Put(new_gen_key, validator.SerializeAsString());
                unbond_batch.Delete(pub_str);
            }
            else
            {
                logging::print("Unbonding validator: ", base58_encode_public_key(pub_str), true);
                unbond_batch.Put(pub_str, header.timestamp().SerializeAsString());
                batch_lookup.Delete(pub_str);
            }

        }
    }
    db_validator_unbond::store_batch(unbond_batch);
    db_validator_lookup::store_batch(batch_lookup);
    db_validators::store_batch(batch);

    std::vector<std::string> keys;
    std::vector<std::string> values;
    
    db_validators::get_all_data(keys, values);

    if(keys.size() == 1)
    {
        zera_txn::Validator validator;
        validator.ParseFromString(values[0]);
        validator.set_online(true);
        std::string base58_pub = base58_encode_public_key(keys[0]);
        db_validators::store_single(keys[0], validator.SerializeAsString());
    }
}