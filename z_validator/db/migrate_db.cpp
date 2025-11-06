#include "migrate_db.h"
#include "reorg.h"

#include <iostream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <set>
#include <map>
#include "../logging/logging.h"

const char *const db_contracts_1_tag::DB_NAME = "contracts";
const char *const db_contract_items_1_tag::DB_NAME = "contract_items";
const char *const db_hash_index_1_tag::DB_NAME = "hash_lookup";
const char *const db_wallets_1_tag::DB_NAME = "wallets";
const char *const db_contract_supply_1_tag::DB_NAME = "contract_supply";
const char *const db_transactions_1_tag::DB_NAME = "transactions";
const char *const db_wallets_temp_1_tag::DB_NAME = "wallets_temp";
const char *const db_smart_contracts_1_tag::DB_NAME = "smart_contracts";
const char *const db_block_txns_1_tag::DB_NAME = "block_transactions";
const char *const db_restricted_wallets_1_tag::DB_NAME = "restricted_wallets";
const char *const db_validator_lookup_1_tag::DB_NAME = "validators";
const char *const db_validators_1_tag::DB_NAME = "validator_lookup";
const char *const db_blocks_1_tag::DB_NAME = "blocks";
const char *const db_headers_1_tag::DB_NAME = "block_headers";
const char *const db_validator_unbond_1_tag::DB_NAME = "unbond";
const char *const db_process_ledger_1_tag::DB_NAME = "proposal_ledger";
const char *const db_process_adaptive_ledger_1_tag::DB_NAME = "process_adaptive_ledger";
const char *const db_proposal_ledger_1_tag::DB_NAME = "process_ledger";
const char *const db_proposals_1_tag::DB_NAME = "proposals";
const char *const db_status_fee_1_tag::DB_NAME = "votes";
const char *const db_expense_ratio_1_tag::DB_NAME = "expense_ratio";
const char *const db_proposal_wallets_1_tag::DB_NAME = "proposal_wallets";
const char *const db_proposals_temp_1_tag::DB_NAME = "proposal_wallets_temp";
const char *const db_delegate_vote_1_tag::DB_NAME = "delegated_voting";
const char *const db_delegate_recipient_1_tag::DB_NAME = "delegated_recipient";
const char *const db_delegate_wallets_1_tag::DB_NAME = "delegated_wallets";
const char *const db_timed_txns_1_tag::DB_NAME = "timed_txns";
const char *const db_quash_ledger_1_tag::DB_NAME = "quash_ledger";
const char *const db_quash_ledger_lookup_1_tag::DB_NAME = "quash_ledger_lookup";
const char *const db_quash_lookup_1_tag::DB_NAME = "quash_lookup";
const char *const db_wallet_lookup_1_tag::DB_NAME = "wallet_lookup";
const char *const db_fast_quorum_1_tag::DB_NAME = "fast_quorum";
const char *const db_duplicate_txn_1_tag::DB_NAME = "duplicate_txn";
const char *const db_delegatees_1_tag::DB_NAME = "delegatees";
const char *const db_voted_proposals_1_tag::DB_NAME = "voted_proposals";
const char *const db_wallet_nonce_1_tag::DB_NAME = "wallet_nonce";
const char *const db_processed_txns_1_tag::DB_NAME = "processed_txns";
const char *const db_processed_wallets_1_tag::DB_NAME = "processed_wallets";
const char *const db_preprocessed_nonce_1_tag::DB_NAME = "preprocessed_nonce";
const char *const db_validate_txns_1_tag::DB_NAME = "validate_txns";
const char *const db_gov_txn_1_tag::DB_NAME = "gov_txns";
const char *const db_sc_transactions_1_tag::DB_NAME = "sc_transactions";
const char *const db_contract_price_1_tag::DB_NAME = "contract_price";
const char *const db_attestation_1_tag::DB_NAME = "attestation";
const char *const db_confirmed_blocks_1_tag::DB_NAME = "confirmed_blocks";
const char *const db_attestation_ledger_1_tag::DB_NAME = "attestation_ledger";
const char *const db_validator_archive_1_tag::DB_NAME = "validator_archive";
const char *const db_system_1_tag::DB_NAME = "system";
const char *const db_gossip_1_tag::DB_NAME = "gossip";
const char *const db_sc_temp_1_tag::DB_NAME = "sc_temp";

template <typename T>
leveldb::DB *migrate_db_base<T>::db = nullptr;
template <typename T>
leveldb::Options migrate_db_base<T>::options;
template <typename T>
std::mutex migrate_db_base<T>::db_mutex;

template <typename T>
int migrate_db_base<T>::migrate(std::string &backup_path)
{
    std::lock_guard<std::mutex> lock(db_mutex);

    // Backup path
    std::string full_backup_path = DB_REORGS + backup_path + "/" + std::string(T::DB_NAME);
    std::string database = DB_DIRECTORY + std::string(T::DB_NAME);

    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, full_backup_path, &db);

    if (!status.ok()) {
        return 0;
    }

    // Open RocksDB
    rocksdb::DB* rocksdb_ptr;
    rocksdb::Options rocksdb_options;
    rocksdb_options.create_if_missing = true;

    rocksdb::Status rocks_status = rocksdb::DB::Open(rocksdb_options, database, &rocksdb_ptr);


    if (!rocks_status.ok()) {
        std::cerr << "Failed to open RocksDB: " << rocks_status.ToString() << std::endl;
        return 0;
    }


    // Iterate LevelDB and insert into RocksDB
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        rocksdb::Status put_status = rocksdb_ptr->Put(rocksdb::WriteOptions(), it->key().ToString(), it->value().ToString());
        if (!put_status.ok()) {
            std::cerr << "Failed to write key: " << it->key().ToString() << " — " << put_status.ToString() << std::endl;
        }
    }

    delete it;
    delete rocksdb_ptr;
    logging::print("Migration completed from LevelDB to RocksDB for", std::string(T::DB_NAME), "at", database, true);

    return 1;
}
template int migrate_db_base<db_contracts_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_hash_index_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_wallets_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_contract_supply_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_wallets_temp_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_smart_contracts_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_block_txns_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_restricted_wallets_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_validators_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_blocks_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_headers_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_transactions_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_contract_items_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_validator_lookup_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_validator_unbond_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_process_ledger_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_proposal_ledger_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_proposals_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_status_fee_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_process_adaptive_ledger_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_expense_ratio_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_proposal_wallets_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_proposals_temp_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_delegate_vote_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_delegate_recipient_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_delegate_wallets_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_timed_txns_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_quash_ledger_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_quash_lookup_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_wallet_lookup_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_fast_quorum_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_duplicate_txn_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_delegatees_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_voted_proposals_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_wallet_nonce_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_preprocessed_nonce_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_processed_txns_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_processed_wallets_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_validate_txns_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_gov_txn_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_sc_transactions_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_contract_price_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_attestation_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_confirmed_blocks_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_attestation_ledger_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_validator_archive_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_quash_ledger_lookup_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_system_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_gossip_1_tag>::migrate(std::string &backup_path);
template int migrate_db_base<db_sc_temp_1_tag>::migrate(std::string &backup_path);
