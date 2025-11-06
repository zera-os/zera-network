#include "db_base.h"
#include "reorg.h"

#include <iostream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <set>
#include <map>
#include "../logging/logging.h"

const char *const db_contracts_tag::DB_NAME = "contracts";
const char *const db_contract_items_tag::DB_NAME = "contract_items";
const char *const db_hash_index_tag::DB_NAME = "hash_lookup";
const char *const db_wallets_tag::DB_NAME = "wallets";
const char *const db_contract_supply_tag::DB_NAME = "contract_supply";
const char *const db_transactions_tag::DB_NAME = "transactions";
const char *const db_wallets_temp_tag::DB_NAME = "wallets_temp";
const char *const db_smart_contracts_tag::DB_NAME = "smart_contracts";
const char *const db_block_txns_tag::DB_NAME = "block_transactions";
const char *const db_restricted_wallets_tag::DB_NAME = "restricted_wallets";
const char *const db_validator_lookup_tag::DB_NAME = "validators";
const char *const db_validators_tag::DB_NAME = "validator_lookup";
const char *const db_blocks_tag::DB_NAME = "blocks";
const char *const db_headers_tag::DB_NAME = "block_headers";
const char *const db_validator_unbond_tag::DB_NAME = "unbond";
const char *const db_process_ledger_tag::DB_NAME = "proposal_ledger";
const char *const db_process_adaptive_ledger_tag::DB_NAME = "process_adaptive_ledger";
const char *const db_proposal_ledger_tag::DB_NAME = "process_ledger";
const char *const db_proposals_tag::DB_NAME = "proposals";
const char *const db_status_fee_tag::DB_NAME = "votes";
const char *const db_expense_ratio_tag::DB_NAME = "expense_ratio";
const char *const db_proposal_wallets_tag::DB_NAME = "proposal_wallets";
const char *const db_proposals_temp_tag::DB_NAME = "proposal_wallets_temp";
const char *const db_delegate_vote_tag::DB_NAME = "delegated_voting";
const char *const db_delegate_recipient_tag::DB_NAME = "delegated_recipient";
const char *const db_delegate_wallets_tag::DB_NAME = "delegated_wallets";
const char *const db_timed_txns_tag::DB_NAME = "timed_txns";
const char *const db_quash_ledger_tag::DB_NAME = "quash_ledger";
const char *const db_quash_ledger_lookup_tag::DB_NAME = "quash_ledger_lookup";
const char *const db_quash_lookup_tag::DB_NAME = "quash_lookup";
const char *const db_wallet_lookup_tag::DB_NAME = "wallet_lookup";
const char *const db_fast_quorum_tag::DB_NAME = "fast_quorum";
const char *const db_duplicate_txn_tag::DB_NAME = "duplicate_txn";
const char *const db_delegatees_tag::DB_NAME = "delegatees";
const char *const db_voted_proposals_tag::DB_NAME = "voted_proposals";
const char *const db_wallet_nonce_tag::DB_NAME = "wallet_nonce";
const char *const db_processed_txns_tag::DB_NAME = "processed_txns";
const char *const db_processed_wallets_tag::DB_NAME = "processed_wallets";
const char *const db_preprocessed_nonce_tag::DB_NAME = "preprocessed_nonce";
const char *const db_validate_txns_tag::DB_NAME = "validate_txns";
const char *const db_gov_txn_tag::DB_NAME = "gov_txns";
const char *const db_sc_transactions_tag::DB_NAME = "sc_transactions";
const char *const db_contract_price_tag::DB_NAME = "contract_price";
const char *const db_attestation_tag::DB_NAME = "attestation";
const char *const db_confirmed_blocks_tag::DB_NAME = "confirmed_blocks";
const char *const db_attestation_ledger_tag::DB_NAME = "attestation_ledger";
const char *const db_validator_archive_tag::DB_NAME = "validator_archive";
const char *const db_system_tag::DB_NAME = "system";
const char *const db_gossip_tag::DB_NAME = "gossip";
const char *const db_sc_temp_tag::DB_NAME = "sc_temp";
const char *const db_allowance_tag::DB_NAME = "allowance";
const char *const db_sc_subscriber_tag::DB_NAME = "sc_subscriber";
const char *const db_event_management_tag::DB_NAME = "event_management";

template <typename T>
rocksdb::DB *db_base<T>::db = nullptr;
template <typename T>
rocksdb::Options db_base<T>::options;
template <typename T>
std::mutex db_base<T>::db_mutex;

template <typename T>
int db_base<T>::open_db()
{
    std::string database = DB_DIRECTORY + std::string(T::DB_NAME);
    return database::open_db(db, options, database);
}
template int db_base<db_contracts_tag>::open_db();
template int db_base<db_hash_index_tag>::open_db();
template int db_base<db_wallets_tag>::open_db();
template int db_base<db_contract_supply_tag>::open_db();
template int db_base<db_wallets_temp_tag>::open_db();
template int db_base<db_smart_contracts_tag>::open_db();
template int db_base<db_block_txns_tag>::open_db();
template int db_base<db_restricted_wallets_tag>::open_db();
template int db_base<db_validators_tag>::open_db();
template int db_base<db_blocks_tag>::open_db();
template int db_base<db_headers_tag>::open_db();
template int db_base<db_transactions_tag>::open_db();
template int db_base<db_contract_items_tag>::open_db();
template int db_base<db_validator_lookup_tag>::open_db();
template int db_base<db_validator_unbond_tag>::open_db();
template int db_base<db_process_ledger_tag>::open_db();
template int db_base<db_proposal_ledger_tag>::open_db();
template int db_base<db_proposals_tag>::open_db();
template int db_base<db_status_fee_tag>::open_db();
template int db_base<db_process_adaptive_ledger_tag>::open_db();
template int db_base<db_expense_ratio_tag>::open_db();
template int db_base<db_proposal_wallets_tag>::open_db();
template int db_base<db_proposals_temp_tag>::open_db();
template int db_base<db_delegate_vote_tag>::open_db();
template int db_base<db_delegate_recipient_tag>::open_db();
template int db_base<db_delegate_wallets_tag>::open_db();
template int db_base<db_timed_txns_tag>::open_db();
template int db_base<db_quash_ledger_tag>::open_db();
template int db_base<db_quash_lookup_tag>::open_db();
template int db_base<db_wallet_lookup_tag>::open_db();
template int db_base<db_fast_quorum_tag>::open_db();
template int db_base<db_duplicate_txn_tag>::open_db();
template int db_base<db_delegatees_tag>::open_db();
template int db_base<db_voted_proposals_tag>::open_db();
template int db_base<db_wallet_nonce_tag>::open_db();
template int db_base<db_preprocessed_nonce_tag>::open_db();
template int db_base<db_processed_txns_tag>::open_db();
template int db_base<db_processed_wallets_tag>::open_db();
template int db_base<db_validate_txns_tag>::open_db();
template int db_base<db_gov_txn_tag>::open_db();
template int db_base<db_sc_transactions_tag>::open_db();
template int db_base<db_contract_price_tag>::open_db();
template int db_base<db_attestation_tag>::open_db();
template int db_base<db_confirmed_blocks_tag>::open_db();
template int db_base<db_attestation_ledger_tag>::open_db();
template int db_base<db_validator_archive_tag>::open_db();
template int db_base<db_quash_ledger_lookup_tag>::open_db();
template int db_base<db_system_tag>::open_db();
template int db_base<db_gossip_tag>::open_db();
template int db_base<db_sc_temp_tag>::open_db();
template int db_base<db_allowance_tag>::open_db();
template int db_base<db_sc_subscriber_tag>::open_db();
template int db_base<db_event_management_tag>::open_db();

template <typename T>
void db_base<T>::close_db()
{
    database::close_db(db);
}
template void db_base<db_contracts_tag>::close_db();
template void db_base<db_hash_index_tag>::close_db();
template void db_base<db_wallets_tag>::close_db();
template void db_base<db_contract_supply_tag>::close_db();
template void db_base<db_wallets_temp_tag>::close_db();
template void db_base<db_smart_contracts_tag>::close_db();
template void db_base<db_block_txns_tag>::close_db();
template void db_base<db_restricted_wallets_tag>::close_db();
template void db_base<db_validators_tag>::close_db();
template void db_base<db_blocks_tag>::close_db();
template void db_base<db_headers_tag>::close_db();
template void db_base<db_transactions_tag>::close_db();
template void db_base<db_contract_items_tag>::close_db();
template void db_base<db_validator_lookup_tag>::close_db();
template void db_base<db_validator_unbond_tag>::close_db();
template void db_base<db_process_ledger_tag>::close_db();
template void db_base<db_proposal_ledger_tag>::close_db();
template void db_base<db_proposals_tag>::close_db();
template void db_base<db_status_fee_tag>::close_db();
template void db_base<db_process_adaptive_ledger_tag>::close_db();
template void db_base<db_expense_ratio_tag>::close_db();
template void db_base<db_proposal_wallets_tag>::close_db();
template void db_base<db_proposals_temp_tag>::close_db();
template void db_base<db_delegate_vote_tag>::close_db();
template void db_base<db_delegate_recipient_tag>::close_db();
template void db_base<db_delegate_wallets_tag>::close_db();
template void db_base<db_timed_txns_tag>::close_db();
template void db_base<db_quash_ledger_tag>::close_db();
template void db_base<db_quash_lookup_tag>::close_db();
template void db_base<db_wallet_lookup_tag>::close_db();
template void db_base<db_fast_quorum_tag>::close_db();
template void db_base<db_duplicate_txn_tag>::close_db();
template void db_base<db_delegatees_tag>::close_db();
template void db_base<db_voted_proposals_tag>::close_db();
template void db_base<db_wallet_nonce_tag>::close_db();
template void db_base<db_processed_txns_tag>::close_db();
template void db_base<db_processed_wallets_tag>::close_db();
template void db_base<db_preprocessed_nonce_tag>::close_db();
template void db_base<db_validate_txns_tag>::close_db();
template void db_base<db_gov_txn_tag>::close_db();
template void db_base<db_sc_transactions_tag>::close_db();
template void db_base<db_contract_price_tag>::close_db();
template void db_base<db_attestation_tag>::close_db();
template void db_base<db_confirmed_blocks_tag>::close_db();
template void db_base<db_attestation_ledger_tag>::close_db();
template void db_base<db_validator_archive_tag>::close_db();
template void db_base<db_quash_ledger_lookup_tag>::close_db();
template void db_base<db_system_tag>::close_db();
template void db_base<db_gossip_tag>::close_db();
template void db_base<db_sc_temp_tag>::close_db();
template void db_base<db_allowance_tag>::close_db();
template void db_base<db_sc_subscriber_tag>::close_db();
template void db_base<db_event_management_tag>::close_db();

template <typename T>
int db_base<T>::get_single(const std::string &key, std::string &value)
{
    return database::get_data(db, key, value);
}
template int db_base<db_contracts_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_hash_index_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_wallets_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_contract_supply_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_wallets_temp_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_smart_contracts_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_block_txns_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_restricted_wallets_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_validators_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_blocks_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_headers_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_transactions_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_contract_items_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_validator_lookup_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_validator_unbond_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_process_ledger_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_proposal_ledger_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_proposals_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_status_fee_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_process_adaptive_ledger_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_expense_ratio_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_proposal_wallets_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_proposals_temp_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_delegate_vote_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_delegate_recipient_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_delegate_wallets_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_timed_txns_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_quash_ledger_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_quash_lookup_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_wallet_lookup_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_fast_quorum_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_duplicate_txn_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_delegatees_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_voted_proposals_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_wallet_nonce_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_processed_txns_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_processed_wallets_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_preprocessed_nonce_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_validate_txns_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_gov_txn_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_sc_transactions_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_contract_price_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_attestation_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_confirmed_blocks_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_attestation_ledger_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_validator_archive_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_quash_ledger_lookup_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_system_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_gossip_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_sc_temp_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_allowance_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_sc_subscriber_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_event_management_tag>::get_single(const std::string &key, std::string &value);

template <typename T>
int db_base<T>::exist(const std::string &key)
{
    std::string value;
    return database::get_data(db, key, value);
}
template int db_base<db_contracts_tag>::exist(const std::string &key);
template int db_base<db_hash_index_tag>::exist(const std::string &key);
template int db_base<db_wallets_tag>::exist(const std::string &key);
template int db_base<db_contract_supply_tag>::exist(const std::string &key);
template int db_base<db_wallets_temp_tag>::exist(const std::string &key);
template int db_base<db_smart_contracts_tag>::exist(const std::string &key);
template int db_base<db_block_txns_tag>::exist(const std::string &key);
template int db_base<db_restricted_wallets_tag>::exist(const std::string &key);
template int db_base<db_validators_tag>::exist(const std::string &key);
template int db_base<db_blocks_tag>::exist(const std::string &key);
template int db_base<db_headers_tag>::exist(const std::string &key);
template int db_base<db_transactions_tag>::exist(const std::string &key);
template int db_base<db_contract_items_tag>::exist(const std::string &key);
template int db_base<db_validator_lookup_tag>::exist(const std::string &key);
template int db_base<db_validator_unbond_tag>::exist(const std::string &key);
template int db_base<db_process_ledger_tag>::exist(const std::string &key);
template int db_base<db_proposal_ledger_tag>::exist(const std::string &key);
template int db_base<db_proposals_tag>::exist(const std::string &key);
template int db_base<db_status_fee_tag>::exist(const std::string &key);
template int db_base<db_process_adaptive_ledger_tag>::exist(const std::string &key);
template int db_base<db_expense_ratio_tag>::exist(const std::string &key);
template int db_base<db_proposal_wallets_tag>::exist(const std::string &key);
template int db_base<db_proposals_temp_tag>::exist(const std::string &key);
template int db_base<db_delegate_vote_tag>::exist(const std::string &key);
template int db_base<db_delegate_recipient_tag>::exist(const std::string &key);
template int db_base<db_delegate_wallets_tag>::exist(const std::string &key);
template int db_base<db_timed_txns_tag>::exist(const std::string &key);
template int db_base<db_quash_ledger_tag>::exist(const std::string &key);
template int db_base<db_quash_lookup_tag>::exist(const std::string &key);
template int db_base<db_wallet_lookup_tag>::exist(const std::string &key);
template int db_base<db_fast_quorum_tag>::exist(const std::string &key);
template int db_base<db_duplicate_txn_tag>::exist(const std::string &key);
template int db_base<db_delegatees_tag>::exist(const std::string &key);
template int db_base<db_voted_proposals_tag>::exist(const std::string &key);
template int db_base<db_wallet_nonce_tag>::exist(const std::string &key);
template int db_base<db_processed_txns_tag>::exist(const std::string &key);
template int db_base<db_processed_wallets_tag>::exist(const std::string &key);
template int db_base<db_preprocessed_nonce_tag>::exist(const std::string &key);
template int db_base<db_validate_txns_tag>::exist(const std::string &key);
template int db_base<db_gov_txn_tag>::exist(const std::string &key);
template int db_base<db_sc_transactions_tag>::exist(const std::string &key);
template int db_base<db_contract_price_tag>::exist(const std::string &key);
template int db_base<db_attestation_tag>::exist(const std::string &key);
template int db_base<db_confirmed_blocks_tag>::exist(const std::string &key);
template int db_base<db_attestation_ledger_tag>::exist(const std::string &key);
template int db_base<db_validator_archive_tag>::exist(const std::string &key);
template int db_base<db_quash_ledger_lookup_tag>::exist(const std::string &key);
template int db_base<db_system_tag>::exist(const std::string &key);
template int db_base<db_gossip_tag>::exist(const std::string &key);
template int db_base<db_sc_temp_tag>::exist(const std::string &key);
template int db_base<db_allowance_tag>::exist(const std::string &key);
template int db_base<db_sc_subscriber_tag>::exist(const std::string &key);
template int db_base<db_event_management_tag>::exist(const std::string &key);

template <typename T>
int db_base<T>::store_single(const std::string &key, const std::string &value)
{
    return database::store_single(db, key, value);
}
template int db_base<db_contracts_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_hash_index_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_wallets_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_contract_supply_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_wallets_temp_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_smart_contracts_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_block_txns_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_restricted_wallets_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_validators_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_blocks_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_headers_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_transactions_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_contract_items_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_validator_lookup_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_validator_unbond_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_process_ledger_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_proposal_ledger_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_proposals_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_status_fee_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_process_adaptive_ledger_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_expense_ratio_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_proposal_wallets_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_proposals_temp_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_delegate_vote_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_delegate_recipient_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_delegate_wallets_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_timed_txns_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_quash_ledger_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_quash_lookup_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_wallet_lookup_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_fast_quorum_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_duplicate_txn_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_delegatees_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_voted_proposals_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_wallet_nonce_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_processed_txns_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_processed_wallets_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_preprocessed_nonce_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_validate_txns_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_gov_txn_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_sc_transactions_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_contract_price_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_attestation_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_confirmed_blocks_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_attestation_ledger_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_validator_archive_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_quash_ledger_lookup_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_system_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_gossip_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_sc_temp_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_allowance_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_sc_subscriber_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_event_management_tag>::store_single(const std::string &key, const std::string &value);

template <typename T>
int db_base<T>::store_batch(rocksdb::WriteBatch &batch)
{
    return database::store_batch(db, batch);
}
template int db_base<db_contracts_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_hash_index_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_wallets_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_contract_supply_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_wallets_temp_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_smart_contracts_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_block_txns_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_restricted_wallets_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_validators_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_blocks_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_headers_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_transactions_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_contract_items_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_validator_lookup_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_validator_unbond_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_proposal_ledger_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_process_ledger_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_proposals_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_status_fee_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_process_adaptive_ledger_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_expense_ratio_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_proposal_wallets_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_proposals_temp_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_delegate_vote_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_delegate_recipient_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_delegate_wallets_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_timed_txns_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_quash_ledger_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_quash_lookup_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_wallet_lookup_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_fast_quorum_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_duplicate_txn_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_delegatees_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_voted_proposals_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_wallet_nonce_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_processed_txns_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_processed_wallets_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_preprocessed_nonce_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_validate_txns_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_gov_txn_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_sc_transactions_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_contract_price_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_attestation_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_confirmed_blocks_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_attestation_ledger_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_validator_archive_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_quash_ledger_lookup_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_system_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_gossip_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_sc_temp_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_allowance_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_sc_subscriber_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_event_management_tag>::store_batch(rocksdb::WriteBatch &batch);

template <typename T>
int db_base<T>::remove_single(const std::string &key)
{
    return database::remove_single(db, key);
}
template int db_base<db_contracts_tag>::remove_single(const std::string &key);
template int db_base<db_hash_index_tag>::remove_single(const std::string &key);
template int db_base<db_wallets_tag>::remove_single(const std::string &key);
template int db_base<db_contract_supply_tag>::remove_single(const std::string &key);
template int db_base<db_wallets_temp_tag>::remove_single(const std::string &key);
template int db_base<db_smart_contracts_tag>::remove_single(const std::string &key);
template int db_base<db_block_txns_tag>::remove_single(const std::string &key);
template int db_base<db_restricted_wallets_tag>::remove_single(const std::string &key);
template int db_base<db_validators_tag>::remove_single(const std::string &key);
template int db_base<db_blocks_tag>::remove_single(const std::string &key);
template int db_base<db_headers_tag>::remove_single(const std::string &key);
template int db_base<db_transactions_tag>::remove_single(const std::string &key);
template int db_base<db_contract_items_tag>::remove_single(const std::string &key);
template int db_base<db_validator_lookup_tag>::remove_single(const std::string &key);
template int db_base<db_validator_unbond_tag>::remove_single(const std::string &key);
template int db_base<db_proposal_ledger_tag>::remove_single(const std::string &key);
template int db_base<db_process_ledger_tag>::remove_single(const std::string &key);
template int db_base<db_proposals_tag>::remove_single(const std::string &key);
template int db_base<db_status_fee_tag>::remove_single(const std::string &key);
template int db_base<db_process_adaptive_ledger_tag>::remove_single(const std::string &key);
template int db_base<db_expense_ratio_tag>::remove_single(const std::string &key);
template int db_base<db_proposal_wallets_tag>::remove_single(const std::string &key);
template int db_base<db_proposals_temp_tag>::remove_single(const std::string &key);
template int db_base<db_delegate_vote_tag>::remove_single(const std::string &key);
template int db_base<db_delegate_recipient_tag>::remove_single(const std::string &key);
template int db_base<db_delegate_wallets_tag>::remove_single(const std::string &key);
template int db_base<db_timed_txns_tag>::remove_single(const std::string &key);
template int db_base<db_quash_ledger_tag>::remove_single(const std::string &key);
template int db_base<db_quash_lookup_tag>::remove_single(const std::string &key);
template int db_base<db_wallet_lookup_tag>::remove_single(const std::string &key);
template int db_base<db_fast_quorum_tag>::remove_single(const std::string &key);
template int db_base<db_duplicate_txn_tag>::remove_single(const std::string &key);
template int db_base<db_delegatees_tag>::remove_single(const std::string &key);
template int db_base<db_voted_proposals_tag>::remove_single(const std::string &key);
template int db_base<db_wallet_nonce_tag>::remove_single(const std::string &key);
template int db_base<db_processed_txns_tag>::remove_single(const std::string &key);
template int db_base<db_processed_wallets_tag>::remove_single(const std::string &key);
template int db_base<db_preprocessed_nonce_tag>::remove_single(const std::string &key);
template int db_base<db_validate_txns_tag>::remove_single(const std::string &key);
template int db_base<db_gov_txn_tag>::remove_single(const std::string &key);
template int db_base<db_sc_transactions_tag>::remove_single(const std::string &key);
template int db_base<db_contract_price_tag>::remove_single(const std::string &key);
template int db_base<db_attestation_tag>::remove_single(const std::string &key);
template int db_base<db_confirmed_blocks_tag>::remove_single(const std::string &key);
template int db_base<db_attestation_ledger_tag>::remove_single(const std::string &key);
template int db_base<db_validator_archive_tag>::remove_single(const std::string &key);
template int db_base<db_quash_ledger_lookup_tag>::remove_single(const std::string &key);
template int db_base<db_system_tag>::remove_single(const std::string &key);
template int db_base<db_gossip_tag>::remove_single(const std::string &key);
template int db_base<db_sc_temp_tag>::remove_single(const std::string &key);
template int db_base<db_allowance_tag>::remove_single(const std::string &key);
template int db_base<db_sc_subscriber_tag>::remove_single(const std::string &key);
template int db_base<db_event_management_tag>::remove_single(const std::string &key);

template <typename T>
int db_base<T>::get_all_data(std::vector<std::string> &keys, std::vector<std::string> &values)
{
    if (!database::get_all_data(db, keys, values))
    {
        return 0;
    }
    return 1;
}
template int db_base<db_contracts_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_hash_index_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_wallets_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_contract_supply_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_wallets_temp_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_smart_contracts_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_block_txns_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_restricted_wallets_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_validators_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_blocks_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_headers_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_transactions_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_contract_items_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_validator_lookup_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_validator_unbond_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_proposal_ledger_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_process_ledger_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_proposals_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_status_fee_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_process_adaptive_ledger_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_expense_ratio_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_proposal_wallets_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_proposals_temp_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_delegate_vote_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_delegate_recipient_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_delegate_wallets_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_timed_txns_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_quash_ledger_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_quash_lookup_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_wallet_lookup_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_fast_quorum_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_duplicate_txn_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_delegatees_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_voted_proposals_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_wallet_nonce_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_processed_txns_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_processed_wallets_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_preprocessed_nonce_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_validate_txns_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_gov_txn_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_sc_transactions_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_contract_price_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_attestation_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_confirmed_blocks_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_attestation_ledger_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_validator_archive_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_quash_ledger_lookup_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_system_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_gossip_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_sc_temp_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_allowance_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_sc_subscriber_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_event_management_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);

template <typename T>
int db_base<T>::remove_all()
{
    rocksdb::WriteBatch batch;

    // Iterate over each item in the database and add them to the write batch for deletion
    rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());

    for (it->SeekToFirst(); it->Valid(); it->Next())
    {
        batch.Delete(it->key());
    }

    delete it;

    std::lock_guard<std::mutex> lock(db_mutex);
    return database::store_batch(db, batch);
}
template int db_base<db_contracts_tag>::remove_all();
template int db_base<db_hash_index_tag>::remove_all();
template int db_base<db_wallets_tag>::remove_all();
template int db_base<db_contract_supply_tag>::remove_all();
template int db_base<db_wallets_temp_tag>::remove_all();
template int db_base<db_smart_contracts_tag>::remove_all();
template int db_base<db_block_txns_tag>::remove_all();
template int db_base<db_restricted_wallets_tag>::remove_all();
template int db_base<db_validators_tag>::remove_all();
template int db_base<db_blocks_tag>::remove_all();
template int db_base<db_headers_tag>::remove_all();
template int db_base<db_transactions_tag>::remove_all();
template int db_base<db_contract_items_tag>::remove_all();
template int db_base<db_validator_lookup_tag>::remove_all();
template int db_base<db_validator_unbond_tag>::remove_all();
template int db_base<db_proposal_ledger_tag>::remove_all();
template int db_base<db_process_ledger_tag>::remove_all();
template int db_base<db_proposals_tag>::remove_all();
template int db_base<db_status_fee_tag>::remove_all();
template int db_base<db_process_adaptive_ledger_tag>::remove_all();
template int db_base<db_expense_ratio_tag>::remove_all();
template int db_base<db_proposal_wallets_tag>::remove_all();
template int db_base<db_proposals_temp_tag>::remove_all();
template int db_base<db_delegate_vote_tag>::remove_all();
template int db_base<db_delegate_recipient_tag>::remove_all();
template int db_base<db_delegate_wallets_tag>::remove_all();
template int db_base<db_timed_txns_tag>::remove_all();
template int db_base<db_quash_ledger_tag>::remove_all();
template int db_base<db_quash_lookup_tag>::remove_all();
template int db_base<db_wallet_lookup_tag>::remove_all();
template int db_base<db_fast_quorum_tag>::remove_all();
template int db_base<db_duplicate_txn_tag>::remove_all();
template int db_base<db_delegatees_tag>::remove_all();
template int db_base<db_voted_proposals_tag>::remove_all();
template int db_base<db_wallet_nonce_tag>::remove_all();
template int db_base<db_processed_txns_tag>::remove_all();
template int db_base<db_processed_wallets_tag>::remove_all();
template int db_base<db_preprocessed_nonce_tag>::remove_all();
template int db_base<db_validate_txns_tag>::remove_all();
template int db_base<db_gov_txn_tag>::remove_all();
template int db_base<db_sc_transactions_tag>::remove_all();
template int db_base<db_contract_price_tag>::remove_all();
template int db_base<db_attestation_tag>::remove_all();
template int db_base<db_confirmed_blocks_tag>::remove_all();
template int db_base<db_attestation_ledger_tag>::remove_all();
template int db_base<db_validator_archive_tag>::remove_all();
template int db_base<db_quash_ledger_lookup_tag>::remove_all();
template int db_base<db_system_tag>::remove_all();
template int db_base<db_gossip_tag>::remove_all();
template int db_base<db_sc_temp_tag>::remove_all();
template int db_base<db_allowance_tag>::remove_all();
template int db_base<db_sc_subscriber_tag>::remove_all();
template int db_base<db_event_management_tag>::remove_all();

template <typename T>
int db_base<T>::compact_all()
{
    return database::compact_all(db);
}
template int db_base<db_contracts_tag>::compact_all();
template int db_base<db_hash_index_tag>::compact_all();
template int db_base<db_wallets_tag>::compact_all();
template int db_base<db_contract_supply_tag>::compact_all();
template int db_base<db_wallets_temp_tag>::compact_all();
template int db_base<db_smart_contracts_tag>::compact_all();
template int db_base<db_block_txns_tag>::compact_all();
template int db_base<db_restricted_wallets_tag>::compact_all();
template int db_base<db_validators_tag>::compact_all();
template int db_base<db_blocks_tag>::compact_all();
template int db_base<db_headers_tag>::compact_all();
template int db_base<db_transactions_tag>::compact_all();
template int db_base<db_contract_items_tag>::compact_all();
template int db_base<db_validator_lookup_tag>::compact_all();
template int db_base<db_validator_unbond_tag>::compact_all();
template int db_base<db_proposal_ledger_tag>::compact_all();
template int db_base<db_process_ledger_tag>::compact_all();
template int db_base<db_proposals_tag>::compact_all();
template int db_base<db_status_fee_tag>::compact_all();
template int db_base<db_process_adaptive_ledger_tag>::compact_all();
template int db_base<db_expense_ratio_tag>::compact_all();
template int db_base<db_proposal_wallets_tag>::compact_all();
template int db_base<db_proposals_temp_tag>::compact_all();
template int db_base<db_delegate_vote_tag>::compact_all();
template int db_base<db_delegate_recipient_tag>::compact_all();
template int db_base<db_delegate_wallets_tag>::compact_all();
template int db_base<db_timed_txns_tag>::compact_all();
template int db_base<db_quash_ledger_tag>::compact_all();
template int db_base<db_quash_lookup_tag>::compact_all();
template int db_base<db_wallet_lookup_tag>::compact_all();
template int db_base<db_fast_quorum_tag>::compact_all();
template int db_base<db_duplicate_txn_tag>::compact_all();
template int db_base<db_delegatees_tag>::compact_all();
template int db_base<db_voted_proposals_tag>::compact_all();
template int db_base<db_wallet_nonce_tag>::compact_all();
template int db_base<db_processed_txns_tag>::compact_all();
template int db_base<db_processed_wallets_tag>::compact_all();
template int db_base<db_preprocessed_nonce_tag>::compact_all();
template int db_base<db_validate_txns_tag>::compact_all();
template int db_base<db_gov_txn_tag>::compact_all();
template int db_base<db_sc_transactions_tag>::compact_all();
template int db_base<db_contract_price_tag>::compact_all();
template int db_base<db_attestation_tag>::compact_all();
template int db_base<db_confirmed_blocks_tag>::compact_all();
template int db_base<db_attestation_ledger_tag>::compact_all();
template int db_base<db_validator_archive_tag>::compact_all();
template int db_base<db_quash_ledger_lookup_tag>::compact_all();
template int db_base<db_system_tag>::compact_all();
template int db_base<db_gossip_tag>::compact_all();
template int db_base<db_sc_temp_tag>::compact_all();
template int db_base<db_allowance_tag>::compact_all();
template int db_base<db_sc_subscriber_tag>::compact_all();
template int db_base<db_event_management_tag>::compact_all();

template <typename T>
int db_base<T>::backup_database(const std::string &backup_path)
{
    std::lock_guard<std::mutex> lock(db_mutex);

    // Create a snapshot
    const rocksdb::Snapshot *snapshot = db->GetSnapshot();
    rocksdb::ReadOptions read_options;
    read_options.snapshot = snapshot;

    // Backup path
    std::string full_backup_path = DB_REORGS + backup_path + "/" + std::string(T::DB_NAME);

    try
    {
        // Ensure the backup directory exists
        std::filesystem::create_directories(full_backup_path);

        // Open a new rocksdb database at the backup location
        rocksdb::Options options;
        options.create_if_missing = true;
        rocksdb::DB *backup_db;
        rocksdb::Status status = rocksdb::DB::Open(options, full_backup_path, &backup_db);
        if (!status.ok())
        {
            std::cerr << "Unable to open backup DB: " << status.ToString() << std::endl;
            db->ReleaseSnapshot(snapshot);
            return 1;
        }

        // Iterate over the data and write to the backup database
        rocksdb::Iterator *it = db->NewIterator(read_options);
        rocksdb::WriteBatch batch;
        for (it->SeekToFirst(); it->Valid(); it->Next())
        {
            batch.Put(it->key(), it->value());
        }
        status = backup_db->Write(rocksdb::WriteOptions(), &batch);
        delete it;
        delete backup_db;

        // Check for errors during iteration
        if (!status.ok())
        {
            std::cerr << "Error writing to backup DB: " << status.ToString() << std::endl;
            db->ReleaseSnapshot(snapshot);
            return 1;
        }

        db->ReleaseSnapshot(snapshot);

        return 0; // Success
    }
    catch (const std::filesystem::filesystem_error &e)
    {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        db->ReleaseSnapshot(snapshot);
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        db->ReleaseSnapshot(snapshot);
        return 1;
    }
}
template int db_base<db_contracts_tag>::backup_database(const std::string &backup_path);
template int db_base<db_hash_index_tag>::backup_database(const std::string &backup_path);
template int db_base<db_wallets_tag>::backup_database(const std::string &backup_path);
template int db_base<db_contract_supply_tag>::backup_database(const std::string &backup_path);
template int db_base<db_wallets_temp_tag>::backup_database(const std::string &backup_path);
template int db_base<db_smart_contracts_tag>::backup_database(const std::string &backup_path);
template int db_base<db_block_txns_tag>::backup_database(const std::string &backup_path);
template int db_base<db_restricted_wallets_tag>::backup_database(const std::string &backup_path);
template int db_base<db_validators_tag>::backup_database(const std::string &backup_path);
template int db_base<db_blocks_tag>::backup_database(const std::string &backup_path);
template int db_base<db_headers_tag>::backup_database(const std::string &backup_path);
template int db_base<db_transactions_tag>::backup_database(const std::string &backup_path);
template int db_base<db_contract_items_tag>::backup_database(const std::string &backup_path);
template int db_base<db_validator_lookup_tag>::backup_database(const std::string &backup_path);
template int db_base<db_validator_unbond_tag>::backup_database(const std::string &backup_path);
template int db_base<db_proposal_ledger_tag>::backup_database(const std::string &backup_path);
template int db_base<db_process_ledger_tag>::backup_database(const std::string &backup_path);
template int db_base<db_proposals_tag>::backup_database(const std::string &backup_path);
template int db_base<db_status_fee_tag>::backup_database(const std::string &backup_path);
template int db_base<db_process_adaptive_ledger_tag>::backup_database(const std::string &backup_path);
template int db_base<db_expense_ratio_tag>::backup_database(const std::string &backup_path);
template int db_base<db_proposal_wallets_tag>::backup_database(const std::string &backup_path);
template int db_base<db_proposals_temp_tag>::backup_database(const std::string &backup_path);
template int db_base<db_delegate_vote_tag>::backup_database(const std::string &backup_path);
template int db_base<db_delegate_recipient_tag>::backup_database(const std::string &backup_path);
template int db_base<db_delegate_wallets_tag>::backup_database(const std::string &backup_path);
template int db_base<db_timed_txns_tag>::backup_database(const std::string &backup_path);
template int db_base<db_quash_ledger_tag>::backup_database(const std::string &backup_path);
template int db_base<db_quash_lookup_tag>::backup_database(const std::string &backup_path);
template int db_base<db_wallet_lookup_tag>::backup_database(const std::string &backup_path);
template int db_base<db_fast_quorum_tag>::backup_database(const std::string &backup_path);
template int db_base<db_duplicate_txn_tag>::backup_database(const std::string &backup_path);
template int db_base<db_delegatees_tag>::backup_database(const std::string &backup_path);
template int db_base<db_voted_proposals_tag>::backup_database(const std::string &backup_path);
template int db_base<db_wallet_nonce_tag>::backup_database(const std::string &backup_path);
template int db_base<db_processed_txns_tag>::backup_database(const std::string &backup_path);
template int db_base<db_processed_wallets_tag>::backup_database(const std::string &backup_path);
template int db_base<db_preprocessed_nonce_tag>::backup_database(const std::string &backup_path);
template int db_base<db_validate_txns_tag>::backup_database(const std::string &backup_path);
template int db_base<db_gov_txn_tag>::backup_database(const std::string &backup_path);
template int db_base<db_sc_transactions_tag>::backup_database(const std::string &backup_path);
template int db_base<db_contract_price_tag>::backup_database(const std::string &backup_path);
template int db_base<db_attestation_tag>::backup_database(const std::string &backup_path);
template int db_base<db_confirmed_blocks_tag>::backup_database(const std::string &backup_path);
template int db_base<db_attestation_ledger_tag>::backup_database(const std::string &backup_path);
template int db_base<db_validator_archive_tag>::backup_database(const std::string &backup_path);
template int db_base<db_quash_ledger_lookup_tag>::backup_database(const std::string &backup_path);
template int db_base<db_system_tag>::backup_database(const std::string &backup_path);
template int db_base<db_gossip_tag>::backup_database(const std::string &backup_path);
template int db_base<db_sc_temp_tag>::backup_database(const std::string &backup_path);
template int db_base<db_allowance_tag>::backup_database(const std::string &backup_path);
template int db_base<db_sc_subscriber_tag>::backup_database(const std::string &backup_path);
template int db_base<db_event_management_tag>::backup_database(const std::string &backup_path);

template <typename T>
int db_base<T>::restore_database(const std::string &backup_path) {
    std::lock_guard<std::mutex> lock(db_mutex);

    // Backup path
    std::string full_backup_path = DB_COPY + backup_path + "/" + std::string(T::DB_NAME);
    std::string database = DB_DIRECTORY + std::string(T::DB_NAME);
    
    // Close the current database
    close_db();

    try {
        // Ensure the database directory exists
        std::filesystem::create_directories(database);

        // Copy the backup to the database location recursively
        std::filesystem::copy(full_backup_path, database, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);

        logging::print("Restoration completed from", full_backup_path, "to", database);

        // Reopen the database
        open_db();

        return 0; // Success
    }
    catch (const std::filesystem::filesystem_error &e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;

        //open the database if doesnt exist
        open_db();
        return 1; // Error
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        open_db();
        return 1; // Error
    }
}
template int db_base<db_contracts_tag>::restore_database(const std::string &backup_path);
template int db_base<db_hash_index_tag>::restore_database(const std::string &backup_path);
template int db_base<db_wallets_tag>::restore_database(const std::string &backup_path);
template int db_base<db_contract_supply_tag>::restore_database(const std::string &backup_path);
template int db_base<db_wallets_temp_tag>::restore_database(const std::string &backup_path);
template int db_base<db_smart_contracts_tag>::restore_database(const std::string &backup_path);
template int db_base<db_block_txns_tag>::restore_database(const std::string &backup_path);
template int db_base<db_restricted_wallets_tag>::restore_database(const std::string &backup_path);
template int db_base<db_validators_tag>::restore_database(const std::string &backup_path);
template int db_base<db_blocks_tag>::restore_database(const std::string &backup_path);
template int db_base<db_headers_tag>::restore_database(const std::string &backup_path);
template int db_base<db_transactions_tag>::restore_database(const std::string &backup_path);
template int db_base<db_contract_items_tag>::restore_database(const std::string &backup_path);
template int db_base<db_validator_lookup_tag>::restore_database(const std::string &backup_path);
template int db_base<db_validator_unbond_tag>::restore_database(const std::string &backup_path);
template int db_base<db_proposal_ledger_tag>::restore_database(const std::string &backup_path);
template int db_base<db_process_ledger_tag>::restore_database(const std::string &backup_path);
template int db_base<db_proposals_tag>::restore_database(const std::string &backup_path);
template int db_base<db_status_fee_tag>::restore_database(const std::string &backup_path);
template int db_base<db_process_adaptive_ledger_tag>::restore_database(const std::string &backup_path);
template int db_base<db_expense_ratio_tag>::restore_database(const std::string &backup_path);
template int db_base<db_proposal_wallets_tag>::restore_database(const std::string &backup_path);
template int db_base<db_proposals_temp_tag>::restore_database(const std::string &backup_path);
template int db_base<db_delegate_vote_tag>::restore_database(const std::string &backup_path);
template int db_base<db_delegate_recipient_tag>::restore_database(const std::string &backup_path);
template int db_base<db_delegate_wallets_tag>::restore_database(const std::string &backup_path);
template int db_base<db_timed_txns_tag>::restore_database(const std::string &backup_path);
template int db_base<db_quash_ledger_tag>::restore_database(const std::string &backup_path);
template int db_base<db_quash_lookup_tag>::restore_database(const std::string &backup_path);
template int db_base<db_wallet_lookup_tag>::restore_database(const std::string &backup_path);
template int db_base<db_fast_quorum_tag>::restore_database(const std::string &backup_path);
template int db_base<db_duplicate_txn_tag>::restore_database(const std::string &backup_path);
template int db_base<db_delegatees_tag>::restore_database(const std::string &backup_path);
template int db_base<db_voted_proposals_tag>::restore_database(const std::string &backup_path);
template int db_base<db_wallet_nonce_tag>::restore_database(const std::string &backup_path);
template int db_base<db_processed_txns_tag>::restore_database(const std::string &backup_path);
template int db_base<db_processed_wallets_tag>::restore_database(const std::string &backup_path);
template int db_base<db_preprocessed_nonce_tag>::restore_database(const std::string &backup_path);
template int db_base<db_validate_txns_tag>::restore_database(const std::string &backup_path);
template int db_base<db_gov_txn_tag>::restore_database(const std::string &backup_path);
template int db_base<db_sc_transactions_tag>::restore_database(const std::string &backup_path);
template int db_base<db_contract_price_tag>::restore_database(const std::string &backup_path);
template int db_base<db_attestation_tag>::restore_database(const std::string &backup_path);
template int db_base<db_confirmed_blocks_tag>::restore_database(const std::string &backup_path);
template int db_base<db_attestation_ledger_tag>::restore_database(const std::string &backup_path);
template int db_base<db_validator_archive_tag>::restore_database(const std::string &backup_path);
template int db_base<db_quash_ledger_lookup_tag>::restore_database(const std::string &backup_path);
template int db_base<db_system_tag>::restore_database(const std::string &backup_path);
template int db_base<db_gossip_tag>::restore_database(const std::string &backup_path);
template int db_base<db_sc_temp_tag>::restore_database(const std::string &backup_path);
template int db_base<db_allowance_tag>::restore_database(const std::string &backup_path);
template int db_base<db_sc_subscriber_tag>::restore_database(const std::string &backup_path);
template int db_base<db_event_management_tag>::restore_database(const std::string &backup_path);

template <typename T>
int db_base<T>::get_first_data(std::string &key, std::string &value)
{
    if (Reorg::is_in_progress.load()) {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    // Iterate over each item in the database and add them to the write batch for deletion
    rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());
    it->SeekToFirst();

    if (it->Valid())
    {
        if (it->key().ToString() == "commit_marker_key")
        {
            it->Next();

            if (!it->Valid())
            {
                delete it;
                return 0;
            }
        }
        key = it->key().ToString();
        value = it->value().ToString();
        delete it;
        return 1;
    }
    else
    {
        delete it;
        return 0;
    }
}
template int db_base<db_quash_ledger_tag>::get_first_data(std::string &key, std::string &value);

template <typename T>
int db_base<T>::get_next_data(const std::string &iterate_from, std::string &key, std::string &value)
{
    if (Reorg::is_in_progress.load()) {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    // Iterate over each item in the database and add them to the write batch for deletion
    rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());
    it->Seek(iterate_from);

    if (it->Valid() && it->key().ToString() == iterate_from)
    {
        it->Next();
        if (it->Valid())
        {
            key = it->key().ToString();
            value = it->value().ToString();
            delete it;
            return 1;
        }
    }

    delete it;
    return 0;
}
template int db_base<db_quash_ledger_tag>::get_next_data(const std::string &iterate_from, std::string &key, std::string &value);