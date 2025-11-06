#include "reorg.h"

#include <iostream>
#include <filesystem>
#include <regex>
#include <string>
#include <filesystem>

#include "db_base.h"
#include "validator_network_client.h"
#include "../logging/logging.h"

// Initialize the static atomic variable
std::atomic<bool> Reorg::is_in_progress{false};

void Reorg::remove_old_backups(const std::string &block_height)
{
    try
    {
        uint64_t current_block_height = std::stoull(block_height);

        for (const auto &entry : std::filesystem::directory_iterator(DB_REORGS))
        {
            if (entry.is_directory())
            {
                std::string backup_name = entry.path().filename().string();
                try
                {
                    uint64_t backup_block_height = std::stoull(backup_name);

                    if (backup_block_height <= (current_block_height - 3))
                    {
                        std::filesystem::remove_all(entry.path());
                    }
                }
                catch (const std::invalid_argument &)
                {
                    logging::print("Invalid directory name, not an integer:", backup_name);
                }
                catch (const std::out_of_range &)
                {
                    logging::print("Integer out of range:", backup_name);
                }
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error removing old backups: " << e.what() << std::endl;
    }
}

void Reorg::reorg_blockchain()
{
    std::string block_height;
    db_confirmed_blocks::get_single(CONFIRMED_BLOCK_LATEST, block_height);
    is_in_progress.store(true);
    restore_database(block_height);
    is_in_progress.store(false);
    ValidatorNetworkClient::StartSyncBlockchain();
}

void Reorg::backup_blockchain(const std::string &block_height)
{
    db_headers::backup_database(block_height);
    db_blocks::backup_database(block_height);
    db_contract_supply::backup_database(block_height);
    db_contracts::backup_database(block_height);
    db_hash_index::backup_database(block_height);
    db_transactions::backup_database(block_height);
    db_validators::backup_database(block_height);
    db_wallets::backup_database(block_height);
    db_wallets_temp::backup_database(block_height);
    db_smart_contracts::backup_database(block_height);
    db_restricted_wallets::backup_database(block_height);
    db_block_txns::backup_database(block_height);
    db_contract_items::backup_database(block_height);
    db_validator_lookup::backup_database(block_height);
    db_validator_unbond::backup_database(block_height);
    db_proposal_ledger::backup_database(block_height);
    db_proposals::backup_database(block_height);
    db_status_fee::backup_database(block_height);
    db_process_ledger::backup_database(block_height);
    db_process_adaptive_ledger::backup_database(block_height);
    db_expense_ratio::backup_database(block_height);
    db_proposal_wallets::backup_database(block_height);
    db_proposals_temp::backup_database(block_height);
    db_delegate_vote::backup_database(block_height);
    db_delegate_recipient::backup_database(block_height);
    db_timed_txns::backup_database(block_height);
    db_quash_lookup::backup_database(block_height);
    db_quash_ledger::backup_database(block_height);
    db_wallet_lookup::backup_database(block_height);
    db_delegate_wallets::backup_database(block_height);
    db_fast_quorum::backup_database(block_height);
    db_duplicate_txn::backup_database(block_height);
    db_delegatees::backup_database(block_height);
    db_voted_proposals::backup_database(block_height);
    db_wallet_nonce::backup_database(block_height);
    db_processed_txns::backup_database(block_height);
    db_processed_wallets::backup_database(block_height);
    db_preprocessed_nonce::backup_database(block_height);
    db_validate_txns::backup_database(block_height);
    db_sc_transactions::backup_database(block_height);
    db_gov_txn::backup_database(block_height);
    db_contract_price::backup_database(block_height);
    db_attestation::backup_database(block_height);
    db_confirmed_blocks::backup_database(block_height);
    db_attestation_ledger::backup_database(block_height);
    db_validator_archive::backup_database(block_height);
    db_quash_ledger_lookup::backup_database(block_height);
    db_system::backup_database(block_height);
    db_gossip::backup_database(block_height);
    db_sc_temp::backup_database(block_height);
    db_allowance::backup_database(block_height);
    db_event_management::backup_database(block_height);
    db_sc_subscriber::backup_database(block_height);
}

void Reorg::restore_database(const std::string &block_height)
{
    std::string reorg_path = DB_REORGS; 
    std::string block_path = DB_DIRECTORY;

    std::filesystem::remove_all(reorg_path);
    std::filesystem::remove_all(block_path);

    db_headers::restore_database(block_height);
    db_blocks::restore_database(block_height);
    db_contract_supply::restore_database(block_height);
    db_contracts::restore_database(block_height);
    db_hash_index::restore_database(block_height);
    db_transactions::restore_database(block_height);
    db_validators::restore_database(block_height);
    db_wallets::restore_database(block_height);
    db_wallets_temp::restore_database(block_height);
    db_smart_contracts::restore_database(block_height);
    db_restricted_wallets::restore_database(block_height);
    db_block_txns::restore_database(block_height);
    db_contract_items::restore_database(block_height);
    db_validator_lookup::restore_database(block_height);
    db_validator_unbond::restore_database(block_height);
    db_proposal_ledger::restore_database(block_height);
    db_proposals::restore_database(block_height);
    db_status_fee::restore_database(block_height);
    db_process_ledger::restore_database(block_height);
    db_process_adaptive_ledger::restore_database(block_height);
    db_expense_ratio::restore_database(block_height);
    db_proposal_wallets::restore_database(block_height);
    db_proposals_temp::restore_database(block_height);
    db_delegate_vote::restore_database(block_height);
    db_delegate_recipient::restore_database(block_height);
    db_timed_txns::restore_database(block_height);
    db_quash_lookup::restore_database(block_height);
    db_quash_ledger::restore_database(block_height);
    db_wallet_lookup::restore_database(block_height);
    db_delegate_wallets::restore_database(block_height);
    db_fast_quorum::restore_database(block_height);
    db_duplicate_txn::restore_database(block_height);
    db_delegatees::restore_database(block_height);
    db_voted_proposals::restore_database(block_height);
    db_wallet_nonce::restore_database(block_height);
    db_processed_txns::restore_database(block_height);
    db_processed_wallets::restore_database(block_height);
    db_preprocessed_nonce::restore_database(block_height);
    db_validate_txns::restore_database(block_height);
    db_sc_transactions::restore_database(block_height);
    db_gov_txn::restore_database(block_height);
    db_contract_price::restore_database(block_height);
    db_attestation::restore_database(block_height);
    db_confirmed_blocks::restore_database(block_height);
    db_attestation_ledger::restore_database(block_height);
    db_validator_archive::restore_database(block_height);
    db_quash_ledger_lookup::restore_database(block_height);
    db_system::restore_database(block_height);
    db_gossip::restore_database(block_height);
    db_sc_temp::restore_database(block_height);
    db_allowance::restore_database(block_height);
    db_sc_subscriber::restore_database(block_height);
    db_event_management::restore_database(block_height);

    db_preprocessed_nonce::remove_all();
    db_processed_wallets::remove_all();
    db_processed_txns::remove_all();
    db_proposals_temp::remove_all();
    db_fast_quorum::remove_all();
    db_transactions::remove_all();
    db_wallets_temp::remove_all();
    db_gossip::remove_all();

    std::vector<std::string> keys;
    std::vector<std::string> values;
    db_wallet_nonce::get_all_data(keys, values);

    int x = 0;
    rocksdb::WriteBatch batch;
    while (x < keys.size())
    {
        batch.Put(keys.at(x), values.at(x));
        x++;
    }
    db_preprocessed_nonce::store_batch(batch);
    

    logging::print("Restore completed for block height:", block_height);
}
