#include "reorg.h"

#include <iostream>
#include <filesystem>
#include <regex>
#include <string>
#include <filesystem>
#include <chrono>

#include "db_base.h"
#include "validator_network_client.h"
#include "validator.pb.h"
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
    restore_database(block_height, 1);

    // Shutdown triggered.
    if (ValidatorConfig::get_shutdown())
    {
        return;
    }

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

    // Note: backup_blockchain is for reorg recovery (temporary)
    // No tar needed - these get deleted after block confirmation
}

void Reorg::checkpoint_blockchain(const std::string &version, const zera_validator::BlockHeader &header)
{
    // 1. Checkpoint all individual databases
    db_headers::checkpoint_database(version);
    db_blocks::checkpoint_database(version);
    db_contract_supply::checkpoint_database(version);
    db_contracts::checkpoint_database(version);
    db_hash_index::checkpoint_database(version);
    db_transactions::checkpoint_database(version);
    db_validators::checkpoint_database(version);
    db_wallets::checkpoint_database(version);
    db_wallets_temp::checkpoint_database(version);
    db_smart_contracts::checkpoint_database(version);
    db_restricted_wallets::checkpoint_database(version);
    db_block_txns::checkpoint_database(version);
    db_contract_items::checkpoint_database(version);
    db_validator_lookup::checkpoint_database(version);
    db_validator_unbond::checkpoint_database(version);
    db_proposal_ledger::checkpoint_database(version);
    db_proposals::checkpoint_database(version);
    db_status_fee::checkpoint_database(version);
    db_process_ledger::checkpoint_database(version);
    db_process_adaptive_ledger::checkpoint_database(version);
    db_expense_ratio::checkpoint_database(version);
    db_proposal_wallets::checkpoint_database(version);
    db_proposals_temp::checkpoint_database(version);
    db_delegate_vote::checkpoint_database(version);
    db_delegate_recipient::checkpoint_database(version);
    db_timed_txns::checkpoint_database(version);
    db_quash_lookup::checkpoint_database(version);
    db_quash_ledger::checkpoint_database(version);
    db_wallet_lookup::checkpoint_database(version);
    db_delegate_wallets::checkpoint_database(version);
    db_fast_quorum::checkpoint_database(version);
    db_duplicate_txn::checkpoint_database(version);
    db_delegatees::checkpoint_database(version);
    db_voted_proposals::checkpoint_database(version);
    db_wallet_nonce::checkpoint_database(version);
    db_processed_txns::checkpoint_database(version);
    db_processed_wallets::checkpoint_database(version);
    db_preprocessed_nonce::checkpoint_database(version);
    db_validate_txns::checkpoint_database(version);
    db_sc_transactions::checkpoint_database(version);
    db_gov_txn::checkpoint_database(version);
    db_contract_price::checkpoint_database(version);
    db_attestation::checkpoint_database(version);
    db_confirmed_blocks::checkpoint_database(version);
    db_attestation_ledger::checkpoint_database(version);
    db_validator_archive::checkpoint_database(version);
    db_quash_ledger_lookup::checkpoint_database(version);
    db_system::checkpoint_database(version);
    db_gossip::checkpoint_database(version);
    db_sc_temp::checkpoint_database(version);
    db_allowance::checkpoint_database(version);
    db_event_management::checkpoint_database(version);
    db_sc_subscriber::checkpoint_database(version);

    // 2. Create tar.gz of entire checkpoint directory for state sync
    std::string checkpoint_dir = DB_CHECKPOINTS + version;
    std::string tar_file = DB_CHECKPOINTS + version + ".tar.gz";
    std::string cmd = "tar -czf " + tar_file + " -C " + DB_CHECKPOINTS + " " + version;

    int result = system(cmd.c_str());
    if (result == 0)
    {
        logging::print("Checkpoint archive created:", tar_file);
        // Keep raw RocksDB directory for local validators restarting after version upgrade
        // New validators can download tar, existing validators can use raw directory
        // Get file size
        std::string tar_file_temp = DB_CHECKPOINTS + version + ".tar.gz";
        if (!std::filesystem::exists(tar_file_temp))
        {
            logging::error("Cannot store checkpoint info - tar file not found: " + tar_file);
            return;
        }

        uint64_t file_size = std::filesystem::file_size(tar_file);

        // Create and store CheckpointInfo
        zera_validator::CheckpointInfo checkpoint_info;
        checkpoint_info.set_version(version);
        checkpoint_info.set_block_height(header.block_height());
        checkpoint_info.set_block_hash(header.hash());
        checkpoint_info.set_total_size(file_size);
        checkpoint_info.mutable_created_at()->set_seconds(header.timestamp().seconds());

        std::string checkpoint_key = CHECKPOINT_INFO + version;
        std::string latest_key = CHECKPOINT_INFO + "latest";
        db_system::store_single(checkpoint_key, checkpoint_info.SerializeAsString());
        db_system::store_single(latest_key, checkpoint_info.SerializeAsString());
        logging::print("Checkpoint info stored for version:", version, "block height:", std::to_string(header.block_height()));
    }
    else
    {
        logging::error("Failed to create checkpoint archive: " + tar_file);
    }
}

void Reorg::restore_database(const std::string &block_height, int code)
{
    std::string reorg_path = DB_REORGS;
    std::string block_path = DB_DIRECTORY;

    std::filesystem::remove_all(reorg_path);
    std::filesystem::remove_all(block_path);

    db_headers::restore_database(block_height, code);
    db_blocks::restore_database(block_height, code);
    db_contract_supply::restore_database(block_height, code);
    db_contracts::restore_database(block_height, code);
    db_hash_index::restore_database(block_height, code);
    db_transactions::restore_database(block_height, code);
    db_validators::restore_database(block_height, code);
    db_wallets::restore_database(block_height, code);
    db_wallets_temp::restore_database(block_height, code);
    db_smart_contracts::restore_database(block_height, code);
    db_restricted_wallets::restore_database(block_height, code);
    db_block_txns::restore_database(block_height, code);
    db_contract_items::restore_database(block_height, code);
    db_validator_lookup::restore_database(block_height, code);
    db_validator_unbond::restore_database(block_height, code);
    db_proposal_ledger::restore_database(block_height, code);
    db_proposals::restore_database(block_height, code);
    db_status_fee::restore_database(block_height, code);
    db_process_ledger::restore_database(block_height, code);
    db_process_adaptive_ledger::restore_database(block_height, code);
    db_expense_ratio::restore_database(block_height, code);
    db_proposal_wallets::restore_database(block_height, code);
    db_proposals_temp::restore_database(block_height, code);
    db_delegate_vote::restore_database(block_height, code);
    db_delegate_recipient::restore_database(block_height, code);
    db_timed_txns::restore_database(block_height, code);
    db_quash_lookup::restore_database(block_height, code);
    db_quash_ledger::restore_database(block_height, code);
    db_wallet_lookup::restore_database(block_height, code);
    db_delegate_wallets::restore_database(block_height, code);
    db_fast_quorum::restore_database(block_height, code);
    db_duplicate_txn::restore_database(block_height, code);
    db_delegatees::restore_database(block_height, code);
    db_voted_proposals::restore_database(block_height, code);
    db_wallet_nonce::restore_database(block_height, code);
    db_processed_txns::restore_database(block_height, code);
    db_processed_wallets::restore_database(block_height, code);
    db_preprocessed_nonce::restore_database(block_height, code);
    db_validate_txns::restore_database(block_height, code);
    db_sc_transactions::restore_database(block_height, code);
    db_gov_txn::restore_database(block_height, code);
    db_contract_price::restore_database(block_height, code);
    db_attestation::restore_database(block_height, code);
    db_confirmed_blocks::restore_database(block_height, code);
    db_attestation_ledger::restore_database(block_height, code);
    db_validator_archive::restore_database(block_height, code);
    db_quash_ledger_lookup::restore_database(block_height, code);
    db_system::restore_database(block_height, code);
    db_gossip::restore_database(block_height, code);
    db_sc_temp::restore_database(block_height, code);
    db_allowance::restore_database(block_height, code);
    db_sc_subscriber::restore_database(block_height, code);
    db_event_management::restore_database(block_height, code);

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
