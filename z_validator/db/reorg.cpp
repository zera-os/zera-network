#include "reorg.h"
#include "safe_restore.h"
#include "database_inventory.h"
#include <memory>
#include <mutex>
#include <algorithm>

#include <iostream>
#include <filesystem>
#include <regex>
#include <string>
#include <filesystem>
#include <chrono>

#include "db_base.h"
#include "validator_network_client.h"
#include "validator.pb.h"
#include "signatures.h"
#include "validators.h"
#include "hashing.h"
#include "../logging/logging.h"

// Initialize the static atomic variable
std::atomic<bool> Reorg::is_in_progress{false};
namespace { std::mutex recovery_mutex; }

void Reorg::remove_old_backups(const std::string &block_height)
{
    std::lock_guard<std::mutex> lock(recovery_mutex);
    if (is_in_progress.load()) return;
    try
    {
        // The reorgs directory may not exist yet on a fresh node.
        std::filesystem::create_directories(DB_REORGS);

        if (block_height.empty() || !std::all_of(block_height.begin(), block_height.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) return;
        uint64_t current_block_height = std::stoull(block_height);
        if (current_block_height < 3) return; // Avoid unsigned underflow pruning every backup.

        for (const auto &entry : std::filesystem::directory_iterator(DB_REORGS))
        {
            if (!entry.is_symlink() && entry.is_directory())
            {
                std::string backup_name = entry.path().filename().string();
                try
                {
                    if (backup_name.empty() || !std::all_of(backup_name.begin(), backup_name.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) continue;
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
    if (is_in_progress.load() || ValidatorConfig::get_shutdown()) return;
    std::string block_height;
    if (!db_confirmed_blocks::get_single(CONFIRMED_BLOCK_LATEST, block_height)) {
        is_in_progress.store(true);
        ValidatorConfig::set_shutdown(true);
        logging::critical("Cannot find confirmed height for reorg; stopping with all data preserved.");
        return;
    }
    request_restore(block_height, 1);
}

void Reorg::backup_blockchain(const std::string &block_height)
{
    std::lock_guard<std::mutex> lock(recovery_mutex);
    if (is_in_progress.load()) return;
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
    db_fee_tokens::backup_database(block_height);
    db_fee_tokens_temp::backup_database(block_height);
    db_staked_coins_voted::backup_database(block_height);
    db_staked_coins_voted_temp::backup_database(block_height);
    db_smart_contract_states::backup_database(block_height);


    // Note: backup_blockchain is for reorg recovery (temporary)
    // No tar needed - these get deleted after block confirmation
}

void Reorg::checkpoint_blockchain(const std::string &version, const zera_validator::BlockHeader &header)
{
    std::lock_guard<std::mutex> lock(recovery_mutex);
    if (is_in_progress.load()) return;
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
    db_fee_tokens::checkpoint_database(version);
    db_fee_tokens_temp::checkpoint_database(version);
    db_staked_coins_voted::checkpoint_database(version);
    db_staked_coins_voted_temp::checkpoint_database(version);
    db_smart_contract_states::checkpoint_database(version);

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

        // Hash the archive so downloaders can verify the exact bytes they received,
        // and sign the whole CheckpointInfo with this validator's original key so a
        // new validator can pin the expected signer and detect a tampered checkpoint.
        std::vector<uint8_t> file_hash = Hashing::sha256_hash_file(tar_file);
        if (file_hash.empty())
        {
            logging::error("Cannot store checkpoint info - failed to hash tar file: " + tar_file);
            return;
        }

        // Create and store CheckpointInfo
        zera_validator::CheckpointInfo checkpoint_info;
        checkpoint_info.set_version(version);
        checkpoint_info.set_block_height(header.block_height());
        checkpoint_info.set_block_hash(header.hash());
        checkpoint_info.set_total_size(file_size);
        checkpoint_info.mutable_created_at()->set_seconds(header.timestamp().seconds());
        checkpoint_info.set_file_hash(std::string(file_hash.begin(), file_hash.end()));
        checkpoint_info.mutable_public_key()->set_single(ValidatorConfig::get_public_key());
        signatures::sign_checkpoint_info(&checkpoint_info, ValidatorConfig::get_key_pair());

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

namespace
{
    std::unique_ptr<safe_restore::DataDirectoryLock> data_directory_lock;
    std::filesystem::path last_restore_archive;
    bool databases_opened = false;

    std::filesystem::path restore_source(const std::string& identifier, int code)
    {
        if (!safe_restore::safe_component(identifier))
            throw std::runtime_error("Invalid restore snapshot identifier");
        switch (code) {
            case 0: return std::filesystem::path(DB_COPY) / identifier;
            case 1: return std::filesystem::path(DB_REORGS) / identifier;
            case 2: return std::filesystem::path(DB_CHECKPOINTS) / identifier;
            default: throw std::runtime_error("Invalid restore code");
        }
    }

    void validate_snapshot_database(const std::filesystem::path& path)
    {
        rocksdb::Options options;
        options.create_if_missing = false;
        options.paranoid_checks = true;
        rocksdb::DB* raw = nullptr;
        auto status = rocksdb::DB::OpenForReadOnly(options, path.string(), &raw);
        std::unique_ptr<rocksdb::DB> database(raw);
        if (!status.ok()) throw std::runtime_error("Cannot read staged database " + path.string() + ": " + status.ToString());
        status = database->VerifyChecksum();
        if (!status.ok()) throw std::runtime_error("Corrupt staged database " + path.string() + ": " + status.ToString());
    }
}

bool Reorg::restore_database(const std::string& identifier, int code)
{
    // Filesystem replacement is only permitted before RocksDB handles/workers exist.
    if (databases_opened || !data_directory_lock) {
        logging::critical("Restore refused while databases are open; request a restart-based restore instead.");
        ValidatorConfig::set_shutdown(true);
        return false;
    }
    try {
        std::vector<std::string> names;
#define ADD_DATABASE_NAME(DB) names.emplace_back(DB##_tag::DB_NAME);
        ZERA_DATABASES(ADD_DATABASE_NAME)
#undef ADD_DATABASE_NAME
        const auto result = safe_restore::restore(DATA_DIR, restore_source(identifier, code), names, validate_snapshot_database);
        if (!result.ok) throw std::runtime_error(result.error + "; retained evidence: " + result.retained.string());
        last_restore_archive = result.retained;
        logging::print("Restore completed for snapshot:", identifier, "Previous data retained at: " + result.retained.string(), true);
        return true;
    } catch (const std::exception& error) {
        logging::critical("Restore failed; refusing to open databases: " + std::string(error.what()));
        ValidatorConfig::set_shutdown(true);
        return false;
    }
}

void Reorg::mark_databases_open()
{
    databases_opened = true;
}

bool Reorg::recover_before_open()
{
    try {
        data_directory_lock = std::make_unique<safe_restore::DataDirectoryLock>(DATA_DIR);
        safe_restore::check_no_interrupted_restore(DATA_DIR);
        const auto pending = std::filesystem::path(DATA_DIR) / "restore.pending";
        if (std::filesystem::symlink_status(pending).type() != std::filesystem::file_type::not_found) {
            if (std::filesystem::is_symlink(pending) || !std::filesystem::is_regular_file(pending) || std::filesystem::file_size(pending) > 512)
                throw std::runtime_error("Invalid pending restore record");
            std::ifstream file(pending);
            int code;
            std::string identifier, extra;
            if (!(file >> code >> identifier) || (file >> extra)) throw std::runtime_error("Incomplete pending restore record");
            if (!restore_database(identifier, code)) return false;
            std::filesystem::rename(pending, last_restore_archive / "request.txt");
            safe_restore::sync_path(DATA_DIR);
            safe_restore::sync_path(last_restore_archive);
            return true;
        }
        const auto configured = ValidatorConfig::get_block_height();
        if (!configured.empty() && configured != "NONE") return restore_database(configured, 0);
        return true;
    } catch (const std::exception& error) {
        logging::critical("Recovery requires operator attention; data preserved: " + std::string(error.what()));
        ValidatorConfig::set_shutdown(true);
        return false;
    }
}

bool Reorg::request_restore(const std::string& identifier, int code)
{
    std::lock_guard<std::mutex> lock(recovery_mutex);
    if (is_in_progress.load()) return false;
    is_in_progress.store(true);
    ValidatorConfig::set_shutdown(true);
    try {
        restore_source(identifier, code); // Validate before writing the request.
        const auto pending = std::filesystem::path(DATA_DIR) / "restore.pending";
        safe_restore::write_new_file(pending, std::to_string(code) + "\n" + identifier + "\n");
        logging::print("Restore scheduled for restart; existing databases and backups preserved. Snapshot:", identifier, true);
        return true;
    } catch (const std::exception& error) {
        logging::critical("Could not schedule restore; stopping without replacing data: " + std::string(error.what()));
        return false;
    }
}
