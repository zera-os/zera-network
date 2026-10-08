#pragma once

#include <string>
#include <atomic>

// Forward declaration
namespace zera_validator { class BlockHeader; }

class Reorg
{
    public:
    static void backup_blockchain(const std::string& block_height);
    static void remove_old_backups(const std::string& block_height);
    // Offline restore runs before open_dbs. Runtime callers schedule a restart.
    static bool restore_database(const std::string &block_height, int code);
    static bool recover_before_open();
    static bool request_restore(const std::string &identifier, int code);
    static void mark_databases_open();
    static void checkpoint_blockchain(const std::string &version, const zera_validator::BlockHeader &header);
    static void reorg_blockchain();
    static std::atomic<bool> is_in_progress;
};
