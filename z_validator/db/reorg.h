#pragma once

#include <string>
#include <atomic>



class Reorg
{
    public:
    static void backup_blockchain(const std::string& block_height);
    static void remove_old_backups(const std::string& block_height);
    static void restore_database(const std::string &block_height);
    static void reorg_blockchain();
    static std::atomic<bool> is_in_progress;
};
