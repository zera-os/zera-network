#include "temp_data.h"

std::vector<std::string> recieved_txn_tracker::recieved_txns;
std::mutex recieved_txn_tracker::mtx;

void recieved_txn_tracker::add_txn(const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (std::find(recieved_txns.begin(), recieved_txns.end(), txn_hash) != recieved_txns.end())
    {
        return;
    }
    recieved_txns.push_back(txn_hash);
}

void recieved_txn_tracker::remove_txn(const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = std::find(recieved_txns.begin(), recieved_txns.end(), txn_hash);
    if (it != recieved_txns.end())
    {
        recieved_txns.erase(it);
    }
}

bool recieved_txn_tracker::check_txn(const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (std::find(recieved_txns.begin(), recieved_txns.end(), txn_hash) != recieved_txns.end())
    {
        return true;
    }

    return false;
}