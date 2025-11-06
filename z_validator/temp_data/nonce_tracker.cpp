#include "temp_data.h"
#include "rocksdb/write_batch.h"
#include "db_base.h"
#include "base58.h"
#include "../logging/logging.h"

std::map<std::string, uint64_t> nonce_tracker::used_nonce; // key = wallet_address, value = nonce   (txns in block)
std::map<std::string, uint64_t> nonce_tracker::sc_nonce; // key = wallet_address, value = nonce   (txns in block)
std::mutex nonce_tracker::mtx;


//add nonce to temp preprocessed_nonce db
void nonce_tracker::add_nonce(const std::string &wallet_address, const uint64_t &nonce, const std::string &txn_hash)
{
    db_preprocessed_nonce::store_single(wallet_address, std::to_string(nonce));
    nonce_txn_tracker::add_txn_nonce(wallet_address, nonce, txn_hash);
}

//get nonce from temp preprocessed_nonce db
bool nonce_tracker::get_nonce(const std::string &wallet_address, uint64_t &nonce)
{
    std::string nonce_data;
    if(!db_preprocessed_nonce::get_single(wallet_address, nonce_data))
    {
        return false;
    }
    nonce = std::stoull(nonce_data);
    
    return true;
}
bool nonce_tracker::remove_pre_nonce(const std::string &wallet_address, uint64_t &nonce)
{
    std::string nonce_data;
    if(!db_preprocessed_nonce::get_single(wallet_address, nonce_data)){
        return false;
    }

    uint64_t current_nonce = std::stoull(nonce_data);

    if(current_nonce >= nonce)
    {
        current_nonce = nonce - 1;
        db_preprocessed_nonce::store_single(wallet_address, std::to_string(current_nonce));
    }

    return true;
}

void nonce_tracker::store_sc_nonce(const std::string &wallet_address, const uint64_t &nonce)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (sc_nonce.count(wallet_address) == 0) {
        sc_nonce[wallet_address] = nonce;
    }
    else{

        uint64_t old_nonce = sc_nonce[wallet_address];
        
        if(old_nonce < nonce)
        {
            sc_nonce[wallet_address] = nonce;
        }
    }
}

void nonce_tracker::add_used_nonce(const std::string &wallet_address, const uint64_t &nonce)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (used_nonce.count(wallet_address) == 0) {
        // wallet_address does not exist in wallet_nonce
        used_nonce[wallet_address] = nonce;
    }
    else{
        uint64_t old_nonce = used_nonce[wallet_address];
        
        if(old_nonce < nonce)
        {
            used_nonce[wallet_address] = nonce;
        }
    }
}

void nonce_tracker::add_sc_to_used_nonce()
{
    for (auto &nonce : sc_nonce)
    {
        add_used_nonce(nonce.first, nonce.second);
    }

    sc_nonce.clear();
}

void nonce_tracker::clear_sc_nonce()
{
    sc_nonce.clear();
}

void nonce_tracker::store_used_nonce(const std::string& block_height)
{
    std::lock_guard<std::mutex> lock(mtx);
    rocksdb::WriteBatch batch;
    
    for (auto &nonce : used_nonce)
    {
        batch.Put(nonce.first, std::to_string(nonce.second));
    }

    db_wallet_nonce::store_batch(batch);
    used_nonce.clear();
}

std::map<std::string, std::string> nonce_txn_tracker::wallet_nonce; // key = wallet_address + nonce, value = txn_hash
std::mutex nonce_txn_tracker::mtx;

void nonce_txn_tracker::add_txn_nonce(const std::string &wallet_adress, const uint64_t &nonce, const std::string& txn_hash)
{
    std::string key = wallet_adress + std::to_string(nonce);
    std::lock_guard<std::mutex> lock(mtx);
    wallet_nonce[key] = txn_hash;
}

bool nonce_txn_tracker::get_txn_hash(const std::string &wallet_address, const uint64_t &nonce, std::string &txn_hash)
{
    std::string key = wallet_address + std::to_string(nonce);
    std::lock_guard<std::mutex> lock(mtx);

    if (wallet_nonce.count(key) == 0) {
        // wallet_address does not exist in wallet_nonce
        return false;
    }
    
    txn_hash = wallet_nonce[key];
    
    return true;
}

void nonce_txn_tracker::remove_txn_nonce(const std::string &wallet_adress, const uint64_t &nonce)
{
    std::string key = wallet_adress + std::to_string(nonce);
    std::lock_guard<std::mutex> lock(mtx);
    wallet_nonce.erase(key);
}
