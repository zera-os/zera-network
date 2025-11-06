#include "temp_data.h"
#include "db_base.h"
#include "base58.h"
#include "../logging/logging.h"
#include "wallets.h"
#include <unordered_map>

namespace
{
    bool get_proposal_wallet(const std::string &wallet_address, zera_validator::VoteWallet &vote_wallet)
    {
        std::string proposal_wallet_data;
        if (!db_proposal_wallets::get_single(wallet_address, proposal_wallet_data) || !vote_wallet.ParseFromString(proposal_wallet_data))
        {
            return false;
        }
        return true;
    }

    void adjust_proposal_votes(const std::string &wallet_address, const uint256_t &add_amount, const uint256_t &remove_amount, const std::string contract_id)
    {
        zera_validator::VoteWallet vote_wallet;
        if (get_proposal_wallet(wallet_address, vote_wallet))
        {
            for (auto proposal_ledger : vote_wallet.proposal_votes())
            {
                std::vector<uint8_t> vec = base58_decode(proposal_ledger.first);
                std::string proposal_id(vec.begin(), vec.end());
                std::string proposal_data;
                zera_validator::Proposal proposal;
                if ((!db_proposals_temp::get_single(proposal_id, proposal_data) || !proposal.ParseFromString(proposal_data)) &&
                    (!db_proposals::get_single(proposal_id, proposal_data) || !proposal.ParseFromString(proposal_data)))
                {
                    continue;
                }

                if (proposal_ledger.second.has_support())
                {
                    if (proposal_ledger.second.support())
                    {
                        auto map = proposal.mutable_yes();
                        if (map->count(contract_id) > 0)
                        {
                            // The key exists in the map
                            std::string value_str = (*map)[contract_id];
                            uint256_t value = boost::lexical_cast<uint256_t>(value_str);
                            value += add_amount;
                            value -= remove_amount;
                            (*map)[contract_id] = boost::lexical_cast<std::string>(value);
                        }
                        else
                        {
                            continue;
                        }
                    }
                    else
                    {
                        auto map = proposal.mutable_no();
                        if (map->count(contract_id) > 0)
                        {
                            // The key exists in the map
                            std::string value_str = (*map)[contract_id];
                            uint256_t value = boost::lexical_cast<uint256_t>(value_str);
                            value += add_amount;
                            value -= remove_amount;
                            (*map)[contract_id] = boost::lexical_cast<std::string>(value);
                        }
                        else
                        {
                            continue;
                        }
                    }
                }
                else if (proposal_ledger.second.has_option())
                {
                    auto outer_map = proposal.mutable_options();
                    auto inner_map = (*outer_map)[proposal_ledger.second.option()].mutable_vote();

                    if (inner_map->count(contract_id) > 0)
                    {
                        // The key exists in the map
                        std::string value_str = (*inner_map)[contract_id];
                        uint256_t value = boost::lexical_cast<uint256_t>(value_str);
                        value += add_amount;
                        value -= remove_amount;
                        (*inner_map)[contract_id] = boost::lexical_cast<std::string>(value);
                    }
                    else
                    {
                        // The key does not exist in the map
                        continue;
                    }
                }
                db_proposals_temp::store_single(proposal_id, proposal.SerializeAsString());
            }
        }
    }
}

std::map<std::string, uint256_t> balance_tracker::block_balances;
std::map<std::string, std::map<std::string, uint256_t>> balance_tracker::add_txn_balances;
std::map<std::string, std::map<std::string, uint256_t>> balance_tracker::subtract_txn_balances;
std::mutex balance_tracker::mtx;

void balance_tracker::add_txn_balance_transfer(const google::protobuf::RepeatedPtrField<zera_txn::OutputTransfers> &transfers, const std::string &contract_id, const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string balance_key = "ADD_BALANCE_" + txn_hash;
    std::string balance_value;
    zera_validator::BalanceTracker balance_tracker;
    rocksdb::WriteBatch processed_batch;
    std::unordered_map<std::string, std::string> batch_keys;

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
    }

    auto &wallet_balances = *balance_tracker.mutable_wallet_balances();

    for (auto transfer : transfers)
    {
        std::string wallet_key = transfer.wallet_address() + contract_id;

        auto wallet_vec = base58_encode(transfer.wallet_address());
        std::string key(wallet_vec.begin(), wallet_vec.end());
        key = key + contract_id;

        uint256_t amount(transfer.amount());
        if (wallet_balances.find(key) != wallet_balances.end())
        {
            uint256_t balance(wallet_balances[key]);
            balance += amount;
            wallet_balances[key] = boost::lexical_cast<std::string>(balance);
        }
        else
        {
            wallet_balances[key] = boost::lexical_cast<std::string>(amount);
        }

        std::string balance_str;

        if (batch_keys.find(wallet_key) != batch_keys.end())
        {
            uint256_t balance(batch_keys[wallet_key]);
            balance += amount;
            processed_batch.Put(wallet_key, balance.str());
            batch_keys[wallet_key] = balance.str();
        }
        else
        {
            if (!db_processed_wallets::get_single(wallet_key, balance_str))
            {
                db_wallets::get_single(wallet_key, balance_str);
            }

            uint256_t balance(balance_str);
            balance += amount;

            // Add key to the batch and track it in the map
            processed_batch.Put(wallet_key, balance.str());
            batch_keys[wallet_key] = balance.str();
        }
    }

    processed_batch.Put(balance_key, balance_tracker.SerializeAsString());
    db_processed_wallets::store_batch(processed_batch);
}

void balance_tracker::add_txn_balance_premint(const google::protobuf::RepeatedPtrField<zera_txn::PreMintWallet> &premints, const std::string &contract_id, const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string balance_key = "ADD_BALANCE_" + txn_hash;
    std::string balance_value;
    zera_validator::BalanceTracker balance_tracker;
    rocksdb::WriteBatch processed_batch;

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
    }

    auto &wallet_balances = *balance_tracker.mutable_wallet_balances();

    for (auto premint : premints)
    {
        std::string wallet_key = premint.address() + contract_id;

        auto wallet_vec = base58_encode(premint.address());
        std::string key(wallet_vec.begin(), wallet_vec.end());
        key = key + contract_id;

        uint256_t amount(premint.amount());
        if (wallet_balances.find(key) != wallet_balances.end())
        {
            uint256_t balance(wallet_balances[key]);
            balance += amount;
            wallet_balances[key] = boost::lexical_cast<std::string>(balance);
        }
        else
        {
            wallet_balances[key] = boost::lexical_cast<std::string>(amount);
        }

        std::string balance_str;
        if (!db_processed_wallets::get_single(wallet_key, balance_str))
        {
            db_wallets::get_single(wallet_key, balance_str);
        }

        uint256_t balance(balance_str);
        balance += amount;

        processed_batch.Put(wallet_key, balance.str());
    }

    processed_batch.Put(balance_key, balance_tracker.SerializeAsString());
    db_processed_wallets::store_batch(processed_batch);
}

void balance_tracker::add_txn_balance(const std::string &wallet_address, const std::string &contract_id, const uint256_t &amount, const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string balance_key = "ADD_BALANCE_" + txn_hash;
    std::string balance_value;
    zera_validator::BalanceTracker balance_tracker;
    std::string wallet_key = wallet_address + contract_id;

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
    }
    auto &wallet_balances = *balance_tracker.mutable_wallet_balances();

    auto wallet_vec = base58_encode(wallet_address);
    std::string key(wallet_vec.begin(), wallet_vec.end());
    key = key + contract_id;

    if (wallet_balances.find(key) != wallet_balances.end())
    {
        uint256_t balance(wallet_balances[key]);
        balance += amount;
        wallet_balances[key] = boost::lexical_cast<std::string>(balance);
    }
    else
    {
        wallet_balances[key] = boost::lexical_cast<std::string>(amount);
    }

    db_processed_wallets::store_single(balance_key, balance_tracker.SerializeAsString());

    std::string balance_str;
    if (!db_processed_wallets::get_single(wallet_key, balance_str))
    {
        db_wallets::get_single(wallet_key, balance_str);
    }

    uint256_t balance(balance_str);
    balance += amount;
    db_processed_wallets::store_single(wallet_key, boost::lexical_cast<std::string>(balance));
}

ZeraStatus balance_tracker::subtract_txn_balance_transfer_allowance(const google::protobuf::RepeatedPtrField<zera_txn::InputTransfers> &transfers, const std::vector<std::string> &wallet_adrs, const std::string &contract_id, const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string balance_key = "SUB_BALANCE_" + txn_hash;
    std::string balance_value;
    zera_validator::BalanceTracker balance_tracker;
    rocksdb::WriteBatch processed_batch;

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
    }

    auto &wallet_balances = *balance_tracker.mutable_wallet_balances();

    int x = 0;
    for (auto transfer : transfers)
    {
        std::string balance_str;
        uint256_t amount(transfer.amount());
        std::string wallet_adr = wallet_adrs[x];
        std::string wallet_key = wallet_adr + contract_id;
        if (db_processed_wallets::get_single(wallet_key, balance_str) || db_wallets::get_single(wallet_key, balance_str))
        {
            uint256_t balance(balance_str);

            if (balance < amount)
            {
                std::string message = "balance_tracker.cpp: subtract_txn_balances: Insufficient wallet balance.";

                return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, message, zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
            }

            balance -= amount;
            processed_batch.Put(wallet_key, balance.str());
        }
        else
        {
            processed_batch.Put(balance_key, balance_tracker.SerializeAsString());
            db_processed_wallets::store_batch(processed_batch);
            std::string message = "balance_tracker.cpp: subtract_txn_balances_allowance: Invalid wallet address. : " + amount.str();
            return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, message, zera_txn::TXN_STATUS::INVALID_WALLET_ADDRESS);
        }

        auto wallet_vec = base58_encode(wallet_adr);
        std::string key(wallet_vec.begin(), wallet_vec.end());
        key = key + contract_id;
        if (wallet_balances.find(key) != wallet_balances.end())
        {
            // Wallet exists, update the balance
            uint256_t balance(wallet_balances[key]);
            balance += amount;
            wallet_balances[key] = boost::lexical_cast<std::string>(balance);
        }
        else
        {
            // Wallet does not exist, add it
            wallet_balances[key] = boost::lexical_cast<std::string>(amount);
        }

        x++;
    }

    processed_batch.Put(balance_key, balance_tracker.SerializeAsString());
    db_processed_wallets::store_batch(processed_batch);

    return ZeraStatus();
}

ZeraStatus balance_tracker::subtract_txn_balance_transfer(const google::protobuf::RepeatedPtrField<zera_txn::InputTransfers> &transfers, const std::vector<zera_txn::PublicKey> &public_keys, const std::string &contract_id, const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string balance_key = "SUB_BALANCE_" + txn_hash;
    std::string balance_value;
    zera_validator::BalanceTracker balance_tracker;
    rocksdb::WriteBatch processed_batch;

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
    }

    auto &wallet_balances = *balance_tracker.mutable_wallet_balances();

    int x = 0;
    for (auto transfer : transfers)
    {
        std::string balance_str;
        uint256_t amount(transfer.amount());
        std::string wallet_adr = wallets::generate_wallet(public_keys[x]);
        std::string wallet_key = wallet_adr + contract_id;
        if (db_processed_wallets::get_single(wallet_key, balance_str) || db_wallets::get_single(wallet_key, balance_str))
        {
            uint256_t balance(balance_str);

            if (balance < amount)
            {
                std::string message = "balance_tracker.cpp: subtract_txn_balances: Insufficient wallet balance.";

                return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, message, zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
            }

            balance -= amount;
            processed_batch.Put(wallet_key, balance.str());
        }
        else
        {
            processed_batch.Put(balance_key, balance_tracker.SerializeAsString());
            db_processed_wallets::store_batch(processed_batch);
            std::string message = "balance_tracker.cpp: subtract_txn_balances: Invalid wallet address. : " + amount.str();
            return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, message, zera_txn::TXN_STATUS::INVALID_WALLET_ADDRESS);
        }

        auto wallet_vec = base58_encode(wallet_adr);
        std::string key(wallet_vec.begin(), wallet_vec.end());
        key = key + contract_id;
        if (wallet_balances.find(key) != wallet_balances.end())
        {
            // Wallet exists, update the balance
            uint256_t balance(wallet_balances[key]);
            balance += amount;
            wallet_balances[key] = boost::lexical_cast<std::string>(balance);
        }
        else
        {
            // Wallet does not exist, add it
            wallet_balances[key] = boost::lexical_cast<std::string>(amount);
        }

        x++;
    }

    processed_batch.Put(balance_key, balance_tracker.SerializeAsString());
    db_processed_wallets::store_batch(processed_batch);

    return ZeraStatus();
}

ZeraStatus balance_tracker::subtract_txn_balance(const std::string &wallet_address, const std::string &contract_id, const uint256_t &amount, const std::string &txn_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string balance_key = "SUB_BALANCE_" + txn_hash;
    std::string balance_value;
    zera_validator::BalanceTracker balance_tracker;
    std::string wallet_key = wallet_address + contract_id;

    std::string balance_str;

    if (db_processed_wallets::get_single(wallet_key, balance_str) || db_wallets::get_single(wallet_key, balance_str))
    {
        uint256_t balance(balance_str);

        if (balance < amount)
        {
            std::string message = "Wallet_adr: " +  base58_encode(wallet_address) + contract_id + "\nbalance_tracker.cpp: subtract_txn_balances: Insufficient wallet balance.";
            return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, message, zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
        }

        balance -= amount;
        db_processed_wallets::store_single(wallet_key, boost::lexical_cast<std::string>(balance));
    }
    else
    {
        std::string message = "balance_tracker.cpp: subtract_txn_balances: Invalid wallet address. : " + amount.str();

        return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, message, zera_txn::TXN_STATUS::INVALID_WALLET_ADDRESS);
    }

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
    }

    // Use the map for efficient lookups and updates
    auto &wallet_balances = *balance_tracker.mutable_wallet_balances();
    auto wallet_vec = base58_encode(wallet_address);
    std::string key(wallet_vec.begin(), wallet_vec.end());
    key = key + contract_id;
    if (wallet_balances.find(key) != wallet_balances.end())
    {
        // Wallet exists, update the balance
        uint256_t balance(wallet_balances[key]);
        balance += amount;
        wallet_balances[key] = boost::lexical_cast<std::string>(balance);
    }
    else
    {
        // Wallet does not exist, add it
        wallet_balances[key] = boost::lexical_cast<std::string>(amount);
    }

    db_processed_wallets::store_single(balance_key, balance_tracker.SerializeAsString());

    return ZeraStatus();
}
void balance_tracker::get_txn_balance(const std::string &txn_hash, zera_validator::BalanceTracker &add_txn_balance, zera_validator::BalanceTracker &subtract_txn_balance)
{
    std::string balance_key = "ADD_BALANCE_" + txn_hash;
    std::string sub_balance_key = "SUB_BALANCE_" + txn_hash;
    std::string balance_value;
    std::string sub_balance_value;
    zera_validator::BalanceTracker sub_balance_tracker;
    zera_validator::BalanceTracker balance_tracker;

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
        add_txn_balance.CopyFrom(balance_tracker);
    }
    if (db_processed_wallets::get_single(sub_balance_key, sub_balance_value))
    {
        sub_balance_tracker.ParseFromString(sub_balance_value);
        subtract_txn_balance.CopyFrom(sub_balance_tracker);
    }
}

void balance_tracker::remove_txn_balance(const std::string &txn_hash)
{
    std::string balance_key = "ADD_BALANCE_" + txn_hash;
    std::string sub_balance_key = "SUB_BALANCE_" + txn_hash;

    std::string balance_value;
    std::string sub_balance_value;

    zera_validator::BalanceTracker balance_tracker;
    zera_validator::BalanceTracker sub_balance_tracker;

    rocksdb::WriteBatch processed_batch;

    std::map<std::string, uint256_t> balance_map;

    if (db_processed_wallets::get_single(balance_key, balance_value))
    {
        balance_tracker.ParseFromString(balance_value);
    }
    if (db_processed_wallets::get_single(sub_balance_key, sub_balance_value))
    {
        sub_balance_tracker.ParseFromString(sub_balance_value);
    }

    for (auto balance_tracker : balance_tracker.wallet_balances())
    {
        std::string wallet_key = balance_tracker.first;
        uint256_t amount(balance_tracker.second);

        std::string balance_str;

        if (db_processed_wallets::get_single(wallet_key, balance_str))
        {
            uint256_t balance(balance_str);
            balance -= amount;
            processed_batch.Put(wallet_key, balance.str());
            balance_map[wallet_key] = balance;
        }
    }

    for (auto balance_tracker : sub_balance_tracker.wallet_balances())
    {
        std::string wallet_key = balance_tracker.first;
        uint256_t amount(balance_tracker.second);

        std::string balance_str;

        if (db_processed_wallets::get_single(wallet_key, balance_str))
        {
            uint256_t balance(balance_str);
            if (balance_map.find(wallet_key) != balance_map.end())
            {
                uint256_t old_balance(balance_map[wallet_key]);
                balance = old_balance + amount;
            }
            else
            {
                balance += amount;
            }
            processed_batch.Put(wallet_key, balance.str());
        }
    }

    db_processed_wallets::store_batch(processed_batch);
    db_processed_wallets::remove_single(balance_key);
    db_processed_wallets::remove_single(sub_balance_key);
}

void balance_tracker::add_balance(const std::string wallet_address, const std::string contract_id, const uint256_t &amount)
{
    std::string sender_key = wallet_address + contract_id;
    // std::lock_guard<std::mutex> lock(mtx);

    if (block_balances.find(sender_key) == block_balances.end())
    {
        std::string balance_str;
        if (!db_wallets_temp::get_single(sender_key, balance_str) && !db_wallets::get_single(sender_key, balance_str))
        {
            balance_str = "0";
        }

        const uint256_t balance(balance_str);
        block_balances[sender_key] = balance;
    }
    uint256_t zero(0);

    adjust_proposal_votes(wallet_address, amount, zero, contract_id);

    // add new balance to recipient balances
    block_balances[sender_key] += amount;
}

ZeraStatus balance_tracker::remove_balance(const std::string wallet_address, const std::string contract_id, const uint256_t &amount)
{

    std::string sender_key = wallet_address + contract_id;
    // std::lock_guard<std::mutex> lock(mtx);

    if (block_balances.find(sender_key) == block_balances.end())
    {
        std::string balance_str;
        if (!db_wallets_temp::get_single(sender_key, balance_str) && !db_wallets::get_single(sender_key, balance_str))
        {
            return ZeraStatus(ZeraStatus::TXN_FAILED, "balance_tracker.cpp: remove_balance: Invalid wallet address.", zera_txn::TXN_STATUS::INVALID_WALLET_ADDRESS);
        }

        const uint256_t balance(balance_str);
        block_balances[sender_key] = balance;
    }

    if (block_balances[sender_key] < amount)
    {
        return ZeraStatus(ZeraStatus::TXN_FAILED, "balance_tracker.cpp: remove_balance: Insufficient wallet balance.", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
    }
    uint256_t zero(0);

    adjust_proposal_votes(wallet_address, zero, amount, contract_id);
    // add new balance to recipient balances
    block_balances[sender_key] -= amount;

    return ZeraStatus();
}

void balance_tracker::store_temp_database()
{
    // if transaction passed add new balance to temp wallet database, for further processing.
    rocksdb::WriteBatch batch;
    for (const auto &sender_pair : block_balances)
    {
        batch.Put(sender_pair.first, boost::lexical_cast<std::string>(sender_pair.second));
    }

    db_wallets_temp::store_batch(batch);
    clear_balances();
}
void balance_tracker::clear_balances()
{
    std::lock_guard<std::mutex> lock(mtx);
    block_balances.clear();
}
