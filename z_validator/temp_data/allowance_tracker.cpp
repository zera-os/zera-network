#include "temp_data.h"
#include "db_base.h"
#include "../logging/logging.h"
#include "wallets.h"
#include "db_base.h"
#include "../block_process/block_process.h"
#include <ctime>
#include <chrono>
#include "fees.h"

std::map<std::string, zera_validator::AllowanceState> allowance_tracker::block_allowances;
std::map<std::string, std::map<std::string, zera_validator::AllowanceState>> allowance_tracker::add_txn_allowance_state;
std::mutex allowance_tracker::mtx;

bool allowance_tracker::check_allowance(const std::string &wallet_adr, const zera_txn::PublicKey &public_key, const std::string &contract_id, const uint256_t &input_temp, const std::string &txn_hash, const zera_txn::PublicKey &pk)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string allowed_wallet = wallets::generate_wallet(public_key);
    std::string key = wallet_adr + allowed_wallet + contract_id;
    zera_validator::AllowanceState allowance_state;
    std::string value;

    // Check if the transaction exists in add_txn_allowance_state
    if (add_txn_allowance_state.find(txn_hash) != add_txn_allowance_state.end() &&
        add_txn_allowance_state[txn_hash].find(key) != add_txn_allowance_state[txn_hash].end())
    {
        zera_validator::AllowanceState allowance_state = add_txn_allowance_state[txn_hash][key];
    }

    if (db_allowance::get_single("PRE_" + key, value) || db_allowance::get_single(key, value))
    {
        if (!allowance_state.ParseFromString(value))
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    std::string pub_key = wallets::get_public_key_string(pk);
    ZeraStatus status = block_process::check_validator(pub_key, zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE);

    if (!status.ok())
    {
        return false;
    }

    zera_validator::BlockHeader block_header;
    std::string last_key;
    db_headers_tag::get_last_data(block_header, last_key);

    if (allowance_state.start_time().seconds() > block_header.timestamp().seconds())
    {
        return false;
    }

    uint64_t period_end = allowance_state.period_end().seconds();
    uint64_t block_time = block_header.timestamp().seconds();
    bool is_period_end = false;

    if (allowance_state.has_period_seconds() && allowance_state.period_seconds() > 0)
    {
        if (period_end < block_time)
        {
            // Calculate the number of periods needed to reach or exceed block_time
            uint64_t periods = (block_time - period_end + allowance_state.period_seconds() - 1) / allowance_state.period_seconds();
            period_end += periods * allowance_state.period_seconds();
            is_period_end = true;
        }
    }
    else if (allowance_state.has_period_seconds() && allowance_state.period_seconds() == 0)
    {
        is_period_end = true;
    }
    else if (allowance_state.has_period_months())
    {
        // Convert period_end (seconds since epoch) to a tm structure
        std::time_t period_end_time_t = static_cast<std::time_t>(period_end);
        std::tm period_end_tm = *std::gmtime(&period_end_time_t);

        // Calculate the number of months to add
        uint32_t months_to_add = allowance_state.period_months();

        // MAX INT CAP
        if (months_to_add > (2147483647 - period_end_tm.tm_mon))
        {
            months_to_add = 2147483647 - period_end_tm.tm_mon;
        }

        while (std::mktime(&period_end_tm) < static_cast<std::time_t>(block_time) && months_to_add > 0)
        {
            period_end_tm.tm_mon += months_to_add;
            // Normalize the time structure
            period_end = static_cast<uint64_t>(std::mktime(&period_end_tm));
        }
    }

    if (is_period_end)
    {
        allowance_state.set_used_amount("0");
    }

    uint256_t used_amount(allowance_state.used_amount());

    if (allowance_state.has_allowed_amount())
    {
        uint256_t allowed_amount(allowance_state.allowed_amount());
        allowed_amount = allowed_amount - used_amount;

        if (allowed_amount < input_temp)
        {
            allowance_state.mutable_period_end()->set_seconds(period_end);
            add_txn_allowance_state[txn_hash][key] = allowance_state;
            return false;
        }
        else
        {
            allowance_state.set_used_amount((used_amount + input_temp).str());
            allowance_state.mutable_period_end()->set_seconds(period_end);
            add_txn_allowance_state[txn_hash][key] = allowance_state;
            return true;
        }
    }
    else if (allowance_state.has_allowed_currency_equivalent())
    {
        uint256_t equiv;
        if(!zera_fees::get_cur_equiv(contract_id, equiv))
        {
            uint256_t one_dollar(ONE_DOLLAR);
            equiv = one_dollar * 1000000000000;
        }

        zera_txn::InstrumentContract contract;
        block_process::get_contract(contract_id, contract);

        uint256_t denomination(contract.coin_denomination().amount());

        uint256_t total_amount = input_temp * equiv / denomination;

        uint256_t allowed_currency_equivalent(allowance_state.allowed_currency_equivalent());

        allowed_currency_equivalent = allowed_currency_equivalent - used_amount;

        if (allowed_currency_equivalent < total_amount)
        {
            allowance_state.mutable_period_end()->set_seconds(period_end);
            add_txn_allowance_state[txn_hash][key] = allowance_state;
            return false;
        }
        else
        {
            allowance_state.set_used_amount((used_amount + total_amount).str());
            allowance_state.mutable_period_end()->set_seconds(period_end);
            add_txn_allowance_state[txn_hash][key] = allowance_state;
            return true;
        }
    }
    else
    {
        return false;
    }
}

void allowance_tracker::add_txn_to_pre_process(const std::string &block_hash)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (add_txn_allowance_state.find(block_hash) != add_txn_allowance_state.end())
    {
        rocksdb::WriteBatch batch;
        // Iterate through the map for the given block_hash
        for (const auto &pair : add_txn_allowance_state[block_hash])
        {
            const std::string &key = pair.first;                       // The key
            const zera_validator::AllowanceState &value = pair.second; // The value

            batch.Put("PRE_" + key, value.SerializeAsString()); // Add to batch
        }

        db_allowance::store_batch(batch); // Store the batch in the database
    }
}
void allowance_tracker::remove_txn_allowance(const std::string &block_hash)
{
    add_txn_allowance_state.erase(block_hash);
}

void allowance_tracker::add_block_allowance(const std::vector<std::string> &allowance_txn_hash_vec)
{
    std::lock_guard<std::mutex> lock(mtx);

    for (auto block_hash : allowance_txn_hash_vec)
    {
        if (add_txn_allowance_state.find(block_hash) == add_txn_allowance_state.end())
        {
            continue;
        }
        else
        {
            for (const auto &pair : add_txn_allowance_state[block_hash])
            {
                const std::string &key = pair.first;                       // The key
                const zera_validator::AllowanceState &value = pair.second; // The value

                block_allowances[key] = value; // Add to block allowances
                add_txn_allowance_state.erase(block_hash);
            }
        }
    }
}

void allowance_tracker::update_allowance_database()
{
    rocksdb::WriteBatch batch;
    for (const auto &pair : block_allowances)
    {
        const std::string &key = pair.first;                       // The key
        const zera_validator::AllowanceState &value = pair.second; // The value
        batch.Put(key, value.SerializeAsString());                 // Add to batch
    }
    db_allowance::store_batch(batch); // Store the batch in the database
    block_allowances.clear();         // Clear the block allowances after updating the database
}
