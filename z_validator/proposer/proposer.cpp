#include "proposer.h"

#include <iostream>
#include <regex>

#include "../governance/gov_process.h"
#include "../temp_data/temp_data.h"
#include "../crypto/merkle.h"
#include "wallets.h"
#include "block.h"
#include "validators.h"

std::map<std::string, std::map<std::string, std::map<std::string, boost::multiprecision::uint256_t>>> proposing::txn_token_fees;
std::mutex proposing::mtx;

void proposing::set_txn_token_fees(std::string txn_hash, std::string contract_id, std::string address, boost::multiprecision::uint256_t amount)
{
    std::lock_guard<std::mutex> lock(mtx);

    if (txn_token_fees.find(txn_hash) != txn_token_fees.end())
    {
        if (txn_token_fees[txn_hash].find(address) != txn_token_fees[txn_hash].end())
        {
            if (txn_token_fees[txn_hash][address].find(contract_id) != txn_token_fees[txn_hash][address].end())
            {
                txn_token_fees[txn_hash][address][contract_id] += amount;
            }
            else
            {
                txn_token_fees[txn_hash][address][contract_id] = amount;
            }
        }
        else
        {
            txn_token_fees[txn_hash][address][contract_id] = amount;
        }
    }
    else
    {
        txn_token_fees[txn_hash][address][contract_id] = amount;
    }
}

void proposing::add_temp_wallet_balance(const std::vector<std::string> &txn_hash_vec, const std::string &fee_address)
{

    for (auto txn_hash : txn_hash_vec)
    {
        zera_validator::BalanceTracker txn_balance_tracker;
        zera_validator::BalanceTracker subtract_txn_balance_tracker;

        balance_tracker::get_txn_balance(txn_hash, txn_balance_tracker, subtract_txn_balance_tracker);

        for (auto balance : txn_balance_tracker.wallet_balances())
        {
            // Find the position of the last '$' in the string
            std::size_t pos = balance.first.find_last_of('$');
            // Extract the contract ID (everything after the last '$')
            std::string contract_id = balance.first.substr(pos); // Includes the '$'
            // Extract the wallet address (everything before the last '$')
            std::string wallet_address = balance.first.substr(0, pos);
            auto wallet_vec = base58_decode(wallet_address);
            std::string key(wallet_vec.begin(), wallet_vec.end());
            std::string fee_wallet = key;

            if (fee_wallet == PREPROCESS_PLACEHOLDER)
            {
                fee_wallet = fee_address;
            }
            uint256_t balance_value(balance.second);
            balance_tracker::add_balance(fee_wallet, contract_id, balance_value);
        }

        for (auto subtract : subtract_txn_balance_tracker.wallet_balances())
        {
            // Find the position of the last '$' in the string
            std::size_t pos = subtract.first.find_last_of('$');
            // Extract the contract ID (everything after the last '$')
            std::string contract_id = subtract.first.substr(pos); // Includes the '$'
            // Extract the wallet address (everything before the last '$')
            std::string wallet_address = subtract.first.substr(0, pos);
            auto wallet_vec = base58_decode(wallet_address);
            std::string key(wallet_vec.begin(), wallet_vec.end());
            // Convert the balance string to uint256_t
            uint256_t subtract_value(subtract.second);
            balance_tracker::remove_balance(key, contract_id, subtract_value);
        }
        balance_tracker::remove_txn_balance(txn_hash);
    }

    balance_tracker::store_temp_database();
}
void proposing::set_all_token_fees(zera_validator::Block *block, const std::vector<std::string> &txn_hash_vec, const std::string &fee_address)
{

    std::map<std::string, std::map<std::string, boost::multiprecision::uint256_t>> token_fees;

    std::lock_guard<std::mutex> lock(mtx);

    for (auto txn_hash : txn_hash_vec)
    {
        auto txn_hash_map = txn_token_fees[txn_hash];
        for (auto address : txn_hash_map)
        {
            for (auto contract : address.second)
            {
                set_token_fees(contract.first, address.first, contract.second, token_fees);
            }
        }
        txn_token_fees.erase(txn_hash);
    }

    // Define a nested map to accumulate token amounts
    std::map<std::string, std::map<std::string, uint256_t>> accumulated_fees;

    // Accumulate token amounts
    for (const auto &token_fee : token_fees)
    {
        std::string address = token_fee.first;
        if (address == PREPROCESS_PLACEHOLDER)
        {
            address = fee_address;
        }

        for (const auto &token : token_fee.second)
        {

            accumulated_fees[address][token.first] += token.second;
        }
    }

    // Add accumulated amounts to the block
    for (const auto &token_fee : accumulated_fees)
    {
        zera_txn::TokenFees *temp_fees = block->mutable_transactions()->add_token_fees();
        for (const auto &token : token_fee.second)
        {
            zera_txn::Token *temp_token = temp_fees->add_tokens();
            temp_token->set_amount(boost::lexical_cast<std::string>(token.second));
            temp_token->set_contract_id(token.first);
        }
        temp_fees->set_address(token_fee.first);
    }
}

void proposing::set_token_fees(std::string contract_id, std::string address, boost::multiprecision::uint256_t amount, std::map<std::string, std::map<std::string, boost::multiprecision::uint256_t>> &token_fees)
{
    if (token_fees.find(address) != token_fees.end())
    {
        if (token_fees[address].find(contract_id) != token_fees[address].end())
        {
            token_fees[address][contract_id] += amount;
        }
        else
        {
            token_fees[address][contract_id] = amount;
        }
    }
    else
    {
        token_fees[address][contract_id] = amount;
    }
}

ZeraStatus proposing::make_block(zera_validator::Block *block, const transactions &txns, const Stopwatch &stopwatch)
{

    // add prepocessed txns to block
    // this function will remove the txns from the processed database
    bool added_txn = add_processed(txns.processed_keys, txns.processed_values, block, stopwatch);

    if (txns.timed_keys.size() > 0)
    {
        ZeraStatus status = proposing::process_txns(txns.timed_values, txns.timed_keys, block, true);
        if (status.ok())
        {
            added_txn = true;
        }
    }
    // process txns
    if (txns.keys.size() > 0)
    {
        // process and add any txns that have not been processed
        // this function will remove the txns from the pending database
        ZeraStatus status = proposing::process_txns(txns.values, txns.keys, block);

        if (!status.ok())
        {
            if (!added_txn)
            {
                return status;
            }
        }
        added_txn = true;
    }
    if (txns.gov_keys.size() > 0)
    {
        ZeraStatus status = proposing::process_txns(txns.gov_values, txns.gov_keys, block, false);
        if (status.ok())
        {
            added_txn = true;
        }
    }
    int x = 0;
    std::vector<std::string> sc_keys;
    std::vector<std::string> sc_values;
    while (db_sc_transactions::get_all_data(sc_keys, sc_values) && x < 10)
    {
        ZeraStatus status = proposing::process_txns(sc_values, sc_keys, block, false);
        if (status.ok())
        {
            added_txn = true;
        }

        for (auto key : sc_keys)
        {
            db_sc_transactions::remove_single(key);
        }
        sc_keys.clear();
        sc_values.clear();
        x++;
    }
    for (auto key : txns.gov_keys)
    {
        db_gov_txn::remove_single(key);
    }
    if (!added_txn)
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "proposer.h: make_block: No txns added to block.");
    }
    auto block_txns = block->mutable_transactions();
    // process fast quorum proposals if any
    gov_process::process_fast_quorum(block_txns);
    quash_tracker::quash_result(block_txns);
    std::vector<std::string> txn_hash_vec;
    std::vector<std::string> allowance_txn_hash_vec;
    txn_hash_tracker::get_hash(txn_hash_vec, allowance_txn_hash_vec);

    for (auto result : block_txns->proposal_result_txns())
    {
        txn_hash_vec.push_back(result.proposal_id());
    }

    set_all_token_fees(block, txn_hash_vec, ValidatorConfig::get_fee_address_string());
    add_temp_wallet_balance(txn_hash_vec, ValidatorConfig::get_fee_address_string());
    allowance_tracker::add_block_allowance(allowance_txn_hash_vec);
    merkle_tree::build_merkle_tree(block);
    block_utils::set_block(block);
    std::string block_write;
    std::string header_write;
    std::string key1 = block_utils::block_to_write(block, block_write, header_write);
    if (db_blocks::exist(key1))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "proposer.h: make_block: Block already exists.");
    }
    db_blocks::store_single(key1, block_write);
    db_headers::store_single(key1, header_write);
    db_hash_index::store_single(block->block_header().hash(), key1);
    db_hash_index::store_single(std::to_string(block->block_header().block_height()), key1);
    signatures::sign_block_broadcast(block, ValidatorConfig::get_gen_key_pair());
    return ZeraStatus(ZeraStatus::OK);
}

ZeraStatus proposing::make_block_sync(zera_validator::Block *block, const transactions &txns, const std::string &fee_address)
{

    // add prepocessed txns to block
    // this function will remove the txns from the processed database
    bool added_txn = add_processed_sync(txns.processed_keys, txns.processed_values, block);

    if (txns.timed_keys.size() > 0)
    {
        ZeraStatus status = proposing::process_txns(txns.timed_values, txns.timed_keys, block, true);
        if (status.ok())
        {
            added_txn = true;
        }
    }
    // process txns
    if (txns.keys.size() > 0)
    {
        // process and add any txns that have not been processed
        // this function will remove the txns from the pending database
        ZeraStatus status = proposing::process_txns(txns.values, txns.keys, block, false, fee_address);

        if (!status.ok())
        {
            if (!added_txn)
            {
                return status;
            }
        }
        added_txn = true;
    }

    if (txns.gov_keys.size() > 0)
    {
        ZeraStatus status = proposing::process_txns(txns.gov_values, txns.gov_keys, block, false, fee_address);
        if (status.ok())
        {
            added_txn = true;
        }
    }

    int x = 0;
    std::vector<std::string> sc_keys;
    std::vector<std::string> sc_values;
    while (db_sc_transactions::get_all_data(sc_keys, sc_values) && x < 10)
    {
        ZeraStatus status = proposing::process_txns(sc_values, sc_keys, block, false);
        if (status.ok())
        {
            added_txn = true;
        }

        for (auto key : sc_keys)
        {
            db_sc_transactions::remove_single(key);
        }
        sc_keys.clear();
        sc_values.clear();
        x++;
    }

    for (auto key : txns.gov_keys)
    {
        db_gov_txn::remove_single(key);
    }

    if (!added_txn)
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "proposer.h: make_block: No txns added to block.");
    }

    return ZeraStatus(ZeraStatus::OK);
}