#include "restricted_keys.h"

#include <iostream>
#include <ctime>
#include <regex>
#include <chrono>

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

#include "../governance/time_calc.h"
#include "db_base.h"
#include "verify_process_txn.h"
#include "wallets.h"
#include "../block_process/block_process.h"
#include "utils.h"
#include "../logging/logging.h"

namespace
{

    bool check_restricted_required(const zera_txn::TRANSACTION_TYPE &txn_type)
    {
        switch (txn_type)
        {
        case zera_txn::TRANSACTION_TYPE::COIN_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::NFT_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::VOTE_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::DELEGATED_VOTING_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::SBT_BURN_TYPE:
            return true;
        case zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE:
            return true;
        default:
            return false;
        }
    }
    bool check_type(const zera_txn::RestrictedKey &restricted_key, const zera_txn::TRANSACTION_TYPE &txn_type)
    {
        switch (txn_type)
        {
        case zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE:
            return restricted_key.update_contract();
        case zera_txn::TRANSACTION_TYPE::COIN_TYPE:
            return restricted_key.transfer();
        case zera_txn::TRANSACTION_TYPE::NFT_TYPE:
            return restricted_key.transfer();
        case zera_txn::TRANSACTION_TYPE::QUASH_TYPE:
            return restricted_key.quash();
        case zera_txn::TRANSACTION_TYPE::MINT_TYPE:
            return restricted_key.mint();
        case zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE:
            return restricted_key.mint();
        case zera_txn::TRANSACTION_TYPE::VOTE_TYPE:
            return restricted_key.vote();
        case zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE:
            return restricted_key.propose();
        case zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE:
            return restricted_key.expense_ratio();
        case zera_txn::TRANSACTION_TYPE::REVOKE_TYPE:
            return restricted_key.revoke();
        case zera_txn::TRANSACTION_TYPE::COMPLIANCE_TYPE:
            return restricted_key.compliance();
        case zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE:
            return restricted_key.transfer();
        default:
            return true;
        }

        return false;
    }

    bool check_delegated_keys(const std::string &public_key, zera_txn::InstrumentContract &contract, std::vector<std::string> &checked_inherited,
                              const zera_txn::TRANSACTION_TYPE &txn_type, uint64_t &time_delay, zera_txn::RestrictedKey &restricted_key, uint32_t &key_weight)
    {
        if (std::find(checked_inherited.begin(), checked_inherited.end(), contract.contract_id()) != checked_inherited.end())
        {
            return false;
        }

        checked_inherited.push_back(contract.contract_id());
        std::regex pattern("^\\$[A-Z]{3,20}\\+\\d{4}$");
        std::regex pattern2("^\\$sol-[A-Z]{1,32}\\+\\d{6}$");

        for (auto key : contract.restricted_keys())
        {
            // std::string r_public_key = *(key.mutable_public_key()->mutable_single());
            std::smatch matches;
            std::string r_public_key_str = wallets::get_public_key_string(key.public_key());
            if (std::regex_match(r_public_key_str, matches, pattern) || std::regex_match(r_public_key_str, matches, pattern2))
            {
                zera_txn::InstrumentContract inherited_contract;

                block_process::get_contract(r_public_key_str, inherited_contract);

                if (check_delegated_keys(public_key, inherited_contract, checked_inherited, txn_type, time_delay, restricted_key, key_weight))
                {
                    return true;
                }
            }
            else if (r_public_key_str == public_key && check_type(key, txn_type))
            {
                restricted_key.CopyFrom(key);
                time_delay = key.time_delay();

                if (key.key_weight() < key_weight)
                {
                    key_weight = key.key_weight();
                }

                return true;
            }
        }

        return false;
    }
    bool check_gov_sc_restricted(const std::string &public_key, zera_txn::InstrumentContract &contract, zera_txn::RestrictedKey &restricted_key, bool gov = true)
    {
        if (gov)
        {
            for (auto key : contract.restricted_keys())
            {
                if (key.public_key().governance_auth() == public_key)
                {
                    restricted_key.CopyFrom(key);
                    return true;
                }
            }
        }
        else
        {
            for (auto key : contract.restricted_keys())
            {
                if (key.public_key().smart_contract_auth() == public_key)
                {
                    restricted_key.CopyFrom(key);
                    return true;
                }
            }
        }
        return false;
    }
}

template <typename TXType>
ZeraStatus restricted_keys_check::check_restricted_keys(const TXType *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed)
{
    HashType wallet_type = wallets::get_wallet_type(txn->base().public_key());

    // if key is not restricted/gov/sc check to see if txn requires
    if (wallet_type != HashType::wallet_r && wallet_type != HashType::wallet_g && wallet_type != HashType::wallet_sc)
    {
        // if restricted key is required fail key
        // else pass key
        if (!check_restricted_required(txn_type))
        {
            return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not restricted. 1", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
        }

        return ZeraStatus();
    }

    std::vector<std::string> checked_inherited;
    uint64_t time_delay = 0;
    uint32_t key_weight = 4294967295;
    zera_txn::RestrictedKey restricted_key;
    std::string auth_key_str = wallets::get_public_key_string(txn->base().public_key());

    // check to see if key is included in contract
    if (!check_delegated_keys(auth_key_str, contract, checked_inherited, txn_type, time_delay, restricted_key, key_weight))
    {
        // if key is not included and txn requires restricted key, fail key
        // if txn does not require restricted key, pass key

        if (!check_restricted_required(txn_type))
        {
            return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not Authorized to this contract", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
        }

        return ZeraStatus();
    }

    if (check_type(restricted_key, txn_type))
    {
        time_delay = restricted_key.time_delay();
    }
    else
    {
        return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not Authorized to this contract gov 1", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
    }

    if (time_delay > 0 && !timed)
    {
        make_quash_ledger(time_delay, txn);
        return ZeraStatus(ZeraStatus::Code::TIME_DELAY, "restricted_key.cpp: check_auth_key: TimeDelay", zera_txn::TXN_STATUS::TIME_DELAY_INITIALIZED);
    }

    return ZeraStatus();
}
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::MintTXN>(const zera_txn::MintTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::ItemizedMintTXN>(const zera_txn::ItemizedMintTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed);

template <>
ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::CoinTXN>(const zera_txn::CoinTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &txn_type, const bool timed)
{

    for (auto auth_key : txn->auth().public_key())
    {
        HashType wallet_type = wallets::get_wallet_type(auth_key);

        // if key is not restricted/gov/sc check to see if txn requires
        if (wallet_type != HashType::wallet_r && wallet_type != HashType::wallet_g && wallet_type != HashType::wallet_sc)
        {
            // if restricted key is required fail key
            // else pass key
            if (!check_restricted_required(txn_type))
            {
                return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not restricted. 1", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
            }
        }
    }

    for (auto public_key : txn->auth().public_key())
    {
        bool auth_key = false;
        HashType wallet_type = wallets::get_wallet_type(public_key);

        if (wallet_type != HashType::wallet_r && wallet_type != HashType::wallet_g && wallet_type != HashType::wallet_sc)
        {
            continue;
        }
        std::vector<std::string> checked_inherited;
        uint64_t time_delay = 0;
        uint32_t key_weight = 4294967295;
        zera_txn::RestrictedKey restricted_key;
        std::string auth_key_str = wallets::get_public_key_string(public_key);

        // check to see if key is included in contract
        if (!check_delegated_keys(auth_key_str, contract, checked_inherited, txn_type, time_delay, restricted_key, key_weight))
        {
            // if key is not included and txn requires restricted key, fail key
            // if txn does not require restricted key, pass key
            if (!check_restricted_required(txn_type))
            {
                return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not Authorized to this contract 1", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
            }

            return ZeraStatus();
        }

        if (check_type(restricted_key, txn_type))
        {
            time_delay = restricted_key.time_delay();
        }
        else
        {
            return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not Authorized to this contract gov 2", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
        }

        if (time_delay > 0 && !timed)
        {
            if (txn->auth().public_key_size() > 1)
            {
                return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_key.cpp: check_auth_key: Cannot have time delay with multiple senders on CoinTXN", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }

            make_quash_ledger(time_delay, txn);
            return ZeraStatus(ZeraStatus::Code::TIME_DELAY, "restricted_key.cpp: check_auth_key: TimeDelay", zera_txn::TXN_STATUS::TIME_DELAY_INITIALIZED);
        }
    }

    return ZeraStatus();
}

template <typename TXType>
ZeraStatus restricted_keys_check::check_restricted_keys(const TXType *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &type,
                                                        zera_txn::RestrictedKey &restricted_key, uint32_t &key_weight)
{

    HashType wallet_type = wallets::get_wallet_type(txn->base().public_key());

    // if key is not restricted/gov/sc check to see if txn requires
    if (wallet_type != HashType::wallet_r && wallet_type != HashType::wallet_g && wallet_type != HashType::wallet_sc)
    {
        // if restricted key is required fail key
        // else pass key
        if (!check_restricted_required(type))
        {
            return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not restricted. 1", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
        }

        return ZeraStatus();
    }

    std::vector<std::string> checked_inherited;
    uint64_t time_delay = 0;
    key_weight = 4294967295;
    std::string auth_key_str = wallets::get_public_key_string(txn->base().public_key());

    // check to see if key is included in contract
    if (!check_delegated_keys(auth_key_str, contract, checked_inherited, type, time_delay, restricted_key, key_weight))
    {
        // if key is not included and txn requires restricted key, fail key
        // if txn does not require restricted key, pass key
        if (!check_restricted_required(type))
        {
            return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not Authorized to this contract 1", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
        }

        return ZeraStatus();
    }

    if (check_type(restricted_key, type))
    {
        time_delay = restricted_key.time_delay();

        if (restricted_key.key_weight() < key_weight)
        {
            key_weight = restricted_key.key_weight();
        }
    }
    else
    {
        return ZeraStatus(ZeraStatus::Code::NON_RESTRICTED_KEY, "restricted_keys.cpp: check_restricted_keys: sender public key is not Authorized to this contract gov 3", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
    }

    if (time_delay > 0)
    {
        make_quash_ledger(time_delay, txn);
        return ZeraStatus(ZeraStatus::Code::TIME_DELAY, "restricted_key.cpp: check_auth_key: TimeDelay", zera_txn::TXN_STATUS::TIME_DELAY_INITIALIZED);
    }

    return ZeraStatus();
}
template ZeraStatus restricted_keys_check::check_restricted_keys<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, zera_txn::InstrumentContract &contract, const zera_txn::TRANSACTION_TYPE &type,
                                                                                              zera_txn::RestrictedKey &restricted_key, uint32_t &key_weight);

void restricted_keys_check::check_quash_ledger(const zera_validator::Block *block)
{

    google::protobuf::Timestamp timestamp = block->block_header().timestamp();

    std::tm now = time_calc::get_start_date(timestamp);

    std::string key = time_calc::convert_to_key_minutes(now);

    std::string quash_data;
    zera_validator::QuashLedger quash_ledger;

    if (!db_quash_ledger::get_single(key, quash_data) || !quash_ledger.ParseFromString(quash_data))
    {
        return;
    }

    rocksdb::WriteBatch txn_batch;

    for (auto txn_id : quash_ledger.txn_ids())
    {
        std::string txn_data;
        zera_txn::TXNWrapper txn_wrapper;

        if (!db_timed_txns::get_single(txn_id, txn_data) && !txn_wrapper.ParseFromString(txn_data))
        {
            continue;
        }

        txn_batch.Put(txn_id, txn_data);
    }

    db_transactions::store_batch(txn_batch);
    db_quash_ledger::remove_single(key);
}

template <typename TXType>
void restricted_keys_check::make_quash_ledger(uint32_t time_delay, const TXType *txn)
{

    auto now = std::chrono::system_clock::now();
    now += std::chrono::seconds(time_delay);
    auto now_as_time = std::chrono::system_clock::to_time_t(now);
    std::string key = get_seconds_key(now_as_time);

    std::string quash_data;
    zera_validator::QuashLedger quash_ledger;

    db_quash_ledger::get_single(key, quash_data);
    quash_ledger.ParseFromString(quash_data);

    quash_ledger.add_txn_ids(txn->base().hash());

    db_quash_ledger::store_single(key, quash_ledger.SerializeAsString());

    zera_txn::TXNWrapper txn_wrapper;
    verify_txns::store_wrapper(txn, txn_wrapper);
    db_timed_txns::store_single(txn->base().hash(), txn_wrapper.SerializeAsString());
}

template <typename TXType>
void restricted_keys_check::store_timed_txn(const TXType *txn)
{
    zera_txn::TXNWrapper txn_wrapper;
    verify_txns::store_wrapper(txn, txn_wrapper);
    db_timed_txns::store_single(txn->base().hash(), txn_wrapper.SerializeAsString());
}

bool restricted_keys_check::get_timed_txns(std::vector<std::string> &keys, std::vector<std::string> &values)
{

    auto time_now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string iterate_from = "";

    bool done = false;
    while (!done)
    {
        std::string key;
        std::string value;
        if (iterate_from == "")
        {
            if (!db_quash_ledger::get_first_data(key, value))
            {
                return keys.size() > 0;
            }
        }
        else
        {
            if (!db_quash_ledger::get_next_data(iterate_from, key, value))
            {
                return keys.size() > 0;
            }
        }

        iterate_from = key;
        key.erase(0, std::min(key.find_first_not_of('0'), key.size() - 1));
        std::time_t key_time;

        try
        {
            key_time = static_cast<std::time_t>(std::stoll(key));
        }
        catch (std::exception &e)
        {
            db_quash_ledger::remove_single(iterate_from);
            return keys.size() > 0;
        }

        logging::print("get_timed_txns - key_time:", key_time);
        logging::print("get_timed_txns - time_now:", time_now);

        // Compare to time_now
        if (time_now >= key_time)
        {
            db_quash_ledger::remove_single(iterate_from);
            zera_validator::QuashLedger quash_ledger;

            if (quash_ledger.ParseFromString(value))
            {
                rocksdb::WriteBatch txn_batch;
                for (auto txn_id : quash_ledger.txn_ids())
                {
                    db_timed_txns::get_single(txn_id, value);
                    keys.push_back(txn_id);
                    values.push_back(value);
                    txn_batch.Delete(txn_id);
                }
                db_transactions::store_batch(txn_batch);
            }
        }
        else
        {
            return keys.size() > 0;
        }
    }

    return keys.size() > 0;
}