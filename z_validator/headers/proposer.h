#ifndef _PROPOSER_H_
#define _PROPOSER_H_

// Standard library headers
#include <vector>

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>

#include <boost/lexical_cast.hpp>
#include <sstream>
#include <iomanip>

// Project-specific headers
#include "validator.pb.h"
#include "txn.pb.h"
#include "db_base.h"
#include "zera_status.h"
#include "hex_conversion.h"
#include "../block_process/block_process.h"
#include "../temp_data/temp_data.h"
#include "verify_process_txn.h"
#include "utils.h"
#include "../logging/logging.h"
#include "../util/stopwatch.h"
#include "validators.h"

struct WeightedValidator
{
    std::string address;
    uint64_t coinAmount;
};

struct transactions
{
    std::vector<std::string> keys;
    std::vector<std::string> values;
    std::vector<std::string> processed_keys;
    std::vector<std::string> processed_values;
    std::vector<std::string> timed_keys;
    std::vector<std::string> timed_values;
    std::vector<std::string> sc_keys;
    std::vector<std::string> sc_values;
    std::vector<std::string> gov_keys;
    std::vector<std::string> gov_values;
};

struct BlockManager
{
    bool has_transactions;
    bool my_block;
    int proposal_timer;
    int last_heartbeat;
    bool same_block;
    std::string wallet_adr;
    Stopwatch block_watch;
    uint32_t proposer_index;
    uint32_t block_sync_attempts;
    zera_validator::BlockHeader last_header;
    std::string last_key;
    std::vector<zera_txn::Validator> proposers;
    zera_validator::BlockHeader new_header;
    std::string new_key;
    std::string proposer_pub;
    transactions txns;

    void reset()
    {
        txns.gov_keys.clear();
        txns.gov_values.clear();
        txns.keys.clear();
        txns.values.clear();
        txns.processed_keys.clear();
        txns.processed_values.clear();
        txns.timed_keys.clear();
        txns.timed_values.clear();
        txns.sc_keys.clear();
        txns.sc_values.clear();
        proposer_index = 0;
        block_sync_attempts = 0;
        last_header.Clear();
        last_key = "";
        proposers.clear();
        has_transactions = false;
        block_watch.start();
        same_block = true;
        my_block = false;
    }
};

std::vector<zera_txn::Validator> SelectValidatorsByWeight(const std::string &seed_hash, const uint64_t &block_height);

class proposing
{
public:
    static ZeraStatus validate_block(zera_validator::Block &block);
    static void set_txn_token_fees(std::string txn_hash, std::string contract_id, std::string address, boost::multiprecision::uint256_t amount);
    static ZeraStatus process_txns(const std::vector<std::string> &values, const std::vector<std::string> &keys, zera_validator::Block *block, bool timed = false, const std::string &fee_address = "");
    static ZeraStatus make_block(zera_validator::Block *block, const transactions &verify_txns, const Stopwatch &stopwatch);
    static ZeraStatus make_block_sync(zera_validator::Block *block, const transactions &txns, const std::string &fee_address = "");
    static bool add_processed_sync(const std::vector<std::string> &keys, const std::vector<std::string> &values, zera_validator::Block *block);
    static bool add_processed(const std::vector<std::string> &keys, const std::vector<std::string> &values, zera_validator::Block *block, const Stopwatch &stopwatch);
    static void add_temp_wallet_balance(const std::vector<std::string> &txn_hash_vec, const std::string &fee_address);
    static void set_all_token_fees(zera_validator::Block *block, const std::vector<std::string> &txn_hash_vec, const std::string &fee_address);

    static bool get_transactions(transactions &txns)
    {
        bool success = false;
        if (db_transactions::get_all_data(txns.keys, txns.values))
        {
            success = true;
        }
        if (db_processed_txns::get_all_data(txns.processed_keys, txns.processed_values))
        {
            success = true;
        }
        if (restricted_keys_check::get_timed_txns(txns.timed_keys, txns.timed_values))
        {
            success = true;
        }
        if (db_sc_transactions::get_all_data(txns.sc_keys, txns.sc_values))
        {
            success = true;
        }
        if (db_gov_txn::get_all_data(txns.gov_keys, txns.gov_values))
        {
            success = true;
        }
        return success;
    }
    template <typename TXType>
    static ZeraStatus unpack_process_wrapper(TXType *txn, zera_txn::TXNS *block_txns, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed = false, const std::string &fee_address = "", bool sc_txn = false)
    {
        ZeraStatus status;
        zera_txn::TXNStatusFees status_fee;
        std::string value;
        std::string txn_hash = txn->base().hash();

        status_fee.set_smart_contract(sc_txn);
        std::string execute_key = "BLOCK_TXNS_" + txn_hash;

        if (txn_type == zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE || (txn_type == zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE))
        {
            db_smart_contracts::store_single(execute_key, block_txns->SerializeAsString());
        }

        if (!db_block_txns::get_single(txn_hash, value) || timed)
        {

            status = block_process::process_txn(txn, status_fee, txn_type, timed, fee_address, sc_txn);
            status.set_status(status_fee.status());

            if (status.ok())
            {
                if (status_fee.status() != zera_txn::TXN_STATUS::OK)
                {
                    logging::print(txn->base().memo(), "txn failed!", true);
                }
                else
                {
                    logging::print(txn->base().memo(), "txn passed!", true);
                }
                if (txn_type == zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE || (txn_type == zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE))
                {
                    if (status_fee.status() == zera_txn::TXN_STATUS::OK)
                    {
                        std::string value;
                        db_smart_contracts::get_single(execute_key, value);
                        block_txns->Clear();
                        block_txns->ParseFromString(value);
                    }
                }
                status_fee.set_txn_hash(txn->base().hash());
                block_txns->add_txn_fees_and_status()->CopyFrom(status_fee);

                db_block_txns::store_single(txn_hash, "1");
            }
            else
            {
                logging::print(status.read_status());
            }

            if (status.code() == ZeraStatus::Code::NONCE_ERROR)
            {
                logging::print(status.read_status());
            }
        }
        else
        {
            db_smart_contracts::remove_single(execute_key);
            return ZeraStatus(ZeraStatus::DUPLICATE_TXN_ERROR, "Duplicate txn error", zera_txn::TXN_STATUS::FAULTY_TXN);
        }

        if (status.code() == ZeraStatus::Code::BLOCK_FAULTY_TXN)
        {
            db_gov_txn::remove_single(txn->base().hash());
        }

        if (sc_txn && (!status.ok() || status.code() == ZeraStatus::Code::BLOCK_FAULTY_TXN))
        {
            db_smart_contracts::remove_single(execute_key);
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "Smart contract txn failed", zera_txn::TXN_STATUS::FAULTY_TXN);
        }

        db_smart_contracts::remove_single(execute_key);

        return status;
    }

    template <typename TXType>
    static ZeraStatus unpack_process_wrapper(TXType *txn, zera_txn::TXNS *block_txns, bool expense_ratio, const std::string &fee_address = "", bool sc_txn = false)
    {
        ZeraStatus status;
        zera_txn::TXNStatusFees status_fee;
        std::string value;
        std::string txn_hash = txn->base().hash();
        zera_txn::ExpenseRatioResult *expense_results = new zera_txn::ExpenseRatioResult();

        status_fee.set_smart_contract(sc_txn);

        if (!db_block_txns::get_single(txn_hash, value))
        {
            status = block_process::process_txn(txn, status_fee, expense_results, zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE, fee_address, sc_txn);
            if (status.ok())
            {

                if (status_fee.status() != zera_txn::TXN_STATUS::OK)
                {
                    logging::print(txn->base().memo(), "txn failed!", true);
                }
                else
                {
                    block_txns->add_expense_ratio_result_txns()->CopyFrom(*expense_results);
                    logging::print(txn->base().memo(), "txn passed!", true);
                }
                status_fee.set_txn_hash(txn->base().hash());
                block_txns->add_txn_fees_and_status()->CopyFrom(status_fee);
                db_block_txns::store_single(txn_hash, "1");
            }
            else
            {
                logging::print(status.read_status());
            }
        }
        else
        {
            logging::print("Duplicate txn error");
            return ZeraStatus(ZeraStatus::DUPLICATE_TXN_ERROR);
        }
        if (status.code() == ZeraStatus::Code::BLOCK_FAULTY_TXN)
        {
            db_gov_txn::remove_single(txn->base().hash());
        }

        if (sc_txn && status_fee.status() != zera_txn::TXN_STATUS::OK)
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "Smart contract txn failed", status_fee.status());
        }

        return status;
    }

private:
    template <typename TXType>
    static void add_used_nonce(const TXType &txn)
    {
        std::string wallet_adr = wallets::generate_wallet(txn.base().public_key());
        uint64_t nonce = txn.base().nonce();

        nonce_tracker::add_used_nonce(wallet_adr, nonce);
    }

    static void add_used_nonce(const zera_txn::ValidatorHeartbeat &txn)
    {
        std::string validator_data;
        zera_txn::Validator validator;
        db_validators::get_single(wallets::get_public_key_string(txn.base().public_key()), validator_data);
        validator.ParseFromString(validator_data);
        std::string wallet_adr = wallets::generate_wallet(validator.public_key());
        uint64_t nonce = txn.base().nonce();
        nonce_tracker::add_used_nonce(wallet_adr, nonce);
    }
    template <typename TXType>
    static void get_fees_status(const TXType &txn, zera_txn::TXNS *block_txns)
    {
        std::string key = txn.base().hash();
        zera_txn::TXNStatusFees status_fee;
        status_fee_tracker::get_status(status_fee, key);
        block_txns->add_txn_fees_and_status()->CopyFrom(status_fee);
    }
    static ZeraStatus processTransaction(zera_txn::TXNWrapper &wrapper, zera_txn::TXNS *block_txns, bool timed, const std::string &fee_address);
    static void add_transaction(zera_txn::TXNWrapper &wrapper, zera_txn::TXNS *block_txns);
    static void add_used_new_coin_nonce(const zera_txn::CoinTXN &txn, const zera_txn::TXNStatusFees &status_fees, bool timed = false);
    static void set_token_fees(std::string contract_id, std::string address, boost::multiprecision::uint256_t amount, std::map<std::string, std::map<std::string, boost::multiprecision::uint256_t>> &token_fees);
    static std::mutex mtx;
    static std::map<std::string, std::map<std::string, std::map<std::string, boost::multiprecision::uint256_t>>> txn_token_fees;
};

#endif