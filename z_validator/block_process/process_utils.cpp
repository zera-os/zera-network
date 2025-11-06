// Standard library headers

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

// Project-specific headers
#include "const.h"
#include "block_process.h"
#include "wallets.h"
#include "validators.h"
#include "db_base.h"
#include "hashing.h"
#include "proposer.h"
#include "signatures.h"
#include "../temp_data/temp_data.h"
#include "../compliance/compliance.h"
#include "utils.h"
#include "../logging/logging.h"
#include "fees.h"

ZeraStatus block_process::get_sender_wallet(const std::string &sender_key, uint256_t &sender_balance)
{
    std::string wallet_balance;
    // see if sender has already made a transaction in this block if not get wallet from main database
    // if wallet doesnt exist send back error status
  
    if (!db_processed_wallets::get_single(sender_key, wallet_balance))
    {
        logging::print("sender_key: ", sender_key, true);
        if (!db_wallets::get_single(sender_key, wallet_balance))
        {
            return ZeraStatus(ZeraStatus::Code::WALLET_ERROR, "process_utils.cpp: get_sender_wallet: Sender wallet does not exist: ", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
        }
    }

    sender_balance = boost::lexical_cast<uint256_t>(wallet_balance);
    return ZeraStatus(ZeraStatus::Code::OK);
}

ZeraStatus block_process::get_contract(const std::string contract_id, zera_txn::InstrumentContract &contract)
{
    std::string contract_data;
    contract.Clear();
    if (!db_contracts::get_single(contract_id, contract_data) || !contract.ParseFromString(contract_data))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: get_contract: Invalid Contract: " + contract_id, zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }

    return ZeraStatus();
}

void block_process::store_wallets()
{
    std::vector<std::string> addresses;
    std::vector<std::string> wallets_data;
    rocksdb::WriteBatch wallet_batch;
    rocksdb::WriteBatch exist_batch;
    rocksdb::WriteBatch lookup_batch;

    db_wallets_temp::get_all_data(addresses, wallets_data);
    logging::print("starting store");

    for (std::size_t i = 0; i < addresses.size(); ++i)
    {
        auto tres_wallet_vec = base58_decode(ValidatorConfig::get_treasury_wallet());

        const std::string &address = addresses[i];
        std::string burn_wallet = std::string(BURN_WALLET) + ZERA_SYMBOL;
        std::string treasury_wallet(tres_wallet_vec.begin(), tres_wallet_vec.end());
        treasury_wallet += ZERA_SYMBOL;
        std::string postfix;
        std::string address_no_symbol;

        size_t pos = address.find_last_of('$');
        if (pos != std::string::npos)
        {
            postfix.assign(address.begin() + pos, address.end());
            address_no_symbol.assign(address.begin(), address.begin() + pos);
        }

        std::string wallet_balance1;
        // ADD LOGS AGAIN!
        if (db_wallets::get_single(address, wallet_balance1))
        {
            if (address == burn_wallet)
            {
                logging::print("current wallet -", address, " amount: ", wallet_balance1);
            }
            else
            {
                logging::print("current wallet -", base58_encode(address_no_symbol) + postfix, "amount:", wallet_balance1);
            }
        }
        else
        {
            logging::print("current wallet -", base58_encode(address_no_symbol) + postfix , "amount:", wallet_balance1);
        }

        const std::string &wallet_balance = wallets_data[i];
        if (address == burn_wallet)
        {
            logging::print("temp_wallet -   ", address, "amount: ", wallet_balance + "\n");
        }
        else
        {
            logging::print("temp_wallet -   ", base58_encode(address_no_symbol) + postfix, "amount:", wallet_balance + "\n");
        }

        wallet_batch.Put(address, wallet_balance);

        if (!db_wallet_lookup::exist(address_no_symbol))
        {
            zera_validator::WalletLookup wallet_lookup;
            exist_batch.Put(address_no_symbol, wallet_lookup.SerializeAsString());
        }

        std::string token_lookup_key = "TOKEN_LOOKUP_" + address_no_symbol;
        std::string data;
        db_wallet_lookup::get_single(token_lookup_key, data);
        zera_validator::TokenLookup token_lookup;
        token_lookup.ParseFromString(data);

        bool found = false;
        bool remove = false;
        int x = 0;
        for (auto token : token_lookup.tokens())
        {
            if (postfix == token)
            {
                if (wallet_balance == "0")
                {
                    remove = true;
                }
                found = true;
                break;
            }
            x++;
        }
        if (remove)
        {
            token_lookup.mutable_tokens()->SwapElements(x, token_lookup.tokens_size() - 1);
            token_lookup.mutable_tokens()->RemoveLast();
            lookup_batch.Put(token_lookup_key, token_lookup.SerializeAsString());
        }
        if (!found)
        {
            token_lookup.add_tokens(postfix);
            lookup_batch.Put(token_lookup_key, token_lookup.SerializeAsString());
        }
    }

    
    db_wallets::store_batch(wallet_batch);
    db_wallets_temp::remove_all();
    db_wallet_lookup::store_batch(exist_batch);
    db_wallet_lookup::store_batch(lookup_batch);
}


ZeraStatus block_process::check_validator(const std::string &public_key, const zera_txn::TRANSACTION_TYPE &txn_type)
{

    if (txn_type == zera_txn::TRANSACTION_TYPE::VOTE_TYPE || txn_type == zera_txn::TRANSACTION_TYPE::VALIDATOR_REGISTRATION_TYPE || txn_type == zera_txn::TRANSACTION_TYPE::VALIDATOR_HEARTBEAT_TYPE)
    {
        return ZeraStatus();
    }
    // if sender is a validator remove txn. validators can only recieve coins
    if (db_validator_lookup::exist(public_key))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: coin_process: The sender of this transaction is a validator.", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
    }
    if (db_validator_unbond::exist(public_key))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: coin_process: The sender of this transaction is in an unbonding period.", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
    }

    return ZeraStatus();
}

bool check_safe_send(const zera_txn::BaseTXN base, const std::string &wallet_address)
{
    if(base.safe_send() && !db_wallet_lookup::exist(wallet_address))
    {
        return false;
    }

    return true;
}
