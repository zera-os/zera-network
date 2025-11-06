// Project-specific headers
#include "fees.h"
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

// function to get the cur equivalent of both the token and the fee token
// 1.00$ = 1 000 000 000 000 000 000
bool zera_fees::get_cur_equiv(const std::string &contract_id, uint256_t &cur_equiv)
{

    std::string ace_sc_key;

    if (!db_smart_contracts::get_single(ACE_PROXY, ace_sc_key) || ace_sc_key == "")
    {
        if (contract_id == "$ZRA+0000")
        {
            cur_equiv = ONE_DOLLAR;
            return true;
        }

        return false;
    }

    ace_sc_key += "_" + contract_id;

    std::string rate_data;
    if (!db_smart_contracts::get_single(ace_sc_key, rate_data) || rate_data == "")
    {
        if (contract_id == "$ZRA+0000")
        {
            cur_equiv = ONE_DOLLAR;
            return true;
        }

        return false;
    }

    if (!is_valid_uint256(rate_data))
    {
        if (contract_id == "$ZRA+0000")
        {
            cur_equiv = ONE_DOLLAR;
            return true;
        }

        return false;
    }

    uint256_t rate(rate_data);

    if (contract_id == "$ZRA+0000")
    {
        if (rate < ONE_DOLLAR)
        {
            cur_equiv = ONE_DOLLAR;
            return true;
        }
    }

    cur_equiv = rate;
    return true;
}

ZeraStatus zera_fees::check_allowed_contract_fee(const google::protobuf::RepeatedPtrField<std::string> &allowed_fees, const std::string contract_id, zera_fees::ALLOWED_CONTRACT_FEE &allowed_fee)
{
    allowed_fee = zera_fees::ALLOWED_CONTRACT_FEE::NOT_ALLOWED;
    for (const auto fee_id : allowed_fees)
    {
        logging::print("fee_id: ", fee_id);
        // if fee_id is qualified do you not break!
        // this is due to the possibility of other unqualified tokens being allowed
        if (fee_id == "QUALIFIED")
        {
            allowed_fee = zera_fees::ALLOWED_CONTRACT_FEE::QUALIFIED;
            break;
        }
        else if (fee_id == "ANY")
        {
            allowed_fee = zera_fees::ALLOWED_CONTRACT_FEE::ANY;
            break;
        }
        if (contract_id == fee_id)
        {
            allowed_fee = zera_fees::ALLOWED_CONTRACT_FEE::ALLOWED;
            break;
        }
    }

    if (allowed_fee == zera_fees::ALLOWED_CONTRACT_FEE::NOT_ALLOWED)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_utils.cpp: check_contract_fee_id: Fee contract id is not allowed: " + contract_id, zera_txn::TXN_STATUS::INVALID_CONTRACT_FEE_ID);
    }

    if (!db_contracts::exist(contract_id))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_utils.cpp: check_contract_fee_id: Fee contract id does not exist", zera_txn::TXN_STATUS::INVALID_CONTRACT_FEE_ID);
    }

    return ZeraStatus();
}

// function to check if token is qualified, and get the usd equiv of token
bool zera_fees::check_qualified(const std::string &contract_id)
{

    if (contract_id == ZERA_SYMBOL)
    {
        return true;
    }

    if (!db_contracts::exist(contract_id))
    {
        return false;
    }

    std::string ace_sc_key;

    if (!db_smart_contracts::get_single(ACE_PROXY, ace_sc_key) || ace_sc_key == "")
    {
        return false;
    }

    ace_sc_key += "_" + contract_id;

    std::string rate_data;
    if (!db_smart_contracts::get_single(ace_sc_key, rate_data) || rate_data == "")
    {
        return false;
    }

    return true;
}

ZeraStatus zera_fees::calculate_fees(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                     const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const zera_txn::PublicKey &public_key, const bool safe_send)
{

    uint256_t fee_per_byte(FEE_PER_BYTE);
    uint256_t fee = fee_per_byte * bytes;
    uint256_t denomination(denomination_str);
    uint256_t item_fee = denomination * fee;
    txn_fee_amount = item_fee / TOKEN_USD_EQIV;

    uint256_t authorized_fees_uint(authorized_fees);

    uint256_t key_fee = get_key_fee(public_key);
    uint256_t key_fee_amount = key_fee * denomination;

    if (safe_send)
    {
        uint256_t safe_send_fee = get_fee("SAFE_SEND");
        uint256_t safe_send_amount = safe_send_fee * denomination;
        txn_fee_amount += safe_send_amount / TOKEN_USD_EQIV;
    }

    txn_fee_amount += key_fee_amount / TOKEN_USD_EQIV;

    if (txn_fee_amount > authorized_fees_uint)
    {
        logging::print("process_coin.cpp: calculate_fees: The sender did not authorize enough fees.", txn_fee_amount.str(), true);
        logging::print("authorized_fees_uint: ", authorized_fees_uint.str(), true);
        return ZeraStatus(ZeraStatus::Code::COIN_TXN_ERROR, "process_coin.cpp: calculate_fees: The sender did not authorize enough fees.", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
    }

    return ZeraStatus();
}

ZeraStatus zera_fees::calculate_fees(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                     const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const bool safe_send)
{

    uint256_t fee_per_byte(FEE_PER_BYTE);
    uint256_t fee = fee_per_byte * bytes;
    uint256_t denomination(denomination_str);
    uint256_t item_fee = denomination * fee;
    txn_fee_amount = item_fee / TOKEN_USD_EQIV;

    uint256_t authorized_fees_uint(authorized_fees);

    if (safe_send)
    {
        uint256_t safe_send_fee = get_fee("SAFE_SEND");
        uint256_t safe_send_amount = safe_send_fee * denomination;
        txn_fee_amount += safe_send_amount / TOKEN_USD_EQIV;
    }

    if (txn_fee_amount > authorized_fees_uint)
    {
        logging::print("process_coin.cpp: calculate_fees: The sender did not authorize enough fees.", txn_fee_amount.str(), true);
        logging::print("authorized_fees_uint: ", authorized_fees_uint.str(), true);
        return ZeraStatus(ZeraStatus::Code::COIN_TXN_ERROR, "process_coin.cpp: calculate_fees: The sender did not authorize enough fees.", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
    }

    return ZeraStatus();
}

ZeraStatus zera_fees::calculate_fees_heartbeat(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                               const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const zera_txn::PublicKey &public_key)
{
    uint256_t fee_per_byte(FEE_PER_BYTE);
    uint256_t fee = fee_per_byte * bytes;
    uint256_t denomination(denomination_str);
    uint256_t item_fee = denomination * fee;
    txn_fee_amount = item_fee / TOKEN_USD_EQIV;

    uint256_t authorized_fees_uint(authorized_fees);

    if (txn_fee_amount > authorized_fees_uint)
    {
        return ZeraStatus(ZeraStatus::Code::COIN_TXN_ERROR, "process_coin.cpp: calculate_fees: The sender did not authorize enough fees.", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
    }

    return ZeraStatus();
}

ZeraStatus zera_fees::process_fees(const zera_txn::InstrumentContract &contract, uint256_t fee_amount,
                                   const std::string &wallet_adr, const std::string &fee_symbol,
                                   bool base, zera_txn::TXNStatusFees &status_fees, const std::string &txn_hash, const std::string &current_validator_address, const bool storage_fees)
{

    const uint256_t zero_256 = 0;
    uint256_t sender_balance;
    ZeraStatus status = ZeraStatus();
    if (!storage_fees)
    {
        status = balance_tracker::subtract_txn_balance(wallet_adr, fee_symbol, fee_amount, txn_hash);
    }

    if (!status.ok())
    {
        logging::print("process_utils.cpp: process_fees: ", status.read_status());

        if (base)
        {
            return ZeraStatus(ZeraStatus::Code::WALLET_INSUFFICIENT_FUNDS, "process_utils.cpp: process_fess: " + status.read_status());
        }

        return status;
    }
    std::string validator_fee_address = ValidatorConfig::get_fee_address_string();

    if (current_validator_address != "")
    {
        validator_fee_address = current_validator_address;
    }

    auto tres_wallet_vec = base58_decode(ValidatorConfig::get_treasury_wallet());
    std::string treasury_wallet(tres_wallet_vec.begin(), tres_wallet_vec.end());

    uint256_t burn_percent = get_fee("BURN_FEE_PERCENTAGE");
    uint256_t validator_percent = get_fee("VALIDATOR_FEE_PERCENTAGE");
    uint256_t treasury_percent = 0;
    uint256_t contract_percent = 0;

    uint256_t validator_fee = 0;
    uint256_t contract_fee = 0;
    uint256_t treasury_fee = 0;
    uint256_t burn_fee = 0;

    if (!base)
    {
        burn_percent = boost::lexical_cast<uint256_t>(contract.contract_fees().burn());
        validator_percent = boost::lexical_cast<uint256_t>(contract.contract_fees().validator());
        contract_percent = 100 - burn_percent - validator_percent;
    }
    else
    {
        treasury_percent = get_fee("TREASURY_FEE_PERCENTAGE");
    }
    if (validator_percent > zero_256)
    {
        validator_fee = (validator_percent * fee_amount) / 100;
        balance_tracker::add_txn_balance(validator_fee_address, fee_symbol, validator_fee, txn_hash);
        proposing::set_txn_token_fees(txn_hash, fee_symbol, validator_fee_address, validator_fee);
    }
    if (treasury_percent > zero_256)
    {
        treasury_fee = (treasury_percent * fee_amount) / 100;
        balance_tracker::add_txn_balance(treasury_wallet, fee_symbol, treasury_fee, txn_hash);
        proposing::set_txn_token_fees(txn_hash, fee_symbol, treasury_wallet, treasury_fee);
    }
    if (burn_percent > zero_256)
    {
        if (base)
        {
            burn_fee = fee_amount - validator_fee - contract_fee - treasury_fee;
        }
        else
        {
            burn_fee = (burn_percent * fee_amount) / 100;
        }

        balance_tracker::add_txn_balance(BURN_WALLET, fee_symbol, burn_fee, txn_hash);
        proposing::set_txn_token_fees(txn_hash, fee_symbol, BURN_WALLET, burn_fee);
    }
    if (contract_percent > zero_256)
    {
        contract_fee = fee_amount - validator_fee - burn_fee;
        balance_tracker::add_txn_balance(contract.contract_fees().fee_address(), fee_symbol, contract_fee, txn_hash);
        proposing::set_txn_token_fees(txn_hash, fee_symbol, contract.contract_fees().fee_address(), contract_fee);
    }

    if (!storage_fees)
    {
        if (is_valid_uint256(status_fees.base_fees()))
        {
            uint256_t total_fee(status_fees.base_fees());
            total_fee += fee_amount;
            status_fees.set_base_fees(boost::lexical_cast<std::string>(total_fee));
        }
        else
        {
            status_fees.set_base_contract_id(fee_symbol);
            status_fees.set_base_fees(boost::lexical_cast<std::string>(fee_amount));
        }
    }
    else
    {
        status_fees.set_native_function_fees(boost::lexical_cast<std::string>(fee_amount));
    }

    return ZeraStatus(ZeraStatus::Code::OK);
}
ZeraStatus zera_fees::process_interface_fees(const zera_txn::CoinTXN *txn, zera_txn::TXNStatusFees &status_fees)
{
    zera_txn::BaseTXN base = txn->base();

    if (base.interface_fee().empty() || base.interface_fee_id().empty() || base.interface_fee_id().empty())
    {
        return ZeraStatus();
    }

    if (!is_valid_uint256(base.interface_fee()))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_utils.cpp: process_interface_fees: Invalid interface fee", zera_txn::TXN_STATUS::INVALID_UINT256);
    }

    uint256_t interface_fee(base.interface_fee());

    if (interface_fee <= 0)
    {
        return ZeraStatus();
    }

    std::string contract_id = base.interface_fee_id();
    std::string interface_wallet = base.interface_address();
    std::string interface_amount = base.interface_fee();
    uint256_t fee_amount = boost::lexical_cast<uint256_t>(interface_amount);
    std::string txn_hash = base.hash();

    auto sender_wallet = wallets::generate_wallet(base.public_key());

    uint256_t divided_fee = fee_amount / txn->auth().public_key_size();

    int x = 1;
    for (auto auth : txn->auth().public_key())
    {
        uint256_t auth_fee = divided_fee;
        if (x == txn->auth().public_key_size())
        {
            auth_fee = fee_amount - (divided_fee * (x - 1));
        }

        auto auth_wallet = wallets::generate_wallet(auth);
        ZeraStatus status = balance_tracker::subtract_txn_balance(auth_wallet, contract_id, auth_fee, txn_hash);

        if (!status.ok())
        {
            logging::print("process_interface_fees.cpp: ", status.read_status());

            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_utils.cpp: process_fess: " + status.read_status(), zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
        }

        x++;
    }

    balance_tracker::add_txn_balance(interface_wallet, contract_id, fee_amount, txn_hash);
    proposing::set_txn_token_fees(txn_hash, contract_id, interface_wallet, fee_amount);

    status_fees.set_interface_fee(interface_amount);
    status_fees.set_interface_fee_id(contract_id);

    return ZeraStatus();
}

ZeraStatus zera_fees::process_interface_fees(const zera_txn::BaseTXN &base, zera_txn::TXNStatusFees &status_fees)
{
    if (base.interface_fee().empty() || base.interface_fee_id().empty() || base.interface_fee_id().empty())
    {
        return ZeraStatus();
    }

    if (!is_valid_uint256(base.interface_fee()))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_utils.cpp: process_interface_fees: Invalid interface fee", zera_txn::TXN_STATUS::INVALID_UINT256);
    }

    uint256_t interface_fee(base.interface_fee());

    if (interface_fee <= 0)
    {
        return ZeraStatus();
    }

    std::string contract_id = base.interface_fee_id();
    std::string interface_wallet = base.interface_address();
    std::string interface_amount = base.interface_fee();
    uint256_t fee_amount = boost::lexical_cast<uint256_t>(interface_amount);
    std::string txn_hash = base.hash();

    auto sender_wallet = wallets::generate_wallet(base.public_key());

    ZeraStatus status = balance_tracker::subtract_txn_balance(sender_wallet, contract_id, fee_amount, txn_hash);

    if (!status.ok())
    {
        logging::print("process_interface_fees.cpp: ", status.read_status());

        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_utils.cpp: process_fess: " + status.read_status(), zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
    }

    balance_tracker::add_txn_balance(interface_wallet, contract_id, fee_amount, txn_hash);
    proposing::set_txn_token_fees(txn_hash, contract_id, interface_wallet, fee_amount);

    status_fees.set_interface_fee(interface_amount);
    status_fees.set_interface_fee_id(contract_id);

    return ZeraStatus();
}