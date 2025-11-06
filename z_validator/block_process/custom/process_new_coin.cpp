// Standard library headers

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

// Project-specific headers
#include "const.h"
#include "../block_process.h"
#include "wallets.h"
#include "validators.h"
#include "db_base.h"
#include "utils.h"
#include "../../temp_data/temp_data.h"
#include "../../compliance/compliance.h"
#include "../../logging/logging.h"
#include "fees.h"

namespace
{

    ZeraStatus check_contract_fee_percent(const zera_txn::CoinTXN &txn)
    {
        uint256_t total_percent(0);
        for (auto input : txn.input_transfers())
        {
            total_percent += input.contract_fee_percent();
        }

        if (total_percent != 100000000)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: check_contract_fee_percent: Contract fee percent is not equal to 100%", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        return ZeraStatus();
    }
    void get_fixed_contract_fee(const zera_txn::InstrumentContract &contract, const uint256_t &contract_fee, const std::string &fee_id, uint256_t &fixed_fee_amount)
    {

        std::string priority_fee_id = contract.contract_fees().allowed_fee_instrument().at(0);
        fixed_fee_amount = contract_fee;

        logging::print("priority fee id:", priority_fee_id);
        logging::print("fee id:", fee_id);
        logging::print("contract fee:", contract_fee.str());

        if (fee_id == priority_fee_id)
        {
            return;
        }

        uint256_t fee_equiv;
        if(!zera_fees::get_cur_equiv(fee_id, fee_equiv))
        {
            fee_equiv = ONE_DOLLAR;
        }
        uint256_t priority_equiv;

        if(!zera_fees::get_cur_equiv(priority_fee_id, priority_equiv))
        {
            priority_equiv = ONE_DOLLAR;
        }

        logging::print("fee_equiv:", fee_equiv.str());
        logging::print("priority_equiv:", priority_equiv.str());

        fixed_fee_amount = (fixed_fee_amount * priority_equiv) / fee_equiv;
    }
    void get_percent_contract_fee(const uint256_t &contract_fee, const std::string &fee_id, const std::string &txn_contract_id, const uint256_t &amount, uint256_t &perc_fee_amount)
    {
        uint256_t quintillion(QUINTILLION);

        perc_fee_amount = amount * contract_fee / quintillion;

        if (txn_contract_id == fee_id)
        {
            return;
        }

        uint256_t fee_equiv;
        if(!zera_fees::get_cur_equiv(fee_id, fee_equiv))
        {
            fee_equiv = ONE_DOLLAR;
        }
        uint256_t txn_equiv;
        if(!zera_fees::get_cur_equiv(fee_id, fee_equiv))
        {
            txn_equiv = ONE_DOLLAR;
        }

        perc_fee_amount = (perc_fee_amount * txn_equiv) / fee_equiv;
    }
    void calculate_fixed_fee(zera_txn::CoinTXN *txn, uint256_t &fixed_fee_amount, const uint256_t &usd_equiv)
    {
        fixed_fee_amount = 0;
        for (auto public_key : txn->auth().public_key())
        {
            fixed_fee_amount += get_key_fee(public_key);
        }

        fixed_fee_amount = fixed_fee_amount / usd_equiv;
    }

    ZeraStatus calculate_contract_fee(const zera_txn::InstrumentContract &contract, const uint256_t amount, const zera_txn::CoinTXN &txn, uint256_t &contract_fee_amount)
    {

        if (!txn.has_contract_fee_id())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: calculate_contract_fee: No contract fee id", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        for (auto id : contract.contract_fees().allowed_fee_instrument())
        {
            if (id == txn.contract_fee_id())
            {
                break;
            }
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: calculate_contract_fee: Invalid contract fee id", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        uint256_t contract_fee(contract.contract_fees().fee());
        uint256_t denomination(contract.coin_denomination().amount());

        switch (contract.contract_fees().contract_fee_type())
        {
        case zera_txn::CONTRACT_FEE_TYPE::CUR_EQUIVALENT:
        {
            // contract fee has quintillion multiplier
            // fee_equiv has 1 quintillion multiplier
            uint256_t fee_equiv;
            if(!zera_fees::get_cur_equiv(txn.contract_fee_id(), fee_equiv))
            {
                fee_equiv = ONE_DOLLAR;
            }
            contract_fee_amount = (contract_fee * denomination) / fee_equiv;
            break;
        }
        case zera_txn::CONTRACT_FEE_TYPE::FIXED:
        {
            get_fixed_contract_fee(contract, contract_fee, txn.contract_fee_id(), contract_fee_amount);
            break;
        }
        case zera_txn::CONTRACT_FEE_TYPE::PERCENTAGE:
        {
            get_percent_contract_fee(contract_fee, txn.contract_fee_id(), txn.contract_id(), amount, contract_fee_amount);
            break;
        }
        default:
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: calculate_contract_fee: Invalid contract fee type", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            break;
        }
        return ZeraStatus();
    }
    ZeraStatus calculate_byte_fees(const uint256_t &FEE_PER_BYTE, const int &bytes, uint256_t &txn_fee_amount, std::string denomination_str)
    {
        uint256_t fee_per_byte(FEE_PER_BYTE);
        uint256_t fee = fee_per_byte * bytes;
        uint256_t denomination(denomination_str);
        txn_fee_amount = denomination * fee;

        return ZeraStatus();
    }

    ZeraStatus check_auth(const zera_txn::TransferAuthentication &auth, const zera_txn::TRANSACTION_TYPE &txn_type, bool sc_txn, const bool gov)
    {
        ZeraStatus status;
        if (sc_txn || gov)
        {
            if (auth.public_key_size() != auth.nonce_size())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: check_auth: Invalid auth size: Smart contract txn", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }
        }
        else if (auth.signature_size() != auth.public_key_size() && auth.signature_size() != auth.nonce_size())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: check_auth: Invalid auth size", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        for (auto public_key : auth.public_key())
        {

            std::string pub_str = wallets::get_public_key_string(public_key);
            status = block_process::check_validator(pub_str, txn_type);

            if (!status.ok())
            {
                return status;
            }
        }

        return ZeraStatus();
    }

    ZeraStatus check_restricted(const zera_txn::CoinTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed)
    {
        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

        if (!status.ok())
        {
            return status;
        }

        status = restricted_keys_check::check_restricted_keys(txn, contract, txn_type, timed);

        return status;
    }
    ZeraStatus process_contract_fees(const zera_txn::CoinTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address, const bool allowance)
    {
        std::string contract_fee_symbol = txn->contract_id();
        zera_txn::InstrumentContract contract;

        ZeraStatus status = block_process::get_contract(contract_fee_symbol, contract);

        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_contract_fee: Invalid contract fee symbol: " + contract_fee_symbol, zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        if (!contract.has_contract_fees())
        {
            return ZeraStatus();
        }

        status = check_contract_fee_percent(*txn);

        if (!status.ok())
        {
            return status;
        }

        uint256_t amount = 0;

        for (auto input : txn->input_transfers())
        {
            uint256_t input_amount(input.amount());
            amount += input_amount;
        }

        uint256_t contract_fee_amount;

        status = calculate_contract_fee(contract, amount, *txn, contract_fee_amount);

        logging::print("contract_fee_amount", contract_fee_amount.str());
        
        if (!status.ok())
        {
            return status;
        }
        // check if fee type is compatible with token
        zera_fees::ALLOWED_CONTRACT_FEE allowed_fee;
        status = zera_fees::check_allowed_contract_fee(contract.contract_fees().allowed_fee_instrument(), txn->contract_fee_id(), allowed_fee);

        if (!status.ok())
        {
            return status;
        }

        if (allowed_fee == zera_fees::ALLOWED_CONTRACT_FEE::QUALIFIED)
        {
            if (!zera_fees::check_qualified(txn->contract_fee_id()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_contract_fee: Contract requires qualified token fees", zera_txn::TXN_STATUS::INVALID_CONTRACT_FEE_ID);
            }
        }

        // check authorized fee amount
        if (!is_valid_uint256(txn->contract_fee_amount()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_contract_fee: Invalid uint256 - txn->contract_fee_amount()", zera_txn::TXN_STATUS::INVALID_UINT256);
        }

        uint256_t authorized_fees(txn->contract_fee_amount());

        if (contract_fee_amount > authorized_fees)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_contract_fee: Insufficient authorized contract fees.", zera_txn::TXN_STATUS::AUTHORIZED_INSUFFICIENT_CONTRACT_FEES);
        }

        if (allowance)
        {
            uint256_t transfer_fee_amount = contract_fee_amount;
            std::string wallet_adr = wallets::generate_wallet(txn->auth().public_key(0));
            std::string txn_hash = txn->base().hash();
            status = zera_fees::process_fees(contract, transfer_fee_amount, wallet_adr, contract_fee_symbol, false, status_fees, txn_hash, fee_address);
            if (!status.ok())
            {
                return status;
            }
        }
        else
        {
            int x = 0;

            for (auto input : txn->input_transfers())
            {

                logging::print("input.contract_fee_percent()", std::to_string(input.contract_fee_percent()));

                uint256_t transfer_fee_amount = (contract_fee_amount * input.contract_fee_percent()) / 100000000;

                logging::print("transfer_fee_amount", transfer_fee_amount.str());

                std::string wallet_adr = wallets::generate_wallet(txn->auth().public_key(x));
                std::string txn_hash = txn->base().hash();
                status = zera_fees::process_fees(contract, transfer_fee_amount, wallet_adr, contract_fee_symbol, false, status_fees, txn_hash, fee_address);
                if (!status.ok())
                {
                    return status;
                }

                x++;
            }
        }
        status_fees.set_contract_contract_id(contract_fee_symbol);
        status_fees.set_contract_fees(boost::lexical_cast<std::string>(contract_fee_amount));

        return ZeraStatus();
    }
    ZeraStatus process_base_fees(const zera_txn::CoinTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address, const bool allowance)
    {
        ZeraStatus status;
        uint256_t fee_type(get_txn_fee(zera_txn::TRANSACTION_TYPE::COIN_TYPE));

        uint256_t txn_fee_amount;
        // zera_txn::InstrumentContract base_contract;
        // status = block_process::get_contract(txn->contract_id(), base_contract);

        zera_txn::InstrumentContract contract;
        status = block_process::get_contract(txn->base().fee_id(), contract);

        if (!status.ok())
        {
            return status;
        }

        if (!is_valid_uint256(txn->base().fee_amount()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_base_fees: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
        }

        calculate_byte_fees(fee_type, txn->ByteSize(), txn_fee_amount, contract.coin_denomination().amount());

        uint32_t base_fee_percent = 0;

        if (!allowance)
        {
            for (auto input : txn->input_transfers())
            {
                base_fee_percent += input.fee_percent();
            }
        }
        else
        {
            base_fee_percent = 100000000;
        }

        if (base_fee_percent != 100000000)
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_transfer_fees: base fee percent is greater or smaller than 100%");
        }

        // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
        uint256_t equiv;


        if(!zera_fees::get_cur_equiv(contract.contract_id(), equiv))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: invalid token for fees CoinTXN: " + contract.contract_id());
        }

        if (!is_valid_uint256(txn->base().fee_amount()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_base_fees: Invalid uint256 - txn->base().base_fee_amount()", zera_txn::TXN_STATUS::INVALID_UINT256);
        }

        uint256_t base_fee(txn->base().fee_amount());

        txn_fee_amount /= equiv;

        uint256_t denomination(contract.coin_denomination().amount());

        for (auto public_key : txn->auth().public_key())
        {
            uint256_t key_fee = get_key_fee(public_key);

            txn_fee_amount += (key_fee * denomination) / equiv;
        }

        logging::print("FEE AMOUNT!!!", txn_fee_amount.str(), true);
        logging::print("TXN_SIZE!!!", std::to_string(txn->ByteSize()), true);
        if (!allowance)
        {
            int x = 0;

            for (auto input : txn->input_transfers())
            {

                uint256_t fee_amount = (txn_fee_amount * input.fee_percent()) / 100000000;

                uint256_t auth_amount = (base_fee * input.fee_percent()) / 100000000;

                if (fee_amount > auth_amount)
                {
                    return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: fee amount is greater than auth amount: " + contract.contract_id());
                }

                std::string wallet_key = wallets::generate_wallet(txn->auth().public_key(x));
                status = zera_fees::process_fees(contract, fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);

                if (!status.ok())
                {
                    return status;
                }

                x++;
            }
        }
        else
        {
            uint256_t fee_amount = txn_fee_amount;

            uint256_t auth_amount = base_fee;

            if (fee_amount > auth_amount)
            {
                return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: fee amount is greater than auth amount: " + contract.contract_id());
            }

            std::string wallet_key = wallets::generate_wallet(txn->auth().public_key(0));
            status = zera_fees::process_fees(contract, fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);

            if (!status.ok())
            {
                return status;
            }
        }
        status_fees.set_base_contract_id(contract.contract_id());
        status_fees.set_base_fees(boost::lexical_cast<std::string>(txn_fee_amount));

        return ZeraStatus();
    }
    ZeraStatus validate_wallets(const zera_txn::CoinTXN *txn, const bool allowance)
    {
        uint256_t input_amount = 0;
        uint256_t output_amount = 0;
        std::vector<std::string> wallet_adrs;
        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);
        if (!status.ok())
        {
            return status;
        }
        int x = 0;
        for (auto input : txn->input_transfers())
        {
            if (!is_valid_uint256(input.amount()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfers: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
            }

            uint256_t input_temp(input.amount());
            input_amount += input_temp;
            std::string wallet_adr;

            if (allowance)
            {
                wallet_adr = txn->auth().allowance_address(x);

                if (!allowance_tracker::check_allowance(wallet_adr, txn->auth().public_key(0), txn->contract_id(), input_temp, txn->base().hash(), txn->base().public_key()))
                {
                    return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfers: Insufficient allowance", zera_txn::TXN_STATUS::INVALID_ALLOWANCE);
                }
            }
            else
            {
                wallet_adr = wallets::generate_wallet(txn->auth().public_key(x));
            }

            if (std::find(wallet_adrs.begin(), wallet_adrs.end(), wallet_adr) != wallet_adrs.end())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfers: Duplicate wallet address", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }

            if (!compliance::check_compliance(wallet_adr, contract))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. input wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
            }

            uint256_t increment(input.amount());
            uint256_t sender_balance;

            logging::print("wallet_adr + txn->contract_id(): ", wallet_adr + txn->contract_id(), true);
            logging::print("base58_encode(wallet_adr): ", base58_encode(wallet_adr), true);
            ZeraStatus status = block_process::get_sender_wallet(wallet_adr + txn->contract_id(), sender_balance);
            if (!status.ok())
            {
                return status;
            }

            if (sender_balance < increment)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfers: Insufficient funds input amount.", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
            }

            wallet_adrs.push_back(wallet_adr);
            x++;
        }

        for (auto output : txn->output_transfers())
        {
            if (!check_safe_send(txn->base(), output.wallet_address()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_single: Coin transactions cannot be safe send.", zera_txn::TXN_STATUS::INVALID_SAFE_SEND);
            }
            if (!is_valid_uint256(output.amount()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfers: Invalid uint256 output amount.", zera_txn::TXN_STATUS::INVALID_UINT256);
            }
            if (output.wallet_address().empty() || output.wallet_address().size() == 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfers: Empty wallet address", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }
            if (!compliance::check_compliance(output.wallet_address(), contract))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
            }
            uint256_t output_temp(output.amount());
            output_amount += output_temp;
        }

        if (input_amount != output_amount)
        {
            logging::print("input_amount", input_amount.str());
            logging::print("output_amount", output_amount.str());
            
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfers: input amount does not equal output amount", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        return ZeraStatus();
    }

    ZeraStatus process_transfers(const zera_txn::CoinTXN *txn, const bool allowance)
    {
        int x = 0;
        ZeraStatus status;

        if (allowance)
        {
            std::vector<std::string> wallet_adrs;

            for (auto adress : txn->auth().allowance_address())
            {
                wallet_adrs.push_back(adress);
            }

            status = balance_tracker::subtract_txn_balance_transfer_allowance(txn->input_transfers(), wallet_adrs, txn->contract_id(), txn->base().hash());
        }
        else
        {
            std::vector<zera_txn::PublicKey> public_keys;

            for (auto input : txn->input_transfers())
            {
                public_keys.push_back(txn->auth().public_key(x));
                x++;
            }

            status = balance_tracker::subtract_txn_balance_transfer(txn->input_transfers(), public_keys, txn->contract_id(), txn->base().hash());
        }

        if (!status.ok())
        {
            return status;
        }

        balance_tracker::add_txn_balance_transfer(txn->output_transfers(), txn->contract_id(), txn->base().hash());

        return ZeraStatus();
    }
    ZeraStatus check_transfer_parameters(const zera_txn::CoinTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn, const bool allowance, const bool gov)
    {
        ZeraStatus status;
        status = zera_fees::process_interface_fees(txn, status_fees);

        if (!status.ok())
        {
            return status;
        }

        status = check_auth(txn->auth(), txn_type, sc_txn, gov);
        if (!status.ok())
        {
            return status;
        }

        if (!timed)
        {
            status = check_restricted(txn, txn_type, timed);
            if (!status.ok())
            {
                return status;
            }
        }

        status = validate_wallets(txn, allowance);
        if (!status.ok())
        {
            return status;
        }
        status = process_contract_fees(txn, status_fees, fee_address, allowance);

        if (!status.ok())
        {
            return status;
        }
        status = process_transfers(txn, allowance);

        return status;
    }
    ZeraStatus process_allowance(const zera_txn::CoinTXN *txn, const bool timed, const bool gov, bool &gov_auth, bool sc_txn)
    {
        if (txn->auth().allowance_address_size() != txn->input_transfers_size())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Allowance address size does not match input transfer size", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        if (txn->auth().allowance_address_size() != txn->auth().allowance_nonce_size())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Allowance address size does not match allowance nonce size", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        if (txn->auth().public_key_size() != 1)
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: There needs to be exactly 1 public key for allowance txn", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        if (!timed)
        {
            uint64_t nonce = txn->auth().nonce(0);
            zera_txn::PublicKey public_key = txn->auth().public_key(0);

            if (gov && public_key.has_governance_auth())
            {
                if (txn->base().public_key().governance_auth() != public_key.governance_auth())
                {
                    return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Governance auth does not match", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
                }
                gov_auth = true;
            }

            if (!gov_auth)
            {
                ZeraStatus status = block_process::check_nonce(public_key, nonce, txn->base().hash(), sc_txn);

                if (!status.ok())
                {
                    return status;
                }
            }

            int x = 0;
            //TODO - check about allowance nonce for smart contract txn
            if(sc_txn)
            {
                return ZeraStatus();
            }

            for (auto allowance_address : txn->auth().allowance_address())
            {
                ZeraStatus status = block_process::check_nonce_adr(allowance_address, txn->auth().allowance_nonce(x), txn->base().hash());

                if (!status.ok())
                {
                    return status;
                }

                x++;
            }
        }

        return ZeraStatus();
    }
    ZeraStatus process_standard(const zera_txn::CoinTXN *txn, const bool timed, const bool gov, bool &gov_auth, bool sc_txn)
    {
        if (txn->auth().public_key_size() != txn->auth().nonce_size())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Public key size does not match nonce size", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        if (txn->auth().public_key_size() != txn->input_transfers_size())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Public key size does not match input transfer size", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        int x = 0;
        for (auto public_key : txn->auth().public_key())
        {
            uint64_t nonce = txn->auth().nonce(x);

            if (!timed)
            {
                if (gov && public_key.has_governance_auth())
                {
                    if (txn->base().public_key().governance_auth() != public_key.governance_auth())
                    {
                        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Governance auth does not match", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
                    }
                    gov_auth = true;
                    break;
                }
                ZeraStatus status = block_process::check_nonce(public_key, nonce, txn->base().hash(), sc_txn);

                if (!status.ok())
                {
                    return status;
                }
            }

            x++;
        }

        return ZeraStatus();
    }
}

template <>
ZeraStatus block_process::process_txn<zera_txn::CoinTXN>(const zera_txn::CoinTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{
    bool gov = false;
    bool allowance = false;
    if (txn->base().public_key().has_governance_auth())
    {
        ZeraStatus status = block_process::check_nonce(txn->base().public_key(), 0, txn->base().hash(), sc_txn);
        if (!status.ok())
        {
            return status;
        }
        gov = true;
    }
    if (timed && txn->auth().public_key_size() > 1)
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Timed transactions cannot have multiple public keys", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }

    bool gov_auth = false;

    if (txn->auth().allowance_address_size() > 0)
    {
        ZeraStatus status = process_allowance(txn, timed, gov, gov_auth, sc_txn);

        if (!status.ok())
        {
            return status;
        }

        allowance = true;
    }
    if (!allowance)
    {
        ZeraStatus status = process_standard(txn, timed, gov, gov_auth, sc_txn);

        if (!status.ok())
        {
            return status;
        }
    }

    if (gov && !gov_auth)
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_coin.cpp: process_txn: Governance auth not found", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }

    ZeraStatus status = process_base_fees(txn, status_fees, fee_address, allowance);

    if (!status.ok())
    {
        return status;
    }

    status = check_transfer_parameters(txn, status_fees, txn_type, timed, fee_address, sc_txn, allowance, gov);
    int x = 0;

    if (allowance && status.ok())
    {   
        std::string wallet_adr = wallets::generate_wallet(txn->auth().public_key(0));
        uint64_t txn_nonce = txn->auth().nonce(0);
        if(!sc_txn)
        {
            nonce_tracker::add_nonce(wallet_adr, txn_nonce, txn->base().hash());
        }

        while (x < txn->auth().allowance_address_size() && !sc_txn)
        {
            std::string wallet_adr1 = txn->auth().allowance_address(x);
            txn_nonce = txn->auth().allowance_nonce(x);
            nonce_tracker::add_nonce(wallet_adr1, txn_nonce, txn->base().hash());
            x++;
        }
    }
    else
    {
        while (x < txn->input_transfers_size() && !sc_txn)
        {
            std::string wallet_adr = wallets::generate_wallet(txn->auth().public_key(x));
            uint64_t txn_nonce = txn->auth().nonce(x);
            nonce_tracker::add_nonce(wallet_adr, txn_nonce, txn->base().hash());
            x++;
        }
    }

    status_fees.set_status(status.txn_status());

    if (!status.ok())
    {
        if (allowance)
        {
            allowance_tracker::remove_txn_allowance(txn->base().hash());
        }
        logging::print(status.read_status());
    }

    if (allowance && status.ok())
    {
        allowance_tracker::add_txn_to_pre_process(txn->base().hash());
    }

    return ZeraStatus();
}