#include "../block_process.h"
#include "utils.h"
#include "../logging/logging.h"
#include "fees.h"

namespace
{
    uint256_t convert_to_cur_equiv(const uint256_t &cur_equiv, const uint256_t &amount, const std::string &contract_id)
    {
        zera_txn::InstrumentContract contract;
        block_process::get_contract(contract_id, contract);
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t convert_amount = amount * cur_equiv / QUINTILLION / denomination;
        return convert_amount;
    }

    uint256_t get_wallet_balance(const zera_txn::Validator &validator, const std::string &contract_id)
    {
        uint256_t cur_equiv;
        if(!zera_fees::get_cur_equiv(contract_id, cur_equiv))
        {
            return 0;
        }

        std::string wallet_adr = wallets::generate_wallet(validator.public_key(), contract_id);
        std::string wallet_balance;

        if (!db_wallets::get_single(wallet_adr, wallet_balance))
        {
            return 0;
        }

        uint256_t amount(wallet_balance);

        return convert_to_cur_equiv(cur_equiv, amount, contract_id);
    }

    ZeraStatus process_registration_fees(const zera_txn::ValidatorRegistration *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const zera_txn::PublicKey &public_key, const std::string &fee_address)
    {
        uint256_t fee_type = get_txn_fee(txn_type);

        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
        if (!status.ok())
        {
            return status;
        }

        // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
        uint256_t usd_equiv;

        if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_heartbeat.cpp: process_fees: invalid token for fees: " + contract.contract_id());
        }
        // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
        uint256_t txn_fee_amount;
        status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), public_key);

        if (!status.ok())
        {
            return status;
        }

        std::string wallet_key = wallets::generate_wallet(public_key);

        status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);

        return status;
    }

    ZeraStatus check_validator_balance(const zera_txn::ValidatorRegistration *txn, const std::string &wallet_str)
    {
        uint256_t total_value = 0;
        uint256_t total_balance = 0;
        uint256_t validator_min_hold = get_fee("VALIDATOR_HOLDING_MINIMUM");
        uint256_t validator_min_zera = get_fee("VALIDATOR_MINIMUM_ZERA");
        if (txn->validator().staked_contract_ids_size() <= 0)
        {
            std::string balance_str;
            uint256_t cur_equiv;
            zera_txn::InstrumentContract contract;

            db_wallets::get_single(wallet_str + ZERA_SYMBOL, balance_str);
            if(!zera_fees::get_cur_equiv(ZERA_SYMBOL, cur_equiv))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_heartbeat.cpp: process_fees: THIS WILL NEVER HAPPEN - INVALID CUR EQUIV: " + std::string(ZERA_SYMBOL));
            }
            block_process::get_contract(ZERA_SYMBOL, contract);

            uint256_t balance(balance_str);
            total_balance = balance;
            uint256_t denomination(contract.coin_denomination().amount());

            total_value = (balance * cur_equiv) / denomination;

            if (total_balance < validator_min_zera && total_value < validator_min_hold)
            {
                logging::print("Validator does not have enough coin to stake. -", balance_str);
                logging::print("wallet:", base58_encode(wallet_str));
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_registration.cpp: check_validator_balance: Validator does not have enough coin to stake. - " + balance_str, zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
            }
        }
        else
        {
            std::string stake_data;
            zera_validator::StakeMultipliers stake_multipliers;
            db_system::get_single(STAKE_MULTIPLIER, stake_data);
            stake_multipliers.ParseFromString(stake_data);
            stake_multipliers.ParseFromString(stake_data);

            std::string full_multiplier = stake_multipliers.default_multiplier();
            uint256_t default_multiplier;

            if (full_multiplier != "N/A")
            {
                default_multiplier = boost::multiprecision::uint256_t(full_multiplier);
            }

            for (auto stake_id : txn->validator().staked_contract_ids())
            {
                uint256_t wallet_balance;

                if (stake_id != ZERA_SYMBOL)
                {
                    wallet_balance = get_wallet_balance(txn->validator(), stake_id);

                    auto it = stake_multipliers.contract_multipliers().find(stake_id);
                    std::string contract_multiplier = "N/A";

                    if (it != stake_multipliers.contract_multipliers().end())
                    {
                        contract_multiplier = it->second;
                    }
                    else
                    {
                        continue;
                        // Handle the error appropriately
                    }

                    if (contract_multiplier != "N/A")
                    {
                        uint256_t multiplier(contract_multiplier);
                        wallet_balance *= multiplier;
                        wallet_balance /= STAKED_MATH_MULTIPLIER;
                    }

                    if (full_multiplier != "N/A")
                    {
                        wallet_balance *= default_multiplier;
                        wallet_balance /= STAKED_MATH_MULTIPLIER;
                    }

                    total_value += wallet_balance;
                }
                else
                {
                    std::string balance_str;
                    uint256_t cur_equiv;
                    zera_txn::InstrumentContract contract;

                    db_wallets::get_single(wallet_str + ZERA_SYMBOL, balance_str);

                    if(!zera_fees::get_cur_equiv(ZERA_SYMBOL, cur_equiv))
                    {
                        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_heartbeat.cpp: process_fees: THIS WILL NEVER HAPPEN - INVALID CUR EQUIV: " + std::string(ZERA_SYMBOL));
                    }

                    block_process::get_contract(ZERA_SYMBOL, contract);

                    uint256_t balance(balance_str);
                    total_balance = balance;
                    uint256_t denomination(contract.coin_denomination().amount());
                    uint256_t zera_value = (balance * cur_equiv) / denomination;

                    if (total_balance >= validator_min_zera || zera_value >= validator_min_hold)
                    {

                        return ZeraStatus();
                    }

                    total_value += zera_value;
                }
            }
        }

        return ZeraStatus();
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::ValidatorRegistration>(const zera_txn::ValidatorRegistration *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{
    uint64_t nonce = txn->base().nonce();
    ZeraStatus status;

    HashType original_hash_type = wallets::get_wallet_type(txn->validator().public_key());

    std::string pub_key_str = wallets::get_public_key_string(txn->validator().public_key());
    KeyType key_type = signatures::get_key_type(pub_key_str);

    if (original_hash_type == HashType::wallet_r || original_hash_type == HashType::wallet_g || original_hash_type == HashType::wallet_sc || key_type == KeyType::ERROR_TYPE)
    {
        return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, "process_registration.cpp: process_txn: Original validator key is not accepted.", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
    }

    HashType gen_hash_type = wallets::get_wallet_type(txn->base().public_key());
    std::string pub_key_str_gen = wallets::get_public_key_string(txn->base().public_key());
    KeyType key_type_gen = signatures::get_key_type(pub_key_str_gen);
    if (gen_hash_type == HashType::wallet_r || gen_hash_type == HashType::wallet_g || gen_hash_type == HashType::wallet_sc || key_type_gen == KeyType::ERROR_TYPE)
    {
        return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, "process_registration.cpp: process_txn: Generated public key is not accepted.", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
    }

    status = block_process::check_nonce(txn->validator().public_key(), nonce, txn->base().hash(), sc_txn);

    if (!status.ok())
    {
        return status;
    }

    status = process_registration_fees(txn, status_fees, txn_type, txn->validator().public_key(), fee_address);

    if (!status.ok())
    {
        return status;
    }

    status = zera_fees::process_interface_fees(txn->base(), status_fees);

    if (!status.ok())
    {
        status_fees.set_status(status.txn_status());
        if(!sc_txn)
        {
            nonce_tracker::add_nonce(wallets::generate_wallet(txn->validator().public_key()), nonce, txn->base().hash());
        }
        return status;
    }

    if (txn->validator().public_key().has_governance_auth() || txn->base().public_key().has_smart_contract_auth() || txn->validator().public_key().has_multi())
    {
        status = ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_registration.cpp: process_txn: Validator public key has governance/sc/multi auth.", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
        status_fees.set_status(status.txn_status());
        if(!sc_txn)
        {
            nonce_tracker::add_nonce(wallets::generate_wallet(txn->validator().public_key()), nonce, txn->base().hash());
        }
        return status;
    }

    if (wallets::get_public_key_string(txn->base().public_key()) != wallets::get_public_key_string(txn->validator().public_key()))
    {
        status = ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_registration.cpp: process_txn: Validator public key does not match generated public key.", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
        status_fees.set_status(status.txn_status());
        if(!sc_txn)
        {
            nonce_tracker::add_nonce(wallets::generate_wallet(txn->base().public_key()), nonce, txn->base().hash());
        }
        return status;
    }

    std::string wallet_adr = wallets::generate_wallet(txn->validator().public_key());

    if (!db_validator_lookup::exist(wallets::get_public_key_string(txn->validator().public_key())))
    {
        if (!txn->register_())
        {
            logging::print("Validator does not exist, cannot unbond. 1");
            status = ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_registration.cpp: process_txn: Validator does not exist, cannot unbond.", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
            status_fees.set_status(status.txn_status());
            if(!sc_txn)
            {
                nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
            }
            return status;
        }
    }
    else
    {
        logging::print("Validator does exist");
    }

    if (txn->register_())
    {
        status = check_validator_balance(txn, wallet_adr);
    }
    status_fees.set_status(status.txn_status());
    if(!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }

    return status;
}