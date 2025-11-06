#include "../block_process.h"
#include "../../temp_data/temp_data.h"
#include "const.h"
#include "wallets.h"
#include "smart_contract_service.h"
#include <typeinfo>
#include <any>
#include "../logging/logging.h"
#include "validators.h"
#include "fees.h"
#include "zera_api.pb.h"
#include "validator_api_client.h"
#include "hex_conversion.h"

namespace
{
    void storage_fees(const zera_txn::SmartContractExecuteTXN *txn, const uint256_t &fees, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        uint256_t usd_equiv;
        std::string contract_id = "$ZRA+0000";
        zera_txn::InstrumentContract contract;

        auto wallet_adr = wallets::generate_wallet(txn->base().public_key());

        zera_fees::process_fees(contract, fees, wallet_adr, contract_id, true, status_fees, txn->base().hash(), fee_address, true);
    }

    ZeraStatus gas_fees(const zera_txn::SmartContractExecuteTXN *txn, const uint64_t &used_gas, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        uint256_t usd_equiv;
        std::string contract_id = txn->base().fee_id();
        zera_txn::InstrumentContract contract;

        if(!zera_fees::get_cur_equiv(contract_id, usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_smart_contract_execute.cpp: gas_fees: invalid token for fees: " + contract_id);
        }

        block_process::get_contract(contract_id, contract);
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t gas_used_fee = used_gas * get_fee("GAS_FEE");

        uint256_t gas_used_fee_value = (gas_used_fee * denomination) / usd_equiv;
        auto wallet_adr = wallets::generate_wallet(txn->base().public_key());

        return zera_fees::process_fees(contract, gas_used_fee_value, wallet_adr, contract_id, true, status_fees, txn->base().hash(), fee_address);
    }
    ZeraStatus gas_limit_calc(const uint256_t &fee_taken, const zera_txn::SmartContractExecuteTXN *txn, uint64_t &gas_approved, uint256_t &fee_left)
    {
        uint256_t usd_equiv;
        std::string contract_id = txn->base().fee_id();
        zera_txn::InstrumentContract contract;

        if(!zera_fees::get_cur_equiv(contract_id, usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_smart_contract_execute.cpp: gas_limit_calc: invalid token for fees: " + contract_id);
        }

        block_process::get_contract(contract_id, contract);
        uint256_t denomination(contract.coin_denomination().amount());

        uint256_t fee_left_value = (fee_left * usd_equiv) / denomination;

        uint256_t gas = fee_left_value / get_fee("GAS_FEE");
        logging::print("fee_taken:", fee_taken.str());
        logging::print("gas_approved:", gas.str());

        gas_approved = static_cast<uint64_t>(gas);

        auto wallet_adr = wallets::generate_wallet(txn->base().public_key());

        return balance_tracker::subtract_txn_balance(wallet_adr, contract_id, fee_left, txn->base().hash());
    }
    ZeraStatus check_execute(const zera_txn::SmartContractExecuteTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address, const uint64_t &gas_approved, uint64_t &used_gas, std::vector<std::string> &txn_hashes, zera_api::SmartContractEventsResponse &event)
    {

        ZeraStatus status1 = zera_fees::process_interface_fees(txn->base(), status_fees);

        if (!status1.ok())
        {
            return status1;
        }

        std::vector<std::any> params_vector;

        for (auto param : txn->parameters())
        {

            const char *value = param.value().c_str();
            std::string type = param.type();

            if (type == "string")
            {
                logging::print("string: ", value, true);
                params_vector.push_back(param.value());
            }
            else if (type == "uint64")
            {
                uint64_t val;
                std::memcpy(&val, value, sizeof(uint64_t));
                params_vector.push_back(val);
            }
            else if (type == "uint32")
            {
                uint32_t val;
                std::memcpy(&val, value, sizeof(uint32_t));
                params_vector.push_back(val);
            }
            else if (type == "bytes")
            {
                size_t length = param.value().size();
                std::vector<uint8_t> byte_array(value, value + length);
                params_vector.push_back(byte_array);
            }
        }

        if (txn->function() == "init")
        {
            logging::print("[ProcessSmartContractExecute] DONE with ERROR: call 'init' function not allowed");
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "call 'init' function not allowed", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        int instance_number = txn->instance();
        const std::string instance_string = std::to_string(instance_number);

        zera_txn::SmartContractTXN db_contract;

        // read instance contract
        std::string instance_name = txn->smart_contract_name() + "_" + instance_string;

        std::string raw_data;
        db_smart_contracts::get_single(instance_name, raw_data);

        if (raw_data.empty())
        {
            logging::print("[ProcessSmartContractExecute] DONE with ERROR: no smart contract found:", instance_name);
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "no smart contract found", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        db_contract.ParseFromString(raw_data);

        std::string sender_wallet_adr = wallets::generate_wallet(txn->base().public_key());
        // get dependencies contracts
        std::vector<std::string> dependencies_vector;
        // for (auto dep : db_contract.dependencies())
        // {
        //     dependencies_vector.push_back(dep);
        // }

        const std::string sender_pub_key = wallets::get_public_key_string(txn->base().public_key());

        uint64_t timestamp = txn->base().timestamp().seconds();
        std::string block_txns_key = "BLOCK_TXNS_" + txn->base().hash();
        zera_txn::PublicKey smart_contract_pub_key;
        smart_contract_pub_key.set_smart_contract_auth("sc_" + instance_name);
        std::string smart_contract_wallet = wallets::generate_wallet(smart_contract_pub_key);

        try
        {
            std::vector<std::any> results = smart_contract_service::eval(sender_pub_key, sender_wallet_adr,
                                                                         instance_name, db_contract.binary_code(),
                                                                         db_contract.language(), txn->function(),
                                                                         params_vector, dependencies_vector,
                                                                         txn->base().hash(), timestamp,
                                                                         block_txns_key, fee_address,
                                                                         smart_contract_wallet, gas_approved,
                                                                         used_gas, txn_hashes);

            // store result
            std::string event_data = "";
            for (int i = results.size() - 1; i >= 0; --i)
            {
                std::string val = std::any_cast<std::string>(results[i]);
                logging::print("result", std::to_string(i), ":", val);
                status_fees.add_smart_contract_result(val);

                event_data += "[res]" + val + "[end]";
            }

            if (event_data.size() > 0)
            {

                std::string sc_data;
                std::string txn_hash = hex_conversion::bytes_to_hex(txn->base().hash());

                db_event_management::get_single(EVENT_MANAGEMENT_TEMP, sc_data);
                zera_api::SmartContractEventManagementTemp event_management_temp;
                event_management_temp.ParseFromString(sc_data);
                event_management_temp.add_event_keys(txn_hash);
                event_management_temp.add_smart_contract_ids(instance_name);
                db_event_management::store_single(EVENT_MANAGEMENT_TEMP, event_management_temp.SerializeAsString());

                zera_api::SmartContractEventsResponse event_management;
                event_management.set_smart_contract(instance_name);
                event_management.set_instance(txn->instance());
                event_management.set_gas_used(used_gas);
                event_management.set_gas_approved(gas_approved);
                event_management.set_function(txn->function());
                event_management.mutable_caller()->CopyFrom(txn->base().public_key());
                event_management.set_function(txn->function());
                event_management.set_txn_hash(txn_hash);
                event_management.set_event_data(event_data);
                db_event_management::store_single(txn_hash, event_management.SerializeAsString());
            }

            if (db_sc_subscriber::exist(instance_name))
            {
                event.set_smart_contract(txn->smart_contract_name());
                event.set_instance(txn->instance());
                event.set_gas_used(used_gas);
                event.set_gas_approved(gas_approved);
                event.set_function(txn->function());
                event.mutable_caller()->CopyFrom(txn->base().public_key());
                event.set_function(txn->function());
                std::string txn_hash = hex_conversion::bytes_to_hex(txn->base().hash());
                event.set_txn_hash(txn_hash);
                event.set_event_data(event_data);
            }

            txn_hash_tracker::add_sc_to_hash();
            nonce_tracker::add_sc_to_used_nonce();
            db_sc_temp::remove_all();
            return ZeraStatus();
        }
        catch (const std::exception &e)
        {
            logging::print("[ProcessSmartContractExecute] Exception caught:", e.what(), true);

            logging::print("gas fees:", std::to_string(used_gas));
            nonce_tracker::clear_sc_nonce();
            txn_hash_tracker::clear_sc_txn_hash();
            for (auto hash : txn_hashes)
            {
                balance_tracker::remove_txn_balance(hash);
            }

            std::vector<std::string> keys;
            std::vector<std::string> values;

            db_sc_temp::get_all_data(keys, values);

            int x = 0;

            for (auto key : keys)
            {
                if (values[x].empty())
                {
                    db_smart_contracts::remove_single(key);
                }
                else
                {
                    db_smart_contracts::store_single(key, values[x]);
                }
                x++;
            }

            txn_hash_tracker::add_sc_to_hash();
            nonce_tracker::add_sc_to_used_nonce();
            db_sc_temp::remove_all();
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Failed to execute txn", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
        }
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{
    logging::print("[ProcessSmartContractExecute] executing smart contract...", txn->smart_contract_name());
    logging::print("instance:", txn->smart_contract_name());
    logging::print("function:", txn->function());
    logging::print("parameters_size:", std::to_string(txn->parameters_size()));

    uint64_t nonce = txn->base().nonce();
    ZeraStatus status;

    // timed txns do need to check nonce, they have already been checked on the original txn
    if (!timed)
    {
        // check nonce, if its bad return failed txn
        status = block_process::check_nonce(txn->base().public_key(), nonce, txn->base().hash(), sc_txn);

        if (!status.ok())
        {
            return status;
        }
    }

    // only check restricted keys if not timed, original txn has already been checked if it is timed
    if (!timed)
    {
        // this checks to see if the key is valid to send this type of txn, also checks to see if key is from a validator, which is not allowed
        std::string pub_key = wallets::get_public_key_string(txn->base().public_key());
        status = block_process::check_validator(pub_key, txn_type);

        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, status.message(), zera_txn::TXN_STATUS::INVALID_TXN_DATA);
        }
    }

    uint256_t fee_taken = 0;
    // process base fees. If wallet cannot pay fees or anything else is wrong with the fees return failed txn
    status = zera_fees::process_simple_fees_gas(txn, status_fees, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE, fee_taken, fee_address);

    if (!status.ok())
    {
        return status;
    }

    uint64_t gas_approved;
    uint256_t fee_approved(txn->base().fee_amount());
    if (fee_approved < fee_taken)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_smart_contract_execute.cpp: process_txn: Fee taken is greater than fee approved", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
    }

    uint256_t fee_left = fee_approved - fee_taken;
    uint64_t used_gas = 0;
    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());

    status = gas_limit_calc(fee_taken, txn, gas_approved, fee_left);

    std::vector<std::string> txn_hashes;
    if (status.ok())
    {
        zera_api::SmartContractEventsResponse event;
        status = check_execute(txn, status_fees, fee_address, gas_approved, used_gas, txn_hashes, event);
        balance_tracker::add_txn_balance(wallet_adr, txn->base().fee_id(), fee_left, txn->base().hash());
        status_fees.set_gas(used_gas);

        std::string storage_key = "STORAGE_FEE_" + txn->smart_contract_name() + "_" + std::to_string(txn->instance());
        std::string storage_data;
        uint256_t total_fee = 0;

        if (db_smart_contracts::get_single(storage_key, storage_data))
        {
            if (is_valid_uint256(storage_data))
            {
                total_fee = boost::lexical_cast<uint256_t>(storage_data);
            }

            storage_fees(txn, total_fee, status_fees, fee_address);
            db_smart_contracts::remove_single(storage_key);
        }

        if (used_gas > 0)
        {
            gas_fees(txn, used_gas, status_fees, fee_address);
        }

        if (event.has_caller())
        {
            event.set_storage_fee(total_fee.str());
            ValidatorAPIClient::StageEvent(event);
        }
    }

    // nothing went wrong, status is good!
    // add nonce to nonce tracker, if block passed nonce will be stored for wallet

    if (!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }
    status_fees.set_status(status.txn_status());

    if (!status.ok())
    {

        logging::print(status.read_status());
    }

    logging::print("[ProcessSmartContractExecute] DONE");

    return ZeraStatus();
}