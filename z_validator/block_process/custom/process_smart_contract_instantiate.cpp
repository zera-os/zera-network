#include "../block_process.h"
#include "../../temp_data/temp_data.h"
#include "const.h"
#include "wallets.h"
#include "smart_contract_service.h"
#include <any>
#include "../logging/logging.h"
#include "validators.h"
#include "fees.h"
#include "hex_conversion.h"
#include "validator_api_client.h"
#include <algorithm>

namespace
{
    void storage_fees(const zera_txn::SmartContractInstantiateTXN *txn, const uint256_t &fees, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        uint256_t usd_equiv;
        zera_txn::InstrumentContract contract;

        auto wallet_adr = wallets::generate_wallet(txn->base().public_key());

        zera_fees::process_fees(contract, fees, wallet_adr, txn->base().fee_id(), true, status_fees, txn->base().hash(), fee_address, true);
    }

    ZeraStatus gas_fees(const zera_txn::SmartContractInstantiateTXN *txn, const uint64_t &used_gas, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        uint256_t usd_equiv;
        std::string contract_id = txn->base().fee_id();
        zera_txn::InstrumentContract contract;

        if(!zera_fees::get_cur_equiv(contract_id, usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_smart_contract_instantiate.cpp: gas_fees: invalid token for fees: " + contract_id);
        }
        block_process::get_contract(contract_id, contract);
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t gas_used_fee;
        
        if(contract_id != NETWORK_CONTRACT)
        {
            gas_used_fee = used_gas * (get_fee("GAS_FEE") * get_fee("TOKEN_MULTIPLIER")) ;
        }
        else
        {
            gas_used_fee = used_gas * get_fee("GAS_FEE");
        }

        uint256_t gas_used_fee_value = (gas_used_fee * denomination) / usd_equiv;
        auto wallet_adr = wallets::generate_wallet(txn->base().public_key());

        return zera_fees::process_fees(contract, gas_used_fee_value, wallet_adr, contract_id, true, status_fees, txn->base().hash(), fee_address);
    }

    ZeraStatus gas_limit_calc(const uint256_t &fee_taken, const zera_txn::SmartContractInstantiateTXN *txn, uint64_t &gas_approved, uint256_t &fee_left)
    {
        uint256_t usd_equiv;
        std::string contract_id = txn->base().fee_id();
        zera_txn::InstrumentContract contract;

        if(!zera_fees::get_cur_equiv(contract_id, usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_smart_contract_instantiate.cpp: gas_limit_calc: invalid token for fees: " + contract_id);
        }
        
        block_process::get_contract(contract_id, contract);
        uint256_t denomination(contract.coin_denomination().amount());

        uint256_t fee_left_value = (fee_left * usd_equiv) / denomination;

        uint256_t gas;

        if(contract_id != NETWORK_CONTRACT)
        {
            gas = fee_left_value / (get_fee("GAS_FEE") * get_fee("TOKEN_MULTIPLIER")) ;
        }
        else
        {
            gas = fee_left_value / get_fee("GAS_FEE");
        }
        
        logging::print("fee_taken:", fee_taken.str());
        logging::print("gas_approved:", gas.str());

        gas_approved = gas > std::numeric_limits<uint64_t>::max() ? std::numeric_limits<uint64_t>::max() : static_cast<uint64_t>(gas);

        auto wallet_adr = wallets::generate_wallet(txn->base().public_key());

        return balance_tracker::subtract_txn_balance(wallet_adr, contract_id, fee_left, txn->base().hash());
    }

    ZeraStatus instantiate(const zera_txn::SmartContractInstantiateTXN *txn, const std::string &fee_address, const uint64_t &gas_approved, uint64_t &used_gas, std::vector<std::string> &txn_hashes, zera_txn::TXNStatusFees &status_fees, std::vector<zera_api::SmartContractEventsResponse> &events)
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
                logging::print("string:", value, true);
                params_vector.push_back(param.value());
            }
            else if (type == "int")
            {
                int val;
                std::memcpy(&val, value, sizeof(int));
                params_vector.push_back(val);
            }
            else if (type == "bytes")
            {
                size_t length = param.value().size();
                std::vector<uint8_t> byte_array(value, value + length);
                params_vector.push_back(byte_array);
            }
        }

        const std::string instance_string = std::to_string(txn->instance());
        std::string instance_name = txn->smart_contract_name() + "_" + instance_string;
        // check to see if nonce already exists for this smart contract
        // will need a temp database to store this until after the block is verified
        if (db_smart_contracts::exist(instance_name))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Smart contract nonce already exists", zera_txn::TXN_STATUS::DUPLICATE_SMART_CONTRACT_NONCE);
        }

        zera_txn::SmartContractTXN db_contract;

        // E.g. the contract name is 'MyAwesomeContract',
        // then the master contract will be store at 'MyAwesomeContract' key,
        // an instance contract will be store at 'MyAwesomeContract_<nonce>' key,
        // and a wallet will be store at 'MyAwesomeContract_<nonce>_wallet' key.

        // read master contract
        std::string raw_data;
        if (!db_smart_contracts::get_single(txn->smart_contract_name(), raw_data) || !db_contract.ParseFromString(raw_data))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Failed to get smart contract", zera_txn::TXN_STATUS::INVALID_SMART_CONTRACT);
        }

        const std::string sender_pub_key = wallets::get_public_key_string(txn->base().public_key());

        const std::string constructor_function_name = "init";
        std::string sender_wallet_adr = wallets::generate_wallet(txn->base().public_key());

        std::vector<std::string> dependencies;
        uint64_t timestamp = txn->base().timestamp().seconds();
        std::string block_txns_key = "BLOCK_TXNS_" + txn->base().hash();
        zera_txn::PublicKey smart_contract_pub_key;
        smart_contract_pub_key.set_smart_contract_auth("sc_" + instance_name);
        std::string smart_contract_wallet = wallets::generate_wallet(smart_contract_pub_key);
        std::map<std::string, std::string> derived_wallets;
        std::map<std::string, BlockEmitType> block_emits;
        bool panic = false;
        try
        {
            std::vector<std::any> results = smart_contract_service::eval(sender_pub_key, sender_wallet_adr,
                                         instance_name, db_contract.binary_code(),
                                         db_contract.language(), constructor_function_name,
                                         params_vector, dependencies,
                                         txn->base().hash(), timestamp,
                                         block_txns_key, fee_address,
                                         smart_contract_wallet, gas_approved,
                                         used_gas, txn_hashes, derived_wallets, txn->base().fee_id(), block_emits, panic);

            // store result
            std::vector<std::string> vector_results;
            for (int i = results.size() - 1; i >= 0; --i)
            {
                std::string val = std::any_cast<std::string>(results[i]);
                logging::print("result", std::to_string(i), ":", val);
                status_fees.add_smart_contract_result(val);

                vector_results.push_back(val);
            }
            std::string txn_hash = hex_conversion::bytes_to_hex(txn->base().hash());
            std::vector<BlockEmitType> sorted_emits;
            sorted_emits.reserve(block_emits.size());
            for (const auto &[key, entry] : block_emits)
            {
                sorted_emits.push_back(entry);
            }
            std::sort(sorted_emits.begin(), sorted_emits.end(),
                      [](const BlockEmitType &a, const BlockEmitType &b) { return a.depth < b.depth; });

            for (const auto &value : sorted_emits)
            {
                zera_txn::NestedResult *nested_result = status_fees.add_nested_results();
                std::string sc_data;
                std::string sc_key = value.smart_contract_name + "_" + value.smart_contract_instance;
                // sc_key
                db_event_management::get_single(EVENT_MANAGEMENT_TEMP, sc_data);
                zera_api::SmartContractEventManagementTemp event_management_temp;
                event_management_temp.ParseFromString(sc_data);
                event_management_temp.add_event_keys(txn_hash);
                event_management_temp.add_smart_contract_ids(sc_key);
                db_event_management::store_single(EVENT_MANAGEMENT_TEMP, event_management_temp.SerializeAsString());

                zera_api::SmartContractEventsResponse event_management;
                event_management.set_smart_contract(value.smart_contract_name);
                event_management.set_instance(std::stoull(value.smart_contract_instance));
                event_management.set_gas_used(used_gas);
                event_management.set_gas_approved(gas_approved);
                event_management.set_function(value.function);
                event_management.mutable_caller()->CopyFrom(txn->base().public_key());
                event_management.set_txn_hash(txn_hash);

                nested_result->set_smart_contract_name(value.smart_contract_name);
                nested_result->set_smart_contract_instance(std::stoull(value.smart_contract_instance));
                nested_result->set_function(value.function);
                for (const auto &emit : value.emits)
                {

                    event_management.add_event_data(emit);
                    nested_result->add_emits(emit);
                }
                db_event_management::store_single(txn_hash, event_management.SerializeAsString());

                if (db_sc_subscriber::exist(sc_key))
                {
                    events.push_back(event_management);
                }
            }

            if (vector_results.size() > 0)
            {

                std::string sc_data;

                db_event_management::get_single(EVENT_MANAGEMENT_TEMP, sc_data);
                zera_api::SmartContractEventManagementTemp event_management_temp;
                event_management_temp.ParseFromString(sc_data);
                event_management_temp.add_event_keys(txn_hash);
                event_management_temp.add_smart_contract_ids(instance_name);
                db_event_management::store_single(EVENT_MANAGEMENT_TEMP, event_management_temp.SerializeAsString());

                zera_api::SmartContractEventsResponse event_management;
                event_management.set_smart_contract(txn->smart_contract_name());
                event_management.set_instance(txn->instance());
                event_management.set_gas_used(used_gas);
                event_management.set_gas_approved(gas_approved);
                event_management.set_function(constructor_function_name);
                event_management.mutable_caller()->CopyFrom(txn->base().public_key());
                event_management.set_txn_hash(txn_hash);
                for (const auto &result : vector_results)
                {
                    event_management.add_event_data(result);
                }
                db_event_management::store_single(txn_hash, event_management.SerializeAsString());

                if (db_sc_subscriber::exist(instance_name))
                {
                    events.push_back(event_management);
                }
            }

            nonce_tracker::add_sc_to_used_nonce();
            txn_hash_tracker::add_sc_to_hash();
            db_sc_temp::remove_all();
            logging::print("[ProcessSmartContractInstantiate] DONE");

            if(derived_wallets.size() > 0)
            {
                for(const auto& [key, value] : derived_wallets)
                {
                    std::string db_key = value;
                    std::string db_value = key;
                    std::string temp_value;
                    zera_wallets::DerivedWallets derived_wallet;
                    db_smart_contract_states::get_single(db_key, temp_value);
                    derived_wallet.ParseFromString(temp_value);

                    derived_wallet.mutable_wallets()->insert({db_value, true});
                    db_smart_contract_states::store_single(db_key, derived_wallet.SerializeAsString());
                    logging::print("[ProcessSmartContractExecute] Storing derived wallet:", db_key, "->", db_value, true);
                }
            }
        }
        catch (...)
        {


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
                    db_smart_contract_states::remove_single(key);
                }
                else
                {
                    db_smart_contract_states::store_single(key, values[x]);
                }
                x++;
            }

            nonce_tracker::add_sc_to_used_nonce();
            txn_hash_tracker::add_sc_to_hash();
            db_sc_temp::remove_all();

            if(used_gas >= gas_approved)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Failed: used gas is greater than gas approved", zera_txn::TXN_STATUS::OUT_OF_GAS);
            }
            else if(panic)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Failed: panic", zera_txn::TXN_STATUS::SMART_CONTRACT_PANIC);
            }

            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Failed to execute txn", zera_txn::TXN_STATUS::SMART_CONTRACT_CRASH);
        }
        return ZeraStatus();
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn, const std::string &sc_fee_address)
{
    logging::print("[ProcessSmartContractInstantiate] instantiating smart contract...", txn->smart_contract_name());
    logging::print("instance:", std::to_string(txn->instance()), true);

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
    status = zera_fees::process_simple_fees_gas(txn, status_fees, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE, fee_taken, fee_address, sc_txn, sc_fee_address);
    if (!status.ok())
    {
        return status;
    }

    uint64_t gas_approved;
    uint256_t fee_approved(txn->base().fee_amount());
    uint256_t fee_left = fee_approved - fee_taken;
    uint64_t used_gas = 0;
    std::string sender_wallet_adr = wallets::generate_wallet(txn->base().public_key());

    status = gas_limit_calc(fee_taken, txn, gas_approved, fee_left);
    std::vector<std::string> txn_hashes;

    if (status.ok())
    {
        std::vector<zera_api::SmartContractEventsResponse> events;
        status = instantiate(txn, fee_address, gas_approved, used_gas, txn_hashes, status_fees, events);
        status_fees.set_gas(used_gas);
        balance_tracker::add_txn_balance(sender_wallet_adr, txn->base().fee_id(), fee_left, txn->base().hash());

        std::string storage_key = "STORAGE_FEE_" + txn->smart_contract_name() + "_" + std::to_string(txn->instance());
        std::string storage_data;

        uint256_t total_fee = 0;
        logging::print("storage_key: instantiate:", storage_key);
        if (db_smart_contracts::get_single(storage_key, storage_data))
        {
            logging::print("storage_data: execute:", storage_data);

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

        for (auto &event : events)
        {
            if (event.has_caller())
            {
                event.set_storage_fee(total_fee.str());
                ValidatorAPIClient::StageEvent(event);
            }
        }
    }

    if (!status.ok())
    {
        logging::print("block_process::process_txn:", status.read_status());
    }

    status_fees.set_status(status.txn_status());
    if (!sc_txn)
    {
        nonce_tracker::add_nonce(sender_wallet_adr, nonce, txn->base().hash());
    }

    return ZeraStatus();
}