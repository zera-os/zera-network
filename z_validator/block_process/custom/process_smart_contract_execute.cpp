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
#include <algorithm>
#include <limits>
#include "hex_conversion.h"
#include <map>
#include <set>
#include "block_emit_type.h"
#include "utils.h"
namespace
{
    // Convert a gas amount into its fee-currency value (same conversion gas_fees
    // uses to charge), for informational reporting on smart contract events.
    uint256_t gas_to_value(const zera_txn::SmartContractExecuteTXN *txn, const uint64_t &gas)
    {
        uint256_t usd_equiv;
        std::string contract_id = txn->base().fee_id();
        zera_txn::InstrumentContract contract;

        if (gas == 0 || !zera_fees::get_cur_equiv(contract_id, usd_equiv) || usd_equiv == 0)
        {
            return 0;
        }

        block_process::get_contract(contract_id, contract);
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t gas_fee_value;

        if (contract_id != NETWORK_CONTRACT)
        {
            gas_fee_value = gas * (get_fee("GAS_FEE") * get_fee("TOKEN_MULTIPLIER"));
        }
        else
        {
            gas_fee_value = gas * get_fee("GAS_FEE");
        }

        return (gas_fee_value * denomination) / usd_equiv;
    }

    ZeraStatus gas_fees(const zera_txn::SmartContractExecuteTXN *txn, const uint64_t &used_gas, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        uint256_t usd_equiv;
        std::string contract_id = txn->base().fee_id();
        zera_txn::InstrumentContract contract;

        if (!zera_fees::get_cur_equiv(contract_id, usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_smart_contract_execute.cpp: gas_fees: invalid token for fees: " + contract_id);
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
    ZeraStatus gas_limit_calc(const uint256_t &fee_taken, const zera_txn::SmartContractExecuteTXN *txn, uint64_t &gas_approved, uint256_t &fee_left)
    {
        uint256_t usd_equiv;
        std::string contract_id = txn->base().fee_id();
        zera_txn::InstrumentContract contract;

        if (!zera_fees::get_cur_equiv(contract_id, usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_smart_contract_execute.cpp: gas_limit_calc: invalid token for fees: " + contract_id);
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
    ZeraStatus check_execute(const zera_txn::SmartContractExecuteTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address, const uint64_t &gas_approved, uint64_t &used_gas, std::vector<std::string> &txn_hashes, std::vector<zera_api::SmartContractEventsResponse> &events, uint64_t &storage_gas, uint64_t &txn_fee_gas)
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
                if (param.value().size() < sizeof(uint64_t))
                {
                    return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_smart_contract_execute.cpp: check_execute: uint64 parameter too short", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
                }
                uint64_t val;
                std::memcpy(&val, value, sizeof(uint64_t));
                params_vector.push_back(val);
            }
            else if (type == "uint32")
            {
                if (param.value().size() < sizeof(uint32_t))
                {
                    return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_smart_contract_execute.cpp: check_execute: uint32 parameter too short", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
                }
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
        std::map<std::string, std::string> derived_wallets;
        std::map<std::string, BlockEmitType> block_emits;
        bool panic = false;

        // Build the user-signed per-execution outflow allowance budget. Duplicate
        // contract_id entries sum; an explicit "unlimited" wins over a capped entry
        // for the same token. Invalid amounts make the whole txn invalid.
        std::map<std::string, std::string> allowance_remaining;
        std::set<std::string> allowance_unlimited;
        bool allowance_provided = txn->allowances_size() > 0;
        for (const auto &allowance : txn->allowances())
        {
            const std::string &allowance_token = allowance.contract_id();

            if (allowance.unlimited())
            {
                allowance_unlimited.insert(allowance_token);
                allowance_remaining.erase(allowance_token);
                continue;
            }

            if (allowance_unlimited.count(allowance_token))
            {
                continue;
            }

            const std::string &allowance_amount = allowance.allowed_amount();
            if (!is_valid_uint256(allowance_amount))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "invalid smart contract allowance amount", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }

            auto existing = allowance_remaining.find(allowance_token);
            if (existing == allowance_remaining.end())
            {
                allowance_remaining[allowance_token] = allowance_amount;
            }
            else
            {
                allowance_remaining[allowance_token] = (uint256_t(existing->second) + uint256_t(allowance_amount)).str();
            }
        }

        try
        {
            std::vector<std::any> results = smart_contract_service::eval(sender_pub_key, sender_wallet_adr,
                                                                         instance_name, db_contract.binary_code(),
                                                                         db_contract.language(), txn->function(),
                                                                         params_vector, dependencies_vector,
                                                                         txn->base().hash(), timestamp,
                                                                         block_txns_key, fee_address,
                                                                         smart_contract_wallet, gas_approved,
                                                                         used_gas, txn_hashes, derived_wallets, txn->base().fee_id(), block_emits, panic, storage_gas, txn_fee_gas,
                                                                         allowance_remaining, allowance_unlimited, allowance_provided);

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
                logging::print(value.smart_contract_name + "_" + value.smart_contract_instance + " ", value.function, true);
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
                    logging::print("nested result: ", emit, true);
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
                event_management.set_function(txn->function());
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

            logging::print("[ProcessSmartContractExecute] Derived wallets size:", std::to_string(derived_wallets.size()), true);

            if (derived_wallets.size() > 0)
            {
                for (const auto &[key, value] : derived_wallets)
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
                    db_smart_contract_states::remove_single(key);
                }
                else
                {
                    db_smart_contract_states::store_single(key, values[x]);
                }
                x++;
            }

            txn_hash_tracker::add_sc_to_hash();
            nonce_tracker::add_sc_to_used_nonce();
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
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn, const std::string &sc_fee_address)
{
    logging::print("[ProcessSmartContractExecute] executing smart contract...", txn->smart_contract_name());
    logging::print("instance:", txn->smart_contract_name());
    logging::print("function:", txn->function());
    logging::print("parameters_size:", std::to_string(txn->parameters_size()));

    // Network safety net: any uncaught exception below (e.g. uint256_t /
    // boost::multiprecision parse errors from malformed fee strings) must
    // NOT terminate the validator. Catch everything and surface as a
    // failed txn instead.
    try
    {
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

        // Guard fee_amount before constructing uint256_t. cpp_int's parser
        // throws std::runtime_error("Unexpected character encountered in
        // input") on any non-digit, which would otherwise propagate up
        // unhandled and terminate the node.
        if (!is_valid_uint256(txn->base().fee_amount()))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_smart_contract_execute.cpp: process_txn: invalid fee_amount", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
        }

        uint256_t fee_taken = 0;
        // process base fees. If wallet cannot pay fees or anything else is wrong with the fees return failed txn
        status = zera_fees::process_simple_fees_gas(txn, status_fees, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE, fee_taken, fee_address, sc_txn, sc_fee_address);

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
        uint64_t storage_gas = 0;
        uint64_t txn_fee_gas = 0;
        if (status.ok())
        {
            std::vector<zera_api::SmartContractEventsResponse> events;
            status = check_execute(txn, status_fees, fee_address, gas_approved, used_gas, txn_hashes, events, storage_gas, txn_fee_gas);
            balance_tracker::add_txn_balance(wallet_adr, txn->base().fee_id(), fee_left, txn->base().hash());

            // Storage (emit) fees and internal txn network fees are metered as gas
            // pulled from the approved budget. Charge them together with the compute
            // gas, but only on success. On a crash/terminate they are dropped
            // (refunded), so only the compute gas is billed (base txn fee is kept).
            uint64_t chargeable_gas = used_gas;
            if (status.ok())
            {
                chargeable_gas += storage_gas + txn_fee_gas;
            }

            // Report the full gas billed (compute + storage + internal txn fees) so
            // the block's gas field matches what the wallet was charged via gas_fees.
            status_fees.set_gas(chargeable_gas);

            logging::print("[sc_execute settle] status.ok: " + std::string(status.ok() ? "true" : "false") + " used_gas: " + std::to_string(used_gas) + " storage_gas: " + std::to_string(storage_gas) + " txn_fee_gas: " + std::to_string(txn_fee_gas) + " chargeable_gas: " + std::to_string(chargeable_gas) + " gas_approved: " + std::to_string(gas_approved), true);

            if (!status.ok() && storage_gas == 0)
            {
                logging::print("[sc_execute settle] crash/terminate: storage gas refunded (not billed), only compute gas charged", true);
            }

            if (chargeable_gas > 0)
            {
                gas_fees(txn, chargeable_gas, status_fees, fee_address);
            }

            uint256_t storage_fee_value = status.ok() ? gas_to_value(txn, storage_gas) : uint256_t(0);


            for (auto &event : events)
            {
                if (event.has_caller())
                {
                    event.set_storage_fee(storage_fee_value.str());
                    ValidatorAPIClient::StageEvent(event);
                }
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
    catch (const std::exception &e)
    {
        logging::print("[ProcessSmartContractExecute] FATAL exception caught (safety net):", e.what(), true);
        status_fees.set_status(zera_txn::TXN_STATUS::SMART_CONTRACT_CRASH);
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, std::string("uncaught exception: ") + e.what(), zera_txn::TXN_STATUS::SMART_CONTRACT_CRASH);
    }
    catch (...)
    {
        logging::print("[ProcessSmartContractExecute] FATAL unknown exception caught (safety net)", true);
        status_fees.set_status(zera_txn::TXN_STATUS::SMART_CONTRACT_CRASH);
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "uncaught unknown exception", zera_txn::TXN_STATUS::SMART_CONTRACT_CRASH);
    }
}