#include <regex>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

#include "../block_process.h"
#include "wallets.h"
#include "utils.h"
#include "../../logging/logging.h"
#include "validators.h"

namespace
{
    bool compare_permissions(const zera_txn::RestrictedKey& original, const zera_txn::RestrictedKey& new_key)
    {
        return original.time_delay() == new_key.time_delay() && 
               original.global() == new_key.global() &&
               original.update_contract() == new_key.update_contract() &&
               original.transfer() == new_key.transfer() &&
               original.quash() == new_key.quash() &&
               original.mint() == new_key.mint() &&
               original.vote() == new_key.vote() &&
               original.propose() == new_key.propose() &&
               original.compliance() == new_key.compliance() &&
               original.expense_ratio() == new_key.expense_ratio() &&
               original.revoke() == new_key.revoke() &&
               original.key_weight() == new_key.key_weight();


    }
    ZeraStatus check_restricted_duplicate(const zera_txn::ContractUpdateTXN *txn)
    {
        std::set<std::string> restricted_keys;

        for (auto key : txn->restricted_keys())
        {
            std::string single_key = wallets::get_public_key_string(key.public_key());
            if (restricted_keys.find(single_key) != restricted_keys.end())
            {
                // Duplicate key found, handle accordingly
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_restricted: Duplicate key found", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            else
            {
                restricted_keys.insert(single_key);
            }
        }

        return ZeraStatus();
    }

    ZeraStatus check_days_stages(const zera_txn::Governance &governance)
    {
        int cycle_length = governance.voting_period();
        int calc_length = 0;
        int last_index = governance.stage_length_size() - 1;
        int index = 0;

        for (auto stage : governance.stage_length())
        {
            if (index != last_index && stage.length() == 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_days_stages: Remainder needs to be on last index", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            if (stage.period() == zera_txn::MONTHS)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_days_stages: Governance type is days but stage length is months.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            else if (stage.period() == zera_txn::DAYS)
            {
                calc_length += stage.length();
            }
            index++;
        }

        if ((calc_length == cycle_length && governance.stage_length().at(last_index).length() != 0) ||
            (calc_length < cycle_length && governance.stage_length().at(last_index).length() == 0))
        {
            return ZeraStatus();
        }

        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_days_stages: Governance stages do not equal cycle length", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }

    ZeraStatus check_months_stages(const zera_txn::Governance &governance)
    {
        int cycle_length = governance.voting_period();
        int calc_length_months = 0;
        int calc_length_days = 0;
        int last_index = governance.stage_length_size() - 1;
        int index = 0;
        bool days = false;

        for (auto stage : governance.stage_length())
        {
            if (index != last_index && stage.length() == 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_months_stages: Remainder needs to be on last index", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            if (stage.period() == zera_txn::DAYS)
            {
                days = true;
                calc_length_days += stage.length();
            }
            else if (stage.period() == zera_txn::MONTHS)
            {
                calc_length_months += stage.length();
                calc_length_days += stage.length() * 31;
            }
            else
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_months_stages: Governance type is months but stage length is days.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            index++;
        }
        if (days)
        {
            int cycle_length_days = cycle_length * 28;
            if (governance.stage_length().at(last_index).length() != 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_months_stages: Governance stages, when using Days as stage period, remainder is required.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            if (calc_length_days >= cycle_length_days)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_months_stages: Governance stages are bigger or equal to cycle length. When using Days as stage period, remainder is required", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
        }
        else
        {

            if (cycle_length > calc_length_months && governance.stage_length().at(last_index).length() != 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_months_stages: Governance stages is larger than cycle length", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            else if (cycle_length < calc_length_months)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_months_stages: Governance stages is smaller than cycle length and no remainder is present", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
            else if (cycle_length == calc_length_months && governance.stage_length().at(last_index).length() == 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_months_stages: Governance stages are equal to cycle length, but remainder is present.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
        }

        return ZeraStatus();
    }

    ZeraStatus check_governance(const zera_txn::ContractUpdateTXN *txn)
    {

        if (!txn->has_governance())
        {
            return ZeraStatus();
        }

        zera_txn::Governance governance = txn->governance();

        if (governance.voting_instrument_size() <= 0 ||
            governance.allowed_proposal_instrument_size() <= 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance has no voting or proposal instrument.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        std::regex pattern("^\\$[A-Z]{3,20}\\+\\d{4}$");
        std::regex pattern2("^\\$sol-[A-Z]{1,32}\\+\\d{6}$");

        for (auto instrument : governance.voting_instrument())
        {
            // if (!std::regex_match(instrument, pattern) && !std::regex_match(instrument, pattern2))
            // {
            //     return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Voting Instrument is invalid. " + instrument, zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            // }

            if (instrument.length() > 40)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Voting Instrument is invalid. " + instrument, zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
        }

        if (governance.type() == zera_txn::GOVERNANCE_TYPE::STAGED && (governance.stage_length_size() < 1 || governance.stage_length_size() > 99))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is staged but less than 1 stage lengths are provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        else if (governance.type() != zera_txn::GOVERNANCE_TYPE::STAGED && governance.stage_length_size() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is not staged but stage lengths are provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        if (governance.type() == zera_txn::GOVERNANCE_TYPE::ADAPTIVE && (governance.has_proposal_period() || governance.has_voting_period()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is adaptive but proposal period is provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        else if (governance.type() != zera_txn::ADAPTIVE && (!governance.has_proposal_period() || !governance.has_voting_period()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is not adaptive but proposal period is not provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        if (governance.type() == zera_txn::GOVERNANCE_TYPE::STAGED || governance.type() == zera_txn::GOVERNANCE_TYPE::CYCLE)
        {
            if (!governance.has_start_timestamp())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is staged or cycle but no start timestamp is provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
        }

        if (governance.type() == zera_txn::GOVERNANCE_TYPE::STAGED)
        {
            if (governance.stage_length_size() < 1)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is staged but no stage lengths are provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }

            ZeraStatus status;
            if (governance.proposal_period() == zera_txn::PROPOSAL_PERIOD::DAYS)
            {
                status = check_days_stages(governance);
            }
            else if (governance.proposal_period() == zera_txn::PROPOSAL_PERIOD::MONTHS)
            {
                status = check_months_stages(governance);
            }
            else
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is staggered but proposal period is not days or months.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }

            if (!status.ok())
            {
                return status;
            }
        }
        return ZeraStatus();
    }
}
template <>
ZeraStatus block_process::check_parameters<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{

    logging::log("process_update_contract.cpp: check_parameters: ContractUpdateTXN");
    std::string base_pub_key = wallets::get_public_key_string(txn->base().public_key());
    HashType type = wallets::get_wallet_type(base_pub_key);
    if (wallets::get_wallet_type(base_pub_key) != HashType::wallet_r && wallets::get_wallet_type(base_pub_key) != HashType::wallet_g)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: sender key is not restricted", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
    }

    std::string contract_data;
    zera_txn::InstrumentContract contract;
    if (!db_contracts::get_single(txn->contract_id(), contract_data) || !contract.ParseFromString(contract_data))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: contract does not exist: " + txn->contract_id(), zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }

    zera_txn::RestrictedKey restricted_key;
    uint32_t key_weight;
    ZeraStatus status = restricted_keys_check::check_restricted_keys(txn, contract, zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE, restricted_key, key_weight);

    if (!status.ok())
    {
        return status;
    }

    if (contract.contract_version() >= txn->contract_version())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: Contract version must increase." + txn->contract_id(), zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }
    if (contract.type() != zera_txn::CONTRACT_TYPE::TOKEN && txn->expense_ratio_size() > 0)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: Non token contract cannot have expense ratio parameter.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }
    if (txn->has_name())
    {
        std::regex name_pattern("^[A-Za-z0-9 ]");

        if (txn->name().size() < 3 || txn->name().size() > 200 || !std::regex_match(txn->name(), name_pattern))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: Contract name is either too big or too small.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
    }

    if (txn->restricted_keys_size() > 50)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: too many restricted keys.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }

    std::vector<zera_txn::RestrictedKey> added_keys;
    status = check_restricted_duplicate(txn);

    if (!status.ok())
    {
        return status;
    }

    std::regex pattern("^\\$[A-Z]{3,20}\\+\\d{4}$");
    std::regex pattern2("^\\$sol-[A-Za-z0-9]{1,32}\\+\\d{6}$");
    
    for (auto key : txn->restricted_keys())
    {

        std::string pub_key = wallets::get_public_key_string(key.public_key());
        HashType type = wallets::get_wallet_type(pub_key);
        if ((type != HashType::wallet_r && type != HashType::wallet_g && type != HashType::wallet_sc && !std::regex_match(pub_key, pattern) && !std::regex_match(pub_key, pattern2)) || pub_key == txn->contract_id())
        {
            logging::print(pub_key, true);
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Non restricted key in list.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        if (key.global())
        {
            std::string wallet_adr = wallets::generate_wallet(key.public_key());

            if (db_wallet_nonce::exist(wallet_adr))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Restricted key already in use", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
        }

        if (key.expense_ratio() && key.time_delay() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Restricted key cannot have time delay and expense ratio", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        added_keys.push_back(key);
    }
    for (auto added_key : added_keys)
    {
        std::string added_key_str = wallets::get_public_key_string(added_key.public_key());
        bool new_key = true;

        for (auto key : contract.restricted_keys())
        {
            std::string key_str = wallets::get_public_key_string(key.public_key());
            if(added_key_str == key_str)
            {
                new_key = false;
                break;
            }
        }

        if(new_key)
        {
            if(added_key.key_weight() < key_weight)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: New restricted key key_weight cannot be lower than sender key.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
        }
    }
    if (txn->restricted_keys_size() > 0)
    {
        std::string txn_pub_key = wallets::get_public_key_string(txn->base().public_key());

        for (auto key : contract.restricted_keys())
        {
            std::string key_str = wallets::get_public_key_string(key.public_key());
            logging::print("original", key_str, true);
            logging::print(std::to_string(key.key_weight()));
            bool removed = true;

            for (auto added_key : added_keys)
            {
                std::string added_key_str = wallets::get_public_key_string(added_key.public_key());
                logging::print("new", added_key_str, true);
                logging::print(std::to_string(added_key.key_weight()));
                if (added_key_str == key_str)
                {
                    if(added_key.key_weight() != key.key_weight())
                    {
                        if(key.key_weight() <= key_weight || added_key.key_weight() < key_weight)
                        {
                            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: Updated restricted key key_weight cannot be lower than sender key", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
                        }
                    }
                    else
                    {
                        if(added_key_str == txn_pub_key && added_key.key_weight() < key_weight)
                        {
                            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: Cannot make your own key weight lower.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
                        }
                        else if(added_key_str != txn_pub_key && key.key_weight() <= key_weight && !compare_permissions(key, added_key))
                        {
                            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: Updated restricted key permissions of the <= key_weight cannot be different than original key", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
                        }

                    }
                    
                    removed = false;
                    break;
                }
            }

            if (removed)
            {
                if (txn_pub_key == key_str)
                {
                    continue;
                }
                else if (key.key_weight() <= key_weight)
                {
                    return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_update_contract.cpp: check_parameters: Restricted key does not have permission to remove restricted_key.", zera_txn::TXN_STATUS::KEY_WEIGHT_TOO_LOW);
                }
            }
        }
    }

    if (txn->has_contract_fees())
    {
        if (contract.type() == zera_txn::SBT || contract.type() == zera_txn::NFT)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract fees are not valid for NFT/SBT contracts.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        if (!contract.update_contract_fees())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract fees are not allowed to be updated.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        if (!is_valid_uint256(txn->contract_fees().fee()) || !is_valid_uint256(txn->contract_fees().burn()) || !is_valid_uint256(txn->contract_fees().validator()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
        }

        if (txn->contract_fees().fee() == "0")
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract fee is 0", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
    }

    if (contract.type() == zera_txn::CONTRACT_TYPE::NFT || contract.type() == zera_txn::CONTRACT_TYPE::SBT)
    {
        if (txn->expense_ratio_size() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract type SBT", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
    }

    if (txn->expense_ratio_size() > 0)
    {
        if (!contract.update_expense_ratio())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract expense ratio cannot be updated", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
    }

    if ((txn->kyc_status() != contract.kyc_status()) && contract.immutable_kyc_status())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract kyc status cannot be updated", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }

    if ((txn->immutable_kyc_status() != contract.immutable_kyc_status()) && !txn->immutable_kyc_status())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract immutable kyc status cannot be updated", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }

    if (txn->token_compliance_size() > 0 && !txn->kyc_status())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract kyc status must be true to add compliance", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }

    if (txn->token_compliance_size() <= 0 && txn->kyc_status())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract kyc status must be false to remove compliance", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }
    if (!contract.update_contract_fees() && txn->contract_fees().ByteSizeLong() > 0)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract fees cannot be removed", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }

    status = check_governance(txn);

    return status;
}
