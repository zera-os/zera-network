// Standard library headers
#include <regex>

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

namespace
{

    ZeraStatus check_release(const zera_txn::InstrumentContract *txn, const uint256_t premint_amount)
    {
        if (txn->max_supply_release_size() <= 0)
        {
            return ZeraStatus();
        }

        uint256_t total_release = 0;
        uint256_t initial_release = 0;
        std::string key;
        zera_validator::BlockHeader header;
        db_headers_tag::get_last_data(header, key);

        int release_date = -1;

        for (auto release : txn->max_supply_release())
        {

            release.release_date().seconds();
            if (!is_valid_uint256(release.amount()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_release: Invalid release amount", zera_txn::TXN_STATUS::INVALID_UINT256);
            }

            uint256_t release_amount(release.amount());
            if (release.release_date().seconds() <= header.timestamp().seconds())
            {
                initial_release += release_amount;
            }

            if (release_date >= release.release_date().seconds())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_release: Release dates are not in order", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }

            release_date = release.release_date().seconds();
            total_release += release_amount;
        }

        if (premint_amount > initial_release)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_release: Premint amount is greater than total release", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        uint256_t max_supply(txn->max_supply());

        if (max_supply != total_release)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: check_release: Total release does not match max supply", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        return ZeraStatus();
    }

    ZeraStatus check_restricted_duplicate(const zera_txn::InstrumentContract *txn)
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
    ZeraStatus check_premints(const zera_txn::InstrumentContract *txn)
    {
        uint256_t total_amount = 0;

        std::unordered_set<std::string> unique_addresses;

        for (auto premint : txn->premint_wallets())
        {
            // Check if the address is unique
            if (unique_addresses.find(premint.address()) != unique_addresses.end())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_premints: Duplicate address found: " + base58_encode(premint.address()), zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }

            // Add the address to the set
            unique_addresses.insert(premint.address());

            if (!is_valid_uint256(premint.amount()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_premints: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
            }
            uint256_t amount(premint.amount());
            total_amount += amount;
        }
        uint256_t max_supply(txn->max_supply());

        if (total_amount > max_supply)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_premints: Premints are greater than max supply", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        ZeraStatus status = check_release(txn, total_amount);
        if (!status.ok())
        {
            return status;
        }

        balance_tracker::add_txn_balance_premint(txn->premint_wallets(), txn->contract_id(), txn->base().hash());

        return ZeraStatus();
    }
    ZeraStatus check_governance(const zera_txn::InstrumentContract *txn, bool bridge)
    {
        if (!txn->has_governance())
        {
            return ZeraStatus();
        }
        zera_txn::Governance governance = txn->governance();

        // type cannot be remove on contract creation, this is only for contract update
        if (governance.type() == zera_txn::GOVERNANCE_TYPE::REMOVE)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is remove.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        // governance voting instrument cannot be empty for any type of governance
        // governance proposal instrument cannot be empty for any type of governance
        if (governance.voting_instrument_size() <= 0 ||
            governance.allowed_proposal_instrument_size() <= 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance has no voting or proposal instrument.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        std::regex pattern("^\\$[A-Z]{3,20}\\+\\d{4}$");
        std::regex pattern2("^\\$sol-[A-Z]{1,32}\\+\\d{6}$");

        // check if voting instrument is valid
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

        // if governance is staged stage length must be at least 1 and at most 99
        // if governance is not staged stage length must be 0
        if (governance.type() == zera_txn::GOVERNANCE_TYPE::STAGED && (governance.stage_length_size() < 1 || governance.stage_length_size() > 99))
        {
            logging::print(std::to_string(governance.stage_length_size()));
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is staged but less than 1 stage lengths are provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        else if (governance.type() != zera_txn::GOVERNANCE_TYPE::STAGED && governance.stage_length_size() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is not staged but stage lengths are provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        // if governance type is adaptive it cannot have proposal or voting period
        // if governance type is not adaptive it must have proposal and voting period
        if (governance.type() == zera_txn::GOVERNANCE_TYPE::ADAPTIVE && (governance.has_proposal_period() || governance.has_voting_period()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is adaptive but proposal period is provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        else if (governance.type() != zera_txn::ADAPTIVE && (!governance.has_proposal_period() || !governance.has_voting_period()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is not adaptive but proposal period is not provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        // if governance type is staged or cycle it must have start timestamp (this is the timestamp that the governance starts)
        if (governance.type() == zera_txn::GOVERNANCE_TYPE::STAGED || governance.type() == zera_txn::GOVERNANCE_TYPE::CYCLE)
        {
            if (!governance.has_start_timestamp())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Governance type is staged or cycle but no start timestamp is provided.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
            }
        }

        if (governance.type() == zera_txn::GOVERNANCE_TYPE::STAGED)
        {
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
ZeraStatus block_process::check_parameters<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{

    bool bridge = false;

    if (txn->base().public_key().has_smart_contract_auth())
    {
        if (txn->base().public_key().smart_contract_auth() == "sc_bridge_proxy_1")
        {
            bridge = true;
        }
    }

    zera_txn::PublicKey gov_public_key;
    std::string gov_auth = "gov_" + txn->contract_id();
    gov_public_key.set_governance_auth(gov_auth);
    auto gov_wallet = wallets::generate_wallet(gov_public_key);

    logging::print("process_contract.cpp: check_parameters: Gov auth: " + base58_encode(gov_wallet), true);

    std::string contract_data;

    if (db_contracts::exist(txn->contract_id()))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract ID already exists " + txn->contract_id(), zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }

    ZeraStatus status = check_restricted_duplicate(txn);

    if (!status.ok())
    {
        return status;
    }
    if (txn->has_contract_fees())
    {
        if (txn->type() == zera_txn::SBT || txn->type() == zera_txn::NFT)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract fees are not valid for NFT/SBT contracts.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        if (!is_valid_uint256(txn->contract_fees().fee()) || !is_valid_uint256(txn->contract_fees().burn()) || !is_valid_uint256(txn->contract_fees().validator()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
        }
        uint256_t fee(txn->contract_fees().fee());
        if (fee == 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract fee is 0", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        bool zra_found = false;

        for (auto id : txn->contract_fees().allowed_fee_instrument())
        {
            if (id == "$ZRA+0000")
            {
                zra_found = true;
                break;
            }
        }

        if (!zra_found)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: ZRA is not allowed as a fee instrument", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
    }
    if (txn->has_max_supply())
    {
        if (!is_valid_uint256(txn->max_supply()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
        }
    }
    if (txn->has_coin_denomination())
    {
        std::string amount_str = txn->coin_denomination().amount();

        if (!is_valid_uint256(txn->coin_denomination().amount()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
        }
    }

    if (is_restricted_symbol(txn->symbol()))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Restricted symbol", zera_txn::TXN_STATUS::RESTRICTED_SYMBOL);
    }

    if (!bridge)
    {
        std::regex symbol_pattern("^[A-Z0-9]*$");
        std::regex name_pattern("^[A-Za-z0-9 ]*$");
        if (txn->name().size() < 3 || txn->name().size() > 200 || !std::regex_match(txn->name(), name_pattern))
        {

            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract name is either too big or too small. " + txn->name() + " : " + std::to_string(txn->name().size()), zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        if (txn->symbol().size() < 3 || txn->symbol().size() > 20 || !std::regex_match(txn->symbol(), symbol_pattern))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract symbol is either too big or too small. " + txn->symbol(), zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }

        std::regex pattern("^\\$" + txn->symbol() + "\\+\\d{4}$");

        if (!std::regex_match(txn->contract_id(), pattern))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: Contract ID does match required pattern. " + txn->contract_id(), zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
    }
    status = check_governance(txn, bridge);

    if (!status.ok())
    {
        return status;
    }
    switch (txn->type())
    {
    case zera_txn::CONTRACT_TYPE::TOKEN:
    {
        if (!txn->has_max_supply() || !txn->has_coin_denomination())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract type token failed.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        break;
    }
    case zera_txn::CONTRACT_TYPE::NFT:
    {
        if (txn->has_coin_denomination() || txn->expense_ratio_size() > 0 || txn->premint_wallets_size() > 0 || txn->has_contract_fees())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract type NFT", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        break;
    }
    case zera_txn::CONTRACT_TYPE::SBT:
    {
        if (txn->has_coin_denomination() || txn->expense_ratio_size() > 0 || txn->premint_wallets_size() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: contract type SBT", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        }
        break;
    }
    default:
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: DEFAULT?", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
        break;
    }
    }

    if (txn->restricted_keys_size() > 50)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_contract.cpp: check_parameters: too many restricted keys.", zera_txn::TXN_STATUS::INVALID_CONTRACT_PARAMETERS);
    }

    for (auto key : txn->restricted_keys())
    {
        std::string pub_key = wallets::get_public_key_string(key.public_key());
        HashType type = wallets::get_wallet_type(pub_key);

        std::regex pattern1("^\\$[A-Z]{3,20}\\+\\d{4}$");
        std::regex pattern2("^\\$sol-[A-Za-z0-9]{1,32}\\+\\d{6}$");

        if ((type != HashType::wallet_r && type != HashType::wallet_g && type != HashType::wallet_sc && !std::regex_match(pub_key, pattern1) && !std::regex_match(pub_key, pattern2)) || pub_key == txn->contract_id())
        {
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
    }

    status = check_premints(txn);

    if (status.ok())
    {
        if (!bridge)
        {
            contract_price_tracker::update_price(txn->contract_id());
        }
    }

    return status;
}
