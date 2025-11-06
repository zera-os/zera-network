#include "validators.h"
#include "wallets.h"
#include "../block_process/block_process.h"
#include "../logging/logging.h"
#include "fees.h"

namespace
{
    bool check_online_version(zera_txn::Validator &validator, const std::string &block_height_str)
    {

        uint64_t block_height = std::stoull(block_height_str);

        std::string version_str;
        db_system::get_single(REQUIRED_VERSION, version_str);
        zera_txn::RequiredVersion required_version;
        required_version.ParseFromString(version_str);

        if (!validator.online())
        {
            logging::print("validator is offline", true);
            return false;
        }

        if (block_height >= 500)
        {

            uint64_t last_block_height = block_height - 500;

            if (validator.last_heartbeat() < last_block_height)
            {
                return false;
            }
        }

        if(required_version.version_size() == 0)
        {
            required_version.add_version(100000);
            db_system::store_single(REQUIRED_VERSION, required_version.SerializeAsString());
        }
        
        for (auto version : required_version.version())
        {
            logging::print("Validator version:", std::to_string(validator.version()), "Required version:", std::to_string(version), true);
            if (validator.version() == version)
            {
                return true;
            }
        }
        logging::print("made it here", true);
        logging::print("required version:", required_version.SerializeAsString(), true);
        return false;
    }

    uint256_t convert_to_cur_equiv(const uint256_t &cur_equiv, const uint256_t &amount, const std::string &contract_id)
    {
        zera_txn::InstrumentContract contract;
        block_process::get_contract(contract_id, contract);
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t convert_amount = amount * cur_equiv / QUINTILLION / denomination;
        return convert_amount;
    }

    uint256_t get_wallet_balance(const std::string wallet_adr, const std::string &contract_id)
    {
        if (!zera_fees::check_qualified(contract_id))
        {
            return 0;
        }

        std::string wallet_balance;

        if (!db_wallets::get_single(wallet_adr + contract_id, wallet_balance))
        {
            logging::print("validator public key:", base58_encode_public_key(wallet_adr), true);
            logging::print("wallet does not exist for.", contract_id);
            return 0;
        }
        uint256_t cur_equiv;
        uint256_t amount(wallet_balance);
        if(!zera_fees::get_cur_equiv(contract_id, cur_equiv))
        {
            return 0;
        }

        return convert_to_cur_equiv(cur_equiv, amount, contract_id);
    }

    void update_balance_map(const std::string &symbol, const std::string &wallet_adr, std::map<std::string, uint256_t> &scaled_stake)
    {
        uint256_t balance = get_wallet_balance(wallet_adr, symbol);
        // Check if the symbol exists in the map
        if (scaled_stake.find(symbol) != scaled_stake.end())
        {
            // If it exists, add the balance to the current value
            scaled_stake[symbol] += balance;
        }
        else
        {
            // If it doesn't exist, insert the new balance
            scaled_stake[symbol] = balance;
        }
    }

    void calculate_scaled_stake(zera_validator::StakeMultipliers &stake_multipliers, const std::string &block_height)
    {
        std::vector<std::string> keys;
        std::vector<std::string> values;
        db_validators::get_all_data(keys, values);
        zera_validator::ValidatorArchive validator_archive;

        std::map<std::string, uint256_t> scaled_stake_map;
        for (int i = 0; i < keys.size(); i++)
        {
            zera_txn::Validator validator;
            validator.ParseFromString(values[i]);

            if (!check_online_version(validator, block_height))
            {
                std::string encoded_key(keys[i].begin(), keys[i].end());
                logging::print("validator is offline or version is not correct:", base58_encode_public_key(encoded_key));
                continue;
            }

            std::string wallet_adr = wallets::generate_wallet(validator.public_key(), "");

            if (validator.staked_contract_ids_size() == 0)
            {
                update_balance_map(ZERA_SYMBOL, wallet_adr, scaled_stake_map);
            }

            for (auto contract_id : validator.staked_contract_ids())
            {
                update_balance_map(contract_id, wallet_adr, scaled_stake_map);
            }
        }

        uint256_t total_stake_balance = 0;
        for (auto &stake : scaled_stake_map)
        {
            if (stake.first != ZERA_SYMBOL)
            {
                //TODO : add something in the future for max validator stake

                // std::string cur_data;
                // zera_validator::CurrencyRate cur_rate;
                // db_currency_equiv::get_single(stake.first, cur_data);
                // cur_rate.ParseFromString(cur_data);

                // uint256_t max_stake(cur_rate.max_stake());

                // //
                // if (stake.second > max_stake)
                // {
                //     uint256_t scaled_stake_multiplier = (max_stake * STAKED_MATH_MULTIPLIER) / stake.second;
                //     scaled_stake_multiplier.str();
                //     stake_multipliers.mutable_contract_multipliers()->operator[](stake.first) = scaled_stake_multiplier.str();
                //     stake.second = max_stake;
                // }
                // else
                // {
                //     stake_multipliers.mutable_contract_multipliers()->operator[](stake.first) = "N/A";
                // }

                // total_stake_balance += stake.second;
            }
            else
            {
                total_stake_balance += stake.second;
            }
        }

        if (total_stake_balance == 0)
        {
            return;
        }

        uint256_t zera_scaled_value = scaled_stake_map[ZERA_SYMBOL] * 1000;
        uint256_t zera_stake_percent = zera_scaled_value / total_stake_balance;

        if (zera_stake_percent < ZERA_STAKE_PERCENTAGE)
        {
            uint256_t misc_stake_percent = (1000 - zera_stake_percent);
            uint256_t scaled_stake_percent = zera_stake_percent * STAKED_MATH_MULTIPLIER;

            uint256_t misc_stake_multiplier = scaled_stake_percent / misc_stake_percent;
            stake_multipliers.set_default_multiplier(misc_stake_multiplier.str());
        }
        else
        {
            stake_multipliers.set_default_multiplier("N/A");
        }
    }
}

void validator_utils::archive_balances(const std::string &block_height)
{
    zera_validator::StakeMultipliers stake_multipliers;

    calculate_scaled_stake(stake_multipliers, block_height);

    std::vector<std::string> keys;
    std::vector<std::string> values;
    db_validators::get_all_data(keys, values);
    uint256_t total_validator_balance = 0;
    zera_validator::ValidatorArchive validator_archive;

    std::string full_multiplier = stake_multipliers.default_multiplier();
    uint256_t default_multiplier;

    if (full_multiplier != "N/A")
    {
        default_multiplier = boost::multiprecision::uint256_t(full_multiplier);
    }

    for (int i = 0; i < keys.size(); i++)
    {
        zera_txn::Validator validator;
        validator.ParseFromString(values[i]);

        if (!check_online_version(validator, block_height))
        {
            continue;
        }

        std::string wallet_adr = wallets::generate_wallet(validator.public_key(), "");
        uint256_t total_wallet_balance = 0;
        if (validator.staked_contract_ids_size() == 0)
        {
            total_wallet_balance += get_wallet_balance(wallet_adr, ZERA_SYMBOL);
        }

        for (auto contract_id : validator.staked_contract_ids())
        {
            uint256_t wallet_balance = get_wallet_balance(wallet_adr, contract_id);

            if (contract_id != ZERA_SYMBOL)
            {
                std::string contract_multiplier = stake_multipliers.contract_multipliers().at(contract_id);
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
            }

            total_wallet_balance += wallet_balance;
        }

        std::string encoded_key = base58_encode_public_key(keys[i]);
        logging::print("archive balances:", encoded_key, total_wallet_balance.str(), true);
        total_validator_balance += total_wallet_balance;
        zera_validator::ValidatorBalance validator_balance;
        validator_balance.mutable_public_key()->CopyFrom(validator.public_key());
        validator_balance.set_total_balance(total_wallet_balance.str());
        (*validator_archive.mutable_validators())[encoded_key] = validator_balance;
    }
    validator_archive.set_total_balance(total_validator_balance.str());

    db_system::store_single(STAKE_MULTIPLIER, stake_multipliers.SerializeAsString());
    db_validator_archive::store_single(block_height, validator_archive.SerializeAsString());
}
