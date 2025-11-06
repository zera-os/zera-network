#include "proposer.h"
#include "const.h"
#include <random>
#include "base58.h"
#include "wallets.h"
#include "../block_process/block_process.h"
#include "../logging/logging.h"
#include <thread>
#include "fees.h"

namespace
{

    bool check_online_version(const std::string &public_key, const uint64_t &block_height)
    {
        std::string gen_key;
        if (!db_validator_lookup::get_single(public_key, gen_key))
        {
            return false;
        }
        zera_txn::Validator validator;
        std::string validator_data;

        if (!db_validators::get_single(gen_key, validator_data) || !validator.ParseFromString(validator_data))
        {
            return false;
        }

        std::string version_str;
        db_system::get_single(REQUIRED_VERSION, version_str);
        zera_txn::RequiredVersion required_version;
        required_version.ParseFromString(version_str);

        if (!validator.online())
        {
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

        for (auto version : required_version.version())
        {
            if (validator.version() == version)
            {
                return true;
            }
        }

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

    uint256_t get_wallet_balance(zera_txn::Validator &validator, const std::string &contract_id)
    {
        if (!zera_fees::check_qualified(contract_id))
        {
            return 0;
        }

        std::string wallet_adr = wallets::generate_wallet(validator.public_key(), contract_id);
        std::string wallet_balance;

        if (!db_wallets::get_single(wallet_adr, wallet_balance))
        {
            std::string pub_key = wallets::get_public_key_string(validator.public_key());;
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

    void GetAllWeightedValidators(std::vector<WeightedValidator> &weighted_validators, const uint64_t &block_height)
    {
        std::vector<std::string> keys;
        std::string height_str = std::to_string(block_height);
        std::string archive_data;

        while(!db_validator_archive::get_single(height_str, archive_data))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        zera_validator::ValidatorArchive validator_archive;

        while(!validator_archive.ParseFromString(archive_data) || validator_archive.validators_size() == 0)
        {
            db_validator_archive::get_single(height_str, archive_data);
            logging::print("validator archive parse error - block height:", height_str, true);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        

        for (auto validator : validator_archive.validators())
        {
            std::string original_pub_key = wallets::get_public_key_string(validator.second.public_key());

            if (!check_online_version(original_pub_key, block_height))
            {
                logging::print("validator is offline or is on wrong version:", base58_encode_public_key(original_pub_key), true);
                continue;
            }

            validator.second.total_balance();
            uint64_t amount = std::stoull(validator.second.total_balance());
            WeightedValidator tmp_validator = {original_pub_key, amount};
            weighted_validators.push_back(tmp_validator);
        }
    }

    uint64_t base58_to_uint64(const std::string &base58_str)
    {
        uint64_t big_int = 0;
        uint64_t base = 1;

        for (auto it = base58_str.rbegin(); it != base58_str.rend(); ++it)
        {
            char c = *it;
            size_t index = base58_str.find(c);
            if (index == std::string::npos)
            {
                throw std::runtime_error("Invalid Base58 character: " + std::string(1, c));
            }
            big_int += base * index;
            base *= 58;
        }

        return big_int;
    }
}

std::vector<zera_txn::Validator> SelectValidatorsByWeight(const std::string &seed_hash, const uint64_t &block_height)
{

    uint64_t seed = base58_to_uint64(base58_encode(seed_hash));

    std::vector<WeightedValidator> weighted_validators;

    GetAllWeightedValidators(weighted_validators, block_height);

    std::sort(weighted_validators.begin(), weighted_validators.end(), [](const WeightedValidator &a, const WeightedValidator &b)
              { return a.address > b.address; });

    std::vector<zera_txn::Validator> validators;

    if (weighted_validators.size() <= 0)
    {
        logging::print("select - no validators");
        return validators;
    }

    int numValidators = weighted_validators.size();

    uint64_t totalWeight = 0;
    for (const auto &validator : weighted_validators)
    {
        totalWeight += validator.coinAmount;
    }

    std::mt19937 generator(seed); // Mersenne Twister random number generator
    std::uniform_int_distribution<uint64_t> distribution(1, totalWeight);

    std::vector<std::string> selectedValidators;

    std::unordered_set<std::string> selectedAddresses;

    while (selectedValidators.size() < numValidators)
    {
        uint64_t targetWeight = distribution(generator);
        uint64_t runningSum = 0;

        for (const auto &validator : weighted_validators)
        {
            runningSum += validator.coinAmount;
            if (runningSum >= targetWeight)
            {
                if (selectedAddresses.find(validator.address) == selectedAddresses.end())
                {
                    std::string gen_key;
                    db_validator_lookup::get_single(validator.address, gen_key);
                    selectedValidators.push_back(gen_key);
                    selectedAddresses.insert(validator.address);
                    break;
                }
            }
        }
    }

    for (const auto &key : selectedValidators)
    {
        std::string value;
        zera_txn::Validator validator;
        if (!db_validators::get_single(key, value))
        {
            logging::print("select - could not get validator");
        }
        else
        {
            if (validator.ParseFromString(value))
            {
                validators.push_back(validator);
            }
        }
    }

    return validators;
}