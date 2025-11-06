// Standard library headers
#include <iostream>
#include <fstream>
#include <random>

// Third-party library headers
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

// Project-specific headers
#include "validators.h"
#include "const.h"
#include "validator.pb.h"
#include "test.h"
#include "signatures.h"
#include "db_base.h"
// #include "db_validators.h"
// #include "db_wallets.h"
#include "hashing.h"
#include "wallets.h"
#include "validator_network_client.h"
#include "utils.h"

namespace
{
    // Reads a list of validator seeds from a file and populates a vector with them.
    // Returns 1 on success, or 0 on failure.
    int read_validator_seeds(std::vector<std::string> &seeds, std::string seed_directory)
    {
        // Open the file specified by seed_directory
        std::ifstream file(seed_directory);

        // Check if the file was successfully opened
        if (file.is_open())
        {
            int line_num = 0; // Keep track of the current line number
            std::string line; // Declare a variable to hold each line of the file

            // Read each line of the file
            while (std::getline(file, line))
            {
                line_num++; // Increment the line number counter

                seeds.push_back(line);
            }

            // Close the file
            file.close();
        }
        else
        {
            // Handle the case where the file could not be opened
            std::cerr << "Error: Opening file: " << seed_directory << std::endl;
            return 0;
        }

        // Return success
        return 1;
    }

    // Chooses a random seed from the seeds vector and returns it
    std::string random_seed(std::vector<std::string> &seeds)
    {
        // Create a random number generator
        std::random_device rng;
        std::mt19937 gen(rng());

        // Choose a random index between 0 and the size of the seeds vector - 1
        std::uniform_int_distribution<> dist(0, seeds.size() - 1);
        int idx = dist(gen);

        // Return the validator seed at the chosen index
        return seeds[idx];
    }
}

bool store_self(zera_txn::Validator *validator)
{
    /////////
    validator->set_host(ValidatorConfig::get_host());
    validator->set_validator_port(ValidatorConfig::get_validator_port());
    validator->set_client_port(ValidatorConfig::get_client_port());

    validator->set_benchmark(100);
    validator->set_lite(false);
    validator->mutable_public_key()->set_single(ValidatorConfig::get_public_key());
    validator->set_online(true);

    validator->set_version(ValidatorConfig::get_version());

    for (auto staked_id : ValidatorConfig::get_staked_contract_id())
    {
        validator->add_staked_contract_ids(staked_id);
    }

    google::protobuf::Timestamp *tsp = validator->mutable_timestamp();
    tsp->CopyFrom(google::protobuf::util::TimeUtil::GetCurrentTime());

    if (ValidatorConfig::get_seed_validators().size() <= 0)
    {
        std::string old_gen_key;
        if (db_validator_lookup::get_single(ValidatorConfig::get_public_key(), old_gen_key))
        {
            db_validators::remove_single(old_gen_key);
        }

        std::string validator_pub = wallets::get_public_key_string(validator->public_key());
        db_validator_lookup::store_single(ValidatorConfig::get_public_key(), ValidatorConfig::get_gen_public_key());
        std::string base58_pub = base58_encode_public_key(ValidatorConfig::get_gen_public_key());
        logging::print("Store Self:", base58_pub, true);
        db_validators::store_single(ValidatorConfig::get_gen_public_key(), validator->SerializeAsString());
    }

    validator->set_online(false);

    return true;
}

void get_validator_registration(zera_txn::Validator *self, zera_txn::ValidatorRegistration *registration_request)
{
    uint64_t nonce = 0;
    if (ValidatorConfig::get_seed_validators().size() > 0)
    {
        std::string server_address = ValidatorConfig::get_seed_validators().at(0);
        zera_validator::NonceResponse response = ValidatorNetworkClient::GetNonce(server_address);
        nonce = response.nonce() + 1;
    }
    else
    {
        std::string nonce_str;
        if (db_wallet_nonce::get_single(wallets::generate_wallet_single(ValidatorConfig::get_public_key()), nonce_str))
        {
            nonce = std::stoull(nonce_str) + 1;
        }
        else
        {
            nonce = 1;
        }
    }
    //set the generated public key
    registration_request->mutable_generated_public_key()->set_single(ValidatorConfig::get_gen_public_key());
    zera_txn::Validator *validator = registration_request->mutable_validator();
    validator->CopyFrom(*self);

    logging::print("Validator created - nonce:", std::to_string(nonce), true);
    //set the base
    uint256_t validator_registration_fee = get_fee("VALIDATOR_REGISTRATION_TXN_FEE");
    registration_request->mutable_base()->set_fee_amount(validator_registration_fee.str());
    registration_request->mutable_base()->set_fee_id(ZERA_SYMBOL);
    registration_request->mutable_base()->mutable_public_key()->set_single(ValidatorConfig::get_public_key());

    registration_request->mutable_base()->set_nonce(nonce);

    registration_request->set_register_(true);
    google::protobuf::Timestamp *tsp = registration_request->mutable_base()->mutable_timestamp();
    tsp->CopyFrom(google::protobuf::util::TimeUtil::GetCurrentTime());

    //sign main transaction with original key
    signatures::sign_txns(registration_request, ValidatorConfig::get_key_pair());

    std::vector<uint8_t> hash = Hashing::sha256_hash(registration_request->SerializeAsString());
    std::string hash_str(hash.begin(), hash.end());
    registration_request->mutable_base()->set_hash(hash_str);
    std::string gen_sig = signatures::sign_block_hash(hash_str, ValidatorConfig::get_gen_key_pair());
    registration_request->set_generated_signature(gen_sig);
}
