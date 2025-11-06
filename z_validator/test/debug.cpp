#include <string>

#include "debug.h"
#include "validators.h"
#include "../logging/logging.h"


void debug::startup_logs(){
    logging::print("----------------Version 1.1.8------------------", false);
    logging::print("----------------CONFIG------------------", false);
    logging::print("Host:", ValidatorConfig::get_host(), false);
    logging::print("Client Port:", ValidatorConfig::get_client_port(), false);
    logging::print("Validator Port:", ValidatorConfig::get_validator_port(), false);
    if(ValidatorConfig::get_api_port() != "0")
    {
        logging::print("API Port:", ValidatorConfig::get_api_port(), false);
    }
    logging::print("Fee Wallet Address:", base58_encode(ValidatorConfig::get_fee_address()), false);
    logging::print("Public Key:", base58_encode_public_key(ValidatorConfig::get_public_key()), false);
    logging::print("Generated Private Key:", base58_encode(ValidatorConfig::get_gen_private_key()), true);
    logging::print("Generated Public Key:", base58_encode_public_key(ValidatorConfig::get_gen_public_key()), false);
    for (auto seed : ValidatorConfig::get_seed_validators())
    {
        logging::print("Seed Validator:", seed, false);
    }
    logging::print("----------------------------------------", false);
}