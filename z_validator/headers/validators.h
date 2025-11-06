#ifndef VALIDATORS_H
#define VALIDATORS_H

// Standard library headers
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <random>

// Third-party library headers
// None in this case

// Project-specific headers
#include "signatures.h"
#include "base58.h"
//#include "db_validators.h"
#include "db_base.h"

struct BlockWork{
	uint64_t block_height;
	bool working_on_block;
};

class ValidatorConfig{
public:
	static void set_config();								//set validator configurations
	static void set_fee_address();							//set address of the validator fees
	static void generate_keys();							//generate keys for the validator (these are the keys used to sign the blocks & txns)
	static std::string get_host();							//get the host of the validator
	static std::vector<std::string> get_seed_validators();  //get selected seed validators
	static std::string get_client_port();					//get the client port of the validator
	static std::string get_validator_port();				//get the validator port of the validator
	static std::string get_api_port();						//get the api port of the validator
	static std::vector<std::string> get_staked_contract_id();//get all contract ids that this validator is staking with

	static KeyPair get_key_pair();							//get the original key pair of the validator
	static std::string get_public_key();					//get the original public key of the validator
	static std::string get_private_key();					//get the original private key of the validator

	static KeyPair get_gen_key_pair();						//get the generated key pair of the validator (used for signing blocks & txns)
	static std::string get_gen_public_key();				//get the generated public key of the validator (used for signing blocks & txns)
	static std::string get_gen_private_key();				//get the generated private key of the validator (used for signing blocks & txns)

	static std::vector<uint8_t> get_fee_address();			//get the address of the validator fees
	static std::string get_fee_address_string();			//get the address of the validator fees in string format
	static std::string get_current_fee_address();			//get the current address of the validator fees
	static std::string set_current_fee_address(const std::string& fee_address); //set the current address of the validator fees
	static uint32_t get_version();							//get the version of the validator
	static uint32_t get_required_version();					//get the required version of the validator
	static std::string get_treasury_wallet();				//get the treasury wallet of the network
	static std::string get_register();
	static std::vector<std::string> get_whitelist(); 		//get whitelisted ips for rate_limiter
	static void set_required_version(const uint32_t& version);
	static bool get_hack();
	static void set_hack(const bool hack);
	static BlockWork get_block_work();
	static bool get_nuke();

	static std::string get_block_height();
	static bool get_dev_mode();

	static void set_version(const uint32_t& version);
	static void set_treasury_wallet(const std::string& treasury_wallet);

	private:
	static std::string treasury_wallet_;
	static std::string host_;
	static std::string client_port_;
	static std::string api_port_;
	static std::string validator_port_;
	static std::vector<std::string> seed_validators_;
	static KeyPair key_pair_;
	static std::vector<uint8_t> fee_address_;
	static std::string fee_address_string_;
	static std::mutex mutex_;
	static KeyPair gen_key_pair_;
	static std::vector<std::string> staked_contract_ids_;
	static std::string current_fee_address_;
	static uint32_t version_;
	static uint32_t required_version_;
	static std::string block_height_;
	static bool dev_mode_;
	static std::string register_;
	static std::vector<std::string> white_list_;
	//TODO - Remove "hack"
	static bool hack_;
	static BlockWork block_work_;
	static bool nuke_;

	static void set_block_work(uint64_t block_height);
	static void clear_block_work();
	static void set_host(const std::string& host);
	static void set_client_port(const std::string& client_port);
	static void set_validator_port(const std::string& validator_port);
	static void set_seed_validators(const std::string& seed_validator);
	static void set_public_key(const std::string& public_key);
	static void set_private_key(const std::string& private_key);
	static void set_fee_address(const std::string& fee_address);
	static void set_fee_address_string(const std::vector<uint8_t>& fee_address);
	static void set_configs(const std::string &line);
	static void process_config_file(std::ifstream &configFile);
	static void copy_and_process_config_file(std::ifstream &srcFile, std::ofstream &destFile);
	static void set_staked_contract_id(const std::string& staked_contract_id);
	static void set_block_height(const std::string& block_height);
	static void set_dev_mode(bool dev_mode);
	static void set_register(const std::string& register_str);
	static void set_api_port(const std::string& api_port);
	static void set_whitelist(const std::string& whitelist);
	static void set_nuke(bool nuke);
};


bool store_self(zera_txn::Validator* validator);
void get_validator_registration(zera_txn::Validator* self, zera_txn::ValidatorRegistration* registration_request);

static std::vector <zera_txn::Validator> get_random_validators()
	{
		std::vector<zera_txn::Validator> validators;
		db_validators_tag::get_all_validators(validators);

		if (validators.size() <= 10) {
			return validators;
		}

		std::vector<zera_txn::Validator> randomValues = validators; // Copy the original vector
		std::random_device rd;
		std::mt19937 gen(rd());

		int n = static_cast<int>(randomValues.size());
		for (int i = 0; i < VALIDATOR_AMOUNT; ++i) {
			std::uniform_int_distribution<> dis(i, n - 1);
			int randomIndex = dis(gen);

			// Swap the randomly chosen element with the current element
			std::swap(randomValues[i], randomValues[randomIndex]);
		}

		// Resize the vector to the desired count
		randomValues.resize(VALIDATOR_AMOUNT);
		return randomValues;
	}

	namespace validator_utils
	{
		void archive_balances(const std::string& block_height);
	}

#endif