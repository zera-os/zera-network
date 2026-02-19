#ifndef _CONST_H_
#define _CONST_H_

#include <string>
#include <cstdlib>

constexpr int VERSION = 100003; //version of the validator
//1000000000000000000 1 dollar
//10000000000000000   1 cent
//1 000 000 000 000 000 000 1 dollar
//2000000000000000
/////////

//FIXED VALUES              
const long ATTESTATION_QUORUM = 51;   //51% quorum 

constexpr unsigned long long ONE_DOLLAR = 1000000000000000000; // 10^18
constexpr unsigned long long QUINTILLION = 1000000000000000000; 
constexpr unsigned long long FIRST_TIME_WALLET_FEE_VALUE = 200000000000000000; //the fee for the first time wallet 0.25$

constexpr long ZERA_STAKE_PERCENTAGE = 500;       //50%
constexpr long STAKED_MATH_MULTIPLIER = 100000;     //100%

const size_t CHUNK_SIZE = 3.8 * 1024 * 1024; // 4MB

//INTS
constexpr int TOKEN_MULTIPLIER_VALUE = 10; //10x
constexpr int PROPOSER_AMOUNT = 10; //amount of randomly generated proposers
constexpr int VALIDATOR_AMOUNT = 10; //amount of validators to broadcast to
constexpr int BLOCK_TIMER = 5000; //amount of time between blocks in milliseconds
constexpr int BLOCK_SYNC = 100; //amount of blocks requested at once when syncing blockchain
constexpr int VALIDATOR_FEE_PERCENTAGE = 50; //the percentage of the fees that the validator recieves 
constexpr int BURN_FEE_PERCENTAGE = 25; //the percentage of the fees that the burn recieves 
constexpr int TREASURY_FEE_PERCENTAGE = 25; //the percentage of the fees that the treasury recieves 
constexpr int VALIDATOR_REGISTRATION_TXN_FEE = 1000000000; //the fee for the validator registration transaction

//STRINGS

inline const std::string NETWORK_CONTRACT = "$ZRA+0000";
inline const std::string NETWORK_GOVERNANCE = "gov_$ZRA+0000";
inline const std::string IMPROVEMENT_GOVERNANCE = "gov_$ZIP+0000";

inline const std::string FIRST_TIME_WALLET_FEE = "FIRST_TIME_WALLET_FEE";
inline const std::string TOKEN_MULTIPLIER = "TOKEN_MULTIPLIER";

inline const std::string EVENT_MANAGEMENT_TEMP = "event_management_temp";
inline const std::string NETWORK_FEE_PROXY = "network_fee_proxy_1<>NETWORK_SC";
inline const std::string ACE_PROXY = "zera_dex_proxy_1<>ACE_";
inline const std::string ZERA_DEX_PROXY = "zera_dex_proxy_1<>";
inline const std::string ZERA_DEX_LP = "zera_dex_proxy_1<>LP_25$ZRA+0000";
inline const std::string RESTRICTED_PROXY = "restricted_symbols_proxy_1<>RESTRICTED_SC";
inline const std::string CIRCULATING_SUPPLY_CONTRACT = "circulating_supply_proxy_1<>WHITELIST_SC";
inline const std::string STAKING_PROXY_CONTRACT = "staking_proxy_1<>";
inline const std::string STAKED_COINS_CONTRACT = "staking_proxy_1<>SMART_CONTRACT_";
inline const std::string TOKEN_WHITELIST = "network_values_proxy_1<>TOKEN_WHITELIST";
inline const std::string OPTION_BLACKLIST = "network_values_proxy_1<>OPTION_BLACKLIST";
inline const std::string STABLE_COIN_CONTRACT = "$sol-USDC+000000";
inline const std::string STABLE_COIN_SC = "network_values_proxy_1<>STABLE_TOKEN";


inline const std::string STAKE_MULTIPLIER = "stake_multiplier";
inline const std::string REQUIRED_VERSION = "REQUIRED_VERSION";
inline const std::string CONFIRMED_BLOCK_LATEST = "confirmed_block_latest";
inline const std::string ZERA_SYMBOL = "$ZRA+0000";
inline const std::string CHECKPOINT_INFO = "CHECKPOINT_INFO";
inline const std::string GEN_KEY_PAIR = "GEN_KEY_PAIR";
inline const std::string FEE_TOKENS = "FEE_TOKENS";

// Environment variable for data directory (defaults to "/data/")
inline std::string get_data_dir() {
    const char* env_val = std::getenv("DATA_DIR");
    return env_val ? std::string(env_val) : "/data";
}

inline const std::string DATA_DIR = get_data_dir();
inline const std::string VALIDATOR_CONFIG = DATA_DIR + "/config/validator.conf";
inline const std::string EXPLORER_CONFIG = DATA_DIR + "/config/explorer_servers.conf";
inline const std::string ACTIVITY_WHITELIST = DATA_DIR + "/config/activity_whitelist.conf";
inline const std::string GEN_KEY_FILE = DATA_DIR + "/config/gen_kp.config";
inline const std::string DB_DIRECTORY = DATA_DIR + "/blockchain/";
inline const std::string DB_REORGS = DATA_DIR + "/reorgs/";
inline const std::string DB_CHECKPOINTS = DATA_DIR + "/checkpoints/";
inline const std::string DB_COPY = DATA_DIR + "/copy/";
inline const std::string LOG_DIRECTORY = DATA_DIR + "/logs/";

inline const std::string EMPTY_KEY = "";
inline const std::string BURN_WALLET = ":fire:";
inline const std::string TREASURY_WALLET = "4Yg2ZeYrzMjVBXvU2YWtuZ7CzWR9atnQCD35TQj1kKcH";
inline const std::string PREPROCESS_PLACEHOLDER = "ThiSiSaPrePrOcesSPlaCeHolDer";
inline const std::string TREASURY_KEY = "TREASURY_KEY";


#endif
