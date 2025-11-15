#ifndef _CONST_H_
#define _CONST_H_

constexpr int VERSION = 100000; //version of the validator
//1000000000000000000 1 dollar
//10000000000000000   1 cent
//1 000 000 000 000 000 000 1 dollar
//2000000000000000
/////////

//FIXED VALUES              
const long ATTESTATION_QUORUM = 51;   //51% quorum 

constexpr unsigned long long ONE_DOLLAR = 1000000000000000000;
constexpr unsigned long long QUINTILLION = 1000000000000000000; 

constexpr long ZERA_STAKE_PERCENTAGE = 500;       //50%
constexpr long STAKED_MATH_MULTIPLIER = 100000;     //100%

const size_t CHUNK_SIZE = 3.8 * 1024 * 1024; // 4MB

//INTS
constexpr int PROPOSER_AMOUNT = 10; //amount of randomly generated proposers
constexpr int VALIDATOR_AMOUNT = 10; //amount of validators to broadcast to
constexpr int BLOCK_TIMER = 5000; //amount of time between blocks in milliseconds
constexpr int BLOCK_SYNC = 100; //amount of blocks requested at once when syncing blockchain
constexpr int VALIDATOR_FEE_PERCENTAGE = 50; //the percentage of the fees that the validator recieves 
constexpr int BURN_FEE_PERCENTAGE = 25; //the percentage of the fees that the burn recieves 
constexpr int TREASURY_FEE_PERCENTAGE = 25; //the percentage of the fees that the treasury recieves 
constexpr int VALIDATOR_REGISTRATION_TXN_FEE = 1000000000; //the fee for the validator registration transaction

//STRINGS
constexpr auto EVENT_MANAGEMENT_TEMP = "event_management_temp";
constexpr auto NETWORK_FEE_PROXY = "network_fee_proxy_1_NETWORK_SC";
constexpr auto ACE_PROXY = "ace_proxy_1_ACE_SC";
constexpr auto RESTRICTED_PROXY = "restricted_symbols_proxy_1_RESTRICTED_SC";
constexpr auto CIRCULATING_SUPPLY_CONTRACT = "circulating_supply_proxy_1_WHITELIST_SC";
constexpr auto STAKE_MULTIPLIER = "stake_multiplier";
constexpr auto REQUIRED_VERSION = "REQUIRED_VERSION";
constexpr auto CONFIRMED_BLOCK_LATEST = "confirmed_block_latest";
constexpr auto ZERA_SYMBOL = "$ZRA+0000";
constexpr auto VALIDATOR_CONFIG = "/data/config/validator.conf";
constexpr auto EXPLORER_CONFIG = "/data/config/explorer_servers.conf";
constexpr auto ACTIVITY_WHITELIST = "/data/config/activity_whitelist.conf";
constexpr auto DB_DIRECTORY = "/data/blockchain/";
constexpr auto DB_REORGS = "/data/reorgs/";
constexpr auto DB_COPY = "/data/copy/";

constexpr auto EMPTY_KEY = "";
constexpr auto BURN_WALLET = ":fire:";
constexpr auto TREASURY_WALLET = "4Yg2ZeYrzMjVBXvU2YWtuZ7CzWR9atnQCD35TQj1kKcH";
constexpr auto PREPROCESS_PLACEHOLDER = "ThiSiSaPrePrOcesSPlaCeHolDer";
constexpr auto TREASURY_KEY = "TREASURY_KEY";


#endif