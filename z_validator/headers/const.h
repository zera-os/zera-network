#ifndef _CONST_H_
#define _CONST_H_

#include <string>
#include <cstdlib>
#include <cstdint>

constexpr int VERSION = 100007; //version of the validator

// Smart contract outflow allowance rollout gate.
// When false (this build): a SmartContractExecuteTXN/InstantiateTXN with NO
// allowance entry for a token allows unlimited user outflow of that token
// (legacy behavior), letting the ecosystem adopt allowances gracefully. Flip to
// true in a future build to enforce default-deny (no entry => zero outflow).
// Network-wide consistency is guaranteed because all nodes run the same VERSION
// (enforced via REQUIRED_VERSION).
constexpr bool SC_ALLOWANCE_DEFAULT_DENY = false;
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

// Bounds on a single block-sync response, enforced client-side BEFORE the streamed
// data is buffered/verified. A legitimate response is at most BLOCK_SYNC (100) blocks;
// even a worst-case full block (~1-2k txns) is on the order of ~1.5MB, so ~150MB is the
// realistic maximum. 256MB gives large headroom while preventing a malicious sync peer
// from streaming unbounded chunk data and exhausting the syncing validator's memory.
constexpr size_t MAX_BLOCK_SYNC_RESPONSE_BYTES = 256ull * 1024 * 1024; // 256MB hard ceiling
constexpr int MAX_BLOCK_SYNC_CHUNKS = 128;                             // secondary guard (CHUNK_SIZE each)
constexpr int BLOCK_SYNC_DEADLINE_SECONDS = 60;                        // wall-clock cap per sync stream (anti-slowloris)

// Bounds on inbound P2P streaming RPCs (StreamBlockAttestation / StreamBroadcast),
// enforced server-side INSIDE the read loop, before the buffered payload is parsed
// or signature-verified. Without these, any peer that can reach the P2P port can
// stream chunks indefinitely and the validator buffers all of them in memory before
// validation ever runs (CWE-400).
//
// Sizing: a BlockAttestation is a hash + validator-support list (KBs, ~1 chunk);
// a broadcast Block is ~1.5MB worst case today. Caps are set with large headroom
// so legitimate growth never trips them while still bounding a malicious stream.
constexpr size_t MAX_ATTESTATION_STREAM_BYTES = 16ull * 1024 * 1024; // 16MB ceiling for attestation streams
constexpr size_t MAX_BROADCAST_STREAM_BYTES = 64ull * 1024 * 1024;   // 64MB ceiling for a single broadcast block
constexpr int MAX_INBOUND_STREAM_CHUNKS = 32;                        // secondary guard (CHUNK_SIZE each)
constexpr int INBOUND_STREAM_DEADLINE_SECONDS = 30;                  // wall-clock cap per inbound stream (anti-slowloris)

// Bounds on public API bulk endpoints (port 50053). The per-IP rate limiter
// caps request COUNT (5/sec, burst 100) but not per-request cost; without
// these caps a single request can make the validator scan, base58-encode and
// ship entire column families or event histories (CWE-400).
//
// ProposalLedger: the response is capped just under gRPC's 4MB default client
// max-receive size, so the server never builds a response a default client
// couldn't accept anyway. Oversized ledgers are truncated (the data is
// public; a cursor-based pagination API is the long-term fix).
constexpr size_t MAX_PROPOSAL_LEDGER_RESPONSE_BYTES = 3584ull * 1024; // 3.5MB
// SmartContractEventsSearch: events are pruned after 3 days, but a busy
// contract can still accumulate a large history and each event costs a DB
// read. Results are returned oldest-first and capped at this count; clients
// page by advancing search_start past the newest event received (the
// existing timestamp field acts as a cursor, no proto change needed).
constexpr size_t MAX_EVENT_SEARCH_RESULTS = 256;

// Hard cap on a single (pointer, size) parameter a smart contract passes to a
// native host function (read via read_wasm_param). Enforced BEFORE any host-side
// allocation so a contract can't hand the host a bogus multi-GB size and exhaust
// validator memory (CWE-400). Legitimate params are keys/addresses/JSON payloads
// (KBs); 16MB is far beyond anything a contract can affordably store or send.
constexpr uint32_t MAX_WASM_PARAM_BYTES = 16u * 1024 * 1024; // 16MB per host-call parameter

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

// Balance-tracker hash prefix used to isolate smart contract storage (emit)
// fees from the main txn fees so they can be reverted independently if the
// contract crashes/terminates after emitting.
inline const std::string STORAGE_FEE_HASH_PREFIX = "STORAGE_FEE_BALANCE_";
inline const std::string NETWORK_FEE_PROXY = "network_fee_proxy_1<>NETWORK_SC";
inline const std::string ACE_PROXY = "zera_dex_proxy_v1_1<>ACE_";
inline const std::string ZERA_DEX_PROXY = "zera_dex_proxy_v1_1<>";
inline const std::string ZERA_DEX_LP = "zera_dex_proxy_v1_1<>LP_25$ZRA+0000";
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

// Path to the external wasm2wat tool used to validate smart contract deploys.
// Absolute by default (a relative path would resolve against each operator's
// cwd); overridable via WASM2WAT_PATH for non-standard installs.
inline std::string get_wasm2wat_path()
{
    const char *env_val = std::getenv("WASM2WAT_PATH");
    return env_val ? std::string(env_val) : "/usr/local/bin/wasm2wat";
}
inline const std::string WASM2WAT_LOCATION = get_wasm2wat_path();

// Release-pinned SHA3-256 (lowercase hex) of the wasm2wat binary.
//
// wasm2wat output feeds consensus: every validator runs it on the same bytes
// during smart contract deploy validation, so validators on different wabt
// builds could disagree on the validity of the same contract and split the
// network. Pinning the tool hash next to VERSION ties the wabt build to the
// validator build, which REQUIRED_VERSION already enforces network-wide.
//
// At startup the binary at WASM2WAT_LOCATION is hashed and compared against
// this value; on mismatch the validator refuses to run. A validator that
// bypasses the check with a different wabt build will produce divergent txn
// results and be rejected by the rest of the network anyway.
//
inline const std::string WASM2WAT_EXPECTED_SHA3_256 = "";
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
