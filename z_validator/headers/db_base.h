#pragma once

#include <vector>
#include <string>
#include "database.h"
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/write_batch.h>
#include "validator.pb.h"

#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <leveldb/options.h>

template <typename T>
class db_base
{
    friend class db_validators_tag;
    friend class db_blocks_tag;
    friend class db_headers_tag;

public:
    static int open_db();
    static void close_db();
    static int get_all_data(std::vector<std::string> &keys, std::vector<std::string> &values);
    static int get_single(const std::string &key, std::string &value);
    static int store_single(const std::string &key, const std::string &value);
    static int store_batch(rocksdb::WriteBatch &batch);
    static int remove_single(const std::string &key);
    static int remove_all();
    static int exist(const std::string &key);
    static int get_first_data(std::string &key, std::string &value);
    static int get_next_data(const std::string &iterate_from, std::string &key, std::string &value);
    static int backup_database(const std::string &backup_path);
    static int restore_database(const std::string &backup_path);
    static int compact_all();

private:
    static rocksdb::DB *db;
    static rocksdb::Options options;
    static std::mutex db_mutex;
};

class db_event_management_tag
{
public:
    static const char *const DB_NAME;
};
class db_sc_subscriber_tag
{
public:
    static const char *const DB_NAME;
};
class db_sc_temp_tag
{
public:
    static const char *const DB_NAME;
};
class db_gossip_tag
{
public:
    static const char *const DB_NAME;
};
class db_system_tag
{
public:
    static const char *const DB_NAME;
};
class db_validator_archive_tag
{
public:
    static const char *const DB_NAME;
};
class db_attestation_ledger_tag
{
public:
    static const char *const DB_NAME;
};
class db_confirmed_blocks_tag
{
public:
    static const char *const DB_NAME;
};
class db_attestation_tag
{
public:
    static const char *const DB_NAME;
};
class db_contract_price_tag
{
public:
    static const char *const DB_NAME;
};
class db_sc_transactions_tag
{
public:
    static const char *const DB_NAME;
};
class db_gov_txn_tag
{
public:
    static const char *const DB_NAME;
};
class db_validate_txns_tag
{
public:
    static const char *const DB_NAME;
};
class db_processed_wallets_tag
{
public:
    static const char *const DB_NAME;
};
class db_processed_txns_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallet_nonce_tag
{
public:
    static const char *const DB_NAME;
};
class db_preprocessed_nonce_tag
{
public:
    static const char *const DB_NAME;
};
class db_voted_proposals_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegatees_tag
{
public:
    static const char *const DB_NAME;
};
class db_duplicate_txn_tag
{
public:
    static const char *const DB_NAME;
};
class db_fast_quorum_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallet_lookup_tag
{
public:
    static const char *const DB_NAME;
};
class db_quash_lookup_tag
{
public:
    static const char *const DB_NAME;
};
class db_quash_ledger_tag
{
public:
    static const char *const DB_NAME;
};
class db_quash_ledger_lookup_tag
{
public:
    static const char *const DB_NAME;
};
class db_timed_txns_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegate_wallets_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegate_recipient_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegate_vote_tag
{
public:
    static const char *const DB_NAME;
};
class db_expense_ratio_tag
{
public:
    static const char *const DB_NAME;
};

class db_proposals_temp_tag
{
public:
    static const char *const DB_NAME;
};
class db_proposal_wallets_tag
{
public:
    static const char *const DB_NAME;
};
class db_status_fee_tag
{
public:
    static const char *const DB_NAME;
};
class db_proposal_ledger_tag
{
public:
    static const char *const DB_NAME;
};
class db_process_adaptive_ledger_tag
{
public:
    static const char *const DB_NAME;
};
class db_process_ledger_tag
{
public:
    static const char *const DB_NAME;
};
class db_proposals_tag
{
public:
    static const char *const DB_NAME;
};
class db_contracts_tag
{
public:
    static const char *const DB_NAME;
};
class db_hash_index_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallets_tag
{
public:
    static const char *const DB_NAME;
};
class db_contract_supply_tag
{
public:
    static const char *const DB_NAME;
};
class db_transactions_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallets_temp_tag
{
public:
    static const char *const DB_NAME;
};
class db_smart_contracts_tag
{
public:
    static const char *const DB_NAME;
};
class db_block_txns_tag
{
public:
    static const char *const DB_NAME;
};
class db_restricted_wallets_tag
{
public:
    static const char *const DB_NAME;
};
class db_contract_items_tag
{
public:
    static const char *const DB_NAME;
};
class db_validator_lookup_tag
{
public:
    static const char *const DB_NAME;
};
class db_validator_unbond_tag
{
public:
    static const char *const DB_NAME;
};
class db_allowance_tag
{
public:
    static const char *const DB_NAME;
};
class db_validators_tag
{
public:
    static const char *const DB_NAME;
    static int get_all_keys(std::vector<std::string> &keys);
    static int get_all_validators(std::vector<zera_txn::Validator> &validators);
};
class db_blocks_tag
{
public:
    static const char *const DB_NAME;
    static int get_multi_data(std::string &start_key, int amount, std::vector<zera_validator::Block> &blocks);
    static int get_last_data(zera_validator::Block &block, std::string &last_key);
    static int get_all_blocks(std::vector<zera_validator::Block> &blocks);
    static int get_multi_data_keys(std::string &start_key, int amount, std::vector<zera_validator::Block> &blocks, std::vector<std::string>& keys);
};
class db_headers_tag
{
public:
    static const char *const DB_NAME;
    static int get_multi_data(std::string &start_key, int amount, std::vector<zera_validator::BlockHeader> &block_headers);
    static int get_last_data(zera_validator::BlockHeader &block_header, std::string &last_key);
    static int get_last_amount(std::vector<zera_validator::BlockHeader> &headers, std::vector<std::string> &keys, int amount);
    static int get_multi_data_keys(std::string &start_key, int amount, std::vector<zera_validator::BlockHeader> &blocks, std::vector<std::string>& keys);
};

void open_dbs();
void close_dbs();
void nuke_db();

// Type aliases for each database
using db_contracts = db_base<db_contracts_tag>;                   // store ALL contracts
using db_contract_items = db_base<db_contract_items_tag>;         // store all nfts/sbts. Key = contract_id + item_id (value = item)
using db_headers = db_base<db_headers_tag>;                       // store all block headers
using db_validators = db_base<db_validators_tag>;                 // store all active validators. Key = validator address (value = validator)
using db_blocks = db_base<db_blocks_tag>;                         // store all blocks
using db_hash_index = db_base<db_hash_index_tag>;                 // quick lookup for block hash (key = block hash) (value = block hash)
using db_wallets = db_base<db_wallets_tag>;                       // store values of each wallet (key = wallet address + contract_id) (value = wallet value
using db_contract_supply = db_base<db_contract_supply_tag>;       // store supply of each contract (key = contract_id) (value = supply)
using db_transactions = db_base<db_transactions_tag>;             // store all transactions
using db_wallets_temp = db_base<db_wallets_temp_tag>;             // temp store for wallets for calculating wallet balances while processing a block
using db_smart_contracts = db_base<db_smart_contracts_tag>;       // store all smart contracts
using db_block_txns = db_base<db_block_txns_tag>;                 // storing all txns pending to be in block
using db_restricted_wallets = db_base<db_restricted_wallets_tag>; // store all restricted wallets to determine if global or not
using db_validator_lookup = db_base<db_validator_lookup_tag>;     // lookup for db_vaidators(key = original public_key) (value = validator)
using db_validator_unbond = db_base<db_validator_unbond_tag>;     // store all validators that are unbonding (key = validator address) (value = validator)
using db_proposal_ledger = db_base<db_proposal_ledger_tag>;       // store all governance details for each contract (staged/cycle) (key = contract_id) (value = ProposalLedger)
using db_process_ledger = db_base<db_process_ledger_tag>;         // store all proposals that need to be processed (adaptive/staggered) (key = proposal_id) (value = timestamp - time to process) 
using db_proposals = db_base<db_proposals_tag>;                   // store all proposals (key = proposal_id) (value = proposal)
using db_status_fee = db_base<db_status_fee_tag>;                           // deprecated
using db_process_adaptive_ledger = db_base<db_process_adaptive_ledger_tag>;
using db_expense_ratio = db_base<db_expense_ratio_tag>;           // store the data and time an expense ratio txn can be called for a contract
using db_proposal_wallets = db_base<db_proposal_wallets_tag>;     // store values to temp wallets that the proposer will use to pay for the proposal
using db_proposals_temp = db_base<db_proposals_temp_tag>;         // store all proposals that are pending to be processed
using db_delegate_vote = db_base<db_delegate_vote_tag>;           // store all people that you want to delegate your vote to  (key = wallet_adr)
using db_delegate_recipient = db_base<db_delegate_recipient_tag>; // storage of all people who have delegated their vote to you
using db_delegate_wallets = db_base<db_delegate_wallets_tag>;     //
using db_timed_txns = db_base<db_timed_txns_tag>;                 // store all txns that have a time delay
using db_quash_ledger = db_base<db_quash_ledger_tag>;             // store all quash ledgers
using db_quash_ledger_lookup = db_base<db_quash_ledger_lookup_tag>;  // lookup for quash_ledger (key = txn_hash) (value = quash_ledger key (time)) 
using db_quash_lookup = db_base<db_quash_lookup_tag>;             //
using db_wallet_lookup = db_base<db_wallet_lookup_tag>;           // store kyc data for each wallet
using db_fast_quorum = db_base<db_fast_quorum_tag>;               // store all fast quorum proposals that need to be processed into results
using db_duplicate_txn = db_base<db_duplicate_txn_tag>;           // store all txns that have been processed in last two hours to prevent double spending. key = time to process, value = list of txn hash
using db_delegatees = db_base<db_delegatees_tag>;                 // store all delegatees for each public_key that has done a delegation (used for delegatee to check if they are still delegated)
using db_voted_proposals = db_base<db_voted_proposals_tag>;       // store all proposals that have been voted on at which priority for each public key (key = wallet_adr) (zera_validator::Delegated (map<base58(proposal_id), priority>))
using db_wallet_nonce = db_base<db_wallet_nonce_tag>;             // store all nonces for each wallet
using db_preprocessed_nonce = db_base<db_preprocessed_nonce_tag>; // store all nonces for each wallet for preprocessed txns
using db_processed_txns = db_base<db_processed_txns_tag>;         // store all txns that have been preprocessed and are ready to be added into a block (proposer use all of these | validators compares proposed block to these)
using db_processed_wallets = db_base<db_processed_wallets_tag>;   // running total of pre processed wallet balances to confirm that each txn is valid (key = wallet address + contract_id) (value = wallet value)
using db_validate_txns = db_base<db_validate_txns_tag>;           // store all txns that need to be validated for newest block (key = txn_hash+nonce) (value = txn wrapper)
using db_gov_txn = db_base<db_gov_txn_tag>;                       // store all governance txns that have been approved and are ready to be processed (key = proposal_id) (value = true)
using db_sc_transactions = db_base<db_sc_transactions_tag>;       // store all txns sent by transactions (key = txn_hash) (value = txn wrapper)
using db_contract_price = db_base<db_contract_price_tag>;         // store all contract prices (key = contract symbol) (value = price)
using db_attestation = db_base<db_attestation_tag>;               // store all attestations (key = block_height) (value = BlockAttestation)
using db_confirmed_blocks = db_base<db_confirmed_blocks_tag>;     // store all confirmed blocks (key = block_height) (value = block hash)
using db_attestation_ledger = db_base<db_attestation_ledger_tag>; // store all different/verified attestations that have been recieved by validators for each block height (key = block_height) (value = AttetationLedger)
using db_validator_archive = db_base<db_validator_archive_tag>;   // archive of all validator balances for each block height (key = block_height) (value = ValidatorArchive)
using db_system = db_base<db_system_tag>;                         // store all system data (key = system data type) (value = system data) example. Version #
using db_gossip = db_base<db_gossip_tag>;                         // store all txns ready for gossip (key = txn_hash) (value = txn data)
using db_sc_temp = db_base<db_sc_temp_tag>;                       // store all temp state data for smart contracts (key = ???) (value = temp state data)
using db_allowance = db_base<db_allowance_tag>;                   // store all allowance data for each wallet (key = pub_key + wallet_adr + contract_id) (value = allowance value)
using db_sc_subscriber = db_base<db_sc_subscriber_tag>;           // store all subscribers for each smart contract (key = smart_contract_id) (value = map<wallet_adr_base58, Subscriber>) and key = wallet_adr_base58_NONCE (value = nonce)
using db_event_management = db_base<db_event_management_tag>;     // store all event management data (key = smart_contract_id) (value = list of event_keys/timestamps)