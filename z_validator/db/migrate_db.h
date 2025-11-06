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
class migrate_db_base
{
    friend class db_validators_1_tag;
    friend class db_blocks_1_tag;
    friend class db_headers_1_tag;

public:
    static int migrate(std::string &backup_path);
private:
    static leveldb::DB *db;
    static leveldb::Options options;
    static std::mutex db_mutex;
};

class db_sc_temp_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_gossip_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_system_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_validator_archive_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_attestation_ledger_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_confirmed_blocks_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_attestation_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_contract_price_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_sc_transactions_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_gov_txn_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_validate_txns_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_processed_wallets_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_processed_txns_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallet_nonce_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_preprocessed_nonce_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_voted_proposals_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegatees_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_duplicate_txn_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_fast_quorum_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallet_lookup_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_quash_lookup_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_quash_ledger_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_quash_ledger_lookup_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_timed_txns_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegate_wallets_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegate_recipient_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_delegate_vote_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_expense_ratio_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_proposals_temp_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_proposal_wallets_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_status_fee_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_proposal_ledger_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_process_adaptive_ledger_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_process_ledger_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_proposals_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_contracts_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_hash_index_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallets_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_contract_supply_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_transactions_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_wallets_temp_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_smart_contracts_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_block_txns_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_restricted_wallets_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_contract_items_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_validator_lookup_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_validator_unbond_1_tag
{
public:
    static const char *const DB_NAME;
};
class db_validators_1_tag
{
public:
    static const char *const DB_NAME;
    static int get_all_keys(std::vector<std::string> &keys);
    static int get_all_validators(std::vector<zera_txn::Validator> &validators);
};
class db_blocks_1_tag
{
public:
    static const char *const DB_NAME;
    static int get_multi_data(std::string &start_key, int amount, std::vector<zera_validator::Block> &blocks);
    static int get_last_data(zera_validator::Block &block, std::string &last_key);
    static int get_all_blocks(std::vector<zera_validator::Block> &blocks);
    static int get_multi_data_keys(std::string &start_key, int amount, std::vector<zera_validator::Block> &blocks, std::vector<std::string>& keys);
};
class db_headers_1_tag
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

// Type aliases for each database
using db_contracts_1 = migrate_db_base<db_contracts_1_tag>;                   // store ALL contracts
using db_contract_items_1 = migrate_db_base<db_contract_items_1_tag>;         // store all nfts/sbts. Key = contract_id + item_id (value = item)
using db_headers_1 = migrate_db_base<db_headers_1_tag>;                       // store all block headers
using db_validators_1 = migrate_db_base<db_validators_1_tag>;                 // store all active validators. Key = validator address (value = validator)
using db_blocks_1 = migrate_db_base<db_blocks_1_tag>;                         // store all blocks
using db_hash_index_1 = migrate_db_base<db_hash_index_1_tag>;                 // quick lookup for block hash (key = block hash) (value = block hash)
using db_wallets_1 = migrate_db_base<db_wallets_1_tag>;                       // store values of each wallet (key = wallet address + contract_id) (value = wallet value
using db_contract_supply_1 = migrate_db_base<db_contract_supply_1_tag>;       // store supply of each contract (key = contract_id) (value = supply)
using db_transactions_1 = migrate_db_base<db_transactions_1_tag>;             // store all transactions
using db_wallets_temp_1 = migrate_db_base<db_wallets_temp_1_tag>;             // temp store for wallets for calculating wallet balances while processing a block
using db_smart_contracts_1 = migrate_db_base<db_smart_contracts_1_tag>;       // store all smart contracts
using db_block_txns_1 = migrate_db_base<db_block_txns_1_tag>;                 // storing all txns pending to be in block
using db_restricted_wallets_1 = migrate_db_base<db_restricted_wallets_1_tag>; // store all restricted wallets to determine if global or not
using db_validator_lookup_1 = migrate_db_base<db_validator_lookup_1_tag>;     // lookup for db_vaidators(key = original public_key) (value = validator)
using db_validator_unbond_1 = migrate_db_base<db_validator_unbond_1_tag>;     // store all validators that are unbonding (key = validator address) (value = validator)
using db_proposal_ledger_1 = migrate_db_base<db_proposal_ledger_1_tag>;       // store all governance details for each contract (s_1_taged/cycle) (key = contract_id) (value = ProposalLedger)
using db_process_ledger_1 = migrate_db_base<db_process_ledger_1_tag>;         // store all proposals that need to be processed (adaptive/s_1_taggered) (key = proposal_id) (value = timestamp - time to process) 
using db_proposals_1 = migrate_db_base<db_proposals_1_tag>;                   // store all proposals (key = proposal_id) (value = proposal)
using db_status_fee_1 = migrate_db_base<db_status_fee_1_tag>;                 //store preprecossed statys fees
using db_process_adaptive_ledger_1 = migrate_db_base<db_process_adaptive_ledger_1_tag>;
using db_expense_ratio_1 = migrate_db_base<db_expense_ratio_1_tag>;           // store the data and time an expense ratio txn can be called for a contract
using db_proposal_wallets_1 = migrate_db_base<db_proposal_wallets_1_tag>;     // store values to temp wallets that the proposer will use to pay for the proposal
using db_proposals_temp_1 = migrate_db_base<db_proposals_temp_1_tag>;         // store all proposals that are pending to be processed
using db_delegate_vote_1 = migrate_db_base<db_delegate_vote_1_tag>;           // store all people that you want to delegate your vote to  (key = wallet_adr)
using db_delegate_recipient_1 = migrate_db_base<db_delegate_recipient_1_tag>; // storage of all people who have delegated their vote to you
using db_delegate_wallets_1 = migrate_db_base<db_delegate_wallets_1_tag>;     //
using db_timed_txns_1 = migrate_db_base<db_timed_txns_1_tag>;                 // store all txns that have a time delay
using db_quash_ledger_1 = migrate_db_base<db_quash_ledger_1_tag>;             // store all quash ledgers
using db_quash_ledger_lookup_1 = migrate_db_base<db_quash_ledger_lookup_1_tag>;  // lookup for quash_ledger (key = txn_hash) (value = quash_ledger key (time)) 
using db_quash_lookup_1 = migrate_db_base<db_quash_lookup_1_tag>;             //
using db_wallet_lookup_1 = migrate_db_base<db_wallet_lookup_1_tag>;           // store kyc data for each wallet
using db_fast_quorum_1 = migrate_db_base<db_fast_quorum_1_tag>;               // store all fast quorum proposals that need to be processed into results
using db_duplicate_txn_1 = migrate_db_base<db_duplicate_txn_1_tag>;           // store all txns that have been processed in last two hours to prevent double spending. key = time to process, value = list of txn hash
using db_delegatees_1 = migrate_db_base<db_delegatees_1_tag>;                 // store all delegatees for each public_key that has done a delegation (used for delegatee to check if they are still delegated)
using db_voted_proposals_1 = migrate_db_base<db_voted_proposals_1_tag>;       // store all proposals that have been voted on at which priority for each public key (key = wallet_adr) (zera_validator::Delegated (map<base58(proposal_id), priority>))
using db_wallet_nonce_1 = migrate_db_base<db_wallet_nonce_1_tag>;             // store all nonces for each wallet
using db_preprocessed_nonce_1 = migrate_db_base<db_preprocessed_nonce_1_tag>; // store all nonces for each wallet for preprocessed txns
using db_processed_txns_1 = migrate_db_base<db_processed_txns_1_tag>;         // store all txns that have been preprocessed and are ready to be added into a block (proposer use all of these | validators compares proposed block to these)
using db_processed_wallets_1 = migrate_db_base<db_processed_wallets_1_tag>;   // running total of pre processed wallet balances to confirm that each txn is valid (key = wallet address + contract_id) (value = wallet value)
using db_validate_txns_1 = migrate_db_base<db_validate_txns_1_tag>;           // store all txns that need to be validated for newest block (key = txn_hash+nonce) (value = txn wrapper)
using db_gov_txn_1 = migrate_db_base<db_gov_txn_1_tag>;                       // store all governance txns that have been approved and are ready to be processed (key = proposal_id) (value = true)
using db_sc_transactions_1 = migrate_db_base<db_sc_transactions_1_tag>;       // store all txns sent by transactions (key = txn_hash) (value = txn wrapper)
using db_contract_price_1 = migrate_db_base<db_contract_price_1_tag>;         // store all contract prices (key = contract symbol) (value = price)
using db_attestation_1 = migrate_db_base<db_attestation_1_tag>;               // store all attestations (key = block_height) (value = BlockAttestation)
using db_confirmed_blocks_1 = migrate_db_base<db_confirmed_blocks_1_tag>;     // store all confirmed blocks (key = block_height) (value = block hash)
using db_attestation_ledger_1 = migrate_db_base<db_attestation_ledger_1_tag>; // store all different/verified attestations that have been recieved by validators for each block height (key = block_height) (value = AttetationLedger)
using db_validator_archive_1 = migrate_db_base<db_validator_archive_1_tag>;   // archive of all validator balances for each block height (key = block_height) (value = ValidatorArchive)
using db_system_1 = migrate_db_base<db_system_1_tag>;                         // store all system data (key = system data type) (value = system data) example. Version #
using db_gossip_1 = migrate_db_base<db_gossip_1_tag>;                         // store all txns ready for gossip (key = txn_hash) (value = txn data)
using db_sc_temp_1 = migrate_db_base<db_sc_temp_1_tag>;                       // store all temp state data for smart contracts (key = ???) (value = temp state data)