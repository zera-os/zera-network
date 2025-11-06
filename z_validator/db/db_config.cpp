#include "db_base.h"
#include <rocksdb/write_batch.h>
#include "hex_conversion.h"

void open_dbs()
{
    db_headers::open_db();
    db_blocks::open_db();
    db_contract_supply::open_db();
    db_contracts::open_db();
    db_hash_index::open_db();
    db_transactions::open_db();
    db_validators::open_db();
    db_wallets::open_db();
    db_wallets_temp::open_db();
    db_smart_contracts::open_db();
    db_restricted_wallets::open_db();
    db_block_txns::open_db();
    db_contract_items::open_db();
    db_validator_lookup::open_db();
    db_validator_unbond::open_db();
    db_proposal_ledger::open_db();
    db_proposals::open_db();
    db_status_fee::open_db();
    db_process_ledger::open_db();
    db_process_adaptive_ledger::open_db();
    db_expense_ratio::open_db();
    db_proposal_wallets::open_db();
    db_proposals_temp::open_db();
    db_delegate_vote::open_db();
    db_delegate_recipient::open_db();
    db_timed_txns::open_db();
    db_quash_lookup::open_db();
    db_quash_ledger::open_db();
    db_wallet_lookup::open_db();
    db_delegate_wallets::open_db();
    db_fast_quorum::open_db();
    db_duplicate_txn::open_db();
    db_delegatees::open_db();
    db_voted_proposals::open_db();
    db_wallet_nonce::open_db();
    db_processed_txns::open_db();
    db_processed_wallets::open_db();
    db_preprocessed_nonce::open_db();
    db_validate_txns::open_db();
    db_sc_transactions::open_db();
    db_gov_txn::open_db();
    db_contract_price::open_db();
    db_attestation::open_db();
    db_confirmed_blocks::open_db();
    db_attestation_ledger::open_db();
    db_validator_archive::open_db();
    db_quash_ledger_lookup::open_db();
    db_system::open_db();
    db_gossip::open_db();
    db_sc_temp::open_db();
    db_allowance::open_db();
    db_sc_subscriber::open_db();
    db_event_management::open_db();

    std::string confirmed_height;
    if (!db_confirmed_blocks::get_single(CONFIRMED_BLOCK_LATEST, confirmed_height))
    {
        confirmed_height = "0";
        db_confirmed_blocks::store_single(CONFIRMED_BLOCK_LATEST, confirmed_height);
    }

    // remove all data from temp databases
    db_preprocessed_nonce::remove_all();
    db_processed_wallets::remove_all();
    db_processed_txns::remove_all();
    db_proposals_temp::remove_all();
    db_fast_quorum::remove_all();
    db_transactions::remove_all();
    db_wallets_temp::remove_all();
    db_gossip::remove_all();
    db_sc_temp::remove_all();
    

    std::vector<std::string> keys;
    std::vector<std::string> values;
    db_wallet_nonce::get_all_data(keys, values);

    int x = 0;
    rocksdb::WriteBatch batch;
    while (x < keys.size())
    {
        batch.Put(keys.at(x), values.at(x));
        x++;
    }
    db_preprocessed_nonce::store_batch(batch);
}

void close_dbs()
{
    db_blocks::close_db();
    db_headers::close_db();
    db_contract_supply::close_db();
    db_contracts::close_db();
    db_hash_index::close_db();
    db_transactions::close_db();
    db_validators::close_db();
    db_wallets::close_db();
    db_wallets_temp::close_db();
    db_smart_contracts::close_db();
    db_restricted_wallets::close_db();
    db_block_txns::close_db();
    db_contract_items::close_db();
    db_validator_lookup::close_db();
    db_validator_unbond::close_db();
    db_proposal_ledger::close_db();
    db_proposals::close_db();
    db_status_fee::close_db();
    db_process_ledger::close_db();
    db_process_adaptive_ledger::close_db();
    db_expense_ratio::close_db();
    db_proposal_wallets::close_db();
    db_proposals_temp::close_db();
    db_delegate_vote::close_db();
    db_delegate_recipient::close_db();
    db_timed_txns::close_db();
    db_quash_lookup::close_db();
    db_quash_ledger::close_db();
    db_wallet_lookup::close_db();
    db_delegate_wallets::close_db();
    db_fast_quorum::close_db();
    db_duplicate_txn::close_db();
    db_delegatees::close_db();
    db_voted_proposals::close_db();
    db_wallet_nonce::close_db();
    db_processed_txns::close_db();
    db_processed_wallets::close_db();
    db_preprocessed_nonce::close_db();
    db_validate_txns::close_db();
    db_sc_transactions::close_db();
    db_gov_txn::close_db();
    db_contract_price::close_db();
    db_attestation::close_db();
    db_confirmed_blocks::close_db();
    db_attestation_ledger::close_db();
    db_validator_archive::close_db();
    db_quash_ledger_lookup::close_db();
    db_system::close_db();
    db_gossip::close_db();
    db_sc_temp::close_db();
    db_allowance::close_db();
    db_sc_subscriber::close_db();
    db_event_management::close_db();
}

void nuke_db()
{
    db_blocks::remove_all();
    db_headers::remove_all();
    db_contract_supply::remove_all();
    db_contracts::remove_all();
    db_hash_index::remove_all();
    db_transactions::remove_all();
    db_validators::remove_all();
    db_wallets::remove_all();
    db_wallets_temp::remove_all();
    db_smart_contracts::remove_all();
    db_restricted_wallets::remove_all();
    db_block_txns::remove_all();
    db_contract_items::remove_all();
    db_validator_lookup::remove_all();
    db_validator_unbond::remove_all();
    db_proposal_ledger::remove_all();
    db_proposals::remove_all();
    db_status_fee::remove_all();
    db_process_ledger::remove_all();
    db_process_adaptive_ledger::remove_all();
    db_expense_ratio::remove_all();
    db_proposal_wallets::remove_all();
    db_proposals_temp::remove_all();
    db_delegate_vote::remove_all();
    db_delegate_recipient::remove_all();
    db_timed_txns::remove_all();
    db_quash_lookup::remove_all();
    db_quash_ledger::remove_all();
    db_wallet_lookup::remove_all();
    db_delegate_wallets::remove_all();
    db_fast_quorum::remove_all();
    db_duplicate_txn::remove_all();
    db_delegatees::remove_all();
    db_voted_proposals::remove_all();
    db_wallet_nonce::remove_all();
    db_processed_txns::remove_all();
    db_processed_wallets::remove_all();
    db_preprocessed_nonce::remove_all();
    db_validate_txns::remove_all();
    db_sc_transactions::remove_all();
    db_gov_txn::remove_all();
    db_contract_price::remove_all();
    db_attestation::remove_all();
    db_confirmed_blocks::remove_all();
    db_attestation_ledger::remove_all();
    db_validator_archive::remove_all();
    db_quash_ledger_lookup::remove_all();
    db_system::remove_all();
    db_gossip::remove_all();
    db_sc_temp::remove_all();
    db_allowance::remove_all();
    db_sc_subscriber::remove_all();
    db_event_management::remove_all();
}