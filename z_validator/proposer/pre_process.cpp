#include "proposer.h"
#include "../governance/gov_process.h"

void proposing::add_transaction(zera_txn::TXNWrapper &wrapper, zera_txn::TXNS *block_txns)
{
    if (wrapper.has_coin_txn())
    {
        txn_hash_tracker::add_allowance_hash(wrapper.coin_txn().base().hash());
        txn_hash_tracker::add_hash(wrapper.coin_txn().base().hash());
        get_fees_status(wrapper.coin_txn(), block_txns);
        block_txns->add_coin_txns()->CopyFrom(wrapper.coin_txn());
        auto size = block_txns->txn_fees_and_status_size() - 1;
        
        add_used_new_coin_nonce(wrapper.coin_txn(), block_txns->txn_fees_and_status(size));
    }
    else if (wrapper.has_contract_txn())
    {
        txn_hash_tracker::add_hash(wrapper.contract_txn().base().hash());
        get_fees_status(wrapper.contract_txn(), block_txns);
        block_txns->add_contract_txns()->CopyFrom(wrapper.contract_txn());
        add_used_nonce(wrapper.contract_txn());
    }
    else if (wrapper.has_governance_proposal())
    {
        txn_hash_tracker::add_hash(wrapper.governance_proposal().base().hash());
        get_fees_status(wrapper.governance_proposal(), block_txns);
        block_txns->add_governance_proposals()->CopyFrom(wrapper.governance_proposal());
        add_used_nonce(wrapper.governance_proposal());
    }
    else if (wrapper.has_governance_vote())
    {
        txn_hash_tracker::add_hash(wrapper.governance_vote().base().hash());
        get_fees_status(wrapper.governance_vote(), block_txns);
        block_txns->add_governance_votes()->CopyFrom(wrapper.governance_vote());
        add_used_nonce(wrapper.governance_vote());
    }
    else if (wrapper.has_mint_txn())
    {
        txn_hash_tracker::add_hash(wrapper.mint_txn().base().hash());
        get_fees_status(wrapper.mint_txn(), block_txns);
        block_txns->add_mint_txns()->CopyFrom(wrapper.mint_txn());
        add_used_nonce(wrapper.mint_txn());
    }
    else if (wrapper.has_item_mint_txn())
    {
        txn_hash_tracker::add_hash(wrapper.item_mint_txn().base().hash());
        get_fees_status(wrapper.item_mint_txn(), block_txns);
        block_txns->add_item_mint_txns()->CopyFrom(wrapper.item_mint_txn());
        add_used_nonce(wrapper.item_mint_txn());
    }
    else if (wrapper.has_nft_txn())
    {
        txn_hash_tracker::add_hash(wrapper.nft_txn().base().hash());
        get_fees_status(wrapper.nft_txn(), block_txns);
        block_txns->add_nft_txns()->CopyFrom(wrapper.nft_txn());
        add_used_nonce(wrapper.nft_txn());
    }
    else if (wrapper.has_contract_update_txn())
    {
        txn_hash_tracker::add_hash(wrapper.contract_update_txn().base().hash());
        get_fees_status(wrapper.contract_update_txn(), block_txns);
        block_txns->add_contract_update_txns()->CopyFrom(wrapper.contract_update_txn());
        add_used_nonce(wrapper.contract_update_txn());
    }
    else if (wrapper.has_smart_contract())
    {
        txn_hash_tracker::add_hash(wrapper.smart_contract().base().hash());
        get_fees_status(wrapper.smart_contract(), block_txns);
        block_txns->add_smart_contracts()->CopyFrom(wrapper.smart_contract());
        add_used_nonce(wrapper.smart_contract());
    }
    else if (wrapper.has_smart_contract_execute())
    {
        txn_hash_tracker::add_hash(wrapper.smart_contract_execute().base().hash());
        get_fees_status(wrapper.smart_contract_execute(), block_txns);
        block_txns->add_smart_contract_executes()->CopyFrom(wrapper.smart_contract_execute());
        add_used_nonce(wrapper.smart_contract_execute());
    }
    else if (wrapper.has_expense_ratios())
    {
        txn_hash_tracker::add_hash(wrapper.expense_ratios().base().hash());
        get_fees_status(wrapper.expense_ratios(), block_txns);
        block_txns->add_expense_ratios()->CopyFrom(wrapper.expense_ratios());
        add_used_nonce(wrapper.expense_ratios());
    }
    else if (wrapper.has_delegated_voting_txn())
    {
        txn_hash_tracker::add_hash(wrapper.delegated_voting_txn().base().hash());
        get_fees_status(wrapper.delegated_voting_txn(), block_txns);
        block_txns->add_delegated_voting_txns()->CopyFrom(wrapper.delegated_voting_txn());
        add_used_nonce(wrapper.delegated_voting_txn());
    }
    else if (wrapper.has_quash_txn())
    {
        txn_hash_tracker::add_hash(wrapper.quash_txn().base().hash());
        get_fees_status(wrapper.quash_txn(), block_txns);
        block_txns->add_quash_txns()->CopyFrom(wrapper.quash_txn());
        add_used_nonce(wrapper.quash_txn());
    }
    else if (wrapper.has_fast_quorum_txn())
    {
        txn_hash_tracker::add_hash(wrapper.fast_quorum_txn().base().hash());
        get_fees_status(wrapper.fast_quorum_txn(), block_txns);
        block_txns->add_fast_quorum_txns()->CopyFrom(wrapper.fast_quorum_txn());
        add_used_nonce(wrapper.fast_quorum_txn());
    }
    else if (wrapper.has_revoke_txn())
    {
        txn_hash_tracker::add_hash(wrapper.revoke_txn().base().hash());
        get_fees_status(wrapper.revoke_txn(), block_txns);
        block_txns->add_revoke_txns()->CopyFrom(wrapper.revoke_txn());
        add_used_nonce(wrapper.revoke_txn());
    }
    else if (wrapper.has_compliance_txn())
    {
        txn_hash_tracker::add_hash(wrapper.compliance_txn().base().hash());
        get_fees_status(wrapper.compliance_txn(), block_txns);
        block_txns->add_compliance_txns()->CopyFrom(wrapper.compliance_txn());
        add_used_nonce(wrapper.compliance_txn());
    }
    else if (wrapper.proposal_result_txn())
    {
        logging::print("Adding proposal result txn to block");
        gov_process::process_ledgers(block_txns, wrapper);
    }
    else if (wrapper.has_burn_sbt_txn())
    {
        txn_hash_tracker::add_hash(wrapper.burn_sbt_txn().base().hash());
        get_fees_status(wrapper.burn_sbt_txn(), block_txns);
        block_txns->add_burn_sbt_txns()->CopyFrom(wrapper.burn_sbt_txn());
        add_used_nonce(wrapper.burn_sbt_txn());
    }
    else if(wrapper.has_validator_heartbeat_txn())
    {
        txn_hash_tracker::add_hash(wrapper.validator_heartbeat_txn().base().hash());
        get_fees_status(wrapper.validator_heartbeat_txn(), block_txns);
        block_txns->add_validator_heartbeat_txns()->CopyFrom(wrapper.validator_heartbeat_txn());
        add_used_nonce(wrapper.validator_heartbeat_txn());
    }
    else if(wrapper.has_validator_registration_txn())
    {
        txn_hash_tracker::add_hash(wrapper.validator_registration_txn().base().hash());
        get_fees_status(wrapper.validator_registration_txn(), block_txns);
        block_txns->add_validator_registration_txns()->CopyFrom(wrapper.validator_registration_txn());
        add_used_nonce(wrapper.validator_registration_txn());
    }
    else if(wrapper.has_smart_contract_instantiate_txn())
    {
        txn_hash_tracker::add_hash(wrapper.smart_contract_instantiate_txn().base().hash());
        get_fees_status(wrapper.smart_contract_instantiate_txn(), block_txns);
        block_txns->add_smart_contract_instantiate_txns()->CopyFrom(wrapper.smart_contract_instantiate_txn());
        add_used_nonce(wrapper.smart_contract_instantiate_txn());
    }
    else if(wrapper.has_allowance_txn())
    {
        txn_hash_tracker::add_hash(wrapper.allowance_txn().base().hash());
        get_fees_status(wrapper.allowance_txn(), block_txns);
        block_txns->add_allowance_txns()->CopyFrom(wrapper.allowance_txn());
        add_used_nonce(wrapper.allowance_txn());
    }
}

bool proposing::add_processed_sync(const std::vector<std::string> &keys, const std::vector<std::string> &values, zera_validator::Block *block)
{
    std::vector<std::string> added_txns;
    zera_txn::TXNS *block_txns = block->mutable_transactions();
    bool txn_added = false;
    int x = 0;
    for (auto txn_str : values)
    {
        zera_txn::TXNWrapper wrapper;

        if (wrapper.ParseFromString(txn_str))
        {
            add_transaction(wrapper, block_txns);
            txn_added = true;
        }
        
        added_txns.push_back(keys[x]);
    }

    rocksdb::WriteBatch remove_txns;

    for (auto key : added_txns)
    {
        remove_txns.Delete(key);
    }

    db_processed_txns::store_batch(remove_txns);

    return txn_added;
}

bool proposing::add_processed(const std::vector<std::string> &keys, const std::vector<std::string> &values, zera_validator::Block *block, const Stopwatch& stopwatch)
{
    std::vector<std::string> added_txns;
    zera_txn::TXNS *block_txns = block->mutable_transactions();
    bool txn_added = false;
    int x = 0;

    for (auto txn_str : values)
    {
        zera_txn::TXNWrapper wrapper;

        if (wrapper.ParseFromString(txn_str))
        {
            add_transaction(wrapper, block_txns);
            txn_added = true;
        }
        
        added_txns.push_back(keys[x]);

        if(stopwatch.elapsed_seconds() > 4)
        {
            break;
        }
        x++;
    }

    rocksdb::WriteBatch remove_txns;

    logging::print("txns added to block:", std::to_string(added_txns.size()), true);
    for (auto key : added_txns)
    {
        remove_txns.Delete(key);
    }

    db_processed_txns::store_batch(remove_txns);

    return txn_added;
}