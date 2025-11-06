#include "proposer.h"
#include "../logging/logging.h"

namespace
{
    uint64_t get_coin_nonce(const zera_txn::CoinTXN &txn)
    {
        uint64_t full_nonce = 0;
        for (auto nonce : txn.auth().nonce())
        {
            full_nonce += nonce;
        }
        return full_nonce;
    }
    std::vector<zera_txn::TXNWrapper> order_nonce_txns(std::vector<zera_txn::TXNWrapper> wrappers)
    {
        std::vector<std::pair<uint64_t, zera_txn::TXNWrapper>> nonce_pairs;

        for (auto wrapper : wrappers)
        {
            if (wrapper.has_coin_txn())
            {
                uint64_t nonce = get_coin_nonce(wrapper.coin_txn());
                nonce_pairs.push_back(std::make_pair(nonce, wrapper));
            }
            else if (wrapper.has_contract_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.contract_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_governance_proposal())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.governance_proposal().base().nonce(), wrapper));
            }
            else if (wrapper.has_governance_vote())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.governance_vote().base().nonce(), wrapper));
            }
            else if (wrapper.has_mint_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.mint_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_item_mint_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.item_mint_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_nft_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.nft_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_contract_update_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.contract_update_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_smart_contract())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.smart_contract().base().nonce(), wrapper));
            }
            else if (wrapper.has_smart_contract_execute())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.smart_contract_execute().base().nonce(), wrapper));
            }
            else if (wrapper.has_expense_ratios())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.expense_ratios().base().nonce(), wrapper));
            }
            else if (wrapper.has_delegated_voting_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.delegated_voting_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_quash_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.quash_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_fast_quorum_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.fast_quorum_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_revoke_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.revoke_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_compliance_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.compliance_txn().base().nonce(), wrapper));
            }
            else if (wrapper.proposal_result_txn())
            {
            }
            else if (wrapper.has_burn_sbt_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.burn_sbt_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_validator_heartbeat_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.validator_heartbeat_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_validator_registration_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.validator_registration_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_smart_contract_instantiate_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.smart_contract_instantiate_txn().base().nonce(), wrapper));
            }
            else if (wrapper.has_required_version_txn())
            {
                nonce_pairs.push_back(std::make_pair(wrapper.required_version_txn().base().nonce(), wrapper));
            }
        }

        // Sort the vector by the nonce (first element of the pair)
        std::sort(nonce_pairs.begin(), nonce_pairs.end(), [](const std::pair<uint64_t, zera_txn::TXNWrapper> &a, const std::pair<uint64_t, zera_txn::TXNWrapper> &b)
                  { return a.first < b.first; });

        std::vector<zera_txn::TXNWrapper> ordered_wrappers;

        for (auto wrapper : nonce_pairs)
        {
            ordered_wrappers.push_back(wrapper.second);
        }

        return ordered_wrappers;
    }
}
ZeraStatus proposing::process_txns(const std::vector<std::string> &values, const std::vector<std::string> &keys, zera_validator::Block *block, bool timed, const std::string &fee_address)
{
    std::vector<std::string> remove_keys;
    std::vector<std::string> nonce_keys;
    std::vector<std::string> nonce_values;
    std::vector<zera_txn::TXNWrapper> nonce_wrappers;

    zera_txn::TXNS *block_txns = block->mutable_transactions();
    std::map<std::string, zera_txn::TXNStatusFees> status_fees;

    ZeraStatus status;

    bool has_txns = false;
    int x = 0;
    for (auto txns : values)
    {
        zera_txn::TXNWrapper wrapper;

        if (wrapper.ParseFromString(txns))
        {      
            status = processTransaction(wrapper, block_txns, timed, fee_address);  

            if (status.ok())
            {
                has_txns = true;
            }
            else
            {
                logging::print(status.read_status());
            }
        }

        // if txn fails? have to remove from preprocessed nonce db
        if (status.code() != ZeraStatus::Code::NONCE_ERROR)
        {
            remove_keys.push_back(keys[x]);
        }
        else
        {
            nonce_wrappers.push_back(wrapper);
            remove_keys.push_back(keys[x]);
        }
        x++;
    }

    std::vector<zera_txn::TXNWrapper> ordered_wrappers = order_nonce_txns(nonce_wrappers);

    for (auto wrapper : ordered_wrappers)
    {

        status = processTransaction(wrapper, block_txns, timed, fee_address);

        if (status.ok())
        {
            has_txns = true;
        }
    }

    // remove txns from pending database
    rocksdb::WriteBatch remove_txns;
    for (auto key : remove_keys)
    {
        remove_txns.Delete(key);
    }

    if (timed)
    {
        db_timed_txns::store_batch(remove_txns);
    }
    else
    {
        db_transactions::store_batch(remove_txns);
    }

    if (block->transactions().proposal_result_txns_size() > 0)
    {
        has_txns = true;
    }

    if (!has_txns)
    {
        return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, "proposer.h: process_txn: All txns failed. Block will fail.");
    }

    return ZeraStatus(ZeraStatus::OK);
}