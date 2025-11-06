#include <regex>
#include "txn_batch.h"

#include "db_base.h"
#include "../temp_data/temp_data.h"
#include "wallet.pb.h"
#include "wallets.h"
#include "../governance/time_calc.h"
#include "../block_process/block_process.h"
#include "base58.h"
#include "utils.h"
#include "../logging/logging.h"

namespace
{
    void wrap_gov_txn(zera_txn::TXNWrapper &wrapper, const zera_txn::GovernanceTXN &gov_txn)
    {
        switch (gov_txn.txn_type())
        {
        case zera_txn::TRANSACTION_TYPE::COIN_TYPE:
        {
            zera_txn::CoinTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);
            break;
        }
        case zera_txn::TRANSACTION_TYPE::MINT_TYPE:
        {
            zera_txn::MintTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE:
        {
            zera_txn::ItemizedMintTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE:
        {
            zera_txn::InstrumentContract txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::VOTE_TYPE:
        {
            zera_txn::GovernanceVote txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE:
        {
            zera_txn::GovernanceProposal txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE:
        {
            zera_txn::SmartContractTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE:
        {
            zera_txn::SmartContractExecuteTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE:
        {
            zera_txn::SmartContractInstantiateTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE:
        {
            zera_txn::ExpenseRatioTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::NFT_TYPE:
        {
            zera_txn::NFTTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE:
        {
            zera_txn::ContractUpdateTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::DELEGATED_VOTING_TYPE:
        {
            zera_txn::DelegatedTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::REVOKE_TYPE:
        {
            zera_txn::RevokeTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::FAST_QUORUM_TYPE:
        {
            zera_txn::FastQuorumTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::COMPLIANCE_TYPE:
        {
            zera_txn::ComplianceTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SBT_BURN_TYPE:
        {
            zera_txn::BurnSBTTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::REQUIRED_VERSION:
        {
            zera_txn::RequiredVersion txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);
            break;
        }
        case zera_txn::TRANSACTION_TYPE::QUASH_TYPE:
        {
            zera_txn::QuashTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE:
        {
            zera_txn::AllowanceTXN txn;
            txn.ParseFromString(gov_txn.serialized_txn());
            verify_txns::store_wrapper(&txn, wrapper);

            break;
        }
        case zera_txn::TRANSACTION_TYPE::UKNOWN_TYPE:
        {
            break;
        }
        default:
            break;
        }
    }

    std::map<std::string, std::map<std::string, std::vector<std::string>>> prepareDeleteMap(const std::vector<std::string> &delegatee_keys, const std::map<std::string, zera_validator::Delegatees> &new_delegatee_map)
    {
        std::map<std::string, std::map<std::string, std::vector<std::string>>> delete_map;
        for (auto key : delegatee_keys)
        {
            std::string data;
            zera_validator::Delegatees delegatees;
            zera_validator::Delegatees new_delegatees;
            try
            {
                new_delegatees = new_delegatee_map.at(key);
            }
            catch (const std::out_of_range &e)
            {
                continue;
            }
            db_delegatees::get_single(key, data);
            delegatees.ParseFromString(data);
            for (const auto &kv : delegatees.delegated_wallets())
            {
                const auto &contract_id = kv.first; // contract_id
                const auto &value = kv.second;
                bool removal = true;
                // Check if a key exists in the other map
                if (new_delegatees.delegated_wallets().count(key) > 0)
                {
                    const auto &wallets = new_delegatees.delegated_wallets().at(key);
                    for (auto old_wallet : value.wallet_adr())
                    {
                        for (auto new_wallet : wallets.wallet_adr())
                        {
                            if (old_wallet == new_wallet)
                            {
                                removal = false;
                                break;
                            }
                        }
                        if (removal)
                        {
                            auto &wallet_map = delete_map[old_wallet];
                            auto &contract_vec = wallet_map[contract_id];
                            contract_vec.push_back(key);
                        }
                    }

                    // The key exists in the other map
                }
                else
                {
                    // The key does not exist in the other map
                    // must delete all of these values
                    for (auto old_wallet : value.wallet_adr())
                    {
                        auto &wallet_map = delete_map[old_wallet];
                        auto &contract_vec = wallet_map[contract_id];
                        contract_vec.push_back(key);
                    }
                }

                // Now you can use key and value
            }
        }
        return delete_map;
    }
    void processDeleteMap(const std::map<std::string, std::map<std::string, std::vector<std::string>>> &delete_map, rocksdb::WriteBatch &recipient_batch)
    {
        recipient_batch.Clear();

        for (const auto &del_rec : delete_map)
        {
            std::string wallet_adr = del_rec.first;
            std::string delegate_data;
            zera_validator::DelegatedRecipient delegate_recipient;
            db_delegate_recipient::get_single(wallet_adr, delegate_data);
            delegate_recipient.ParseFromString(delegate_data);

            for (const auto &contract : del_rec.second)
            {
                std::string contract_id = contract.first;

                for (auto public_key : contract.second)
                {
                    if (delegate_recipient.delegations().count(contract_id) > 0)
                    {
                        auto *delegators = delegate_recipient.mutable_delegations()->operator[](contract_id).mutable_delegator();
                        for (int i = 0; i < delegators->size(); ++i)
                        {
                            std::string pub_key = wallets::get_public_key_string(delegators->Get(i).public_key());
                            if (pub_key == public_key)
                            {
                                // Swap with last and remove last
                                delegators->SwapElements(i, delegators->size() - 1);
                                delegators->RemoveLast();
                                break;
                            }
                        }
                    }
                }
            }
            recipient_batch.Put(wallet_adr, delegate_recipient.SerializeAsString());
        }
    }
    void remove_votes(const uint256_t &client_votes, zera_validator::Proposal &proposal, const std::string voting_id, bool support, int old_support_option)
    {
        // if proposal has option voting add amount to option
        if (proposal.options_size() <= 0)
        {
            if (support)
            {
                auto map = proposal.mutable_yes();
                if (map->count(voting_id) > 0)
                {
                    // The key exists in the map
                    std::string value_str = (*map)[voting_id];
                    uint256_t value = boost::lexical_cast<uint256_t>(value_str);

                    if(value < client_votes)
                    {
                        value = 0;
                    }
                    else
                    {
                        value -= client_votes;
                    }

                    (*map)[voting_id] = boost::lexical_cast<std::string>(value);
                }
            }
            else
            {
                auto map = proposal.mutable_no();
                if (map->count(voting_id) > 0)
                {
                    // The key exists in the map
                    std::string value_str = (*map)[voting_id];
                    uint256_t value = boost::lexical_cast<uint256_t>(value_str);

                    if(value < client_votes)
                    {
                        value = 0;
                    }
                    else
                    {
                        value -= client_votes;
                    }

                    (*map)[voting_id] = boost::lexical_cast<std::string>(value);
                }
            }
        }
        else
        {
            auto outer_map = proposal.mutable_options();
            auto inner_map = (*outer_map)[old_support_option].mutable_vote();

            if (inner_map->count(voting_id) > 0)
            {
                // The key exists in the map
                std::string value_str = (*inner_map)[voting_id];
                uint256_t value = boost::lexical_cast<uint256_t>(value_str);

                if(value < client_votes)
                {
                    value = 0;
                }
                else
                {
                    value -= client_votes;
                }

                (*inner_map)[voting_id] = boost::lexical_cast<std::string>(value);
            }
        }
    }
    void something(std::string &wallet_adr, std::string &voting_id, zera_validator::Proposal &proposal, zera_txn::GovernanceVote &client_vote, int &change_state)
    {
        zera_validator::VoteWallet vote_wallet;
        std::string vote_wallet_data;
        std::string client_amount;

        if (!db_proposal_wallets::get_single(wallet_adr, vote_wallet_data) || !vote_wallet.ParseFromString(vote_wallet_data))
        {
            logging::print("Proposal wallet does not exist:", base58_encode(wallet_adr), true);
        }

        bool change_vote = true;
        int old_support_option = 0;
        bool old_support = false;

        if (vote_wallet.proposal_votes().count(base58_encode(client_vote.proposal_id())) > 0)
        {
            if (proposal.options_set())
            {
                old_support_option = vote_wallet.proposal_votes().at(base58_encode(client_vote.proposal_id())).option();
            }

            if(!vote_wallet.proposal_votes().at(base58_encode(client_vote.proposal_id())).has_stage())
            {
                change_vote = false;
            }
            else if(vote_wallet.proposal_votes().at(base58_encode(client_vote.proposal_id())).stage() !=  proposal.stage())
            {
                change_vote = false;
            }
            else
            {
                old_support = vote_wallet.proposal_votes().at(base58_encode(client_vote.proposal_id())).support();
            }
        }
        else
        {
            change_vote = false;
        }


        zera_validator::Voter voter;
        bool has_amount = true;
        if (!db_wallets::get_single(wallet_adr + voting_id, client_amount))
        {
            has_amount = false;
            client_amount = "0";
        }

        uint256_t client_votes(client_amount);

        if(change_state == 0)
        {
            if(change_vote)
            {
                change_state = 1;
            }
            else
            {
                change_state = 2;
            }
        }

        if (change_state == 1 && has_amount)
        {
            remove_votes(client_votes, proposal, voting_id, old_support, old_support_option);
        }

        // if proposal has option voting add amount to option
        if (!proposal.options_set())
        {
            if (client_vote.support())
            {
                voter.set_support(true);
                auto map = proposal.mutable_yes();
                if (map->count(voting_id) > 0)
                {
                    // The key exists in the map
                    std::string value_str = (*map)[voting_id];
                    uint256_t value = boost::lexical_cast<uint256_t>(value_str);
                    value += client_votes;
                    (*map)[voting_id] = boost::lexical_cast<std::string>(value);
                }
                else
                {
                    // The key does not exist in the map
                    (*map)[voting_id] = boost::lexical_cast<std::string>(client_votes);
                }
            }
            else
            {
                voter.set_support(false);
                auto map = proposal.mutable_no();
                if (map->count(voting_id) > 0)
                {
                    // The key exists in the map
                    std::string value_str = (*map)[voting_id];
                    uint256_t value = boost::lexical_cast<uint256_t>(value_str);
                    value += client_votes;
                    (*map)[voting_id] = boost::lexical_cast<std::string>(value);
                }
                else
                {
                    // The key does not exist in the map
                    (*map)[voting_id] = boost::lexical_cast<std::string>(client_votes);
                }
            }
        }
        else
        {
            voter.set_option(client_vote.support_option());
            auto outer_map = proposal.mutable_options();
            auto inner_map = (*outer_map)[client_vote.support_option()].mutable_vote();

            if (inner_map->count(voting_id) > 0)
            {
                // The key exists in the map
                std::string value_str = (*inner_map)[voting_id];
                uint256_t value = boost::lexical_cast<uint256_t>(value_str);
                value += client_votes;
                (*inner_map)[voting_id] = boost::lexical_cast<std::string>(value);
            }
            else
            {
                // The key does not exist in the map
                (*inner_map)[voting_id] = boost::lexical_cast<std::string>(client_votes);
            }
        }

        voter.set_stage(proposal.stage());
        (*vote_wallet.mutable_proposal_votes())[base58_encode(client_vote.proposal_id())] = voter;

        db_proposal_wallets::store_single(wallet_adr, vote_wallet.SerializeAsString());
        db_proposals::store_single(client_vote.proposal_id(), proposal.SerializeAsString());
    }

    void store_voted_priority(const std::string &wallet_address, const std::string &recipient_wallet, const std::string &proposal_id, const std::string &contract_id)
    {
        std::string delegated_data;
        db_delegate_recipient::get_single(recipient_wallet, delegated_data);
        zera_validator::DelegatedRecipient delegate_recipient;
        delegate_recipient.ParseFromString(delegated_data);

        auto *delegators_ptr = delegate_recipient.mutable_delegations()->operator[](contract_id).mutable_delegator();
        if (delegators_ptr)
        {
            for (zera_validator::Delegator &delegator : *delegators_ptr)
            {
                std::string addr;

                addr = wallets::generate_wallet(delegator.public_key());

                if (addr == wallet_address)
                {
                    zera_validator::Delegated delegated;
                    std::string delegated_data;
                    db_voted_proposals::get_single(wallet_address, delegated_data);
                    delegated.ParseFromString(delegated_data);
                    (*delegated.mutable_proposals())[proposal_id] = delegator.priority();
                    // get value, add map of priority
                    db_voted_proposals::store_single(wallet_address, delegated.SerializeAsString());
                    break;
                }
            }
        }
    }
    void store_own_priority(const std::string &wallet_adress, const std::string &contract_id, const std::string &proposal_id)
    {
        zera_validator::Delegated delegated;
        std::string delegated_data;
        db_voted_proposals::get_single(wallet_adress, delegated_data);
        delegated.ParseFromString(delegated_data);
        (*delegated.mutable_proposals())[proposal_id] = 0;
        // get value, add map of priority
        db_voted_proposals::store_single(wallet_adress, delegated.SerializeAsString());
    }
}
void txn_batch::batch_votes(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch delegate_batch;
    for (auto client_vote : txns.governance_votes())
    {
        if (txn_passed.at(client_vote.base().hash()))
        {
            zera_validator::Proposal proposal;
            std::string votes_data;
            zera_txn::InstrumentContract proposal_contract;
            std::string contract_data;
            std::string client_vote_adr = wallets::generate_wallet(client_vote.base().public_key());
            std::string proposal_id = base58_encode(client_vote.proposal_id());

            store_own_priority(client_vote_adr, proposal.contract_id(), proposal_id);
    
            // get proposal from db and parse into Proposal opject
            if (db_proposals::get_single(client_vote.proposal_id(), votes_data) && proposal.ParseFromString(votes_data))
            {

                // get proposal contract from db and parse into InstrumentContract object
                db_contracts::get_single(proposal.contract_id(), contract_data);
                proposal_contract.ParseFromString(contract_data);

                std::string delegated_data;
                zera_validator::DelegateWallets delegate_wallets;

                if (!db_delegate_wallets::get_single(client_vote.base().hash(), delegated_data) || !delegate_wallets.ParseFromString(delegated_data))
                {
                    logging::print("No delegate wallet found for vote");
                    continue;
                }
                int change_state = 0;

                for (auto wallet_adr : delegate_wallets.wallets())
                {
                    store_voted_priority(wallet_adr, client_vote_adr, proposal_id, proposal.contract_id());
                    for (auto voting_id : proposal_contract.governance().voting_instrument())
                    {
                        something(wallet_adr, voting_id, proposal, client_vote, change_state);
                    }
                }

                for (auto voting_id : proposal_contract.governance().voting_instrument())
                {
                    something(client_vote_adr, voting_id, proposal, client_vote, change_state);
                }
            }

            delegate_batch.Delete(client_vote.base().hash());
        }
    }

    db_delegate_wallets::store_batch(delegate_batch);
}

void txn_batch::batch_proposal_results(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch proposal_batch;
    rocksdb::WriteBatch adaptive_ledger_batch;

    std::vector<std::string> contract_ids;
    std::vector<zera_txn::ProposalResult> staged_results;

    for (auto result : txns.proposal_result_txns())
    {
        if (txn_passed.at(result.base().hash()))
        {
            std::string proposal_data;
            zera_validator::Proposal proposal;
            db_proposals::get_single(result.proposal_id(), proposal_data);
            proposal.ParseFromString(proposal_data);
            zera_txn::InstrumentContract contract;
            block_process::get_contract(result.contract_id(), contract);

            logging::print("final stage:", std::to_string(result.final_stage()), "fast quorum:", std::to_string(result.fast_quorum()));

            if (result.final_stage())
            {
                logging::print("batch_proposal_results final stage contract id:", result.contract_id());
                proposal_batch.Delete(result.proposal_id());

                db_process_adaptive_ledger::remove_single(result.proposal_id());

                if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::CYCLE || contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED)
                {
                    std::string proposal_ledger_data;
                    zera_validator::ProposalLedger proposal_ledger;
                    db_proposal_ledger::get_single(result.contract_id(), proposal_ledger_data);
                    proposal_ledger.ParseFromString(proposal_ledger_data);

                    int index_to_remove = -1;
                    for (int i = 0; i < proposal_ledger.proposal_ids_size(); ++i)
                    {
                        if (proposal_ledger.proposal_ids(i) == result.proposal_id())
                        {
                            index_to_remove = i;
                            break;
                        }
                    }
                    if (index_to_remove != -1)
                    {
                        // Swap with last and remove last
                        proposal_ledger.mutable_proposal_ids()->SwapElements(index_to_remove, proposal_ledger.proposal_ids_size() - 1);
                        proposal_ledger.mutable_proposal_ids()->RemoveLast();
                    }

                    logging::print("batch results end_timestamp:", std::to_string(proposal_ledger.stage_end_date().seconds()));
                    logging::print("batch results start_timestamp:", std::to_string(proposal_ledger.stage_start_date().seconds()));
                    db_proposal_ledger::store_single(result.contract_id(), proposal_ledger.SerializeAsString());
                }
            }
            else if (!result.fast_quorum())
            {
                if (!result.proposal_cut() && result.passed())
                {

                    int stage = proposal.stage();
                    stage += 1;
                    proposal.set_stage(stage);
                    if (proposal.options_size() > 0)
                    {

                        auto &options = *proposal.mutable_options();

                        for (auto &option : options)
                        {
                            option.second.Clear();
                        }
                    }
                    else
                    {
                        proposal.mutable_yes()->clear();
                        proposal.mutable_no()->clear();
                    }
                    proposal_batch.Put(result.proposal_id(), proposal.SerializeAsString());
                }
                else
                {
                    std::string proposal_ledger_data;
                    zera_validator::ProposalLedger proposal_ledger;
                    db_proposal_ledger::get_single(result.contract_id(), proposal_ledger_data);
                    proposal_ledger.ParseFromString(proposal_ledger_data);

                    int index_to_remove = -1;
                    for (int i = 0; i < proposal_ledger.proposal_ids_size(); ++i)
                    {
                        if (proposal_ledger.proposal_ids(i) == result.proposal_id())
                        {
                            index_to_remove = i;
                            break;
                        }
                    }
                    if (index_to_remove != -1)
                    {
                        // Swap with last and remove last
                        proposal_ledger.mutable_proposal_ids()->SwapElements(index_to_remove, proposal_ledger.proposal_ids_size() - 1);
                        proposal_ledger.mutable_proposal_ids()->RemoveLast();
                    }

                    db_proposal_ledger::store_single(result.contract_id(), proposal_ledger.SerializeAsString());

                    proposal_batch.Delete(result.proposal_id());
                }
            }

            logging::print("final stage:", std::to_string(result.final_stage()), "fast quorum:", std::to_string(result.fast_quorum()));
            logging::print("passed:", std::to_string(result.passed()), "governance txn size:", std::to_string(proposal.governance_txn_size()));

            if (result.final_stage() && result.passed() && proposal.governance_txn_size() > 0 && !result.proposal_cut())
            {
                // store txn in gov_txns so validators can confirm this txn came from governance
                int x = 0;
                for (auto gov_txn : proposal.governance_txn())
                {
                    zera_txn::TXNWrapper wrapper;
                    wrap_gov_txn(wrapper, gov_txn);
                    std::string txn_id = get_txn_key(x, result.proposal_id());
                    db_gov_txn::store_single(gov_txn.txn_hash(), wrapper.SerializeAsString());
                    x++;
                }
            }
        }

        db_proposals::store_batch(proposal_batch);
    }
}

void txn_batch::batch_delegated_voting(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch delegatee_batch;
    rocksdb::WriteBatch recipient_batch;

    zera_validator::Delegatees original_delegatees;
    std::vector<std::string> delegatee_keys;
    std::map<std::string, zera_validator::Delegatees> new_delegatee_map;

    for (auto txn : txns.delegated_voting_txns())
    {
        if (!txn_passed.at(txn.base().hash()))
        {
            continue;
        }
        std::string pub_key = wallets::get_public_key_string(txn.base().public_key());
        delegatee_keys.push_back(pub_key);

        zera_validator::DelegatedFees del_fees;
        int x = 1;
        for (auto auth_fee : txn.delegate_fees())
        {
            del_fees.add_contract_ids(auth_fee.contract_id());
        }
        std::string wallet_adr = wallets::generate_wallet(txn.base().public_key());
        // store new DelegatedVote and overwrite old one if existed
        db_delegate_vote::store_single(wallet_adr, del_fees.SerializeAsString());

        // create new Delegatees for each client
        // This will overwrite old data if existed
        zera_validator::Delegatees delegatees;

        for (auto delegate : txn.delegate_votes())
        {
            // get old delegate recipient data
            zera_validator::DelegatedRecipient delegate_recipient;
            std::string delegate_data;
            db_delegate_recipient::get_single(delegate.address(), delegate_data);
            delegate_recipient.ParseFromString(delegate_data);

            for (auto contract : delegate.contracts())
            {
                zera_validator::DelegateeWallets &delegatee_wallets = delegatees.mutable_delegated_wallets()->operator[](contract.contract_id());
                delegatee_wallets.add_wallet_adr(delegate.address());
                zera_validator::Delegators &delegators = delegate_recipient.mutable_delegations()->operator[](contract.contract_id());

                bool found = false;
                auto *delegators_ptr = delegate_recipient.mutable_delegations()->operator[](contract.contract_id()).mutable_delegator();
                if (delegators_ptr)
                {
                    for (zera_validator::Delegator &delegator : *delegators_ptr)
                    {
                        std::string delegator_pub = wallets::get_public_key_string(delegator.public_key());
                        std::string base_pub = wallets::get_public_key_string(txn.base().public_key());
                        if (delegator_pub == base_pub)
                        {
                            found = true;
                            delegator.set_priority(contract.priority());
                            break;
                        }
                    }
                }
                if (!found)
                {
                    zera_validator::Delegator *delegator = delegators.add_delegator();
                    delegator->mutable_public_key()->CopyFrom(txn.base().public_key());
                    delegator->set_priority(contract.priority());
                    continue;
                }
            }
            db_delegate_recipient::store_single(delegate.address(), delegate_recipient.SerializeAsString());
        }
        std::string base_pub = wallets::get_public_key_string(txn.base().public_key());
        new_delegatee_map.insert({{base_pub, delegatees}});
        delegatee_batch.Put(base_pub, delegatees.SerializeAsString());
    }

    db_delegate_recipient::store_batch(recipient_batch);
    db_delegate_wallets::store_batch(delegatee_batch);

    std::map<std::string, std::map<std::string, std::vector<std::string>>> delete_map = prepareDeleteMap(delegatee_keys, new_delegatee_map);
    processDeleteMap(delete_map, recipient_batch);
    db_delegate_recipient::store_batch(recipient_batch);
}