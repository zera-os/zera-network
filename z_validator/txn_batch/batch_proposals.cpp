#include <regex>
#include "txn_batch.h"

#include "db_base.h"
#include "../temp_data/temp_data.h"
#include "wallet.pb.h"
#include "wallets.h"
#include "../governance/time_calc.h"
#include "../block_process/block_process.h"
#include "base58.h"
#include <google/protobuf/util/time_util.h>
#include "../logging/logging.h"

namespace
{
    void setup(zera_validator::Proposal &stored_proposal, zera_txn::GovernanceProposal &proposal)
    {
        if (proposal.options_size() > 0)
        {
            stored_proposal.set_options_set(true);
            int x = 0;
            while (x < proposal.options_size())
            {
                zera_validator::Vote vote;
                stored_proposal.mutable_options()->operator[](x) = vote;
                x++;
            }
        }
        else
        {
            stored_proposal.set_options_set(false);
        }

        std::string wallet_data;
        std::string proposal_wallet = "p_" + proposal.base().hash();
        std::string fee_id = proposal.base().fee_id();

        if (!db_wallets::get_single(proposal_wallet + fee_id, wallet_data))
        {
            logging::print("batch proposals cant find wallet");
        }
        uint256_t wallet_amount(wallet_data);
        zera_txn::InstrumentContract contract;
        std::string contract_data;
        db_contracts::get_single(proposal.contract_id(), contract_data);
        contract.ParseFromString(contract_data);

        stored_proposal.set_contract_id(proposal.contract_id());
        stored_proposal.set_fee_id(fee_id);
        stored_proposal.set_wallet(proposal_wallet);


        if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED)
        {
            wallet_amount /= contract.governance().stage_length_size();
        }

        stored_proposal.set_fee(boost::lexical_cast<std::string>(wallet_amount));
        stored_proposal.set_stage(0);
        stored_proposal.set_number_of_options(proposal.options_size());
        stored_proposal.mutable_public_key()->CopyFrom(proposal.base().public_key());

    }

    void staggered(zera_txn::GovernanceProposal &proposal, zera_validator::Proposal &stored_proposal, zera_txn::InstrumentContract &contract, const uint64_t &block_time)
    {
        google::protobuf::Timestamp *end_ts = stored_proposal.mutable_end_date();
        google::protobuf::Timestamp *ts = stored_proposal.mutable_start_date();
        
        if(proposal.start_timestamp().seconds() < block_time)
        {
            ts->set_seconds(block_time);
        }
        else
        {
            ts->set_seconds(proposal.start_timestamp().seconds());
        }

        uint32_t days = 0;
        uint32_t months = 0;
        if (contract.governance().proposal_period() == zera_txn::PROPOSAL_PERIOD::DAYS)
        {
            days = contract.governance().voting_period();
        }
        else
        {
            months = contract.governance().voting_period();
        }

        std::tm pd = time_calc::process_date_staggered(*ts, days, months);

        std::time_t time = std::mktime(&pd);

        // Set the seconds and nanoseconds fields of the Timestamp
        end_ts->set_seconds(time);

        db_process_adaptive_ledger::store_single(proposal.base().hash(), end_ts->SerializeAsString());

    }

}

void txn_batch::batch_proposals(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const uint64_t &block_time)
{
    rocksdb::WriteBatch proposal_batch;

    for (auto proposal : txns.governance_proposals())
    {
        if (txn_passed.at(proposal.base().hash()))
        {
            // add proposal to proposal_db (proposal_batch / used for voting)
            zera_validator::Proposal stored_proposal;

            // do setup that all proposals require
            setup(stored_proposal, proposal);

            zera_txn::InstrumentContract contract;
            std::string contract_data_1;
            db_contracts::get_single(proposal.contract_id(), contract_data_1);
            contract.ParseFromString(contract_data_1);

            logging::print("Proposal type:", zera_txn::GOVERNANCE_TYPE_Name(contract.governance().type()));
            logging::print("Contract ID:", proposal.contract_id());

            // add proposal to process ledger if adaptive | staggered (this is becuase cycle and staged use contracts to process, which are already present in ledger)
            if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::ADAPTIVE)
            {
                google::protobuf::Timestamp *end_ts = stored_proposal.mutable_end_date();
                end_ts->set_nanos(0);
                end_ts->set_seconds(proposal.end_timestamp().seconds());

                db_process_adaptive_ledger::store_single(proposal.base().hash(), proposal.end_timestamp().SerializeAsString());
            }
            else if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGGERED)
            {
                staggered(proposal, stored_proposal, contract, block_time);
            }
            else if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED || contract.governance().type() == zera_txn::GOVERNANCE_TYPE::CYCLE)
            {
                zera_validator::ProposalLedger proposal_ledger;
                std::string proposal_data;
                db_proposal_ledger::get_single(proposal.contract_id(), proposal_data);
                proposal_ledger.ParseFromString(proposal_data);
                proposal_ledger.add_pending_proposal_ids(proposal.base().hash());
                db_proposal_ledger::store_single(proposal.contract_id(), proposal_ledger.SerializeAsString());
            }
            
            logging::print("proposal governance txn size:", std::to_string(proposal.governance_txn_size()));

            if (proposal.governance_txn_size() > 0)
            {
                for (auto txn : proposal.governance_txn())
                {
                    auto gov_txn = stored_proposal.add_governance_txn();
                    gov_txn->CopyFrom(txn);
                }
            }

            if (proposal.governance_option_txns_size() > 0)
            {
                for (auto option_txn : proposal.governance_option_txns())
                {
                    auto gov_option_txn = stored_proposal.add_governance_option_txns();
                    gov_option_txn->CopyFrom(option_txn);
                }
            }

            logging::print("proposal_hash:", base58_encode(proposal.base().hash()));
            proposal_batch.Put(proposal.base().hash(), stored_proposal.SerializeAsString());
        }
    }
    db_proposals::store_batch(proposal_batch);
}

void txn_batch::batch_proposal_cancel(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch proposal_cancel_batch;
    rocksdb::WriteBatch staked_coins_voted_batch;
    rocksdb::WriteBatch process_adaptive_ledger_batch;
    for (auto proposal_cancel : txns.proposal_cancel_txns())
    {
        if (txn_passed.at(proposal_cancel.base().hash()))
        {
            proposal_cancel_batch.Delete(proposal_cancel.proposal_id());
            process_adaptive_ledger_batch.Delete(proposal_cancel.proposal_id());

            zera_txn::InstrumentContract contract;
            block_process::get_contract(proposal_cancel.contract_id(), contract);
            if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::CYCLE || contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED)
            {
                std::string proposal_ledger_data;
                zera_validator::ProposalLedger proposal_ledger;
                if(db_proposal_ledger::get_single(proposal_cancel.contract_id(), proposal_ledger_data) && proposal_ledger.ParseFromString(proposal_ledger_data))
                {
                    int index_to_remove = -1;
                    for (int i = 0; i < proposal_ledger.proposal_ids_size(); ++i)
                    {
                        if (proposal_ledger.proposal_ids(i) == proposal_cancel.proposal_id())
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

                    db_proposal_ledger::store_single(proposal_cancel.contract_id(), proposal_ledger.SerializeAsString());
                }

                std::vector<std::string> keys;
                std::vector<std::string> values;
                if(db_staked_coins_voted::find_by_prefix(proposal_cancel.proposal_id(), keys, values))
                {
                    int x = 0;
                    while (x < keys.size())
                    {
                        std::string key = keys[x];
                        staked_coins_voted_batch.Delete(key);
                        x++;
                    }
                }
            } 
        }
    }
 
    db_process_adaptive_ledger::store_batch(process_adaptive_ledger_batch);
    db_staked_coins_voted::store_batch(staked_coins_voted_batch);
    db_proposals::store_batch(proposal_cancel_batch);
}
