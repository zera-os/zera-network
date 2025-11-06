#include "txn_batch.h"

#include "db_base.h"
#include "../temp_data/temp_data.h"
#include "wallet.pb.h"
#include "wallets.h"
#include "../governance/time_calc.h"
#include "google/protobuf/timestamp.pb.h"
#include "../logging/logging.h"

namespace
{
    // this looks good for cycle but may need an update for staged
    void make_staged_cycle_ledger(const zera_txn::InstrumentContract &contract)
    {

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

        google::protobuf::Timestamp end_ts = time_calc::get_end_date_cycle(contract.governance().start_timestamp(), days, months);
        zera_validator::ProposalLedger proposal_ledger;
        proposal_ledger.set_stage(0);
        proposal_ledger.mutable_cycle_end_date()->set_seconds(end_ts.seconds());
        proposal_ledger.mutable_cycle_start_date()->set_seconds(contract.governance().start_timestamp().seconds());
        proposal_ledger.set_break_(false);

        if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED && contract.governance().stage_length_size() > 0)
        {
            days = 0;
            months = 0;

            if (contract.governance().stage_length().at(0).period() == zera_txn::PROPOSAL_PERIOD::DAYS)
            {
                days = contract.governance().stage_length().at(0).length();
            }
            else
            {
                months = contract.governance().stage_length().at(0).length();
            }

            google::protobuf::Timestamp stage_ts = time_calc::get_end_date_cycle(contract.governance().start_timestamp(), days, months);

            proposal_ledger.mutable_stage_start_date()->set_seconds(contract.governance().start_timestamp().seconds());
            proposal_ledger.mutable_stage_end_date()->set_seconds(stage_ts.seconds());

            if (contract.governance().stage_length().at(0).break_())
            {
                proposal_ledger.set_break_(true);
            }
        }

        db_proposal_ledger::store_single(contract.contract_id(), proposal_ledger.SerializeAsString());
    }

}
void txn_batch::batch_contracts(const zera_txn::TXNS &txns, const std::map<std::string, bool> txn_passed)
{
    rocksdb::WriteBatch max_batch;
    rocksdb::WriteBatch contract_batch;

    for (auto contract : txns.contract_txns())
    {
        if (txn_passed.at(contract.base().hash()))
        {
            if (contract.has_max_supply())
            {
                zera_wallets::MaxSupply max;
                if (contract.max_supply_release_size() <= 0)
                {
                    max.set_max_supply(contract.max_supply());
                }
                else
                {
                    std::string header_str;
                    std::string header_key;
                    zera_validator::BlockHeader header;
                    std::string key;
                    zera_validator::BlockHeader new_header;
                    db_headers_tag::get_last_data(new_header, key);
                    db_hash_index::get_single(new_header.previous_block_hash(), header_key);
                    db_headers::get_single(header_key, header_str);
                    header.ParseFromString(header_str);

                    int remove = 0;
                    uint256_t initial_release = 0;
                    for (auto release : contract.max_supply_release())
                    {
                        uint256_t release_amount(release.amount());

                        if (release.release_date().seconds() <= header.timestamp().seconds())
                        {
                            initial_release += release_amount;
                            remove++;
                        }
                        else
                        {
                            break;
                        }
                    }

                    max.set_max_supply(initial_release.str());
                    max.mutable_release()->CopyFrom(contract.max_supply_release());

                    for (int x = 0; x < remove; x++)
                    {
                        max.mutable_release()->DeleteSubrange(0, 1);
                    }
                }
                uint256_t total_premint = 0;
                for (auto premint_amount : contract.premint_wallets())
                {
                    total_premint += boost::lexical_cast<uint256_t>(premint_amount.amount());
                }

                max.set_circulation(boost::lexical_cast<std::string>(total_premint));
                max_batch.Put(contract.contract_id(), max.SerializeAsString());
            }
            if (contract.has_governance())
            {
                if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED || contract.governance().type() == zera_txn::GOVERNANCE_TYPE::CYCLE)
                {
                    make_staged_cycle_ledger(contract);
                }
            }
            
            contract_batch.Put(contract.contract_id(), contract.SerializeAsString());
        }
    }
    db_contract_supply::store_batch(max_batch);
    db_contracts::store_batch(contract_batch);
}
void txn_batch::batch_contract_updates(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch contract_batch;
    for (auto update : txns.contract_update_txns())
    {
        if (txn_passed.at(update.base().hash()))
        {
            std::string contract_data;
            zera_txn::InstrumentContract contract;
            if (db_contracts::get_single(update.contract_id(), contract_data) && contract.ParseFromString(contract_data))
            {
                contract.set_contract_version(update.contract_version());

                if (update.has_name())
                {
                    contract.set_name(update.name());
                }
                if (update.restricted_keys_size() > 0)
                {
                    contract.clear_restricted_keys();
                    for (auto key : update.restricted_keys())
                    {
                        zera_txn::RestrictedKey *r_key = contract.add_restricted_keys();
                        r_key->CopyFrom(key);
                    }
                }
                if (update.expense_ratio_size() > 0)
                {
                    contract.clear_expense_ratio();
                    for (auto ratio : update.expense_ratio())
                    {
                        zera_txn::ExpenseRatio *er = contract.add_expense_ratio();
                        er->CopyFrom(ratio);
                    }
                }
                if (update.has_contract_fees())
                {
                    zera_txn::ContractFees *fees = contract.mutable_contract_fees();
                    fees->Clear();
                    if (fees->fee() != "0")
                    {
                        fees->CopyFrom(update.contract_fees());
                    }
                }
                if (update.custom_parameters_size() > 0)
                {
                    contract.clear_custom_parameters();
                    for (auto param : update.custom_parameters())
                    {
                        zera_txn::KeyValuePair *kvp = contract.add_custom_parameters();
                        kvp->CopyFrom(param);
                    }
                }
                if (update.has_kyc_status())
                {
                    if (!update.kyc_status())
                    {
                        contract.clear_token_compliance();
                    }
                    contract.set_kyc_status(update.kyc_status());
                }
                if (update.has_immutable_kyc_status())
                {
                    contract.set_immutable_kyc_status(update.immutable_kyc_status());
                }
                if (update.token_compliance_size() > 0)
                {
                    contract.clear_token_compliance();
                    contract.mutable_token_compliance()->CopyFrom(update.token_compliance());
                }
                if (update.has_quash_threshold())
                {
                    contract.clear_quash_threshold();

                    if (update.quash_threshold() > 0)
                    {
                        contract.set_quash_threshold(update.quash_threshold());
                    }
                }
                if (update.has_governance())
                {
                    zera_txn::Governance *gov = contract.mutable_governance();
                    gov->Clear();

                    if (gov->type() != zera_txn::GOVERNANCE_TYPE::REMOVE)
                    {
                        gov->CopyFrom(update.governance());

                        // remove all current proposals
                        zera_validator::ProposalLedger proposal_ledger;
                        rocksdb::WriteBatch remove_batch;

                        // remove all proposals from proposal db
                        std::string ledger_data;
                        db_proposal_ledger::get_single(update.contract_id(), ledger_data);
                        proposal_ledger.ParseFromString(ledger_data);
                        for (auto ids : proposal_ledger.proposal_ids())
                        {
                            remove_batch.Delete(ids);
                        }
                        for (auto ids : proposal_ledger.pending_proposal_ids())
                        {
                            remove_batch.Delete(ids);
                        }

                        db_proposals::store_batch(remove_batch);

                        if (update.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED || update.governance().type() == zera_txn::GOVERNANCE_TYPE::CYCLE)
                        {

                            make_staged_cycle_ledger(contract);
                        }
                    }
                }
                logging::print("batching update contract id:", contract.contract_id());

                contract_batch.Put(contract.contract_id(), contract.SerializeAsString());
            }
        }
    }

    db_contracts::store_batch(contract_batch);
}
