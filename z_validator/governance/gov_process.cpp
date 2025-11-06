#include <google/protobuf/util/time_util.h>
#include <algorithm>
#include <utility>
#include <regex>

#include "gov_process.h"
#include "db_base.h"
#include "time_calc.h"
#include "wallet.pb.h"
#include "../block_process/block_process.h"
#include "signatures.h"
#include "hashing.h"
#include "validators.h"
#include "../temp_data/temp_data.h"
#include "../logging/logging.h"
#include "hex_conversion.h"
#include "base58.h"
#include "fees.h"
#include "utils.h"

const uint256_t quintillion = 1000000000000000000;

namespace
{
    // Custom comparator for sorting by uint256_t in descending order
    bool compare_by_uint256_t_desc(const std::pair<std::string, uint256_t> &a, const std::pair<std::string, uint256_t> &b)
    {
        return a.second > b.second; // Change to a.second < b.second for ascending order
    }

    uint256_t calculate_votes(std::string &contract_id, const std::string &amount)
    {
        zera_txn::InstrumentContract contract;
        block_process::get_contract(contract_id, contract);
        uint256_t cur_equiv;
        uint256_t denomination(contract.coin_denomination().amount());
        if(!zera_fees::get_cur_equiv(contract.contract_id(), cur_equiv))
        {
            cur_equiv = 1;
        }
        uint256_t votes_amount(amount);
        votes_amount *= cur_equiv; // cur_equiv multiplier 1 quintillion
        votes_amount /= denomination;

        return votes_amount;
    }

    void sort_store_options(const zera_validator::Proposal &proposal, zera_txn::ProposalResult *result)
    {
        uint256_t cur_equiv;

        std::vector<std::pair<int, zera_validator::Vote>> sort;

        for (const auto &vote : proposal.options())
        {
            sort.push_back(std::make_pair(vote.first, vote.second));
        }

        auto compare = [](const auto &a, const auto &b)
        {
            return a.first < b.first;
        };

        std::sort(sort.begin(), sort.end(), compare);

        int x = 0;
        if (proposal.number_of_options() > 0)
        {
            while (x < proposal.number_of_options())
            {
                zera_txn::Votes *vote = result->add_option_votes();
                x++;
            }
        }

        for (const auto &option : sort)
        {
            uint256_t votes_amount = 0;
            zera_txn::Votes *vote = result->mutable_option_votes(option.first);
            for (const auto &voting_currency : option.second.vote())
            {
                zera_txn::VotePair *vote_pair = vote->add_votes();
                std::string key = voting_currency.first;
                std::string value = voting_currency.second;

                vote_pair->set_amount(value);
                vote_pair->set_contract_id(key);
                votes_amount += calculate_votes(key, value);
            }

            result->add_option_cur_equiv(boost::lexical_cast<std::string>(votes_amount));
        }
    }
    bool calculate_passed(std::string yes_votes, std::string no_votes, const zera_txn::InstrumentContract &contract, bool fast_quorum = false)
    {
        std::string max_data;
        zera_wallets::MaxSupply max_supply;
        zera_txn::InstrumentContract voting_contract;
        uint256_t circ_supply = 0;

        bool got_max = false;
        if (contract.governance().voting_instrument_size() >= 1)
        {
            for (auto contract_id : contract.governance().voting_instrument())
            {
                std::string contract_data;

                if (!db_contracts::get_single(contract_id, contract_data) || !voting_contract.ParseFromString(contract_data))
                {
                    continue;
                }

                circ_supply = get_circulating_supply(contract_id);

                if(circ_supply == 0)
                {
                    continue;
                }

                got_max = true;
                break;
            }
        }
        else
        {
            circ_supply = get_circulating_supply(contract.contract_id());

            if(circ_supply == 0)
            {
                return false;
            }

            got_max = true;

            voting_contract.CopyFrom(contract);
        }

        if (!got_max)
        {
            return false;
        }

        uint256_t yes(yes_votes);
        uint256_t no(no_votes);


        uint256_t denomination(voting_contract.coin_denomination().amount());
        uint256_t cur_equiv;
        if(!zera_fees::get_cur_equiv(voting_contract.contract_id(), cur_equiv))
        {
            cur_equiv = 1;
        }

        circ_supply *= cur_equiv;
        circ_supply /= denomination;
        uint256_t total_votes = (yes + no);
        uint256_t thresh_percent = (total_votes * 10000) / circ_supply;

        if (thresh_percent < contract.governance().threshold())
        {
            return false;
        }

        uint256_t yes_percent = 0;

        if (total_votes > 0)
        {
            yes_percent = (yes * 10000) / total_votes;
        }

        if (fast_quorum)
        {
            if (yes_percent < contract.governance().fast_quorum())
            {
                return false;
            }
        }
        else
        {
            if (yes_percent < contract.governance().regular_quorum())
            {
                return false;
            }
        }

        return true;
    }

    void calc_support_against(zera_validator::Proposal &proposal, const zera_txn::InstrumentContract &contract, zera_txn::ProposalResult *result, bool fast_quorum = false)
    {
        int256_t yes_amount = 0;
        uint256_t no_amount = 0;

        for (auto yes_votes : proposal.yes())
        {
            zera_txn::VotePair *vote = result->mutable_support_votes()->add_votes();
            vote->set_amount(yes_votes.second);
            vote->set_contract_id(yes_votes.first);
            std::string key = yes_votes.first;
            std::string value = yes_votes.second;
            yes_amount += calculate_votes(key, value);
        }
        for (auto no_votes : proposal.no())
        {
            zera_txn::VotePair *vote = result->mutable_against_votes()->add_votes();
            vote->set_amount(no_votes.second);
            vote->set_contract_id(no_votes.first);
            std::string key = no_votes.first;
            std::string value = no_votes.second;
            no_amount += calculate_votes(key, value);
        }

        result->set_support_cur_equiv(boost::lexical_cast<std::string>(yes_amount));
        result->set_against_cur_equiv(boost::lexical_cast<std::string>(no_amount));
        result->set_passed(calculate_passed(result->support_cur_equiv(), result->against_cur_equiv(), contract, fast_quorum));

        // TODO - remove HACK
        if(ValidatorConfig::get_hack())
        {
            result->set_passed(true);
        }
    }

    bool calculate_passed_options(const zera_txn::ProposalResult *result, const zera_txn::InstrumentContract &contract, bool fast_quorum = false)
    {
        uint256_t highest_vote = 0;
        uint256_t total_votes = 0;
        for (auto option : result->option_cur_equiv())
        {
            uint256_t check_vote(option);
            if (check_vote > highest_vote)
            {
                highest_vote = check_vote;
            }
            total_votes += check_vote;
        }

        std::string max_data;
        zera_wallets::MaxSupply max_supply;
        zera_txn::InstrumentContract voting_contract;
        uint256_t circ_supply = 0;

        bool got_max = false;
        if (contract.governance().voting_instrument_size() >= 1)
        {
            for (auto contract_id : contract.governance().voting_instrument())
            {
                std::string contract_data;

                if (!db_contracts::get_single(contract_id, contract_data) || !voting_contract.ParseFromString(contract_data))
                {
                    continue;
                }

                circ_supply = get_circulating_supply(contract_id);

                if(circ_supply == 0)
                {
                    continue;
                }
                got_max = true;
                break;
            }
        }
        else
        {
            circ_supply = get_circulating_supply(contract.contract_id());

            if(circ_supply == 0)
            {
                return false;
            }

            got_max = true;
            voting_contract.CopyFrom(contract);
        }

        if (!got_max)
        {
            return false;
        }


        uint256_t denomination(voting_contract.coin_denomination().amount());
        uint256_t cur_equiv;
        if(!zera_fees::get_cur_equiv(voting_contract.contract_id(), cur_equiv))
        {
            cur_equiv = 1;
        }

        circ_supply *= cur_equiv;
        circ_supply /= denomination;
        uint256_t thresh_percent = (total_votes * 10000) / circ_supply;

        if (thresh_percent < contract.governance().threshold())
        {
            return false;
        }

        uint256_t option_percent = (highest_vote * 10000) / total_votes;

        if (fast_quorum)
        {
            if (option_percent < contract.governance().fast_quorum())
            {
                return false;
            }
        }
        else
        {
            if (option_percent < contract.governance().regular_quorum())
            {
                return false;
            }
        }

        return true;
    }
    void calc(zera_validator::Proposal &proposal, const zera_txn::InstrumentContract &contract, zera_txn::ProposalResult *result, bool fast_quorum = false)
    {
        if (proposal.options_set())
        {
            sort_store_options(proposal, result);
            result->set_passed(calculate_passed_options(result, contract, fast_quorum));
        }
        else
        {
            calc_support_against(proposal, contract, result, fast_quorum);
        }
    }
    void sign_hash_result(zera_txn::ProposalResult *result)
    {
        google::protobuf::Timestamp *ts = result->mutable_base()->mutable_timestamp();
        zera_validator::BlockHeader new_header;
        std::string new_key;
        db_headers_tag::get_last_data(new_header, new_key);
        google::protobuf::Timestamp now_ts = new_header.timestamp();

        ts->set_seconds(now_ts.seconds());
        ts->set_nanos(now_ts.nanos());

        result->mutable_base()->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
        signatures::sign_txns(result, ValidatorConfig::get_gen_key_pair());
        auto hash_vec = Hashing::sha256_hash(result->SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        result->mutable_base()->set_hash(hash);
    }

    ZeraStatus proposal_wallet(const zera_validator::Proposal &proposal, bool final_stage, zera_txn::TXNStatusFees *status_fee, zera_txn::ProposalResult *result, const std::string &fee_address)
    {
        std::string wallet_amount;
        if (!db_processed_wallets::get_single(proposal.wallet() + proposal.fee_id(), wallet_amount) && !db_wallets::get_single(proposal.wallet() + proposal.fee_id(), wallet_amount))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_proposal.cpp: proposal_wallet: could not find wallet.");
        }
        uint256_t fee_amount;

        if (final_stage)
        {
            fee_amount = boost::lexical_cast<uint256_t>(wallet_amount);
        }
        else
        {
            fee_amount = boost::lexical_cast<uint256_t>(proposal.fee());
        }

        zera_txn::InstrumentContract contract;

        ZeraStatus status = zera_fees::process_fees(contract, fee_amount, proposal.wallet(), proposal.fee_id(), true, *status_fee, result->proposal_id(), fee_address);

        if (status.ok())
        {
            result->mutable_base()->set_fee_id(proposal.fee_id());
            result->mutable_base()->set_fee_amount(boost::lexical_cast<std::string>(fee_amount));
        }
        return status;
    }
    bool get_process_ledger(zera_validator::ProcessLedger &ledger)
    {
        std::string key = time_calc::get_key_hour();
        std::string process_data;
        if (!db_process_ledger::get_single(key, process_data) || !ledger.ParseFromString(process_data))
        {
            return false;
        }
        if (ledger.proposal_ids_size() <= 0 && ledger.cycle_contract_ids_size() <= 0)
        {
            db_process_ledger::remove_single(key);
            return false;
        }
        return true;
    }

    bool get_adaptive_ledger(zera_validator::ProcessLedger &ledger)
    {
        std::string key = time_calc::get_key_minute();
        std::string adaptive_data;

        if (!db_process_adaptive_ledger::get_single(key, adaptive_data) || !ledger.ParseFromString(adaptive_data))
        {
            return false;
        }
        if (ledger.proposal_ids_size() <= 0)
        {
            db_process_adaptive_ledger::remove_single(key);
            return false;
        }
        return true;
    }
    ZeraStatus process_staged_cycle(const std::string &proposal_id, const zera_txn::InstrumentContract &contract, zera_txn::TXNS *txns, bool staged, zera_txn::TXNStatusFees *status_fee, zera_txn::ProposalResult *result, const std::string &fee_address)
    {
        std::string proposal_data;
        zera_validator::Proposal proposal;

        if (db_proposals::get_single(proposal_id, proposal_data) && proposal.ParseFromString(proposal_data))
        {
            result->set_contract_id(contract.contract_id());
            result->set_proposal_id(proposal_id);

            calc(proposal, contract, result);
            bool final_stage = true;

            if (staged)
            {
                final_stage = proposal.stage() >= contract.governance().stage_length_size();
            }

            ZeraStatus status = proposal_wallet(proposal, final_stage, status_fee, result, fee_address);
            if (!status.ok())
            {
                return status;
            }

            result->set_stage(proposal.stage());
            result->set_final_stage(final_stage);
            result->set_fast_quorum(false);

            sign_hash_result(result);

            return ZeraStatus();
        }

        return ZeraStatus();
    }

    ZeraStatus process_staggered_adaptive(const std::string &proposal_id, zera_txn::TXNS *txns, zera_txn::TXNStatusFees *status_fee, zera_txn::ProposalResult *result)
    {
        std::string proposal_data;
        zera_validator::Proposal proposal;

        if (db_proposals::get_single(proposal_id, proposal_data) && proposal.ParseFromString(proposal_data))
        {
            std::string contract_data;
            zera_txn::InstrumentContract contract;
            std::string contract_id = proposal.contract_id();

            if (!db_contracts::get_single(contract_id, contract_data) || !contract.ParseFromString(contract_data))
            {
                return ZeraStatus(ZeraStatus::Code::CONTRACT_ERROR, "process_proposal.cpp: process_fees: " + contract_id + " Contract does not exist.");
            }

            result->set_contract_id(contract_id);
            result->set_proposal_id(proposal_id);
            result->set_stage(1);
            calc(proposal, contract, result);

            ZeraStatus status = proposal_wallet(proposal, true, status_fee, result, "");
            if (!status.ok())
            {
                return status;
            }

            result->set_final_stage(true);
            result->set_fast_quorum(false);

            sign_hash_result(result);
            return ZeraStatus();
        }
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: process_fees: " + proposal_id + " Proposal does not exist.", zera_txn::TXN_STATUS::INVALID_PROPOSAL);
    }

    bool check_staggered_adaptive(const zera_validator::Block *block, zera_txn::TXNWrapper &wrapper)
    {
        std::vector<std::string> keys;
        std::vector<std::string> values;
        db_process_adaptive_ledger::get_all_data(keys, values);

        int x = 0;
        bool has_proposals = false;
        while (x < keys.size())
        {
            google::protobuf::Timestamp process_date;
            process_date.ParseFromString(values.at(x));

            // TODO - make HACK
            uint64_t process_time = process_date.seconds();
            if(ValidatorConfig::get_hack())
            {
                process_time = process_time - 864000;
            }
            
            if (block->block_header().timestamp().seconds() >= process_time)
            {

                wrapper.add_proposal_ids(keys.at(x));
                has_proposals = true;
            }

            x++;
        }
        return has_proposals;
    }

    bool check_staged_cycle(const zera_validator::Block *block, zera_txn::TXNWrapper &wrapper)
    {

        std::vector<std::string> keys;
        std::vector<std::string> values;
        db_proposal_ledger::get_all_data(keys, values);

        int x = 0;
        bool has_proposals = false;
        while (x < keys.size())
        {
            zera_validator::ProposalLedger ledger;

            ledger.ParseFromString(values.at(x));

            if (ledger.has_stage_end_date())
            {
                if (block->block_header().timestamp().seconds() >= ledger.stage_end_date().seconds())
                {
                    if (ledger.proposal_ids_size() > 0)
                    {
                        zera_txn::ProposalContract *proposal_contract = wrapper.add_proposal_contracts();
                        proposal_contract->set_contract_id(keys.at(x));
                        proposal_contract->set_stage(ledger.stage());

                        for (auto id : ledger.proposal_ids())
                        {
                            proposal_contract->add_proposal_ids(id);
                        }

                        has_proposals = true;
                    }
                }
            }
            else
            {
                if (block->block_header().timestamp().seconds() >= ledger.cycle_end_date().seconds())
                {
                    if (ledger.proposal_ids_size() > 0)
                    {
                        zera_txn::ProposalContract *proposal_contract = wrapper.add_proposal_contracts();
                        proposal_contract->set_contract_id(keys.at(x));
                        proposal_contract->set_stage(1);

                        for (auto id : ledger.proposal_ids())
                        {
                            proposal_contract->add_proposal_ids(id);
                        }

                        has_proposals = true;
                    }
                }
            }
            x++;
        }

        return has_proposals;
    }

    ZeraStatus process_ledger(const zera_txn::TXNWrapper &wrapper, zera_txn::TXNS *txns, const std::string &fee_address)
    {
        ZeraStatus status;

        for (auto proposal_contract : wrapper.proposal_contracts())
        {
            std::string contract_id = proposal_contract.contract_id();
            uint32_t stage = proposal_contract.stage();

            std::string contract_data;
            zera_txn::InstrumentContract contract;

            if (!db_contracts::get_single(contract_id, contract_data) || !contract.ParseFromString(contract_data))
            {
                logging::print("Contract not found for proposal ledger:", contract_id, true);
                break;
            }

            std::vector<zera_txn::ProposalResult> results;
            bool staged = contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED;
            bool cycle = contract.governance().type() == zera_txn::GOVERNANCE_TYPE::CYCLE;

            for (auto id : proposal_contract.proposal_ids())
            {
                zera_txn::TXNStatusFees status_fee;
                zera_txn::ProposalResult result;

                status = process_staged_cycle(id, contract, txns, staged, &status_fee, &result, fee_address);

                results.push_back(result);

                if (status.ok())
                {
                    status_fee.set_status(status.txn_status());
                    status_fee.set_txn_hash(result.base().hash());
                    txns->add_txn_fees_and_status()->CopyFrom(status_fee);
                }
            }

            if (staged)
            {
                std::vector<std::pair<std::string, uint256_t>> next_stage;

                for (auto result : results)
                {
                    if (result.passed())
                    {
                        if (result.option_cur_equiv_size() >= 1)
                        {
                            uint256_t vote = 0;
                            for (auto option : result.option_cur_equiv())
                            {
                                uint256_t check_vote(option);

                                vote += check_vote;
                            }

                            next_stage.push_back(std::make_pair(result.proposal_id(), vote));
                        }
                        else
                        {
                            uint256_t vote = boost::lexical_cast<uint256_t>(result.support_cur_equiv());
                            uint256_t vote2 = boost::lexical_cast<uint256_t>(result.against_cur_equiv());
                            vote += vote2;
                            next_stage.push_back(std::make_pair(result.proposal_id(), vote));
                        }
                    }
                }

                uint32_t proposal_amount = contract.governance().stage_length().at(stage - 1).max_approved();

                if (proposal_amount == 0)
                {
                    for (auto result : results)
                    {
                        result.set_proposal_cut(false);
                    }
                }
                else
                {
                    std::sort(next_stage.begin(), next_stage.end(), compare_by_uint256_t_desc);

                    if (next_stage.size() > proposal_amount)
                    {
                        next_stage.resize(proposal_amount);
                    }
                    for (auto result : results)
                    {
                        bool found = false;
                        for (auto pair : next_stage)
                        {
                            if (result.proposal_id() == pair.first)
                            {
                                found = true;
                            }
                        }

                        result.set_proposal_cut(!found);
                    }
                }
            }
            else if (cycle)
            {
                std::vector<std::pair<std::string, uint256_t>> next_stage;

                for (auto result : results)
                {
                    if (result.passed())
                    {
                        if (result.option_cur_equiv_size() >= 1)
                        {
                            uint256_t vote = 0;
                            for (auto option : result.option_cur_equiv())
                            {
                                uint256_t check_vote(option);

                                vote += check_vote;
                            }

                            next_stage.push_back(std::make_pair(result.proposal_id(), vote));
                        }
                        else
                        {
                            uint256_t vote = boost::lexical_cast<uint256_t>(result.support_cur_equiv());
                            uint256_t vote2 = boost::lexical_cast<uint256_t>(result.against_cur_equiv());
                            vote += vote2;
                            next_stage.push_back(std::make_pair(result.proposal_id(), vote));
                        }
                    }
                }

                uint32_t proposal_amount = 0;
                if (contract.governance().has_max_approved())
                {
                    proposal_amount = contract.governance().max_approved();
                }

                if (proposal_amount == 0)
                {
                    for (auto result : results)
                    {
                        result.set_proposal_cut(false);
                    }
                }
                else
                {

                    std::sort(next_stage.begin(), next_stage.end(), compare_by_uint256_t_desc);

                    if (next_stage.size() > proposal_amount)
                    {
                        next_stage.resize(proposal_amount);
                    }

                    for (auto result : results)
                    {
                        bool found = false;
                        for (auto pair : next_stage)
                        {
                            if (result.proposal_id() == pair.first)
                            {
                                found = true;
                            }
                        }

                        result.set_proposal_cut(!found);
                    }
                }
            }

            for (auto result : results)
            {
                txns->add_proposal_result_txns()->CopyFrom(result);
            }
        }
        return status;
    }
}

void gov_process::process_fast_quorum(zera_txn::TXNS *txns, const std::string &fee_address)
{
    if (txns->fast_quorum_txns_size() <= 0)
    {
        return;
    }
    std::vector<std::string> keys;
    std::vector<std::string> values;
    db_fast_quorum::get_all_data(keys, values);

    for (size_t i = 0; i < keys.size(); ++i)
    {
        zera_txn::ProposalResult *result = txns->add_proposal_result_txns();
        zera_txn::TXNStatusFees *status_fee = txns->add_txn_fees_and_status();
        zera_validator::Proposal proposal;
        std::string proposal_id = keys.at(i);
        proposal.ParseFromString(values.at(i));

        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(proposal.contract_id(), contract);
        if (!status.ok())
        {
            continue;
        }

        result->set_contract_id(contract.contract_id());
        result->set_proposal_id(proposal_id);

        calc(proposal, contract, result, true);

        if (result->passed())
        {
            proposal_wallet(proposal, true, status_fee, result, fee_address);
            result->set_final_stage(true);
        }
        else
        {
            result->set_final_stage(false);
        }

        result->set_fast_quorum(true);

        sign_hash_result(result);

        status_fee->set_status(zera_txn::TXN_STATUS::OK);
        status_fee->set_txn_hash(result->base().hash());
    }

    db_fast_quorum::remove_all();
}

void gov_process::process_fast_quorum_block_sync(zera_txn::TXNS *txns, const zera_validator::Block *original_block)
{
    if (txns->fast_quorum_txns_size() <= 0)
    {
        return;
    }
    std::vector<std::string> keys;
    std::vector<std::string> values;
    db_fast_quorum::get_all_data(keys, values);

    for (size_t i = 0; i < keys.size(); ++i)
    {
        zera_txn::ProposalResult *result = txns->add_proposal_result_txns();
        zera_txn::TXNStatusFees *status_fee = txns->add_txn_fees_and_status();
        zera_validator::Proposal proposal;
        std::string proposal_id = keys.at(i);
        proposal.ParseFromString(values.at(i));

        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(proposal.contract_id(), contract);
        if (!status.ok())
        {
            continue;
        }

        result->set_contract_id(contract.contract_id());
        result->set_proposal_id(proposal_id);

        calc(proposal, contract, result);

        if (result->passed())
        {
            proposal_wallet(proposal, true, status_fee, result, original_block->block_header().fee_address());
            result->set_final_stage(true);
        }
        else
        {
            result->set_final_stage(false);
        }

        result->set_fast_quorum(true);

        for (auto original : original_block->transactions().proposal_result_txns())
        {
            if (original.proposal_id() == proposal_id)
            {
                result->mutable_base()->mutable_public_key()->CopyFrom(original.base().public_key());
                result->mutable_base()->set_signature(original.base().signature());
                google::protobuf::Timestamp *timestamp = result->mutable_base()->mutable_timestamp();
                timestamp->CopyFrom(original.base().timestamp());
            }
        }

        auto hash_vec = Hashing::sha256_hash(result->SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        result->mutable_base()->set_hash(hash);

        status_fee->set_status(zera_txn::TXN_STATUS::OK);
        status_fee->set_txn_hash(result->base().hash());
    }

    db_fast_quorum::remove_all();
}

ZeraStatus gov_process::process_ledgers(zera_txn::TXNS *txns, zera_txn::TXNWrapper &wrapper, const std::string &fee_address)
{
    ZeraStatus status;

    if (wrapper.proposal_contracts_size() > 0)
    {
        status = process_ledger(wrapper, txns, fee_address);
    }

    for (auto id : wrapper.proposal_ids())
    {
        zera_txn::TXNStatusFees status_fee;
        zera_txn::ProposalResult result;
        status = process_staggered_adaptive(id, txns, &status_fee, &result);
        if (status.ok())
        {
            status_fee.set_status(status.txn_status());
            status_fee.set_txn_hash(result.base().hash());
            txns->add_txn_fees_and_status()->CopyFrom(status_fee);
            txns->add_proposal_result_txns()->CopyFrom(result);
        }
        else
        {
            logging::print(status.read_status());
        }
    }

    if (!status.ok())
    {
        logging::print(status.read_status());
    }
    return status;
}

bool gov_process::check_ledgers(const zera_validator::Block *block)
{
    zera_txn::TXNWrapper wrapper;
    db_transactions::remove_single("1");

    bool has_proposals = false;

    if (check_staggered_adaptive(block, wrapper))
    {
        has_proposals = true;
    }

    if (check_staged_cycle(block, wrapper))
    {
        has_proposals = true;
    }

    if (has_proposals)
    {
        wrapper.set_proposal_result_txn(true);
        wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::PROPOSAL_RESULT_TYPE);
        db_transactions::store_single("1", wrapper.SerializeAsString());
    }
}