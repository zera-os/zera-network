#include "block_process.h"
#include "../txn_batch/txn_batch.h"
#include "db_base.h"
#include "../temp_data/temp_data.h"
#include "wallet.pb.h"
#include "wallets.h"
#include "../governance/time_calc.h"
#include "validators.h"
#include "../db/reorg.h"
#include "../governance/gov_process.h"
#include "../restricted/restricted_keys.h"
#include "../logging/logging.h"
#include <string>
#include <vector>
#include <sstream>
#include "base64.h"

// testing
#include "utils.h"
#include "fees.h"

namespace
{

    std::vector<std::string> split_string(const std::string &str, char delimiter)
    {
        std::vector<std::string> result;
        std::string token;
        std::istringstream tokenStream(str);

        while (std::getline(tokenStream, token, delimiter))
        {
            result.push_back(token);
        }

        return result;
    }

    std::string get_block_key(uint64_t height, std::string hash)
    {
        std::ostringstream oss;
        oss << std::setw(20) << std::setfill('0') << height;
        std::string paddedHeight = oss.str();
        return paddedHeight + ":" + hash;
    }

    void staged(const zera_txn::InstrumentContract &contract, zera_validator::ProposalLedger &old_proposal_ledger, zera_validator::ProposalLedger &new_proposal_ledger, const uint64_t timestamp)
    {
        bool final_stage = false;
        int stage = old_proposal_ledger.stage();

        if (old_proposal_ledger.stage() == 0)
        {
            final_stage = true;
            stage = 1;
            new_proposal_ledger.set_stage(1);
        }

        if (old_proposal_ledger.stage() >= contract.governance().stage_length_size())
        {
            stage = 1;
            new_proposal_ledger.set_stage(1);
            final_stage = true;
        }

        if (final_stage)
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
            google::protobuf::Timestamp end_ts = time_calc::get_end_date_cycle(old_proposal_ledger.cycle_end_date(), days, months);

            uint64_t start_date = old_proposal_ledger.cycle_end_date().seconds();

            while (end_ts.seconds() <= timestamp)
            {
                start_date = end_ts.seconds();
                google::protobuf::Timestamp start_ts;
                start_ts.set_seconds(start_date);

                end_ts = time_calc::get_end_date_cycle(start_ts, days, months);
            }

            new_proposal_ledger.mutable_cycle_end_date()->set_seconds(end_ts.seconds());
            new_proposal_ledger.mutable_cycle_start_date()->set_seconds(start_date);
            new_proposal_ledger.mutable_proposal_ids()->CopyFrom(old_proposal_ledger.pending_proposal_ids());
        }
        else
        {
            new_proposal_ledger.mutable_cycle_start_date()->set_seconds(old_proposal_ledger.cycle_start_date().seconds());
            new_proposal_ledger.mutable_cycle_end_date()->set_seconds(old_proposal_ledger.cycle_end_date().seconds());
            new_proposal_ledger.mutable_proposal_ids()->CopyFrom(old_proposal_ledger.proposal_ids());
            new_proposal_ledger.mutable_pending_proposal_ids()->CopyFrom(old_proposal_ledger.pending_proposal_ids());
        }

        if (final_stage)
        {

            for (auto proposal_id : new_proposal_ledger.proposal_ids())
            {
                zera_validator::Proposal proposal;
                std::string proposal_data;
                db_proposals::get_single(proposal_id, proposal_data);
                if (!proposal.ParseFromString(proposal_data))
                {
                    continue;
                }

                if (base58_encode(proposal_id) == "7ageXRbRbWQU2PhnmdLfgmh6S54joqkLKCEdrVrGuYJ4")
                {
                    proposal.set_stage(stage);
                }
                else
                {
                    proposal.set_stage(1);
                }
            }
        }

        uint32_t days = 0;
        uint32_t months = 0;

        if (contract.governance().stage_length_size() < stage)
        {
            return;
        }

        if (contract.governance().stage_length().at(stage - 1).period() == zera_txn::PROPOSAL_PERIOD::DAYS)
        {
            days = contract.governance().stage_length().at(stage - 1).length();
        }
        else
        {
            months = contract.governance().stage_length().at(stage - 1).length();
        }

        if (final_stage)
        {
            google::protobuf::Timestamp end_ts;

            if (days == 0 && months == 0)
            {
                end_ts.set_seconds(new_proposal_ledger.cycle_end_date().seconds());
            }
            else
            {
                time_calc::get_end_date_cycle(new_proposal_ledger.cycle_start_date(), days, months);
                end_ts = time_calc::get_end_date_cycle(new_proposal_ledger.cycle_start_date(), days, months);
            }

            uint64_t start_date = new_proposal_ledger.mutable_cycle_start_date()->seconds();

            for (auto proposal_id : new_proposal_ledger.proposal_ids())
            {
                zera_validator::Proposal proposal;
                std::string proposal_data;
                db_proposals::get_single(proposal_id, proposal_data);
                if (!proposal.ParseFromString(proposal_data))
                {
                    continue;
                }
                proposal.set_stage(1);
                db_proposals::store_single(proposal_id, proposal.SerializeAsString());
            }
            new_proposal_ledger.set_stage(stage);
            new_proposal_ledger.mutable_stage_end_date()->set_seconds(end_ts.seconds());
            new_proposal_ledger.mutable_stage_start_date()->set_seconds(start_date);
        }
        else
        {
            google::protobuf::Timestamp end_ts;

            if (days == 0 && months == 0)
            {
                end_ts.set_seconds(new_proposal_ledger.cycle_end_date().seconds());
            }
            else
            {
                end_ts = time_calc::get_end_date_cycle(old_proposal_ledger.stage_end_date(), days, months);
            }
            new_proposal_ledger.mutable_stage_end_date()->set_seconds(end_ts.seconds());
            new_proposal_ledger.mutable_stage_start_date()->set_seconds(old_proposal_ledger.stage_end_date().seconds());
            new_proposal_ledger.set_stage(stage + 1);
        }
    }
    void cycle(const zera_txn::InstrumentContract &contract, const zera_validator::ProposalLedger &old_proposal_ledger, zera_validator::ProposalLedger &new_proposal_ledger)
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
        google::protobuf::Timestamp end_ts = time_calc::get_end_date_cycle(old_proposal_ledger.cycle_end_date(), days, months);
        new_proposal_ledger.mutable_cycle_end_date()->set_seconds(end_ts.seconds());
        new_proposal_ledger.mutable_cycle_start_date()->set_seconds(old_proposal_ledger.cycle_end_date().seconds());

        new_proposal_ledger.mutable_proposal_ids()->CopyFrom(old_proposal_ledger.pending_proposal_ids());
    }

    void update_staged_cycle(zera_validator::Block *block, uint64_t timestamp)
    {
        std::vector<std::string> contract_ids;
        std::vector<std::string> ledger_data;
        std::string header_data;
        db_proposal_ledger::get_all_data(contract_ids, ledger_data);

        int x = 0;
        while (x < contract_ids.size())
        {
            bool process = false;
            std::string proposal_ledger_data;
            zera_validator::ProposalLedger old_proposal_ledger;
            zera_validator::ProposalLedger new_proposal_ledger;
            std::string contract_data;
            zera_txn::InstrumentContract contract;
            if (!old_proposal_ledger.ParseFromString(ledger_data.at(x)))
            {
                x++;
                continue;
            }
            if (!db_contracts::get_single(contract_ids.at(x), contract_data) || !contract.ParseFromString(contract_data))
            {
                x++;
                continue;
            }

            if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGED)
            {
                if (timestamp >= old_proposal_ledger.stage_end_date().seconds())
                {
                    staged(contract, old_proposal_ledger, new_proposal_ledger, timestamp);
                    process = true;
                }
            }
            else if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::CYCLE)
            {
                if (block->block_header().timestamp().seconds() >= old_proposal_ledger.cycle_end_date().seconds())
                {
                    cycle(contract, old_proposal_ledger, new_proposal_ledger);
                    process = true;
                }
            }

            if (process)
            {
                db_proposal_ledger::store_single(contract_ids.at(x), new_proposal_ledger.SerializeAsString());
            }
            x++;
        }
    }

    void store_proposal_adjustment()
    {
        std::vector<std::string> keys;
        std::vector<std::string> values;
        rocksdb::WriteBatch proposal_batch;
        db_proposals_temp::get_all_data(keys, values);

        int x = 0;

        while (x < keys.size())
        {
            proposal_batch.Put(keys[x], values[x]);
            x++;
        }
        db_proposals::store_batch(proposal_batch);
        db_proposals_temp::remove_all();
    }

    // if you have been unbonding for 7 days, remove from unbonding list
    void remove_unbonding_validators(const zera_validator::BlockHeader &header)
    {
        std::vector<std::string> keys;
        std::vector<std::string> values;
        db_validator_unbond::get_all_data(keys, values);
        rocksdb::WriteBatch unbond_batch;

        int x = 0;
        while (x < keys.size())
        {
            google::protobuf::Timestamp timestamp;
            timestamp.ParseFromString(values[x]);
            int time_passed = header.timestamp().seconds() - timestamp.seconds();

            if (time_passed >= 604800)
            {
                unbond_batch.Delete(keys[x]);
            }

            x++;
        }

        db_validator_unbond::store_batch(unbond_batch);
    }

    void update_proposal_ledgers(zera_validator::Block *block)
    {

        update_staged_cycle(block, block->block_header().timestamp().seconds());
    }

    void update_proposal_heartbeat(zera_validator::Block *block)
    {
        if (block->block_header().block_height() == 0)
        {
            return;
        }

        std::string pub_str = wallets::get_public_key_string(block->block_header().public_key());
        std::string validator_str;
        zera_txn::Validator validator;
        db_validators::get_single(pub_str, validator_str);

        validator.ParseFromString(validator_str);
        validator.set_last_heartbeat(block->block_header().block_height());
        validator.set_online(true);
        validator.set_version(block->block_header().version());
        db_validators::store_single(pub_str, validator.SerializeAsString());
    }

    void update_event_management(zera_validator::Block *block)
    {
        std::string event_management_temp_str;
        db_event_management::get_single(EVENT_MANAGEMENT_TEMP, event_management_temp_str);
        zera_api::SmartContractEventManagementTemp event_management_temp;
        event_management_temp.ParseFromString(event_management_temp_str);

        auto event_keys = event_management_temp.event_keys();
        auto smart_contract_ids = event_management_temp.smart_contract_ids();

        try
        {
            if (event_keys.size() != smart_contract_ids.size())
            {
                logging::print("event_keys and smart_contract_ids sizes do not match", true);
                logging::print("event_keys size: " + std::to_string(event_keys.size()), true);
                logging::print("smart_contract_ids size: " + std::to_string(smart_contract_ids.size()), true);
                logging::print("debug string:", event_management_temp.DebugString(), true);

                return;
            }
            int x = 0;
            for (auto event_key : event_management_temp.event_keys())
            {
                std::string smart_contract_id = event_management_temp.smart_contract_ids().at(x);
                std::string event_data;
                db_event_management::get_single(smart_contract_id, event_data);
                zera_api::SmartContractEventManagement event_management;
                event_management.ParseFromString(event_data);

                // Collect keys to delete first to avoid iterator invalidation
                std::vector<std::string> keys_to_delete;
                for (auto event : event_management.events())
                {
                    if (event.second.seconds() + 259200 < block->block_header().timestamp().seconds()) // 3 days
                    {
                        keys_to_delete.push_back(event.first);
                    }
                }

                // Now delete them
                for (const auto &key : keys_to_delete)
                {
                    event_management.mutable_events()->erase(key);
                    db_event_management::remove_single(key);
                }

                event_management.mutable_events()->insert({event_key, block->block_header().timestamp()});
                db_event_management::store_single(smart_contract_id, event_management.SerializeAsString());
                x++;
            }
            db_event_management::remove_single(EVENT_MANAGEMENT_TEMP);
        }
        catch (const std::exception &e)
        {
            logging::print("Exception caught:", e.what(), true);
        }
    }

    void update_staked_coins_voted()
    {
        std::vector<std::string> keys;
        std::vector<std::string> values;
        db_staked_coins_voted_temp::get_all_data(keys, values);
        rocksdb::WriteBatch staked_coins_voted_batch;
        int x = 0;

        while (x < keys.size())
        {
            std::string key = keys[x];
            std::string value = values[x];
            staked_coins_voted_batch.Put(key, value);
            x++;
        }
        db_staked_coins_voted::store_batch(staked_coins_voted_batch);
        db_staked_coins_voted_temp::remove_all();
    }

    void update_fee_tokens(const uint64_t &new_block_time, const zera_txn::TXNS &txns, const std::map<std::string, bool> &txns_passed)
    {
        std::vector<std::string> keys;
        std::vector<std::string> values;
        rocksdb::WriteBatch fee_tokens_batch;
        db_fee_tokens_temp::get_all_data(keys, values);
        // FEE_TOKENS
        int x = 0;
        while (x < keys.size())
        {
            std::string key = keys[x];
            std::string value = values[x];
            fee_tokens_batch.Put(key, value);
            x++;
        }
        db_fee_tokens::store_batch(fee_tokens_batch);
        db_fee_tokens_temp::remove_all();

        std::unordered_set<std::string> tokens_to_update; // Instead of vector

        for (auto execute : txns.smart_contract_executes())
        {
            if (!txns_passed.at(execute.base().hash()))
            {
                continue;
            }

            if (execute.smart_contract_name() == "zera_dex_proxy" && execute.instance() == 1 && execute.function() == "execute")
            {

                if (execute.parameters().size() != 2)
                {
                    continue;
                }

                zera_txn::Parameters parameter = execute.parameters().at(0);
                zera_txn::Parameters parameter2 = execute.parameters().at(1);

                if (parameter.type() != "string" || parameter2.type() != "string")
                {
                    continue;
                }

                if (parameter.value() != "swap" && parameter.value() != "create_liquidity_pool" && parameter.value() != "remove_liquidity")
                {
                    continue;
                }


                std::vector<std::string> parameters_vec = split_string(parameter2.value(), ',');

                if (parameter.value() == "remove_liquidity")
                {

                    if (parameters_vec.size() != 4)
                    {
                        continue;
                    }

                    if (parameters_vec.at(3) != "25")
                    {
                        continue;
                    }

                    if (parameters_vec.at(0) != NETWORK_CONTRACT && parameters_vec.at(1) != NETWORK_CONTRACT)
                    {
                        continue;
                    }

                    std::string token1 = parameters_vec.at(0);
                    std::string token2 = parameters_vec.at(1);

                    if (token1 == NETWORK_CONTRACT)
                    {
                        if (tokens_to_update.find(token2) == tokens_to_update.end())
                        {
                            tokens_to_update.insert(token2);
                        }
                    }
                    else
                    {
                        if (tokens_to_update.find(token1) == tokens_to_update.end())
                        {
                            tokens_to_update.insert(token1);
                        }
                    }
                }
                else if (parameter.value() == "create_liquidity_pool" || parameter.value() == "swap")
                {
                    if (parameters_vec.size() != 6)
                    {
                        logging::print("parameters_vec.size() != 6", true);
                        continue;
                    }

                    if(parameter.value() == "swap" && parameters_vec.at(3) != "25")
                    {
                        logging::print("parameters_vec.at(3) != 25", true);
                        continue;
                    }

                    if(parameter.value() == "create_liquidity_pool" && parameters_vec.at(4) != "25" )
                    {
                        logging::print("parameters_vec.at(4) != 25", true);
                        continue;
                    }

                    if (parameters_vec.at(0) != "$ZRA+0000" && parameters_vec.at(1) != "$ZRA+0000")
                    {
                        logging::print("parameters_vec.at(0) != $ZRA+0000 && parameters_vec.at(1) != $ZRA+0000", true);
                        continue;
                    }

                    std::string token1 = parameters_vec.at(0);
                    std::string token2 = parameters_vec.at(1);

                    if (token1 == NETWORK_CONTRACT)
                    {
                        if (tokens_to_update.find(token2) == tokens_to_update.end())
                        {
                            tokens_to_update.insert(token2);
                        }
                    }
                    else
                    {
                        if (tokens_to_update.find(token1) == tokens_to_update.end())
                        {
                            tokens_to_update.insert(token1);
                        }
                    }
                }
            }
        }

        std::string update_key = "LAST_UPDATED";
        std::string value;
        uint64_t last_updated;
        if (!db_fee_tokens::get_single(update_key, value))
        {
            last_updated = 0;
        }
        else
        {
            last_updated = boost::lexical_cast<uint64_t>(value);
        }

        std::string stable_coin_contract;
        if(!db_smart_contract_states::get_single(STABLE_COIN_SC, stable_coin_contract) || stable_coin_contract == "" || !db_contracts::exist(stable_coin_contract))
        {
            stable_coin_contract = STABLE_COIN_CONTRACT;
        }

        if (tokens_to_update.size() > 0)
        {
            zera_validator::FeeToken zra_fee_token;
            std::string fee_data;
            db_fee_tokens::get_single(FEE_TOKENS + NETWORK_CONTRACT, fee_data);
            zra_fee_token.ParseFromString(fee_data);


            std::string zra_stable_coin_key = ACE_PROXY + NETWORK_CONTRACT + stable_coin_contract;
            std::string rate_data;
            uint256_t zra_rate;

            if (!db_smart_contract_states::get_single(zra_stable_coin_key, rate_data) || rate_data == "")
            {
                zra_rate = ONE_DOLLAR;
            }
            else
            {
                zra_rate = boost::lexical_cast<uint256_t>(rate_data);
            }

            if (tokens_to_update.find(stable_coin_contract) != tokens_to_update.end())
            {
                zra_fee_token.set_contract_id(NETWORK_CONTRACT);
                zra_fee_token.set_rate(zra_rate.str());
                zra_fee_token.set_authorized(true);
                zra_fee_token.set_whitelisted(true);
                
                db_fee_tokens::store_single(FEE_TOKENS + NETWORK_CONTRACT, zra_fee_token.SerializeAsString());
            }

            for (auto token : tokens_to_update)
            {
                std::string lp_token_data;
                std::string lp_token_key = ZERA_DEX_LP + token;

                if (!db_smart_contract_states::get_single(lp_token_key, lp_token_data) || lp_token_data == "")
                {
                    db_fee_tokens::remove_single(FEE_TOKENS + token);
                    continue;
                }

                LiquidityPool lp_token = decode_liquidity_pool(lp_token_data);
                std::string lp_token_burn_balance;
                std::string burn_wallet = BURN_WALLET + lp_token.lp_token_id;

                if (!db_wallets::get_single(burn_wallet, lp_token_burn_balance) || lp_token_burn_balance == "" || lp_token_burn_balance == "0")
                {
                    lp_token_burn_balance = "0";
                }

                uint256_t lp_token_burn_balance_uint = boost::lexical_cast<uint256_t>(lp_token_burn_balance);
                uint256_t zera_volume = boost::lexical_cast<uint256_t>(lp_token.token1_volume);
                uint256_t lp_token_volume = boost::lexical_cast<uint256_t>(lp_token.circulating_lp_tokens);


                // Calculate what % of LP tokens are burned and apply to ZRA volume
                uint256_t zera_locked_by_burned_lp = (lp_token_burn_balance_uint * zera_volume) / lp_token_volume;


                // Convert locked ZRA to stable coin value
                uint256_t stable_value = (zera_locked_by_burned_lp * zra_rate) / uint256_t("1000000000");

                // Check if at least 1000 stable coins are locked
                uint256_t min_stable_required = 1000 * ONE_DOLLAR;
                bool authorized = true;
                if (stable_value < min_stable_required)
                {
                    authorized = false;
                }

                std::string fee_token_data;
                zera_validator::FeeToken fee_token;
                std::string fee_token_key = FEE_TOKENS + token;
                bool found = true;

                if (!db_fee_tokens::get_single(fee_token_key, fee_token_data) || !fee_token.ParseFromString(fee_token_data))
                {
                    found = false;
                }

                fee_token.set_contract_id(token);

                std::string token_ratio_key = ACE_PROXY + token;
                std::string token_ratio_data;
                if (db_smart_contract_states::get_single(token_ratio_key, token_ratio_data) && token_ratio_data != "")
                {
                    zera_txn::InstrumentContract contract;
                    if(!block_process::get_contract(token, contract).ok())
                    {
                        continue;
                    }
                    uint256_t denomination(contract.coin_denomination().amount());
                    if (is_valid_uint256(token_ratio_data))
                    {
                        uint256_t token_ratio = boost::lexical_cast<uint256_t>(token_ratio_data);
                        uint256_t rate = (token_ratio * zra_rate) / ONE_DOLLAR;
                        uint256_t max_stake = (stable_value *  denomination) / rate;

                        fee_token.set_authorized(authorized);
                        fee_token.set_max_stake(max_stake.str());
                        fee_token.set_rate(rate.str());
                        fee_token.set_stable_value_allowed(stable_value.str());
                        fee_token.set_whitelisted(false);
                        std::string token_whitelist_data;
                        if(db_smart_contract_states::get_single(TOKEN_WHITELIST, token_whitelist_data) && token_whitelist_data != "")
                        {
                            NetworkValues network_values = decode_network_values(token_whitelist_data);
                            if(std::find(network_values.values.begin(), network_values.values.end(), token) != network_values.values.end())
                            {
                                fee_token.set_whitelisted(true);
                            }
                        }

                        db_fee_tokens_temp::store_single(token, fee_token.SerializeAsString());

                        if (!found)
                        {
                            fee_token.set_value_used("0");
                        }
                    }

                    db_fee_tokens::store_single(fee_token_key, fee_token.SerializeAsString());
                }
            }
        }

        uint64_t new_block_day = new_block_time / 86400;

        if (new_block_day > last_updated)
        {
            rocksdb::WriteBatch fee_tokens_batch2;
            fee_tokens_batch2.Put(update_key, std::to_string(new_block_day));

            std::vector<std::string> keys;
            std::vector<std::string> values;
            db_fee_tokens::find_by_prefix(FEE_TOKENS, keys, values);

            int x = 0;
            while (x < keys.size())
            {
                std::string key = keys[x];
                std::string value = values[x];
                zera_validator::FeeToken fee_token;
                fee_token.ParseFromString(value);

                fee_token.set_value_used("0");
                fee_tokens_batch2.Put(key, fee_token.SerializeAsString());
                x++;
            }
            db_fee_tokens::store_batch(fee_tokens_batch2);
        }
    }
}
ZeraStatus block_process::store_txns(zera_validator::Block *block, bool archive, bool backup)
{
    logging::print("****************************\nStoring Block: " + std::to_string(block->block_header().block_height()));
    logging::print("****************************");

    block_process::store_wallets();
    allowance_tracker::update_allowance_database();
    update_event_management(block);
    update_staked_coins_voted();
    auto txns = block->transactions();
    std::map<std::string, bool> txn_passed;
    txn_batch::find_passed(txn_passed, txns);
    update_fee_tokens(block->block_header().timestamp().seconds(), txns, txn_passed);
    txn_batch::batch_contracts(txns, txn_passed);
    txn_batch::batch_contract_updates(txns, txn_passed);
    txn_batch::batch_item_mint(txns, txn_passed);
    txn_batch::batch_nft_transfer(txns, txn_passed);
    txn_batch::batch_proposals(txns, txn_passed, block->block_header().timestamp().seconds());
    store_proposal_adjustment();
    txn_batch::batch_votes(txns, txn_passed);
    txn_batch::batch_proposal_results(txns, txn_passed);
    txn_batch::batch_proposal_cancel(txns, txn_passed);
    txn_batch::batch_compliance(txns, txn_passed);
    txn_batch::batch_delegated_voting(txns, txn_passed);
    txn_batch::batch_validator_registration(txns, txn_passed, block->block_header());
    txn_batch::batch_validator_heartbeat(txns, txn_passed, block->block_header().block_height());
    txn_batch::batch_smart_contract(txns, txn_passed);
    txn_batch::batch_instantiate(txns, txn_passed);
    txn_batch::batch_allowance_txns(txns, txn_passed, block->block_header().timestamp().seconds());
    std::string block_height_str = std::to_string(block->block_header().block_height());
    contract_price_tracker::store_prices();
    nonce_tracker::store_used_nonce(block_height_str);
    item_tracker::clear_items();
    sbt_burn_tracker::clear_burns();
    remove_unbonding_validators(block->block_header());
    supply_tracker::supply_to_database();
    std::string block_height = std::to_string(block->block_header().block_height());

    update_proposal_heartbeat(block);
    if (archive)
    {
        validator_utils::archive_balances(block_height);
    }

    
    if (backup)
    {
        Reorg::backup_blockchain(block_height);
    }

    gov_process::check_ledgers(block);
    update_proposal_ledgers(block);
    restricted_keys_check::check_quash_ledger(block);
    txn_batch::batch_required_version(txns, txn_passed, *block);
    logging::print("****************************\nDONE Storing Block: " + std::to_string(block->block_header().block_height()));
    return ZeraStatus();
}
