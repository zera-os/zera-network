#include "validate_block.h"

#include <thread>

#include "const.h"
#include "../attestation/attestation_process.h"
#include "../governance/gov_process.h"
#include "threadpool.h"
#include <vector>
#include "../logging/logging.h"
#include "../temp_data/temp_data.h"
#include "validator_api_client.h"

namespace
{

    bool check_txn_processed(const std::string &hash)
    {
        int x = 0;

        while (x < 10)
        {
            if (db_block_txns::exist(hash))
            {
                return true;
            }

            if (recieved_txn_tracker::check_txn(hash))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            else
            {
                return false;
            }

            x++;
        }
    }

    void sign_hash_result(zera_validator::Block *block, const zera_txn::ProposalResult *original_result)
    {
        zera_txn::ProposalResult *result = block->mutable_transactions()->mutable_proposal_result_txns(0);

        google::protobuf::Timestamp *ts = result->mutable_base()->mutable_timestamp();
        zera_validator::BlockHeader new_header;
        result->mutable_base()->mutable_timestamp()->set_seconds(original_result->base().timestamp().seconds());
        result->mutable_base()->mutable_public_key()->set_single(original_result->base().public_key().single());
        result->mutable_base()->set_signature(original_result->base().signature());
        auto old_hash = result->mutable_base()->release_hash();
        auto hash_vec = Hashing::sha256_hash(result->SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        result->mutable_base()->set_hash(hash);

        for (auto &status : *block->mutable_transactions()->mutable_txn_fees_and_status())
        {
            if (status.txn_hash() == *old_hash)
            {
                status.set_txn_hash(hash);
            }
        }
    }

    void print_proposal_result(const zera_txn::ProposalResult &result)
    {

        logging::print("************************************\nPROPOSAL RESULT\n****************************************");
        logging::print("contract_id:", result.contract_id());
        logging::print("proposal_id:", base58_encode(result.proposal_id()));
        logging::print("support_cur:", result.support_cur_equiv());
        logging::print("against_cur:", result.against_cur_equiv());

        logging::print("public_key:", base58_encode_public_key(result.base().public_key().single()));
        logging::print("hash:", base58_encode(result.base().hash()));
        logging::print("signature:", base58_encode(result.base().signature()));
        logging::print("timestamp:", std::to_string(result.base().timestamp().seconds()));
        logging::print("base fee_id:", result.base().fee_id());
        logging::print("base fee_amount:", result.base().fee_amount());

        for (auto option : result.option_cur_equiv())
        {
            logging::print("option cur:", option);
        }
        for (auto vote : result.support_votes().votes())
        {
            logging::print("support votes:", vote.contract_id(), "-", vote.amount());
        }
        for (auto vote : result.against_votes().votes())
        {
            logging::print("against votes:", vote.contract_id(), "-", vote.amount());
        }
        for (auto option_vote : result.option_votes())
        {
            for (auto vote : option_vote.votes())
            {
                logging::print("option votes:", vote.contract_id(), "-", vote.amount());
            }
        }
        logging::print("************************************\nEND\n****************************************");
    }
    bool check_token_fees(zera_validator::Block *manual_block, const zera_validator::Block &block)
    {
        for (auto token_fees : block.transactions().token_fees())
        {
            bool accepted = false;
            for (auto man_fees : manual_block->transactions().token_fees())
            {
                if (token_fees.address() == man_fees.address())
                {
                    auto hash1 = Hashing::sha256_hash(token_fees.SerializeAsString());
                    auto hash2 = Hashing::sha256_hash(man_fees.SerializeAsString());
                    Hashing::compare_hash(hash1, hash2) ? accepted = true : accepted = false;

                    if (accepted)
                    {
                        break;
                    }
                }
            }

            if (!accepted)
            {
                return false;
            }
        }

        for (auto status : block.transactions().txn_fees_and_status())
        {
            bool accepted = false;
            for (auto man_status : manual_block->transactions().txn_fees_and_status())
            {
                if (status.txn_hash() == man_status.txn_hash())
                {
                    auto hash1 = Hashing::sha256_hash(status.SerializeAsString());
                    auto hash2 = Hashing::sha256_hash(man_status.SerializeAsString());
                    Hashing::compare_hash(hash1, hash2) ? accepted = true : accepted = false;

                    if (accepted)
                    {
                        break;
                    }
                }
            }
            if (!accepted)
            {
                logging::print("fee status not accepted");
                return false;
            }
        }

        return true;
    }
    void store_validator_nonce(zera_validator::Block *block)
    {
        std::string wallet_adr;
        for (auto txn : block->transactions().validator_registration_txns())
        {
            wallet_adr = wallets::generate_wallet(txn.validator().public_key());
            uint64_t txn_nonce = txn.base().nonce();
            nonce_tracker::add_nonce(wallet_adr, txn_nonce, txn.base().hash());
            nonce_tracker::add_used_nonce(wallet_adr, txn_nonce);
        }
        for (auto txn : block->transactions().validator_heartbeat_txns())
        {
            uint64_t txn_nonce = txn.base().nonce();
            nonce_tracker::add_nonce(wallet_adr, txn_nonce, txn.base().hash());
            nonce_tracker::add_used_nonce(wallet_adr, txn_nonce);
        }
    }

    template <typename TXType>
    void get_nonce(TXType *txn, uint64_t &nonce)
    {
        nonce = txn->base().nonce();
    }

    template <>
    void get_nonce<zera_txn::CoinTXN>(zera_txn::CoinTXN *txn, uint64_t &nonce)
    {
        for (auto input_nonce : txn->auth().nonce())
        {
            nonce += input_nonce;
        }
    }

    std::string get_txn_key(uint64_t nonce, std::string hash)
    {
        std::ostringstream oss;
        oss << std::setw(20) << std::setfill('0') << nonce;
        std::string paddedHeight = oss.str();
        return paddedHeight + ":" + hash;
    }

    template <typename TXType>
    void wrap_txn(TXType *txn, transactions &txns, bool processed)
    {
        std::string txn_hash = txn->base().hash();
        uint64_t txn_nonce = 0;
        get_nonce(txn, txn_nonce);
        std::string txn_key = get_txn_key(txn_nonce, txn_hash);

        zera_txn::TXNWrapper wrapper;
        verify_txns::store_wrapper(txn, wrapper);

        if (processed)
        {
            logging::print("already processed");
            txns.processed_keys.push_back(txn_key);
            txns.processed_values.push_back(wrapper.SerializeAsString());
        }
        else if (db_gov_txn::exist(txn_hash))
        {
            txns.gov_keys.push_back(txn_key);
            txns.gov_values.push_back(wrapper.SerializeAsString());
        }
        else
        {
            txns.keys.push_back(txn_key);
            txns.values.push_back(wrapper.SerializeAsString());
        }
    }

    void wrap_txn_proposal(transactions &txns, bool processed)
    {
        std::string wrapper_data;
        db_transactions::get_single("1", wrapper_data);

        txns.keys.push_back("1");
        txns.values.push_back(wrapper_data);
    }

    // template int db_base<db_validator_unbond_tag>::open_db();

    void wrap_block(const zera_validator::Block &block, transactions &block_txns, bool broadcast)
    {
        zera_txn::TXNS txns;
        txns.CopyFrom(block.transactions());
        std::vector<std::string> sc_hashes;
        for (auto status : block.transactions().txn_fees_and_status())
        {
            if (status.smart_contract())
            {
                sc_hashes.push_back(base58_encode(status.txn_hash()));
            }
        }

        for (auto txn : txns.coin_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }
            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.mint_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.item_mint_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.contract_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.governance_votes())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.governance_proposals())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.smart_contract_executes())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.smart_contracts())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.smart_contract_instantiate_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.expense_ratios())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.nft_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.contract_update_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.validator_registration_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.validator_heartbeat_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.delegated_voting_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.quash_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.fast_quorum_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.revoke_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.compliance_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.burn_sbt_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        for (auto txn : txns.allowance_txns())
        {
            bool processed = check_txn_processed(txn.base().hash());

            if (txn.base().public_key().has_smart_contract_auth() || txn.base().public_key().has_governance_auth())
            {
                continue;
            }
            else
            {
                for (auto hash : sc_hashes)
                {
                    if (txn.base().hash() == hash)
                    {
                        continue;
                    }
                }
            }

            wrap_txn(&txn, block_txns, processed);
        }
        if (txns.proposal_result_txns_size() > 0)
        {
            if (!broadcast)
            {
                if (!db_transactions::exist("1"))
                {
                    gov_process::check_ledgers(&block);
                }
            }

            if (db_transactions::exist("1"))
            {
                wrap_txn_proposal(block_txns, false);
            }
        }

        db_gov_txn::get_all_data(block_txns.gov_keys, block_txns.gov_values);
    }

    void store_block(zera_validator::Block &block)
    {
        if (block.block_header().block_height() != 0)
        {
            merkle_tree::build_merkle_tree(&block);
        }

        std::string block_write;
        std::string header_write;
        std::string key1 = block_utils::block_to_write(&block, block_write, header_write);
        std::string block_data;

        auto key_vec = Hashing::sha256_hash(key1);
        if (db_blocks::get_single(key1, block_data))
        {
            return;
        }
        db_blocks::store_single(key1, block_write);
        db_headers::store_single(key1, header_write);
        db_hash_index::store_single(block.block_header().hash(), key1);
        db_hash_index::store_single(std::to_string(block.block_header().block_height()), key1);
    }

    void store_genesis_premint(const zera_validator::Block &block)
    {
        for (auto premint : block.transactions().contract_txns().at(0).premint_wallets())
        {

            db_wallets_temp::store_single(premint.address() + ZERA_SYMBOL, premint.amount());
        }
    }

    int check_genesis_validator_blocks(const zera_validator::Block &block)
    {
        if (block.block_header().block_height() == 0)
        {
            store_genesis_premint(block);
            return -1;
        }

        std::vector<std::string> keys;
        std::vector<std::string> values;
        db_validators::get_all_data(keys, values);

        if (block.transactions().validator_registration_txns().size() == 1 && block.transactions().validator_heartbeat_txns().size() == 1 && block.transactions().txn_fees_and_status_size() == 2)
        {
            std::string key;
            key = block.transactions().validator_registration_txns().at(0).generated_public_key().single();

            if (block.transactions().validator_heartbeat_txns().at(0).base().public_key().single() == key)
            {

                if (block.transactions().txn_fees_and_status_size() == 2 && block.transactions().txn_fees_and_status().at(0).base_fees() == "0" && block.transactions().txn_fees_and_status().at(1).base_fees() == "0")
                {
                    return -2;
                }
            }
        }

        return 1;
    }

    ZeraStatus check_block_hash_duplicate(const zera_validator::Block &block)
    {
        zera_validator::Block block_copy;
        block_copy.CopyFrom(block);
        zera_validator::BlockHeader *header = block_copy.mutable_block_header();

        std::string key;
        block_copy.release_signature();
        block_copy.release_public_key();
        std::string *hash_str = header->release_hash();
        std::vector<uint8_t> hash(hash_str->begin(), hash_str->end());
        std::vector<uint8_t> man_hash = Hashing::sha256_hash(block_copy.SerializeAsString());

        if (!Hashing::compare_hash(man_hash, hash))
        {
            return ZeraStatus(ZeraStatus::Code::HASH_ERROR, "block_sync_client.cpp: check_block_hash_duplicate: Hash provided and manual hash did not match");
        }
        std::string value;
        if (db_hash_index::get_single(*hash_str, key))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCKCHAIN_DUPLICATE_ERROR, "block_sync_client.cpp: check_block_hash_duplicate: db_hash_index found block, block already exists 1");
        }
        if (db_blocks::get_single(key, value))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCKCHAIN_DUPLICATE_ERROR, "block_sync_client.cpp: check_block_hash_duplicate: db_blocks found block, block already exists 2");
        }
        if (db_headers::get_single(key, value))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCKCHAIN_DUPLICATE_ERROR, "block_sync_client.cpp: check_block_hash_duplicate: db_header found block, block already exists 3");
        }

        return ZeraStatus(ZeraStatus::Code::OK);
    }

    ZeraStatus check_linked_block(const zera_validator::Block &block)
    {

        zera_validator::BlockHeader header;
        zera_validator::BlockHeader last_header;
        std::string previous_header;
        std::string previous_block;
        std::string key = "";
        std::string last_key;
        std::string hash = block.block_header().previous_block_hash();

        db_headers_tag::get_last_data(header, key);

        if (block.block_header().block_height() == 0 && key == "" && header.block_height() == 0)
        {
            return ZeraStatus(ZeraStatus::Code::OK);
        }

        if (!db_hash_index::get_single(hash, key))
            return ZeraStatus(ZeraStatus::Code::DATABASE_ERROR, "block_sync_client.cpp: check_linked_block: db_hash_index could not find previous block");
        else if (!db_headers::get_single(key, previous_header))
            return ZeraStatus(ZeraStatus::Code::DATABASE_ERROR, "block_sync_client.cpp: check_linked_block: db_headers could not find previous block");
        else if (!header.ParseFromString(previous_header))
            return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "block_sync_client.cpp: check_linked_block: could not parse previous header");
        else if (!db_blocks::get_single(key, previous_block))
            return ZeraStatus(ZeraStatus::Code::DATABASE_ERROR, "block_sync_client.cpp: check_linked_block: db_blocks could not find previous block");
        else if ((header.block_height() != block.block_header().block_height() - 1))
            return ZeraStatus(ZeraStatus::Code::BLOCK_HEIGHT_MISMATCH, "block_sync_client.cpp: check_linked_block: previous block height does not match");

        return ZeraStatus(ZeraStatus::Code::OK);
    }

    void finish_process(zera_validator::Block *block, const zera_validator::Block *original_block)
    {
        auto block_txns = block->mutable_transactions();
        // process fast quorum proposals if any
        gov_process::process_fast_quorum_block_sync(block_txns, original_block);

        quash_tracker::quash_result(block_txns);

        std::vector<std::string> txn_hash_vec;
        std::vector<std::string> allowance_txn_hash_vec;

        txn_hash_tracker::get_hash(txn_hash_vec, allowance_txn_hash_vec);

        for (auto result : block_txns->proposal_result_txns())
        {
            txn_hash_vec.push_back(result.proposal_id());
        }

        proposing::set_all_token_fees(block, txn_hash_vec, original_block->block_header().fee_address());

        if (block->transactions().proposal_result_txns_size() > 0 && original_block->transactions().proposal_result_txns_size() > 0)
        {
            sign_hash_result(block, &original_block->transactions().proposal_result_txns(0));
        }

        allowance_tracker::add_block_allowance(allowance_txn_hash_vec);
        proposing::add_temp_wallet_balance(txn_hash_vec, original_block->block_header().fee_address());

        merkle_tree::build_merkle_tree(block);
    }

    ZeraStatus process_block(const zera_validator::Block &block, bool broadcast)
    {
        contract_price_tracker::clear_prices();
        transactions txns;
        wrap_block(block, txns, broadcast);

        zera_validator::Block manual_block;
        ZeraStatus status = proposing::make_block_sync(&manual_block, txns, block.block_header().fee_address());

        if (!status.ok())
        {
            logging::print(status.read_status());
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "block_sync_client.cpp: process_block: Error creating block");
        }

        finish_process(&manual_block, &block);

        if (!check_token_fees(&manual_block, block))
        {
            logging::print("********ORIGINAL BLOCK********");
            logging::print(block.DebugString());
            for(auto fee : block.transactions().token_fees())
            {
                logging::print("fee address: ", base58_encode(fee.address()), " fee amount: ", fee.tokens().at(0).amount(), true);
            }
            // logging::print(base58_encode(block.transactions().token_fees(0).address()));
            logging::print("***MANUAL BLOCK***");
            logging::print(manual_block.DebugString());
            for(auto fee : manual_block.transactions().token_fees())
            {
                logging::print("fee address: ", base58_encode(fee.address()), " fee amount: ", fee.tokens().at(0).amount(), true);
            }
            // logging::print(base58_encode(manual_block.transactions().token_fees(0).address()));
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "block_sync_client.cpp: process_block: Token fees do not match");
        }
        else
        {
            manual_block.mutable_transactions()->clear_token_fees();
            manual_block.mutable_transactions()->mutable_token_fees()->CopyFrom(block.transactions().token_fees());
            manual_block.mutable_transactions()->clear_txn_fees_and_status();
            manual_block.mutable_transactions()->mutable_txn_fees_and_status()->CopyFrom(block.transactions().txn_fees_and_status());
        }

        block_utils::set_block_sync(&manual_block, block.block_header());

        if (block.block_header().block_height() != manual_block.block_header().block_height())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "block_sync_client.cpp: process_block: Block height does not match");
        }

        if (block.block_header().hash() != manual_block.block_header().hash())
        {
            logging::print("********ORIGINAL BLOCK********");
            logging::print(block.DebugString());
            logging::print("********MANUAL BLOCK********");
            logging::print(manual_block.DebugString());
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "block_sync_client.cpp: process_block: Block hash does not match");
        }

        std::string block_write;
        std::string header_write;

        std::string key1 = block_utils::block_to_write(&manual_block, block_write, header_write);

        auto key_vec = Hashing::sha256_hash(key1);

        if (db_blocks::exist(key1))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "proposer.h: make_block: Block already exists.");
        }

        db_blocks::store_single(key1, block_write);
        db_headers::store_single(key1, header_write);
        db_hash_index::store_single(manual_block.block_header().hash(), key1);
        db_hash_index::store_single(std::to_string(manual_block.block_header().block_height()), key1);
        block_process::store_txns(&manual_block, true, broadcast);
        return ZeraStatus();
    }
}

std::mutex ValidateBlock::processing_mutex;

ZeraStatus ValidateBlock::block_process(const zera_validator::Block &block, bool broadcast)
{
    ZeraStatus status = check_block_hash_duplicate(block);

    if (!status.ok())
    {
        status.prepend_message("block_sync_client: BlockSyncProcessResponse");
        return status;
    }

    status = check_linked_block(block);

    if (!status.ok())
    {
        status.prepend_message("block_sync_client: BlockSyncProcessResponse");
        return status;
    }

    if (!broadcast)
    {

        int stat = check_genesis_validator_blocks(block);

        // check for validator blocks
        if (stat == -2)
        {
            zera_validator::Block manual_block;
            manual_block.CopyFrom(block);

            zera_txn::PublicKey public_key;
            public_key.set_single(block.transactions().validator_registration_txns(0).base().public_key().single());

            status = block_process::check_nonce(public_key, block.transactions().validator_registration_txns(0).base().nonce());

            if (!status.ok())
            {
                logging::print(status.read_status());
                return status;
            }

            std::string wallet_adr;
            for (auto txn : block.transactions().validator_registration_txns())
            {
                wallet_adr = wallets::generate_wallet(txn.base().public_key());
                uint64_t txn_nonce = txn.base().nonce();
                nonce_tracker::add_nonce(wallet_adr, txn_nonce, txn.base().hash());
                nonce_tracker::add_used_nonce(wallet_adr, txn_nonce);
            }

            status = block_process::check_nonce(public_key, block.transactions().validator_heartbeat_txns(0).base().nonce());

            if (!status.ok())
            {
                logging::print(status.read_status());
                return status;
            }

            for (auto txn : block.transactions().validator_heartbeat_txns())
            {
                uint64_t txn_nonce = txn.base().nonce();
                nonce_tracker::add_nonce(wallet_adr, txn_nonce, txn.base().hash());
                nonce_tracker::add_used_nonce(wallet_adr, txn_nonce);
            }

            store_block(manual_block);
            block_process::store_txns(&manual_block, true, broadcast);
            return ZeraStatus();
        }
        else if (stat == -1)
        {
            //GENESIS BLOCK
            zera_validator::Block manual_block;
            manual_block.CopyFrom(block);
            store_block(manual_block);
            std::string wallet_adr = wallets::generate_wallet(block.transactions().validator_registration_txns(0).base().public_key());
            nonce_tracker::add_nonce(wallet_adr, 1, block.transactions().validator_registration_txns(0).base().hash());
            nonce_tracker::add_used_nonce(wallet_adr, 1);
            block_process::store_txns(&manual_block, true, broadcast);
            return ZeraStatus();
        }
    }

    status = process_block(block, broadcast);

    if (!status.ok())
    {
        logging::print(status.read_status());
        return status;
    }

    if (broadcast)
    {
        zera_validator::Block *attestation_block = new zera_validator::Block();
        attestation_block->CopyFrom(block);

        try
        {
            ValidatorAPIClient::PromoteStagedEventsToPending(block);
            // Enqueue the task into the thread pool
            ValidatorThreadPool::enqueueTask([attestation_block]()
                                             { 
                AttestationProcess::CreateAttestation(attestation_block); 
                delete attestation_block; });
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }

    return ZeraStatus();
}