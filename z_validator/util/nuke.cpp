#include "nuke.h"
#include <filesystem>

using uint256_t = boost::multiprecision::uint256_t;

namespace
{
    void create_base(zera_txn::InstrumentContract &txn)
    {
        zera_txn::BaseTXN *base = txn.mutable_base();

        base->set_fee_id("$ZRA+0000");
        base->set_fee_amount("0");
        base->set_nonce(0);
        base->mutable_timestamp()->CopyFrom(google::protobuf::util::TimeUtil::GetCurrentTime());
        base->mutable_public_key()->set_single("GENESIS");

        std::vector<uint8_t> hash = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash_str(hash.begin(), hash.end());
        base->set_hash(hash_str);

        base->set_signature("GENESIS");
    }
    // IIT -  month staged, 7 day then rest of month
    // ACE - 1 day staggared

    // Add this helper function at the top of the namespace (after line 15)
    void create_zra_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("ZERA");
        txn.set_symbol("ZRA");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("1000000000000000000");
        txn.set_contract_version(100000);
        txn.set_contract_id("$ZRA+0000");
        txn.mutable_coin_denomination()->set_amount("1000000000");
        txn.mutable_coin_denomination()->set_denomination_name("ZERITE");
        zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        custom_parameter->set_key("uri");
        custom_parameter->set_value("https://cdn.zerafile.io/token/$ZRA+0000/uri-7BhKX7T8SawA.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key, "gov_$ZRA+0000", 0);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_standard_governance(governance);
        nuke::set_all_zra_premints(&txn);
        create_base(txn);

        balance_tracker::add_txn_balance_premint(txn.premint_wallets(), txn.contract_id(), txn.base().hash());
    }

    void create_legal_contract(zera_txn::InstrumentContract &txn)
    {
        zera_txn::BaseTXN *base = txn.mutable_base();
        base->set_memo(nuke::get_legal_string());
        txn.set_name("Legal");
        txn.set_symbol("LEGAL");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);
        txn.set_contract_id("$LEGAL+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("LEGAL");
        zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        custom_parameter->set_key("uri");
        custom_parameter->set_value("https://cdn.zerafile.io/token/$LEGAL+0000/uri-55C5KGnCT7ok.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$LEGAL+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_standard_governance(governance);
        create_base(txn);
    }

    void create_treasury_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("Treasury");
        txn.set_symbol("TREASURY");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);

        txn.set_contract_id("$TREASURY+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("TREASURY");
        zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        custom_parameter->set_key("uri");
        custom_parameter->set_value("https://cdn.zerafile.io/token/$TREASURY+0000/uri-gM3Y8btk51rb.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$TREASURY+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_standard_governance(governance);
        create_base(txn);
    }

    void create_zip_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("ZERA Improvement Proposal");
        txn.set_symbol("ZIP");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);
        txn.set_contract_id("$ZIP+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("ZIP");
        zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        custom_parameter->set_key("uri");
        custom_parameter->set_value("https://cdn.zerafile.io/token/$ZIP+0000/uri-YL6Auqkc6Gcw.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$ZIP+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_standard_governance(governance);
        create_base(txn);
    }

    void create_zmt_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("ZERA Marketing Token");
        txn.set_symbol("ZMT");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);
        txn.set_contract_id("$ZMT+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("ZMT");
        zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        custom_parameter->set_key("uri");
        custom_parameter->set_value("https://cdn.zerafile.io/token/$ZMT+0000/uri-OrQVNMdcXuny.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$ZMT+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_standard_governance(governance);
        create_base(txn);
    }

    void create_iit_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("Innovative Initiatives Token");
        txn.set_symbol("IIT");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);
        txn.set_contract_id("$IIT+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("iota");
        zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        custom_parameter->set_key("uri");
        custom_parameter->set_value("https://cdn.zerafile.io/token/$IIT+0000/uri-vEbqZRjBU7NY.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$IIT+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_iit_governance(governance);
        txn.set_immutable_kyc_status(true);
        txn.set_kyc_status(false);
        create_base(txn);
    }

    void create_bridge_guardian_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("Bridge Guardian");
        txn.set_symbol("BRIDGEGUARDIAN");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);
        txn.set_contract_id("$BRIDGEGUARDIAN+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("guard");
        // zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        // custom_parameter->set_key("uri");
        // custom_parameter->set_value("https://cdn.zerafile.io/token/$IIT+0000/uri-vEbqZRjBU7NY.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$BRIDGEGUARDIAN+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_standard_governance(governance);
        create_base(txn);
    }

    void create_bridge_tokens_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("Bridge Tokens");
        txn.set_symbol("BRIDGETOKENS");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);
        txn.set_contract_id("$BRIDGETOKENS+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("token");
        // zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        // custom_parameter->set_key("uri");
        // custom_parameter->set_value("https://cdn.zerafile.io/token/$IIT+0000/uri-vEbqZRjBU7NY.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$BRIDGETOKENS+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_standard_governance(governance);
        create_base(txn);
    }

    void create_ace_contract_contract(zera_txn::InstrumentContract &txn)
    {
        txn.set_name("Authorized Currency Equivalent");
        txn.set_symbol("ACE");
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        txn.set_max_supply("0");
        txn.set_contract_version(100000);
        txn.set_contract_id("$ACE+0000");
        txn.mutable_coin_denomination()->set_amount("1");
        txn.mutable_coin_denomination()->set_denomination_name("ace");
        // zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        // custom_parameter->set_key("uri");
        // custom_parameter->set_value("https://cdn.zerafile.io/token/$IIT+0000/uri-vEbqZRjBU7NY.json");

        zera_txn::RestrictedKey *restricted_key = txn.add_restricted_keys();
        restricted_key->mutable_public_key()->set_single("$ZRA+0000");
        restricted_key->set_key_weight(0);

        zera_txn::RestrictedKey *restricted_key1 = txn.add_restricted_keys();
        nuke::add_gov_restricted_key(restricted_key1, "gov_$ACE+0000", 1);

        zera_txn::Governance *governance = txn.mutable_governance();
        nuke::set_ace_governance(governance);
        create_base(txn);
    }

    void create_validator_registration_heartbeat(zera_txn::ValidatorRegistration *registration, zera_txn::ValidatorHeartbeat *heartbeat)
    {

        // set the generated public key
        registration->mutable_generated_public_key()->set_single(ValidatorConfig::get_gen_public_key());
        zera_txn::Validator *validator = registration->mutable_validator();
        nuke::make_vali(validator);

        registration->mutable_base()->set_fee_amount("0");
        registration->mutable_base()->set_fee_id(ZERA_SYMBOL);
        registration->mutable_base()->mutable_public_key()->set_single(ValidatorConfig::get_public_key());
        registration->mutable_base()->set_nonce(0);
        registration->set_register_(true);
        registration->mutable_base()->set_memo("Genesis Registration");

        google::protobuf::Timestamp *tsp = registration->mutable_base()->mutable_timestamp();
        tsp->CopyFrom(google::protobuf::util::TimeUtil::GetCurrentTime());

        // sign main transaction with original key
        signatures::sign_txns(registration, ValidatorConfig::get_key_pair());

        std::vector<uint8_t> hash = Hashing::sha256_hash(registration->SerializeAsString());
        std::string hash_str(hash.begin(), hash.end());
        registration->mutable_base()->set_hash(hash_str);
        std::string gen_sig = signatures::sign_block_hash(hash_str, ValidatorConfig::get_gen_key_pair());
        registration->set_generated_signature(gen_sig);

        heartbeat->set_online(true);
        heartbeat->set_version(VERSION);
        zera_txn::BaseTXN *base = heartbeat->mutable_base();
        base->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
        base->set_fee_id("$ZRA+0000");
        base->set_fee_amount("0");
        base->set_memo("Genesis Heartbeat");
        base->set_nonce(1);

        google::protobuf::Timestamp *ts = base->mutable_timestamp();
        google::protobuf::Timestamp now_ts = google::protobuf::util::TimeUtil::GetCurrentTime();
        ts->set_seconds(now_ts.seconds());
        ts->set_nanos(now_ts.nanos());

        signatures::sign_txns(heartbeat, ValidatorConfig::get_gen_key_pair());

        auto heart_hash_vec = Hashing::sha256_hash(heartbeat->SerializeAsString());
        std::string heart_hash(heart_hash_vec.begin(), heart_hash_vec.end());
        base->set_hash(heart_hash);
    }
}

void nuke::create_genesis_block()
{

    set_explorer_config();
    ValidatorConfig::generate_keys();

    zera_validator::Block genny_block;

    zera_txn::InstrumentContract *zera_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *legal_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *treasury_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *zip_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *zmt_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *iit_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *bridge_guardian_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *bridge_tokens_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::InstrumentContract *ace_contract = genny_block.mutable_transactions()->add_contract_txns();
    zera_txn::ValidatorRegistration *registration = genny_block.mutable_transactions()->add_validator_registration_txns();
    zera_txn::ValidatorHeartbeat *heartbeat = genny_block.mutable_transactions()->add_validator_heartbeat_txns();

    zera_txn::TXNStatusFees *status_fees = genny_block.mutable_transactions()->add_txn_fees_and_status();
    status_fees->set_base_contract_id("$ZRA+0000");
    status_fees->set_contract_fees("0");
    status_fees->set_base_fees("0");
    status_fees->set_status(zera_txn::TXN_STATUS::OK);
    zera_txn::TXNStatusFees *status_fees1 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees2 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees3 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees4 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees5 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees6 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees7 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees8 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees9 = genny_block.mutable_transactions()->add_txn_fees_and_status();
    zera_txn::TXNStatusFees *status_fees10 = genny_block.mutable_transactions()->add_txn_fees_and_status();

    status_fees1->CopyFrom(*status_fees);
    status_fees2->CopyFrom(*status_fees);
    status_fees3->CopyFrom(*status_fees);
    status_fees4->CopyFrom(*status_fees);
    status_fees5->CopyFrom(*status_fees);
    status_fees6->CopyFrom(*status_fees);
    status_fees7->CopyFrom(*status_fees);
    status_fees8->CopyFrom(*status_fees);
    status_fees9->CopyFrom(*status_fees);
    status_fees10->CopyFrom(*status_fees);

    create_zra_contract(*zera_contract);
    create_legal_contract(*legal_contract);
    create_treasury_contract(*treasury_contract);
    create_zip_contract(*zip_contract);
    create_zmt_contract(*zmt_contract);
    create_iit_contract(*iit_contract);
    create_bridge_guardian_contract(*bridge_guardian_contract);
    create_bridge_tokens_contract(*bridge_tokens_contract);
    create_ace_contract_contract(*ace_contract);
    create_validator_registration_heartbeat(registration, heartbeat);

    status_fees->set_txn_hash(zera_contract->base().hash());
    status_fees1->set_txn_hash(legal_contract->base().hash());
    status_fees2->set_txn_hash(treasury_contract->base().hash());
    status_fees3->set_txn_hash(zip_contract->base().hash());
    status_fees4->set_txn_hash(zmt_contract->base().hash());
    status_fees5->set_txn_hash(iit_contract->base().hash());
    status_fees6->set_txn_hash(bridge_guardian_contract->base().hash());
    status_fees7->set_txn_hash(bridge_tokens_contract->base().hash());
    status_fees8->set_txn_hash(ace_contract->base().hash());
    status_fees9->set_txn_hash(registration->base().hash());
    status_fees10->set_txn_hash(heartbeat->base().hash());

    zera_validator::BlockHeader *header = genny_block.mutable_block_header();
    google::protobuf::Timestamp *ts = header->mutable_timestamp();
    google::protobuf::Timestamp now_ts = google::protobuf::util::TimeUtil::GetCurrentTime();

    ts->set_seconds(now_ts.seconds());
    ts->set_nanos(now_ts.nanos());
    std::string last_key;

    header->set_block_height(0);
    header->set_version(VERSION);

    merkle_tree::build_merkle_tree(&genny_block);

    signatures::sign_block_proposer(&genny_block, ValidatorConfig::get_gen_key_pair());
    std::vector<uint8_t> hash = Hashing::sha256_hash(genny_block.SerializeAsString());
    std::string hash_str(hash.begin(), hash.end());
    header->set_hash(hash_str);

    std::string wallet_address = wallets::generate_wallet_single(ValidatorConfig::get_public_key());
    nonce_tracker::add_used_nonce(wallet_address, 0);
    nonce_tracker::add_used_nonce(wallet_address, 1);

    std::string write_block;
    std::string write_header;

    std::string key = block_utils::block_to_write(&genny_block, write_block, write_header);

    // Store data in database
    db_blocks::store_single(key, write_block);
    db_headers::store_single(key, write_header);
    db_hash_index::store_single(genny_block.block_header().hash(), key);
    db_hash_index::store_single(std::to_string(genny_block.block_header().block_height()), key);
    std::vector<std::string> txn_hash_vec;
    txn_hash_vec.push_back(zera_contract->base().hash());
    proposing::add_temp_wallet_balance(txn_hash_vec, ValidatorConfig::get_fee_address_string());
    validator_utils::archive_balances("0");
    block_process::store_txns(&genny_block, true);
}