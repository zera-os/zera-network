#include "native_function_get_ace.h"
#include "smart_contract_service.h"
#include "db_base.h"
#include "hashing.h"
#include "../../temp_data/temp_data.h"
#include "wallets.h"
#include "proposer.h"
#include "zera_status.h"
#include "../../block_process/block_process.h"
#include "utils.h"
#include "smart_contract_sender_data.h"
#include "fees.h"
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>
#include "nf_helpers.h"

namespace
{
    void create_gov(zera_txn::InstrumentContract *txn, uint64_t start_timestamp)
    {
        zera_txn::Governance *governance = txn->mutable_governance();
        governance->set_type(zera_txn::GOVERNANCE_TYPE::STAGED);
        governance->set_regular_quorum(5010);
        governance->set_fast_quorum(5010);
        governance->add_voting_instrument(txn->contract_id());
        governance->set_threshold(50);
        governance->set_chicken_dinner(false);
        governance->set_allow_multi(true);
        governance->set_voting_period(1);
        governance->set_proposal_period(zera_txn::PROPOSAL_PERIOD::MONTHS);
        governance->add_allowed_proposal_instrument(txn->contract_id());

        zera_txn::Stage *stage = governance->add_stage_length();
        stage->set_length(1);
        stage->set_max_approved(10);
        stage->set_period(zera_txn::PROPOSAL_PERIOD::DAYS);
        stage->set_break_(false);

        zera_txn::Stage *stage2 = governance->add_stage_length();
        stage2->set_length(0);
        stage2->set_max_approved(3);
        stage2->set_period(zera_txn::PROPOSAL_PERIOD::DAYS);
        stage2->set_break_(false);

        governance->mutable_start_timestamp()->set_seconds(start_timestamp);
    }
    void make_restricted_key(zera_txn::InstrumentContract *txn, const std::string &authorized_key, SenderDataType &sender)
    {
        zera_txn::RestrictedKey restricted_key4;
        restricted_key4.mutable_public_key()->set_smart_contract_auth("sc_zera_bridge_proxy_1");
        restricted_key4.set_mint(true);
        txn->add_restricted_keys()->CopyFrom(restricted_key4);
        restricted_key4.set_key_weight(0);

        zera_txn::RestrictedKey restricted_key;
        restricted_key.mutable_public_key()->set_governance_auth("gov_$BRIDGETOKENS+0000");
        restricted_key.set_update_contract(true);
        restricted_key.set_transfer(true);
        restricted_key.set_quash(true);
        restricted_key.set_vote(true);
        restricted_key.set_propose(true);
        restricted_key.set_expense_ratio(true);
        restricted_key.set_revoke(true);
        restricted_key.set_key_weight(0);
        txn->add_restricted_keys()->CopyFrom(restricted_key);

        zera_txn::RestrictedKey *restricted_key3 = txn->add_restricted_keys();
        std::string own_gov_key = "gov_" + txn->contract_id();
        restricted_key3->mutable_public_key()->set_governance_auth(own_gov_key);
        restricted_key3->set_update_contract(true);
        restricted_key3->set_transfer(true);
        restricted_key3->set_quash(true);
        restricted_key3->set_vote(true);
        restricted_key3->set_propose(true);
        restricted_key3->set_expense_ratio(true);
        restricted_key3->set_revoke(true);
        restricted_key3->set_key_weight(2);

        if (authorized_key == "N/A")
        {
            return;
        }

        std::string convert_pub = "r_A_c_" + authorized_key;
        auto pub_key = base58_decode_public_key(convert_pub);
        std::string pub_key_str(pub_key.begin(), pub_key.end());

        zera_txn::RestrictedKey restricted_key2;
        restricted_key2.mutable_public_key()->set_single(pub_key_str);
        restricted_key2.set_update_contract(true);
        restricted_key2.set_transfer(true);
        restricted_key2.set_quash(true);
        restricted_key2.set_vote(true);
        restricted_key2.set_propose(true);
        restricted_key2.set_expense_ratio(true);
        restricted_key2.set_revoke(true);
        restricted_key2.set_key_weight(1);
        txn->add_restricted_keys()->CopyFrom(restricted_key2);
    }

    std::string process_txn(SenderDataType &sender, const zera_txn::InstrumentContract &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        std::string fee_address = sender.fee_address;
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE, false, fee_address, true, sender.txn_hash, sender.fee_smart_contract_wallet);
        if (status.ok())
        {
            if (status.txn_status() == zera_txn::TXN_STATUS::OK)
            {
                sender.txn_hashes.push_back(txn.base().hash());
                block_txns.add_contract_txns()->CopyFrom(txn);
                txn_hash_tracker::add_sc_hash(txn.base().hash());
            }
            else
            {
                balance_tracker::remove_txn_balance(txn.base().hash());
            }
        }
        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    std::string create_instrument_contract_bridge(SenderDataType &sender, const std::string &symbol, const std::string &name, const std::string &denomination, const std::string &contract_id, const std::string &mint_id, const std::string &uri, const std::string &authorized_key, const std::string &pre_mint_wallet, const std::string &premint_amount)
    {
        zera_txn::InstrumentContract txn;
        // add premint wallet
        zera_txn::BaseTXN *base = txn.mutable_base();

        std::string wrapped_name = "Wrapped " + name;
        set_base(base, sender);
        txn.set_contract_version(1);
        txn.set_symbol(symbol);
        txn.set_name(wrapped_name);
        txn.mutable_coin_denomination()->set_amount(denomination);
        txn.mutable_coin_denomination()->set_denomination_name("unit");
        txn.set_contract_id(contract_id);
        uint256_t denomination_256(denomination);
        uint256_t big_number(1000000000000000000000);
        uint256_t max_supply = big_number * denomination_256;
        txn.set_max_supply(max_supply.str());
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        make_restricted_key(&txn, authorized_key, sender);

        zera_txn::KeyValuePair *custom_parameter = txn.add_custom_parameters();
        custom_parameter->set_key("mint_id");
        custom_parameter->set_value(mint_id);

        zera_txn::KeyValuePair *custom_parameter2 = txn.add_custom_parameters();
        custom_parameter2->set_key("uri");

        if (uri != "N/A")
        {
            custom_parameter2->set_value(uri);
        }
        else
        {
            custom_parameter2->set_value("");
        }

        auto premint_vec = base58_decode(pre_mint_wallet);
        std::string pre_mint_wallet_str(premint_vec.begin(), premint_vec.end());

        zera_txn::PreMintWallet *pre_mint_wallet_obj = txn.add_premint_wallets();
        pre_mint_wallet_obj->set_address(pre_mint_wallet_str);
        pre_mint_wallet_obj->set_amount(premint_amount);

        uint64_t start_timestamp = sender.block_time + 604800;
        create_gov(&txn, start_timestamp);
        uint256_t txn_fee_amount;
        calc_fee_contract_txn(&txn, sender.fee_id, txn_fee_amount);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}

WasmEdge_Result InstrumentContractBridge(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType *sender = (SenderDataType *)Data;

    // if(sender.smart_contract_wallet != "")
    // {
    //     return WasmEdge_Result_Terminate;
    // }

    logging::print("[InstrumentContractBridge] START");

    uint32_t SymbolPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t SymbolSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t NamePointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t NameSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t DenominationPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t DenominationSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t ContractIdPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t ContractIdSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t MintIDPointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t MintIDSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t URIPointer = WasmEdge_ValueGetI32(In[10]);
    uint32_t URISize = WasmEdge_ValueGetI32(In[11]);

    uint32_t AuthorizedkeyPointer = WasmEdge_ValueGetI32(In[12]);
    uint32_t AuthorizedkeySize = WasmEdge_ValueGetI32(In[13]);

    uint32_t PreMintPointer = WasmEdge_ValueGetI32(In[14]);
    uint32_t PreMintSize = WasmEdge_ValueGetI32(In[15]);

    uint32_t PremintAmountPointer = WasmEdge_ValueGetI32(In[16]);
    uint32_t PremintAmountSize = WasmEdge_ValueGetI32(In[17]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[18]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string symbol;
    std::string name;
    std::string denomination;
    std::string contract_id;

    if (!read_wasm_param(MemCxt, SymbolPointer, SymbolSize, symbol))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Symbol:", symbol, true);

    if (!read_wasm_param(MemCxt, NamePointer, NameSize, name))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Name:", name, true);

    if (!read_wasm_param(MemCxt, DenominationPointer, DenominationSize, denomination))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Denomination:", denomination, true);

    if (!read_wasm_param(MemCxt, ContractIdPointer, ContractIdSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Contract ID:", contract_id, true);

    std::string mint_id;
    if (!read_wasm_param(MemCxt, MintIDPointer, MintIDSize, mint_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Mint ID:", mint_id, true);

    std::string uri;
    if (!read_wasm_param(MemCxt, URIPointer, URISize, uri))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] URI:", uri, true);

    std::string authorized_key;
    if (!read_wasm_param(MemCxt, AuthorizedkeyPointer, AuthorizedkeySize, authorized_key))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Authorized Key:", authorized_key, true);

    std::string pre_mint_wallet;
    if (!read_wasm_param(MemCxt, PreMintPointer, PreMintSize, pre_mint_wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Pre Mint Wallet:", pre_mint_wallet, true);

    std::string premint_amount;
    if (!read_wasm_param(MemCxt, PremintAmountPointer, PremintAmountSize, premint_amount))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Premint Amount:", premint_amount, true);

    std::string status = create_instrument_contract_bridge(*sender, symbol, name, denomination, contract_id, mint_id, uri, authorized_key, pre_mint_wallet, premint_amount);

    const char *val = status.c_str();
    const size_t len = status.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
}