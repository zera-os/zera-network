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
        restricted_key4.mutable_public_key()->set_smart_contract_auth("sc_bridge_proxy_1");
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

    void calc_fee(zera_txn::InstrumentContract *txn)
    {
        uint256_t equiv;
        zera_fees::get_cur_equiv("$ZRA+0000", equiv);
        zera_txn::InstrumentContract fee_contract;
        block_process::get_contract("$ZRA+0000", fee_contract);

        uint256_t fee_per_byte(get_txn_fee_contract(zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE, txn));
        int byte_size = txn->ByteSize() + 64;
        std::string denomination_str = fee_contract.coin_denomination().amount();
        int256_t txn_fee_amount;
        uint256_t fee = fee_per_byte * byte_size;
        uint256_t denomination(denomination_str);
        txn_fee_amount = (fee * denomination) / equiv;

        uint256_t key_fee = get_key_fee(txn->base().public_key());
        txn_fee_amount += (key_fee * denomination) / equiv;

        txn->mutable_base()->set_fee_amount(txn_fee_amount.str());
    }

    void set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
    {
        std::string sc_auth = "sc_" + sender.smart_contract_instance;
        base->mutable_public_key()->set_smart_contract_auth(sc_auth);
        base->set_fee_amount("1000000000000");
        base->set_nonce(sender.sc_nonce);
        sender.sc_nonce++;
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        base->mutable_timestamp()->set_seconds(sender.block_time);
    }

    std::string process_txn(SenderDataType &sender, const zera_txn::InstrumentContract &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        std::string fee_address = sender.fee_address;
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE, false, fee_address, true);
        if (status.ok())
        {
            sender.txn_hashes.push_back(txn.base().hash());
            block_txns.add_contract_txns()->CopyFrom(txn);
            txn_hash_tracker::add_sc_hash(txn.base().hash());
        }
        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    std::string create_instrument_contract_bridge(SenderDataType &sender, const std::string &symbol, const std::string &name, const std::string &denomination, const std::string &contract_id, const std::string &mint_id, const std::string &uri, const std::string &authorized_key, const std::string &pre_mint_wallet, const std::string &premint_amount)
    {
        zera_txn::InstrumentContract txn;
        // add premint wallet
        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);
        txn.set_contract_version(1);
        txn.set_symbol(symbol);
        txn.set_name(name);
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
        calc_fee(&txn);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}

WasmEdge_Result InstrumentContractBridge(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType sender = *(SenderDataType *)Data;

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

    std::vector<unsigned char> SymbolKey(SymbolSize);
    std::vector<unsigned char> NameKey(NameSize);
    std::vector<unsigned char> DenominationKey(DenominationSize);
    std::vector<unsigned char> ContractIdKey(ContractIdSize);
    std::vector<unsigned char> MintIDKey(MintIDSize);
    std::vector<unsigned char> URIKey(URISize);
    std::vector<unsigned char> AuthorizedkeyKey(AuthorizedkeySize);
    std::vector<unsigned char> PreMintKey(PreMintSize);
    std::vector<unsigned char> PremintAmountKey(PremintAmountSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string symbol;
    std::string name;
    std::string denomination;
    std::string contract_id;

    logging::print("[InstrumentContractBridge] Res");
    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, SymbolKey.data(), SymbolPointer, SymbolSize);
    if (WasmEdge_ResultOK(Res2))
    {
        std::string symbol_temp(reinterpret_cast<char *>(SymbolKey.data()), SymbolSize);
        symbol = symbol_temp;
        logging::print("[InstrumentContractBridge] Symbol:", symbol, true);
    }
    else
    {
        return Res2;
    }

    logging::print("[InstrumentContractBridge] Res2");
    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, NameKey.data(), NamePointer, NameSize);
    if (WasmEdge_ResultOK(Res3))
    {
        std::string name_temp(reinterpret_cast<char *>(NameKey.data()), NameSize);
        name = name_temp;
        logging::print("[InstrumentContractBridge] Name:", name, true);
    }
    else
    {
        return Res3;
    }

    logging::print("[InstrumentContractBridge] Res3");
    WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, DenominationKey.data(), DenominationPointer, DenominationSize);
    if (WasmEdge_ResultOK(Res4))
    {
        std::string denomination_temp(reinterpret_cast<char *>(DenominationKey.data()), DenominationSize);
        denomination = denomination_temp;
        logging::print("[InstrumentContractBridge] Denomination:", denomination, true);
    }
    else
    {
        return Res4;
    }

    logging::print("[InstrumentContractBridge] Res4");
    WasmEdge_Result Res5 = WasmEdge_MemoryInstanceGetData(MemCxt, ContractIdKey.data(), ContractIdPointer, ContractIdSize);
    if (WasmEdge_ResultOK(Res5))
    {
        std::string contract_id_temp(reinterpret_cast<char *>(ContractIdKey.data()), ContractIdSize);
        contract_id = contract_id_temp;
        logging::print("[InstrumentContractBridge] Contract ID:", contract_id, true);
    }
    else
    {
        return Res5;
    }

    logging::print("[InstrumentContractBridge] Res5");
    WasmEdge_Result Res6 = WasmEdge_MemoryInstanceGetData(MemCxt, MintIDKey.data(), MintIDPointer, MintIDSize);
    std::string mint_id;
    if (WasmEdge_ResultOK(Res6))
    {
        std::string mint_id_temp(reinterpret_cast<char *>(MintIDKey.data()), MintIDSize);
        mint_id = mint_id_temp;
        logging::print("[InstrumentContractBridge] Mint ID:", mint_id, true);
    }
    else
    {
        return Res6;
    }

    logging::print("[InstrumentContractBridge] Res6");
    WasmEdge_Result Res7 = WasmEdge_MemoryInstanceGetData(MemCxt, URIKey.data(), URIPointer, URISize);
    std::string uri;
    if (WasmEdge_ResultOK(Res7))
    {
        std::string uri_temp(reinterpret_cast<char *>(URIKey.data()), URISize);
        uri = uri_temp;
        logging::print("[InstrumentContractBridge] URI:", uri, true);
    }
    else
    {
        return Res7;
    }

    logging::print("[InstrumentContractBridge] Res7");
    WasmEdge_Result Res8 = WasmEdge_MemoryInstanceGetData(MemCxt, AuthorizedkeyKey.data(), AuthorizedkeyPointer, AuthorizedkeySize);
    std::string authorized_key;
    if (WasmEdge_ResultOK(Res8))
    {
        std::string authorized_key_temp(reinterpret_cast<char *>(AuthorizedkeyKey.data()), AuthorizedkeySize);
        authorized_key = authorized_key_temp;
        logging::print("[InstrumentContractBridge] Authorized Key:", authorized_key, true);
    }
    else
    {
        return Res8;
    }

    logging::print("[InstrumentContractBridge] Res8");
    WasmEdge_Result Res9 = WasmEdge_MemoryInstanceGetData(MemCxt, PreMintKey.data(), PreMintPointer, PreMintSize);
    std::string pre_mint_wallet;
    if (WasmEdge_ResultOK(Res9))
    {
        std::string pre_mint_temp(reinterpret_cast<char *>(PreMintKey.data()), PreMintSize);
        pre_mint_wallet = pre_mint_temp;
        logging::print("[InstrumentContractBridge] Pre Mint Wallet:", pre_mint_wallet, true);
    }
    else
    {
        return Res9;
    }

    logging::print("[InstrumentContractBridge] Res9");
    WasmEdge_Result Res10 = WasmEdge_MemoryInstanceGetData(MemCxt, PremintAmountKey.data(), PremintAmountPointer, PremintAmountSize);
    std::string premint_amount;
    if (WasmEdge_ResultOK(Res10))
    {
        std::string premint_amount_temp(reinterpret_cast<char *>(PremintAmountKey.data()), PremintAmountSize);
        premint_amount = premint_amount_temp;
        logging::print("[InstrumentContractBridge] Premint Amount:", premint_amount, true);
    }
    else
    {
        return Res10;
    }

    std::string status = create_instrument_contract_bridge(sender, symbol, name, denomination, contract_id, mint_id, uri, authorized_key, pre_mint_wallet, premint_amount);

    const char *val = status.c_str();
    const size_t len = status.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
}