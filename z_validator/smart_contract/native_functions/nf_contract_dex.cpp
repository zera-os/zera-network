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
#include <regex>
#include "nf_helpers.h"

namespace
{

    void make_mint_key(zera_txn::InstrumentContract *txn)
    {
        zera_txn::RestrictedKey restricted_key;
        restricted_key.mutable_public_key()->set_smart_contract_auth("sc_zera_dex_proxy_v1_1");
        restricted_key.set_mint(true);
        restricted_key.set_update_contract(true);
        restricted_key.set_transfer(true);
        restricted_key.set_key_weight(0);
        txn->add_restricted_keys()->CopyFrom(restricted_key);
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

    std::string create_contract(SenderDataType &sender, const std::string &contract_id, const std::string &pair2, const std::string &premint_amount, const std::string &premint_wallet, const std::string &fee_percentage, std::string &new_contract_id)
    {
        zera_txn::InstrumentContract txn;
        // add premint wallet
        std::string symbol1 = std::regex_replace(contract_id, std::regex("\\+\\d+$"), ""); // Remove +digits
        symbol1 = symbol1.substr(1);
        std::string contract1 = contract_id.substr(1);

        std::string symbol2 = std::regex_replace(pair2, std::regex("\\+\\d+$"), ""); // Remove +digits
        symbol2 = symbol2.substr(1);
        std::string contract2 = pair2.substr(1);

        std::string name = "DEX PAIR " + symbol1 + " " + symbol2;
        std::string symbol = "dex-" + symbol1 + fee_percentage + symbol2;

        std::smatch match;
        std::regex pattern("\\+(\\d+)$");

        std::string contract_id_num;
        if (std::regex_search(contract_id, match, pattern))
        {
            contract_id_num = match[1].str(); // captures just the digits
        }

        std::string pair2_num;
        if (std::regex_search(pair2, match, pattern))
        {
            pair2_num = match[1].str();
        }

        new_contract_id = "$" + symbol + "+" + contract_id_num + pair2_num;

        zera_txn::BaseTXN *base = txn.mutable_base();
        set_base(base, sender);
        txn.set_contract_version(1);
        txn.set_symbol(symbol);
        txn.set_name(name);
        txn.mutable_coin_denomination()->set_amount("1000000000");
        txn.mutable_coin_denomination()->set_denomination_name("lp");
        txn.set_contract_id(new_contract_id);
        uint256_t max_supply = (uint256_t(1) << 256) - 1;
        txn.set_max_supply(max_supply.str());
        txn.set_type(zera_txn::CONTRACT_TYPE::TOKEN);
        make_mint_key(&txn);

        auto premint_vec = base58_decode(premint_wallet);
        std::string pre_mint_wallet_str(premint_vec.begin(), premint_vec.end());

        zera_txn::PreMintWallet *pre_mint_wallet_obj = txn.add_premint_wallets();
        pre_mint_wallet_obj->set_address(pre_mint_wallet_str);
        pre_mint_wallet_obj->set_amount(premint_amount);

        uint256_t txn_fee_amount;
        calc_fee_contract_txn(&txn, sender.fee_id, txn_fee_amount);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}

WasmEdge_Result InstrumentContractDEX(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType *sender = (SenderDataType *)Data;

    if (sender->smart_contract_instance != "zera_dex_proxy_1" && sender->smart_contract_instance != "zera_dex_proxy_v1_1")
    {
        logging::print("[InstrumentContractDEX] FAILED: Not authorized", true);
        return WasmEdge_Result_Terminate;
    }

    logging::print("[InstrumentContractDEX] START");

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t Pair2Pointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t Pair2Size = WasmEdge_ValueGetI32(In[3]);

    uint32_t PreMintPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t PreMintSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t PremintAmountPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t PremintAmountSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t FeePercentagePointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t FeePercentageSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[10]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    logging::print("[InstrumentContractDEX] Res");
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractBridge] Contract ID:", contract_id, true);

    std::string pair2;
    logging::print("[InstrumentContractDEX] Res1");
    if (!read_wasm_param(MemCxt, Pair2Pointer, Pair2Size, pair2))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractDEX] Pair2:", pair2, true);

    std::string pre_mint_wallet;
    logging::print("[InstrumentContractDEX] Res2");
    if (!read_wasm_param(MemCxt, PreMintPointer, PreMintSize, pre_mint_wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractDEX] Pre Mint Wallet:", pre_mint_wallet, true);

    std::string premint_amount;
    logging::print("[InstrumentContractDEX] Res3");
    if (!read_wasm_param(MemCxt, PremintAmountPointer, PremintAmountSize, premint_amount))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractDEX] Premint Amount:", premint_amount, true);

    std::string fee_percentage;
    logging::print("[InstrumentContractDEX] Res4");
    if (!read_wasm_param(MemCxt, FeePercentagePointer, FeePercentageSize, fee_percentage))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[InstrumentContractDEX] Fee Percentage:", fee_percentage, true);

    std::string new_contract_id;
    std::string status = create_contract(*sender, contract_id, pair2, premint_amount, pre_mint_wallet, fee_percentage, new_contract_id);

    if (status != "OK")
    {
        new_contract_id = "0";
    }

    const char *val = new_contract_id.c_str();
    const size_t len = new_contract_id.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
}