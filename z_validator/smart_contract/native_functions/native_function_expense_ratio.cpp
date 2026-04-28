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
#include "nf_helpers.h"


namespace
{
    std::vector<std::string> getWords(std::string s, std::string delim)
    {
        std::vector<std::string> tokens;
        size_t start = 0;
        size_t end = s.find(delim);
        while (end != std::string::npos)
        {
            tokens.push_back(s.substr(start, end - start));
            start = end + delim.length();
            end = s.find(delim, start);
        }
        tokens.push_back(s.substr(start));
        return tokens;
    }

    std::string process_txn(SenderDataType &sender, const zera_txn::ExpenseRatioTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        std::string fee_address = sender.fee_address;
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, true, fee_address, true, sender.txn_hash, sender.fee_smart_contract_wallet);

        if (status.ok())
        {
            if (status.txn_status() == zera_txn::TXN_STATUS::OK)
            {
                sender.txn_hashes.push_back(txn.base().hash());
                block_txns.add_expense_ratios()->CopyFrom(txn);
                txn_hash_tracker::add_sc_hash(txn.base().hash());
                uint64_t nonce = txn.base().nonce();
                nonce_tracker::store_sc_nonce(sender.smart_contract_wallet, nonce);
            }
            else
            {
                balance_tracker::remove_txn_balance(txn.base().hash());
            }
        }

        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    std::string create_expense(SenderDataType &sender, zera_txn::ExpenseRatioTXN &txn)
    {
        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);
        calc_fee(txn.mutable_base(), sender.fee_id, txn.ByteSize(), zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE, txn.output_address(), txn.contract_id());

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}
WasmEdge_Result ExpenseRatio(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    logging::print("[ExpenseRatio] Start");
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AddressesPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AddressesSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t OutputPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t OutputSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_temp;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    zera_txn::ExpenseRatioTXN txn;
    txn.set_contract_id(contract_temp);
    logging::print("[ExpenseRatio] Contract ID: ", contract_temp, false);

    std::string adrs_temp;
    if (!read_wasm_param(MemCxt, AddressesPointer, AddressesSize, adrs_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    std::vector<std::string> addresses_temp = getWords(adrs_temp, "##");
    logging::print("[ExpenseRatio] Addresses: ", adrs_temp, true);
    for(auto &address : addresses_temp)
    {
        auto vec = base58_decode(address);
        std::string address_temp(vec.begin(), vec.end());
        txn.add_addresses(address_temp);
    }

    std::string output_temp;
    if (!read_wasm_param(MemCxt, OutputPointer, OutputSize, output_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[ExpenseRatio] Output Address: ", output_temp, true);
    auto vec = base58_decode(output_temp);
    std::string temp(vec.begin(), vec.end());
    txn.set_output_address(temp);

    std::string status = create_expense(*sender, txn);

    logging::print("[ExpenseRatio] Status: ", status, true);

    const char *val = status.c_str();
    const size_t len = status.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
}