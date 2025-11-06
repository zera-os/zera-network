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

    void calc_fee(zera_txn::ExpenseRatioTXN *txn)
    {
        uint256_t equiv;
        zera_fees::get_cur_equiv("$ZRA+0000", equiv);
        zera_txn::InstrumentContract fee_contract;
        block_process::get_contract("$ZRA+0000", fee_contract);

        uint256_t fee_per_byte(get_txn_fee(zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE));
        int byte_size = txn->ByteSize() + 64;
        std::string denomination_str = fee_contract.coin_denomination().amount();
        int256_t txn_fee_amount;
        uint256_t fee = fee_per_byte * byte_size;
        uint256_t denomination(denomination_str);
        txn_fee_amount = (fee * denomination) / equiv;

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

    std::string process_txn(SenderDataType &sender, const zera_txn::ExpenseRatioTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        std::string fee_address = sender.fee_address;
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, true, fee_address, true);

        if (status.ok())
        {
            sender.txn_hashes.push_back(txn.base().hash());
            block_txns.add_expense_ratios()->CopyFrom(txn);
            txn_hash_tracker::add_sc_hash(txn.base().hash());
            uint64_t nonce = txn.base().nonce();
            nonce_tracker::store_sc_nonce(sender.smart_contract_wallet, nonce);
        }

        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    std::string create_expense(SenderDataType &sender, zera_txn::ExpenseRatioTXN &txn)
    {
        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);
        calc_fee(&txn);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}
WasmEdge_Result ExpenseRatio(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    logging::print("[ExpenseRatio] Start");
    SenderDataType sender = *(SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AddressesPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AddressesSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t OutputPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t OutputSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> AddressesKey(AddressesSize);
    std::vector<unsigned char> OutputKey(OutputSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);
    zera_txn::ExpenseRatioTXN txn;
    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        txn.set_contract_id(contract_temp);
        logging::print("[ExpenseRatio] Contract ID: ", contract_temp, false);
    }
    else
    {
        return Res;
    }

    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, AddressesKey.data(), AddressesPointer, AddressesSize);
    std::vector<std::string> addresses;
    if (WasmEdge_ResultOK(Res2))
    {
        std::string adrs_temp(reinterpret_cast<char *>(AddressesKey.data()), AddressesSize);
        std::vector<std::string> addresses_temp = getWords(adrs_temp, "##");
        logging::print("[ExpenseRatio] Addresses: ", adrs_temp, true);
        for(auto &address : addresses_temp)
        {
            auto vec = base58_decode(address);
            std::string address_temp(vec.begin(), vec.end());
            txn.add_addresses(address_temp);
        }
    }
    else
    {
        return Res2;
    }

    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, OutputKey.data(), OutputPointer, OutputSize);
    std::string output_adr;
    if (WasmEdge_ResultOK(Res3))
    {
        std::string output_temp(reinterpret_cast<char *>(OutputKey.data()), OutputSize);
        logging::print("[ExpenseRatio] Output Address: ", output_temp, true);
        auto vec = base58_decode(output_temp);
        std::string temp(vec.begin(), vec.end());
        txn.set_output_address(temp);
    }
    else
    {
        return Res3;
    }

    std::string status = create_expense(sender, txn);

    logging::print("[ExpenseRatio] Status: ", status, true);

    const char *val = status.c_str();
    const size_t len = status.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
}