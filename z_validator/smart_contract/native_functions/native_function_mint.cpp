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

//*************************************************************
//                          Mint
// Send a mintTXN from smart contract key
//
// Developer Native Function Parameters
// - string contract_id
// - string amount
// - string wallet
//*************************************************************

namespace
{
    void calc_fee(zera_txn::MintTXN *txn)
    {
        uint256_t equiv;
        zera_fees::get_cur_equiv("$ZRA+0000", equiv);
        zera_txn::InstrumentContract fee_contract;
        block_process::get_contract("$ZRA+0000", fee_contract);

        uint256_t fee_per_byte(get_txn_fee(zera_txn::TRANSACTION_TYPE::MINT_TYPE));
        int byte_size = txn->ByteSize() + 64;
        std::string denomination_str = fee_contract.coin_denomination().amount();
        int256_t txn_fee_amount;
        uint256_t fee = fee_per_byte * byte_size;
        uint256_t denomination(denomination_str);
        txn_fee_amount = (fee * denomination)  / equiv;

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

    void current_set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
    {
        size_t call_size = sender.wallet_chain.size();
        int call_index = call_size - 1;

        std::string sc_auth = "sc_" + sender.current_smart_contract_instance;

        base->mutable_public_key()->set_smart_contract_auth(sc_auth);

        base->set_fee_amount("1000000000000");
        base->set_nonce(sender.sc_nonce);
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        sender.sc_nonce++;
        base->mutable_timestamp()->set_seconds(sender.block_time);

    }

    bool delegate_set_base(zera_txn::BaseTXN *base, SenderDataType &sender, const std::string &delegate_wallet)
    {
        std::string sc_auth = "";

        int x = 0;
        for(auto &wallet : sender.wallet_chain)
        {
            if(delegate_wallet == wallet)
            {
                sc_auth = "sc_" + sender.call_chain[x];
                break;
            }
            x++;
        }

        if(sc_auth == "")
        {
            return false;
        }

        base->mutable_public_key()->set_smart_contract_auth(sc_auth);

        base->set_fee_amount("1000000000000");
        base->set_nonce(sender.sc_nonce);
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        sender.sc_nonce++;
        base->mutable_timestamp()->set_seconds(sender.block_time);

        return true;
    }

    std::string process_txn(SenderDataType &sender, const zera_txn::MintTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        std::string fee_address = sender.fee_address;
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::MINT_TYPE, false, fee_address, true);
        if (status.ok())
        {
            sender.txn_hashes.push_back(txn.base().hash());
            block_txns.add_mint_txns()->CopyFrom(txn);
            txn_hash_tracker::add_sc_hash(txn.base().hash());
        }
        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    std::string create_mint(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet)
    {
        zera_txn::MintTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);

        txn.set_amount(amount);
        txn.set_recipient_address(wallet);
        txn.set_contract_id(contract_id);

        calc_fee(&txn);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string current_create_mint(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet)
    {
        zera_txn::MintTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        current_set_base(base, sender);

        txn.set_amount(amount);
        txn.set_recipient_address(wallet);
        txn.set_contract_id(contract_id);

        calc_fee(&txn);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string delegate_create_mint(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet, const std::string &delegate_wallet)
    {
        zera_txn::MintTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        if(!delegate_set_base(base, sender, delegate_wallet))
        {
            return "FAILED: Delegate wallet not found";
        }

        txn.set_amount(amount);
        txn.set_recipient_address(wallet);
        txn.set_contract_id(contract_id);

        calc_fee(&txn);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}
// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result Mint(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType sender = *(SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> AmountKey(AmountSize);
    std::vector<unsigned char> WalletKey(WalletSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

    std::string contract_id;
    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        contract_id = contract_temp;
    }
    else
    {
        return Res;
    }

    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, AmountKey.data(), AmountPointer, AmountSize);
    std::string amount;
    if (WasmEdge_ResultOK(Res2))
    {
        std::string amount_temp(reinterpret_cast<char *>(AmountKey.data()), AmountSize);
        if (!is_valid_uint256(amount_temp))
        {
            std::string result = "[Mint] FAILED: Invalid uint256";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Fail;
        }

        amount = amount_temp;
    }
    else
    {
        return Res2;
    }

    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
    std::string wallet;
    if (WasmEdge_ResultOK(Res3))
    {
        std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
        wallet = wallet_temp;
    }
    else
    {
        return Res3;
    }

    std::vector<uint8_t> wallet_decode;
    if(wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }

    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());
    std::string status = create_mint(sender, contract_id, amount, wallet_string);

    const char *val = status.c_str();
    const size_t len = status.length();

    auto fee_address = sender.fee_address;

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result DelegateMint(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    logging::print("[DelegateMint] Start");
    SenderDataType sender = *(SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DelegateWalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DelegateWalletSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> AmountKey(AmountSize);
    std::vector<unsigned char> WalletKey(WalletSize);
    std::vector<unsigned char> DelegateWalletKey(DelegateWalletSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

    std::string contract_id;
    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        contract_id = contract_temp;
        logging::print("[DelegateMint] Contract ID:", contract_id, true);
    }
    else
    {
        return Res;
    }

    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, AmountKey.data(), AmountPointer, AmountSize);
    std::string amount;
    if (WasmEdge_ResultOK(Res2))
    {
        std::string amount_temp(reinterpret_cast<char *>(AmountKey.data()), AmountSize);
        if (!is_valid_uint256(amount_temp))
        {
            std::string result = "[Mint] FAILED: Invalid uint256";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Fail;
        }

        amount = amount_temp;
    }
    else
    {
        return Res2;
    }

    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
    std::string wallet;
    if (WasmEdge_ResultOK(Res3))
    {
        std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
        wallet = wallet_temp;
        logging::print("[DelegateMint] Wallet:", wallet, true);
    }
    else
    {
        return Res3;
    }

    WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, DelegateWalletKey.data(), DelegateWalletPointer, DelegateWalletSize);
    std::string delegate_wallet;
    if (WasmEdge_ResultOK(Res4))
    {
        std::string wallet_temp(reinterpret_cast<char *>(DelegateWalletKey.data()), DelegateWalletSize);
        delegate_wallet = wallet_temp;
        logging::print("[DelegateMint] Delegate Wallet:", delegate_wallet, true);
    }
    else
    {
        return Res4;
    }

    std::vector<uint8_t> wallet_decode;
    if(wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }

    std::vector<uint8_t> delegate_wallet_decode = base58_decode(delegate_wallet);

    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());
    std::string delegate_wallet_string(delegate_wallet_decode.begin(), delegate_wallet_decode.end());
    std::string status = delegate_create_mint(sender, contract_id, amount, wallet_string, delegate_wallet_string);

    const char *val = status.c_str();
    const size_t len = status.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result CurrentMint(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType sender = *(SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> AmountKey(AmountSize);
    std::vector<unsigned char> WalletKey(WalletSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

    std::string contract_id;
    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        contract_id = contract_temp;
    }
    else
    {
        return Res;
    }

    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, AmountKey.data(), AmountPointer, AmountSize);
    std::string amount;
    if (WasmEdge_ResultOK(Res2))
    {
        std::string amount_temp(reinterpret_cast<char *>(AmountKey.data()), AmountSize);
        if (!is_valid_uint256(amount_temp))
        {
            std::string result = "[Mint] FAILED: Invalid uint256";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Fail;
        }

        amount = amount_temp;
    }
    else
    {
        return Res2;
    }

    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
    std::string wallet;
    if (WasmEdge_ResultOK(Res3))
    {
        std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
        wallet = wallet_temp;
    }
    else
    {
        return Res3;
    }

    std::vector<uint8_t> wallet_decode;
    if(wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }

    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());
    std::string status = current_create_mint(sender, contract_id, amount, wallet_string);

    const char *val = status.c_str();
    const size_t len = status.length();

    auto fee_address = sender.fee_address;

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}