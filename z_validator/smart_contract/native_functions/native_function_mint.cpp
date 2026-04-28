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

    std::string process_txn(SenderDataType &sender, const zera_txn::MintTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        std::string fee_address = sender.fee_address;
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::MINT_TYPE, false, fee_address, true, sender.txn_hash, sender.fee_smart_contract_wallet);
        if (status.ok())
        {
            if (status.txn_status() == zera_txn::TXN_STATUS::OK)
            {
                sender.txn_hashes.push_back(txn.base().hash());
                block_txns.add_mint_txns()->CopyFrom(txn);
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

    std::string create_mint(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet)
    {
        zera_txn::MintTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);

        txn.set_amount(amount);
        txn.set_recipient_address(wallet);
        txn.set_contract_id(contract_id);

        calc_fee(base, sender.fee_id, txn.ByteSize(), zera_txn::TRANSACTION_TYPE::MINT_TYPE, wallet, contract_id);

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

        calc_fee(base, sender.fee_id, txn.ByteSize(), zera_txn::TRANSACTION_TYPE::MINT_TYPE, wallet, contract_id);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string delegate_create_mint(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet, const std::string &delegate_wallet)
    {
        zera_txn::MintTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        std::string sc_auth;

        if(!delegate_set_base(base, sender, delegate_wallet, sc_auth))
        {
            return "FAILED: Delegate wallet not found";
        }

        txn.set_amount(amount);
        txn.set_recipient_address(wallet);
        txn.set_contract_id(contract_id);

        calc_fee(base, sender.fee_id, txn.ByteSize(), zera_txn::TRANSACTION_TYPE::MINT_TYPE, wallet, contract_id);

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
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    if (!is_valid_uint256(amount))
    {
        logging::print("[Mint] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
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
    std::string status = create_mint(*sender, contract_id, amount, wallet_string);

    const char *val = status.c_str();
    const size_t len = status.length();

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
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DelegateWalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DelegateWalletSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DelegateMint] Contract ID:", contract_id, true);

    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    if (!is_valid_uint256(amount))
    {
        logging::print("[DelegateMint] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DelegateMint] Wallet:", wallet, true);

    std::string delegate_wallet;
    if (!read_wasm_param(MemCxt, DelegateWalletPointer, DelegateWalletSize, delegate_wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DelegateMint] Delegate Wallet:", delegate_wallet, true);

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
    std::string status = delegate_create_mint(*sender, contract_id, amount, wallet_string, delegate_wallet_string);

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
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    if (!is_valid_uint256(amount))
    {
        logging::print("[CurrentMint] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
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
    std::string status = current_create_mint(*sender, contract_id, amount, wallet_string);

    const char *val = status.c_str();
    const size_t len = status.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}