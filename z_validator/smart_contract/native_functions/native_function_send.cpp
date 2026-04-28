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
#include "const.h"
#include "nf_helpers.h"

#include <google/protobuf/util/time_util.h>

//*************************************************************
//                        Send
// Send a coinTXN from smart contract wallet to any wallet - DONE
//
// Developer Native Function Parameters
// - string contract_id
// - string amount
// - string wallet
//*************************************************************
namespace
{

    void get_fixed_contract_fee(const zera_txn::InstrumentContract &contract, const uint256_t &contract_fee, const std::string &fee_id, uint256_t &fixed_fee_amount)
    {

        uint256_t fee_equiv;
        zera_fees::get_cur_equiv(fee_id, fee_equiv);
        if(fee_equiv == 1)
        {
            fee_equiv = ONE_DOLLAR;
        }

        uint256_t priority_equiv;
        zera_fees::get_cur_equiv(contract.contract_id(), priority_equiv);
        if(priority_equiv == 1)
        {
            priority_equiv = ONE_DOLLAR;
        }

        fixed_fee_amount = (fixed_fee_amount * priority_equiv) / fee_equiv;
    }
    void get_percent_contract_fee(const uint256_t &contract_fee, const std::string &fee_id, const std::string &txn_contract_id, const uint256_t &amount, uint256_t &perc_fee_amount)
    {
        uint256_t quintillion(QUINTILLION);

        perc_fee_amount = amount * contract_fee / quintillion;

        uint256_t fee_equiv;
        zera_fees::get_cur_equiv(fee_id, fee_equiv);
        if(fee_equiv == 1)
        {
            fee_equiv = ONE_DOLLAR;
        }

        uint256_t txn_equiv;
        zera_fees::get_cur_equiv(fee_id, txn_equiv);
        if(txn_equiv == 1)
        {
            txn_equiv = ONE_DOLLAR;
        }

        perc_fee_amount = (perc_fee_amount * txn_equiv) / fee_equiv;
    }

    bool calc_contract_fee(const std::string amount_str, zera_txn::CoinTXN *txn, uint256_t &contract_fee_amount)
    {
        uint256_t amount(amount_str);
        zera_txn::InstrumentContract contract;
        block_process::get_contract(txn->contract_id(), contract);

        if (!contract.has_contract_fees())
        {
            return true;
        }

        for (auto id : contract.contract_fees().allowed_fee_instrument())
        {
            if (id == NETWORK_CONTRACT)
            {
                break;
            }

            return false;
        }

        txn->set_contract_fee_id(NETWORK_CONTRACT);

        uint256_t contract_fee(contract.contract_fees().fee());
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t contract_equiv;
        zera_fees::get_cur_equiv(contract.contract_id(), contract_equiv);
        if(contract_equiv == 1)
        {
            contract_equiv = ONE_DOLLAR;
        }


        switch (contract.contract_fees().contract_fee_type())
        {
        case zera_txn::CONTRACT_FEE_TYPE::CUR_EQUIVALENT:
        {
            // contract fee has quintillion multiplier
            // fee_equiv has 1 quintillion multiplier
            uint256_t fee_equiv;
            zera_fees::get_cur_equiv(txn->contract_fee_id(), fee_equiv);
            if(fee_equiv == 1)
            {
                fee_equiv = ONE_DOLLAR;
            }

            contract_fee_amount = (contract_fee * denomination) / fee_equiv;
            break;
        }
        case zera_txn::CONTRACT_FEE_TYPE::FIXED:
        {
            get_fixed_contract_fee(contract, contract_fee, txn->contract_fee_id(), contract_fee_amount);
            break;
        }
        case zera_txn::CONTRACT_FEE_TYPE::PERCENTAGE:
        {
            get_percent_contract_fee(contract_fee, txn->contract_fee_id(), txn->contract_id(), amount, contract_fee_amount);
            break;
        }
        default:
            return false;
            break;
        }

        txn->set_contract_fee_amount(contract_fee_amount.str());
        return true;
    }

    void set_auth(zera_txn::TransferAuthentication *auth, SenderDataType &sender)
    {
        auth->add_nonce(sender.sc_nonce);
        sender.sc_nonce++;
        auth->add_public_key()->set_smart_contract_auth("sc_" + sender.smart_contract_instance);
    }

    void delegate_set_auth(zera_txn::TransferAuthentication *auth, SenderDataType &sender, const std::string &sc_auth, const std::string &delegate_wallet)
    {
        auth->add_nonce(sender.sc_nonce);
        sender.sc_nonce++;

        auth->add_public_key()->set_smart_contract_auth(sc_auth);
    }

    void set_input(zera_txn::InputTransfers *input, const std::string &amount)
    {
        input->set_index(0);
        input->set_amount(amount);
        input->set_fee_percent(100000000);
        input->set_contract_fee_percent(100000000);
    }

    void set_output(zera_txn::OutputTransfers *output, const std::string &amount, const std::string &wallet)
    {
        output->set_amount(amount);
        output->set_wallet_address(wallet);
    }

    std::string process_txn(SenderDataType &sender, const zera_txn::CoinTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);

        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::COIN_TYPE, false, sender.fee_address, true, sender.txn_hash, sender.fee_smart_contract_wallet);

        if (status.ok())
        {
            if (status.txn_status() == zera_txn::TXN_STATUS::OK)
            {
                sender.txn_hashes.push_back(txn.base().hash());
                block_txns.add_coin_txns()->CopyFrom(txn);
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

    std::string create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet, bool transfer_all_zra = false)
    {
        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;
        uint256_t amount_int(amount);
        uint256_t total_fee_amount = 0;

        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);
        set_auth(txn.mutable_auth(), sender);
        set_output(txn.add_output_transfers(), amount, wallet);
        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn, contract_fee_amount))
        {
            return "FAILED: Did not calculate contract fee";
        }

        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);

        if (transfer_all_zra)
        {
            amount_int = amount_int - txn_fee_amount;
            amount_int = amount_int - contract_fee_amount;
            txn.mutable_output_transfers(0)->set_amount(amount_int.str());
        }

        set_input(txn.add_input_transfers(), amount_int.str());

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string delegate_create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet, const std::string delegate_wallet, bool transfer_all_zra = false)
    {
        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;
        uint256_t amount_int(amount);
        uint256_t total_fee_amount = 0;

        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        std::string sc_auth;
        if (!delegate_set_base(base, sender, delegate_wallet, sc_auth))
        {
            return "FAILED: Delegate wallet not found";
        }

        delegate_set_auth(txn.mutable_auth(), sender, sc_auth, delegate_wallet);
        set_output(txn.add_output_transfers(), amount, wallet);
        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn, contract_fee_amount))
        {
            return "FAILED: Did not calculate contract fee";
        }

        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);

        if (transfer_all_zra)
        {
            amount_int = amount_int - txn_fee_amount;
            amount_int = amount_int - contract_fee_amount;
        }

        set_input(txn.add_input_transfers(), amount_int.str());

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string current_create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &wallet, bool transfer_all_zra = false)
    {
        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;
        uint256_t amount_int(amount);
        uint256_t total_fee_amount = 0;

        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();

        std::string sc_auth = current_set_base(base, sender);

        if (sc_auth == "")
        {
            return "FAILED: Delegate wallet not found";
        }

        std::string delegate_wallet = sender.current_smart_contract_instance_name;

        delegate_set_auth(txn.mutable_auth(), sender, sc_auth, delegate_wallet);
        set_output(txn.add_output_transfers(), amount, wallet);
        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn, contract_fee_amount))
        {
            return "FAILED: Did not calculate contract fee";
        }

        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);

        if (transfer_all_zra)
        {
            amount_int = amount_int - txn_fee_amount;
            amount_int = amount_int - contract_fee_amount;
        }

        set_input(txn.add_input_transfers(), amount_int.str());

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result Send(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType *sender = (SenderDataType *)Data;

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
    logging::print("[Send] Contract ID: ", contract_id, true);

    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }

    if (!is_valid_uint256(amount))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[Send] Amount: ", amount, true);

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[Send] Wallet: ", wallet, true);

    std::vector<uint8_t> wallet_decode;
    if (wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }
    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());

    std::string status = "OK";

    if(amount != "0")
    {
        status = create_transfer(*sender, contract_id, amount, wallet_string);
    }

    logging::print("[Send] Status: ", status, true);

    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result SendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType *sender = (SenderDataType *)Data;

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> wallet_decode;
    if (wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }

    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());

    std::string wallet_lookup = "TOKEN_LOOKUP_" + sender->smart_contract_wallet;
    std::string lookup_data;
    if (!db_wallet_lookup::get_single(wallet_lookup, lookup_data))
    {
        std::string result = "No tokens found for wallet";
        const char *val = result.c_str();
        const size_t len = result.length();

        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        return WasmEdge_Result_Success;
    }

    zera_validator::TokenLookup token_lookup;

    if (!token_lookup.ParseFromString(lookup_data))
    {
        std::string result = "FAILED: Did not parse token lookup";
        const char *val = result.c_str();
        const size_t len = result.length();

        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        logging::print("[SendAll] FAILED: Did not parse token lookup", true);
        return WasmEdge_Result_Fail;
    }

    std::string transfer_message = "[Transfer All] ";
    for (auto token : token_lookup.tokens())
    {
        if (token == NETWORK_CONTRACT)
        {
            continue;
        }

        std::string amount;
        if (db_wallets::get_single(sender->smart_contract_wallet + token, amount))
        {
            if(amount != "0")
            {
                std::string status = create_transfer(*sender, token, amount, wallet_string);
                transfer_message += token + std::string(": ") + status + std::string(", ");
            }
            else
            {
                transfer_message += token + std::string(": OK, ");
            }
        }
    }

    std::string amount;

    if (db_processed_wallets::get_single(sender->smart_contract_wallet + NETWORK_CONTRACT, amount) || db_wallets::get_single(sender->smart_contract_wallet + NETWORK_CONTRACT, amount))
    {
        if(amount != "0")
        {
            std::string status = create_transfer(*sender, NETWORK_CONTRACT, amount, wallet_string, true);
            transfer_message += std::string("$ZRA+0000 :") + status;
        }
        else
        {
            transfer_message += std::string("$ZRA+0000 :OK");
        }
    }

    std::string result = transfer_message;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result DelegateSend(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    logging::print("[DelegateSend] Start", true);
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType *sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DelegatePointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DelegateSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DelegateSend] Contract ID: ", contract_id, true);

    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    if (!is_valid_uint256(amount))
    {
        logging::print("[DelegateSend] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DelegateSend] Wallet: ", wallet, true);

    std::string delegate_wallet;
    if (!read_wasm_param(MemCxt, DelegatePointer, DelegateSize, delegate_wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DelegateSend] Delegate Wallet: ", delegate_wallet, true);

    std::vector<uint8_t> wallet_decode;
    if (wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }

    std::vector<uint8_t> delegate_wallet_decode = base58_decode(delegate_wallet);
    std::string delegate_string(delegate_wallet_decode.begin(), delegate_wallet_decode.end());

    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());

    std::string status = "OK";

    if(amount != "0")
    {
        status = delegate_create_transfer(*sender, contract_id, amount, wallet_string, delegate_string);
    }

    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result DelegateSendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType *sender = (SenderDataType *)Data;

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t DelegateWalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t DelegateWalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string delegate_wallet;
    if (!read_wasm_param(MemCxt, DelegateWalletPointer, DelegateWalletSize, delegate_wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> wallet_decode;
    if (wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }

    std::vector<uint8_t> delegate_wallet_decode;
    delegate_wallet_decode = base58_decode(delegate_wallet);

    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());
    std::string delegate_wallet_string(delegate_wallet_decode.begin(), delegate_wallet_decode.end());

    std::string wallet_lookup = "TOKEN_LOOKUP_" + delegate_wallet_string;
    std::string lookup_data;
    if (!db_wallet_lookup::get_single(wallet_lookup, lookup_data))
    {
        std::string result = "No tokens found for wallet";
        const char *val = result.c_str();
        const size_t len = result.length();

        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        return WasmEdge_Result_Success;
    }

    zera_validator::TokenLookup token_lookup;

    if (!token_lookup.ParseFromString(lookup_data))
    {
        std::string result = "FAILED: Did not parse token lookup";
        const char *val = result.c_str();
        const size_t len = result.length();

        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        logging::print("[DelegateSendAll] FAILED: Did not parse token lookup", true);
        return WasmEdge_Result_Fail;
    }

    std::string transfer_message = "[Transfer All] ";
    for (auto token : token_lookup.tokens())
    {
        if (token == NETWORK_CONTRACT)
        {
            continue;
        }

        std::string amount;
        if (db_wallets::get_single(delegate_wallet + token, amount))
        {
            if(amount != "0")
            {
                std::string status = delegate_create_transfer(*sender, token, amount, wallet_string, delegate_wallet_string);
                transfer_message += token + std::string(": ") + status + std::string(", ");
            }
            else
            {
                transfer_message += token + std::string(": OK, ");
            }
        }
    }

    std::string amount;

    if (db_processed_wallets::get_single(sender->smart_contract_wallet + NETWORK_CONTRACT, amount) || db_wallets::get_single(sender->smart_contract_wallet + NETWORK_CONTRACT, amount))
    {
        if(amount != "0")
        {
            std::string status = delegate_create_transfer(*sender, NETWORK_CONTRACT, amount, wallet_string, delegate_wallet_string, true);
            transfer_message += std::string("$ZRA+0000 :") + status;
        }
        else
        {
            transfer_message += std::string("$ZRA+0000 :OK");
        }
    }

    std::string result = transfer_message;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result CurrentSend(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType *sender = (SenderDataType *)Data;

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
        logging::print("[CurrentSend] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> wallet_decode;
    if (wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }
    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());

    std::string status = "OK";
    if(amount != "0")
    {
        status = current_create_transfer(*sender, contract_id, amount, wallet_string);
    }


    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result CurrentSendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType *sender = (SenderDataType *)Data;

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> wallet_decode;
    if (wallet == ":fire:")
    {
        wallet_decode.assign(wallet.begin(), wallet.end());
    }
    else
    {
        wallet_decode = base58_decode(wallet);
    }

    std::string wallet_string(wallet_decode.begin(), wallet_decode.end());

    std::string wallet_lookup = "TOKEN_LOOKUP_" + sender->smart_contract_wallet;
    std::string lookup_data;
    if (!db_wallet_lookup::get_single(wallet_lookup, lookup_data))
    {
        std::string result = "No tokens found for wallet";
        const char *val = result.c_str();
        const size_t len = result.length();

        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        return WasmEdge_Result_Success;
    }

    zera_validator::TokenLookup token_lookup;

    if (!token_lookup.ParseFromString(lookup_data))
    {
        std::string result = "FAILED: Did not parse token lookup";
        const char *val = result.c_str();
        const size_t len = result.length();

        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        logging::print("[CurrentSendAll] FAILED: Did not parse token lookup", true);
        return WasmEdge_Result_Fail;
    }

    std::string transfer_message = "[Transfer All] ";
    for (auto token : token_lookup.tokens())
    {
        if (token == NETWORK_CONTRACT)
        {
            continue;
        }

        std::string amount;
        if (db_wallets::get_single(sender->smart_contract_wallet + token, amount))
        {
            if(amount != "0")
            {
                std::string status = current_create_transfer(*sender, token, amount, wallet_string);
                transfer_message += token + std::string(": ") + status + std::string(", ");
            }
            else
            {
                transfer_message += token + std::string(": OK, ");
            }
        }
    }

    std::string amount;

    if (db_processed_wallets::get_single(sender->smart_contract_wallet + NETWORK_CONTRACT, amount) || db_wallets::get_single(sender->smart_contract_wallet + NETWORK_CONTRACT, amount))
    {
        if(amount != "0")
        {
            std::string status = current_create_transfer(*sender, NETWORK_CONTRACT, amount, wallet_string, true);
            transfer_message += std::string("$ZRA+0000 :") + status;
        }
        else
        {
            transfer_message += std::string("$ZRA+0000 :OK");
        }
    }

    std::string result = transfer_message;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}