#include "native_function_txns.h"
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

        bool zra_allowed = false;
        for (auto id : contract.contract_fees().allowed_fee_instrument())
        {
            if (id == NETWORK_CONTRACT)
            {
                zra_allowed = true;
                break;
            }
        }

        if(!zra_allowed)
        {
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

    std::string create_transfer(SenderDataType &sender, const std::string &contract_id, std::string input_amount, const std::vector<std::string> &amounts, const std::vector<std::string> &wallets)
    {
        if(amounts.size() != wallets.size())
        {
            return "FAILED: Amounts and wallets must be the same size";
        }

        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;

        zera_txn::CoinTXN txn;

        for(int i = 0; i < amounts.size(); i++)
        {
            set_output(txn.add_output_transfers(), amounts[i], wallets[i]);
        }

        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);
        set_auth(txn.mutable_auth(), sender);

        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(input_amount, &txn, contract_fee_amount))
        {
            return "FAILED: Did not calculate contract fee";
        }

        set_input(txn.add_input_transfers(), input_amount);

        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string current_create_transfer(SenderDataType &sender, const std::string &contract_id, std::string input_amount, const std::vector<std::string> &amounts, const std::vector<std::string> &wallets)
    {
        if(amounts.size() != wallets.size())
        {
            return "FAILED: Amounts and wallets must be the same size";
        }

        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;

        zera_txn::CoinTXN txn;

        for(int i = 0; i < amounts.size(); i++)
        {
            set_output(txn.add_output_transfers(), amounts[i], wallets[i]);
        }

        zera_txn::BaseTXN *base = txn.mutable_base();

        std::string sc_auth = current_set_base(base, sender);

        if (sc_auth == "")
        {
            return "FAILED: Delegate wallet not found";
        }

        std::string delegate_wallet = sender.current_smart_contract_instance_name;

        delegate_set_auth(txn.mutable_auth(), sender, sc_auth, delegate_wallet);

        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(input_amount, &txn, contract_fee_amount))
        {
            return "FAILED: Did not calculate contract fee";
        }

        set_input(txn.add_input_transfers(), input_amount);

        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string delegate_create_transfer(SenderDataType &sender, const std::string &contract_id, std::string input_amount, const std::vector<std::string> &amounts, const std::vector<std::string> &wallets, const std::string &delegate_wallet)
    {
        if(amounts.size() != wallets.size())
        {
            return "FAILED: Amounts and wallets must be the same size";
        }

        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;

        zera_txn::CoinTXN txn;

        for(int i = 0; i < amounts.size(); i++)
        {
            set_output(txn.add_output_transfers(), amounts[i], wallets[i]);
        }

        zera_txn::BaseTXN *base = txn.mutable_base();

        std::string sc_auth;
        if (!delegate_set_base(base, sender, delegate_wallet, sc_auth))
        {
            return "FAILED: Delegate wallet not found";
        }

        delegate_set_auth(txn.mutable_auth(), sender, sc_auth, delegate_wallet);

        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(input_amount, &txn, contract_fee_amount))
        {
            return "FAILED: Did not calculate contract fee";
        }

        set_input(txn.add_input_transfers(), input_amount);

        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}

// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result SendMulti(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    /*
     * Params: {i32, i32, i32, i32, i32, i32, i32}
     * Returns: {i32}
     */
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t InputAmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t InputAmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[7]);
    
    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string input_amount;
    if (!read_wasm_param(MemCxt, InputAmountPointer, InputAmountSize, input_amount))
    {
        return WasmEdge_Result_Terminate;
    }
    if (!is_valid_uint256(input_amount))
    {
        logging::print("[SendMulti] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string amount_temp;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    std::vector<std::string> amounts;
    uint256_t total_amount = 0;

    {
        //split by comma and push into vector
        std::stringstream ss(amount_temp);
        std::string amount;
        while (std::getline(ss, amount, ','))
        {
            amounts.push_back(amount);
        }

        for(int i = 0; i < amounts.size(); i++)
        {
            if (!is_valid_uint256(amounts[i]))
            {
                logging::print("[SendMulti] FAILED: Invalid uint256", true);
                return WasmEdge_Result_Terminate;
            }

            total_amount += uint256_t(amounts[i]);
        }
    }

    std::string wallet_temp;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    std::vector<std::string> wallets;
    {
        //split by comma and push into vector
        std::stringstream ss(wallet_temp);
        std::string wallet;
        while (std::getline(ss, wallet, ','))
        {
            wallets.push_back(wallet);
        }
    }

    if(total_amount != uint256_t(input_amount))
    {
        logging::print("[SendMulti] FAILED: Total amount does not match input amount", true);
        return WasmEdge_Result_Terminate;
    }

    std::vector<std::string> decoded_wallets;

    for(int i = 0; i < wallets.size(); i++)
    {
        std::vector<uint8_t> wallet_decode;
        if (wallets[i] == ":fire:")
        {
            wallet_decode.assign(wallets[i].begin(), wallets[i].end());
        }
        else
        {
            wallet_decode = base58_decode(wallets[i]);
        }
        std::string wallet_string(wallet_decode.begin(), wallet_decode.end());
        decoded_wallets.push_back(wallet_string);
    }

    std::string status = create_transfer(*sender, contract_id, input_amount, amounts, decoded_wallets);

    logging::print("[SendMulti] Status: ", status, true);

    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result CurrentSendMulti(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t InputAmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t InputAmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string input_amount;
    if (!read_wasm_param(MemCxt, InputAmountPointer, InputAmountSize, input_amount))
    {
        return WasmEdge_Result_Terminate;
    }
    if (!is_valid_uint256(input_amount))
    {
        logging::print("[CurrentSendMulti] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string amount_temp;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    std::vector<std::string> amounts;
    uint256_t total_amount = 0;

    {
        std::stringstream ss(amount_temp);
        std::string amount;
        while (std::getline(ss, amount, ','))
        {
            amounts.push_back(amount);
        }

        for(int i = 0; i < amounts.size(); i++)
        {
            if (!is_valid_uint256(amounts[i]))
            {
                logging::print("[CurrentSendMulti] FAILED: Invalid uint256", true);
                return WasmEdge_Result_Terminate;
            }

            total_amount += uint256_t(amounts[i]);
        }
    }

    std::string wallet_temp;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    std::vector<std::string> wallets;
    {
        std::stringstream ss(wallet_temp);
        std::string wallet;
        while (std::getline(ss, wallet, ','))
        {
            wallets.push_back(wallet);
        }
    }

    if(total_amount != uint256_t(input_amount))
    {
        logging::print("[CurrentSendMulti] FAILED: Total amount does not match input amount", true);
        return WasmEdge_Result_Terminate;
    }

    std::vector<std::string> decoded_wallets;

    for(int i = 0; i < wallets.size(); i++)
    {
        std::vector<uint8_t> wallet_decode;
        if (wallets[i] == ":fire:")
        {
            wallet_decode.assign(wallets[i].begin(), wallets[i].end());
        }
        else
        {
            wallet_decode = base58_decode(wallets[i]);
        }
        std::string wallet_string(wallet_decode.begin(), wallet_decode.end());
        decoded_wallets.push_back(wallet_string);
    }

    std::string status = current_create_transfer(*sender, contract_id, input_amount, amounts, decoded_wallets);

    logging::print("[CurrentSendMulti] Status: ", status, true);

    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result DelegateSendMulti(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t InputAmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t InputAmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t DelegatePointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t DelegateSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[10]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string input_amount;
    if (!read_wasm_param(MemCxt, InputAmountPointer, InputAmountSize, input_amount))
    {
        return WasmEdge_Result_Terminate;
    }
    if (!is_valid_uint256(input_amount))
    {
        logging::print("[DelegateSendMulti] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string amount_temp;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    std::vector<std::string> amounts;
    uint256_t total_amount = 0;

    {
        std::stringstream ss(amount_temp);
        std::string amount;
        while (std::getline(ss, amount, ','))
        {
            amounts.push_back(amount);
        }

        for(int i = 0; i < amounts.size(); i++)
        {
            if (!is_valid_uint256(amounts[i]))
            {
                logging::print("[DelegateSendMulti] FAILED: Invalid uint256", true);
                return WasmEdge_Result_Terminate;
            }

            total_amount += uint256_t(amounts[i]);
        }
    }

    std::string wallet_temp;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    std::vector<std::string> wallets;
    {
        std::stringstream ss(wallet_temp);
        std::string wallet;
        while (std::getline(ss, wallet, ','))
        {
            wallets.push_back(wallet);
        }
    }

    std::string delegate_wallet;
    if (!read_wasm_param(MemCxt, DelegatePointer, DelegateSize, delegate_wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    if(total_amount != uint256_t(input_amount))
    {
        logging::print("[DelegateSendMulti] FAILED: Total amount does not match input amount", true);
        return WasmEdge_Result_Terminate;
    }

    std::vector<std::string> decoded_wallets;

    for(int i = 0; i < wallets.size(); i++)
    {
        std::vector<uint8_t> wallet_decode;
        if (wallets[i] == ":fire:")
        {
            wallet_decode.assign(wallets[i].begin(), wallets[i].end());
        }
        else
        {
            wallet_decode = base58_decode(wallets[i]);
        }
        std::string wallet_string(wallet_decode.begin(), wallet_decode.end());
        decoded_wallets.push_back(wallet_string);
    }

    std::vector<uint8_t> delegate_wallet_decode = base58_decode(delegate_wallet);
    std::string delegate_string(delegate_wallet_decode.begin(), delegate_wallet_decode.end());

    std::string status = delegate_create_transfer(*sender, contract_id, input_amount, amounts, decoded_wallets, delegate_string);

    logging::print("[DelegateSendMulti] Status: ", status, true);

    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}