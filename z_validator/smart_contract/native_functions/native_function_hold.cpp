#include "native_function_get_ace.h"
#include "native_function_txns.h"
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
#include "wallet.pb.h"

//*************************************************************
//                          Holdtxn
// Send a coinTXN from sender wallet to smart contract wallet - DONE
//
// Developer Native Function Parameters
// - string contract_id
// - string amount
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

    bool calc_contract_fee(const std::string amount_str, zera_txn::CoinTXN *txn)
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

        uint256_t contract_fee_amount;
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
    ZeraStatus calculate_byte_fees(const uint256_t &FEE_PER_BYTE, const int &bytes, uint256_t &txn_fee_amount, std::string denomination_str)
    {
        uint256_t fee_per_byte(FEE_PER_BYTE);
        uint256_t fee = fee_per_byte * bytes;
        uint256_t denomination(denomination_str);
        txn_fee_amount = denomination * fee;

        return ZeraStatus();
    }

    void set_auth(zera_txn::TransferAuthentication *auth, SenderDataType &sender)
    {
        auth->add_nonce(sender.sc_nonce);
        sender.sc_nonce++;

        if(smart_contract_service::gov_key(sender.pub_key))
        {
            auth->add_public_key()->set_governance_auth(sender.pub_key);
        }
        else
        {
            auth->add_public_key()->set_single(sender.pub_key);
        }

    }

    void set_input(zera_txn::InputTransfers *input, const std::string &amount)
    {
        input->set_index(0);
        input->set_amount(amount);
        input->set_fee_percent(100000000);
        input->set_contract_fee_percent(100000000);
    }

    void set_output(zera_txn::OutputTransfers *output, const std::string &amount, SenderDataType &sender)
    {
        output->set_amount(amount);
        output->set_wallet_address(sender.smart_contract_wallet);
    }

    void current_set_output(zera_txn::OutputTransfers *output, const std::string &amount, SenderDataType &sender)
    {
        auto index = sender.wallet_chain.size() - 1;
        output->set_amount(amount);
        output->set_wallet_address(sender.wallet_chain[index]);
    }

    std::string process_txn(SenderDataType &sender, const zera_txn::CoinTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);
        std::string fee_address = sender.fee_address;
        
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::COIN_TYPE, false, fee_address, true, sender.txn_hash, sender.fee_smart_contract_wallet);

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

    std::string create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount)
    {
        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();
        zera_txn::InputTransfers *input = txn.add_input_transfers();
        set_base(base, sender);
        set_auth(txn.mutable_auth(), sender);
        set_input(input, amount);
        set_output(txn.add_output_transfers(), amount, sender);
        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn))
        {
            return "FAILED: Did not calculate contract fee";
        }
        uint256_t txn_fee_amount;
        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);
        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string current_create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount)
    {
        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();
        zera_txn::InputTransfers *input = txn.add_input_transfers();
        current_set_base(base, sender);
        set_auth(txn.mutable_auth(), sender);
        set_input(input, amount);
        current_set_output(txn.add_output_transfers(), amount, sender);
        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn))
        {
            return "FAILED: Did not calculate contract fee";
        }

        uint256_t txn_fee_amount;
        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);
        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    bool verify_derived_wallet_ownership(const std::string &base58_derived_wallet, const std::string &instance_key, const SenderDataType &sender)
    {
        auto it = sender.derived_wallets.find(base58_derived_wallet);
        if (it != sender.derived_wallets.end())
        {
            if (it->second == instance_key)
            {
                return true;
            }
        }

        zera_wallets::DerivedWallets derived_wallets;
        std::string derived_wallets_data;

        if (db_smart_contract_states::get_single(instance_key, derived_wallets_data))
        {
            if (derived_wallets.ParseFromString(derived_wallets_data))
            {
                auto wallets_map = derived_wallets.wallets();
                if (wallets_map.count(base58_derived_wallet) > 0)
                {
                    return true;
                }
            }
        }

        logging::print("[VerifyDerivedWallet] Wallet not found or not owned by contract", true);
        return false;
    }

    std::string derived_create_hold(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &derived_wallet_raw)
    {
        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();
        zera_txn::InputTransfers *input = txn.add_input_transfers();
        set_base(base, sender);
        set_auth(txn.mutable_auth(), sender);
        set_input(input, amount);

        zera_txn::OutputTransfers *output = txn.add_output_transfers();
        output->set_amount(amount);
        output->set_wallet_address(derived_wallet_raw);

        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn))
        {
            return "FAILED: Did not calculate contract fee";
        }

        uint256_t txn_fee_amount;
        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);
        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string derived_current_create_hold(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &derived_wallet_raw)
    {
        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();
        zera_txn::InputTransfers *input = txn.add_input_transfers();

        std::string sc_auth = current_set_base(base, sender);
        if (sc_auth.empty())
        {
            return "FAILED: Current smart contract instance not found";
        }

        set_auth(txn.mutable_auth(), sender);
        set_input(input, amount);

        zera_txn::OutputTransfers *output = txn.add_output_transfers();
        output->set_amount(amount);
        output->set_wallet_address(derived_wallet_raw);

        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn))
        {
            return "FAILED: Did not calculate contract fee";
        }

        uint256_t txn_fee_amount;
        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);
        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string delegate_create_hold(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &delegate_wallet)
    {
        bool found = false;
        for (auto &wallet : sender.wallet_chain)
        {
            if (delegate_wallet == wallet)
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            return "FAILED: Delegate wallet not found";
        }

        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();
        zera_txn::InputTransfers *input = txn.add_input_transfers();

        set_base(base, sender);
        set_auth(txn.mutable_auth(), sender);
        set_input(input, amount);

        zera_txn::OutputTransfers *output = txn.add_output_transfers();
        output->set_amount(amount);
        output->set_wallet_address(delegate_wallet);

        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn))
        {
            return "FAILED: Did not calculate contract fee";
        }

        uint256_t txn_fee_amount;
        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);
        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

    std::string derived_delegate_create_hold(SenderDataType &sender, const std::string &contract_id, const std::string &amount, const std::string &derived_wallet_raw, std::string &sc_auth)
    {
        zera_txn::CoinTXN txn;

        zera_txn::BaseTXN *base = txn.mutable_base();
        zera_txn::InputTransfers *input = txn.add_input_transfers();

        if (!delegate_set_base_from_auth(base, sender, sc_auth))
        {
            return "FAILED: Smart contract instance not found";
        }

        set_auth(txn.mutable_auth(), sender);
        set_input(input, amount);

        zera_txn::OutputTransfers *output = txn.add_output_transfers();
        output->set_amount(amount);
        output->set_wallet_address(derived_wallet_raw);

        txn.set_contract_id(contract_id);

        if (!calc_contract_fee(amount, &txn))
        {
            return "FAILED: Did not calculate contract fee";
        }

        uint256_t txn_fee_amount;
        calc_fee_coin_txn(&txn, sender.fee_id, txn_fee_amount);
        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}


// need to send if sc or sender sending txn, contract_id and amount
WasmEdge_Result Hold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
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

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

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
        logging::print("[Hold] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string status = create_transfer(*sender, contract_id, amount);
    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result CurrentHold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
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

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

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
        std::string result = "[Hold] FAILED: Invalid uint256";
        const char *val = result.c_str();
        const size_t len = result.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        logging::print("[CurrentHold] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Fail;
    }

    std::string status = current_create_transfer(*sender, contract_id, amount);
    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result DerivedHold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType *sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[5]);

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
        logging::print("[DerivedHold] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string instance_key = "derived_wallets<>" + sender->smart_contract_instance;
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedHold] FAILED: Derived wallet not owned by this contract", true);
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    std::string status = derived_create_hold(*sender, contract_id, amount, derived_wallet_raw);
    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result DerivedDelegateHold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType *sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DelegatePointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DelegateSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t InstancePointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t InstanceSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[10]);

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
        logging::print("[DerivedDelegateHold] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string sc_name;
    if (!read_wasm_param(MemCxt, DelegatePointer, DelegateSize, sc_name))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string instance;
    if (!read_wasm_param(MemCxt, InstancePointer, InstanceSize, instance))
    {
        return WasmEdge_Result_Terminate;
    }

    std::string sc_auth = sc_name + "_" + instance;

    if (!in_call_chain(sc_auth, *sender))
    {
        logging::print("[DerivedDelegateHold] FAILED: Delegate not in call chain", true);
        return WasmEdge_Result_Terminate;
    }

    std::string instance_key = "derived_wallets<>" + sc_auth;
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedDelegateHold] FAILED: Derived wallet not owned by specified contract", true);
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    std::string status = derived_delegate_create_hold(*sender, contract_id, amount, derived_wallet_raw, sc_auth);
    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result DelegateHold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
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

    uint32_t DelegateWalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t DelegateWalletSize = WasmEdge_ValueGetI32(In[5]);

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
        logging::print("[DelegateHold] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string delegate_wallet_base58;
    if (!read_wasm_param(MemCxt, DelegateWalletPointer, DelegateWalletSize, delegate_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> delegate_wallet_decode = base58_decode(delegate_wallet_base58);
    std::string delegate_wallet_raw(delegate_wallet_decode.begin(), delegate_wallet_decode.end());

    std::string status = delegate_create_hold(*sender, contract_id, amount, delegate_wallet_raw);
    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result DerivedCurrentHold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType *sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[5]);

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
        logging::print("[DerivedCurrentHold] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }

    size_t call_size = sender->call_chain.size();
    int call_index = call_size - 1;
    std::string current_instance = sender->call_chain[call_index];

    std::string instance_key = "derived_wallets<>" + current_instance;
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedCurrentHold] FAILED: Derived wallet not owned by current contract", true);
        return WasmEdge_Result_Terminate;
    }

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    std::string status = derived_current_create_hold(*sender, contract_id, amount, derived_wallet_raw);
    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}
