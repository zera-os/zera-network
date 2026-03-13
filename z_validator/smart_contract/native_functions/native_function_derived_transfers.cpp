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
#include "const.h"
#include "base58.h"
#include "../../logging/logging.h"
#include "wallet.pb.h"
#include "nf_helpers.h"
#include <google/protobuf/util/time_util.h>

//*************************************************************
//                 Derived Wallet Transfers
// These functions allow derived wallets to Send and SendAll
// with additional ownership verification checks
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


    void set_auth(zera_txn::TransferAuthentication *auth, SenderDataType &sender, const std::string &derived_wallet)
    {
        auth->add_nonce(sender.sc_nonce);
        sender.sc_nonce++;
        std::string sc_auth = "scd_" + derived_wallet;
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
            sender.txn_hashes.push_back(txn.base().hash());
            block_txns.add_coin_txns()->CopyFrom(txn);
            txn_hash_tracker::add_sc_hash(txn.base().hash());
        }

        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    // Verify that a derived wallet is owned by the specified smart contract instance
    bool verify_derived_wallet_ownership(const std::string &base58_derived_wallet, const std::string &instance_key, const SenderDataType &sender)
    {

        // First check if wallet was recently derived (in sender.derived_wallets)
        auto it = sender.derived_wallets.find(base58_derived_wallet);
        if (it != sender.derived_wallets.end())
        {
            // Verify the stored instance key matches
            if (it->second == instance_key)
            {
                return true;
            }
        }

        // Check database for previously stored derived wallets
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

    // Create transfer using derived wallet (for Send variant)
    std::string derived_create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount,
                                       const std::string &wallet, const std::string &derived_wallet_raw, bool transfer_all_zra = false)
    {
        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;
        uint256_t amount_int(amount);

        zera_txn::CoinTXN txn;
        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);
        set_auth(txn.mutable_auth(), sender, derived_wallet_raw);
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

        // Temporarily swap the smart contract wallet with the derived wallet for processing
        std::string original_wallet = sender.smart_contract_wallet;
        sender.smart_contract_wallet = derived_wallet_raw;

        std::string result = process_txn(sender, txn);

        // Restore original wallet
        sender.smart_contract_wallet = original_wallet;

        return result;
    }

    // Create transfer using derived wallet with delegate (for DelegateSend variant)
    std::string derived_delegate_create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount,
                                                 const std::string &wallet, std::string &sc_auth,
                                                 const std::string &derived_wallet_raw, bool transfer_all_zra = false)
    {
        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;
        uint256_t amount_int(amount);

        zera_txn::CoinTXN txn;
        zera_txn::BaseTXN *base = txn.mutable_base();


        if(!delegate_set_base_from_auth(base, sender, sc_auth))
        {
            return "FAILED: Smart contract instance not found";
        }

        set_auth(txn.mutable_auth(), sender, derived_wallet_raw);
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

        // Note: For delegate transfers, we don't swap the wallet since delegate already handles this
        return process_txn(sender, txn);
    }

    // Create transfer using derived wallet with current context (for CurrentSend variant)
    std::string derived_current_create_transfer(SenderDataType &sender, const std::string &contract_id, const std::string &amount,
                                                const std::string &wallet, const std::string &derived_wallet_raw, bool transfer_all_zra = false)
    {
        uint256_t contract_fee_amount = 0;
        uint256_t txn_fee_amount = 0;
        uint256_t amount_int(amount);

        zera_txn::CoinTXN txn;
        zera_txn::BaseTXN *base = txn.mutable_base();

        std::string sc_auth = current_set_base(base, sender);

        if(sc_auth == "")
        {
            return "FAILED: Current smart contract instance not found";
        }

        std::string delegate_wallet = sender.current_smart_contract_instance_name;
        set_auth(txn.mutable_auth(), sender, derived_wallet_raw);
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

        // Temporarily swap for current context
        size_t call_size = sender.wallet_chain.size();
        int call_index = call_size - 1;
        std::string original_wallet = sender.wallet_chain[call_index];
        sender.wallet_chain[call_index] = derived_wallet_raw;

        std::string result = process_txn(sender, txn);

        // Restore original wallet
        sender.wallet_chain[call_index] = original_wallet;

        return result;
    }
}


//*************************************************************
//                     DerivedSend
// Send from a derived wallet (sender's contract context)
//*************************************************************
WasmEdge_Result DerivedSend(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    // Get contract ID
    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }

    // Get amount
    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }

    if (!is_valid_uint256(amount))
    {
        logging::print("[DerivedSend] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Terminate;
    }

    // Get destination wallet
    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    // Get derived wallet
    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }

    // Verify derived wallet ownership
    std::string instance_key = "derived_wallets<>" + sender->smart_contract_instance;
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedSend] FAILED: Derived wallet not owned by this contract", true);
        return WasmEdge_Result_Terminate;
    }

    // Decode wallets
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

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    std::string status = derived_create_transfer(*sender, contract_id, amount, wallet_string, derived_wallet_raw);


    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

//*************************************************************
//                  DerivedDelegateSend
// Send from a derived wallet (delegate contract context)
//*************************************************************
WasmEdge_Result DerivedDelegateSend(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t DelegatePointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t DelegateSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t InstancePointer = WasmEdge_ValueGetI32(In[10]);
    uint32_t InstanceSize = WasmEdge_ValueGetI32(In[11]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[12]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    // Get contract ID
    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSend] Contract ID: ", contract_id, true);

    // Get amount
    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }

    if (!is_valid_uint256(amount))
    {
        std::string result = "[DerivedDelegateSend] FAILED: Invalid uint256";
        const char *val = result.c_str();
        const size_t len = result.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        logging::print("[DerivedDelegateSend] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Fail;
    }
    logging::print("[DerivedDelegateSend] Amount: ", amount, true);

    // Get destination wallet
    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSend] Wallet: ", wallet, true);

    // Get delegate wallet
    std::string sc_name;
    if (!read_wasm_param(MemCxt, DelegatePointer, DelegateSize, sc_name))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSend] SC Name: ", sc_name, true);

    // Get derived wallet
    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSend] Derived Wallet: ", derived_wallet_base58, true);

    // Get contract instance name
    std::string instance;
    if (!read_wasm_param(MemCxt, InstancePointer, InstanceSize, instance))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSend] Instance: ", instance, true);



    std::string sc_auth = sc_name + "_" + instance;

    if (!in_call_chain(sc_auth, *sender))
    {
        return WasmEdge_Result_Terminate;
    }

    // Build the instance key for verification
    std::string instance_key = "derived_wallets<>" + sc_auth;

    // Verify derived wallet ownership
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedDelegateSend] FAILED: Derived wallet not owned by specified contract", true);
        return WasmEdge_Result_Terminate;
    }

    // Decode wallets
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


    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    
    std::string status = "OK";
    if(amount != "0")
    {
        status = derived_delegate_create_transfer(*sender, contract_id, amount, wallet_string, sc_auth, derived_wallet_raw);
    }

    logging::print("[DerivedDelegateSend] Status: ", status, true);

    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

//*************************************************************
//                   DerivedCurrentSend
// Send from a derived wallet (current contract context)
//*************************************************************
WasmEdge_Result DerivedCurrentSend(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    // Get contract ID
    std::string contract_id;
    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedCurrentSend] Contract ID: ", contract_id, true);

    // Get amount
    std::string amount;
    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }

    if (!is_valid_uint256(amount))
    {
        std::string result = "[DerivedCurrentSend] FAILED: Invalid uint256";
        const char *val = result.c_str();
        const size_t len = result.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        logging::print("[DerivedCurrentSend] FAILED: Invalid uint256", true);
        return WasmEdge_Result_Fail;
    }
    logging::print("[DerivedCurrentSend] Amount: ", amount, true);

    // Get destination wallet
    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedCurrentSend] Wallet: ", wallet, true);

    // Get derived wallet
    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedCurrentSend] Derived Wallet: ", derived_wallet_base58, true);

    // Get current smart contract instance
    size_t call_size = sender->call_chain.size();
    int call_index = call_size - 1;
    std::string current_instance = sender->call_chain[call_index];

    // Verify derived wallet ownership
    std::string instance_key = "derived_wallets<>" + current_instance;
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedCurrentSend] FAILED: Derived wallet not owned by current contract", true);
        return WasmEdge_Result_Terminate;
    }

    // Decode wallets
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

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());


    std::string status = "OK";
    if(amount != "0")
    {
        status = derived_current_create_transfer(*sender, contract_id, amount, wallet_string, derived_wallet_raw);
    }

    logging::print("[DerivedCurrentSend] Status: ", status, true);

    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

//*************************************************************
//                     DerivedSendAll
// Send all tokens from a derived wallet (sender's context)
//*************************************************************
WasmEdge_Result DerivedSendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    // Get destination wallet
    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    // Get derived wallet
    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedSendAll] Derived Wallet: ", derived_wallet_base58, true);

    // Verify derived wallet ownership
    std::string instance_key = "derived_wallets<>" + sender->smart_contract_instance;
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedSendAll] FAILED: Derived wallet not owned by this contract", true);
        return WasmEdge_Result_Terminate;
    }

    // Decode wallets
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

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    // Get token lookup for derived wallet
    std::string wallet_lookup = "TOKEN_LOOKUP_" + derived_wallet_raw;
    std::string lookup_data;
    if (!db_wallet_lookup::get_single(wallet_lookup, lookup_data))
    {
        std::string result = "No tokens found for derived wallet";
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
        logging::print("[DerivedSendAll] FAILED: Did not parse token lookup", true);

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
        if (db_wallets::get_single(derived_wallet_raw + token, amount))
        {
            std::string status = derived_create_transfer(*sender, token, amount, wallet_string, derived_wallet_raw);
            transfer_message += token + std::string(": ") + status + std::string(", ");
        }
    }

    std::string amount;

    if (db_processed_wallets::get_single(derived_wallet_raw + NETWORK_CONTRACT, amount) || db_wallets::get_single(derived_wallet_raw + NETWORK_CONTRACT, amount))
    {
        std::string status = derived_create_transfer(*sender, NETWORK_CONTRACT, amount, wallet_string, derived_wallet_raw, true);
        transfer_message += std::string(NETWORK_CONTRACT + " :") + status;
    }

    std::string result = transfer_message;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

//*************************************************************
//                DerivedDelegateSendAll
// Send all tokens from a derived wallet (delegate context)
//*************************************************************
WasmEdge_Result DerivedDelegateSendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t DelegateWalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t DelegateWalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t DelegatePointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t DelegateSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t InstancePointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t InstanceSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[10]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    // Get destination wallet
    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    // Get delegate wallet
    std::string delegate_wallet;
    if (!read_wasm_param(MemCxt, DelegateWalletPointer, DelegateWalletSize, delegate_wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    // Get derived wallet
    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSendAll] Derived Wallet: ", derived_wallet_base58, true);

    // Get contract instance name
    std::string instance;
    if (!read_wasm_param(MemCxt, InstancePointer, InstanceSize, instance))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSendAll] Instance: ", instance, true);

    std::string sc_name;
    if (!read_wasm_param(MemCxt, DelegatePointer, DelegateSize, sc_name))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedDelegateSendAll] SC Name: ", sc_name, true);

    std::string sc_auth = sc_name + "_" + instance;

    if (!in_call_chain(sc_auth, *sender))
    {
        return WasmEdge_Result_Fail;
    }

    // Build the instance key for verification
    std::string instance_key = "derived_wallets<>" + sc_auth;

    // Verify derived wallet ownership
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedDelegateSendAll] FAILED: Derived wallet not owned by specified contract", true);
        return WasmEdge_Result_Terminate;
    }

    // Decode wallets
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

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    // Get token lookup for derived wallet
    std::string wallet_lookup = "TOKEN_LOOKUP_" + derived_wallet_raw;
    std::string lookup_data;
    if (!db_wallet_lookup::get_single(wallet_lookup, lookup_data))
    {
        std::string result = "No tokens found for derived wallet";
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
        logging::print("[DerivedDelegateSendAll] FAILED: Did not parse token lookup", true);
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
        if (db_wallets::get_single(derived_wallet_raw + token, amount))
        {
            std::string status = derived_delegate_create_transfer(*sender, token, amount, wallet_string, sc_name, derived_wallet_raw);
            transfer_message += token + std::string(": ") + status + std::string(", ");
        }
    }

    std::string amount;

    if (db_processed_wallets::get_single(derived_wallet_raw + NETWORK_CONTRACT, amount) || db_wallets::get_single(derived_wallet_raw + NETWORK_CONTRACT, amount))
    {
        std::string status = derived_delegate_create_transfer(*sender, NETWORK_CONTRACT, amount, wallet_string, sc_name, derived_wallet_raw, true);
        transfer_message += std::string(NETWORK_CONTRACT + " :") + status;
    }

    std::string result = transfer_message;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

//*************************************************************
//                 DerivedCurrentSendAll
// Send all tokens from a derived wallet (current context)
//*************************************************************
WasmEdge_Result DerivedCurrentSendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t DerivedWalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t DerivedWalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    // Get destination wallet
    std::string wallet;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet))
    {
        return WasmEdge_Result_Terminate;
    }

    // Get derived wallet
    std::string derived_wallet_base58;
    if (!read_wasm_param(MemCxt, DerivedWalletPointer, DerivedWalletSize, derived_wallet_base58))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[DerivedCurrentSendAll] Derived Wallet: ", derived_wallet_base58, true);

    // Get current smart contract instance
    size_t call_size = sender->call_chain.size();
    int call_index = call_size - 1;
    std::string current_instance = sender->call_chain[call_index];

    // Verify derived wallet ownership
    std::string instance_key = "derived_wallets<>" + current_instance;
    if (!verify_derived_wallet_ownership(derived_wallet_base58, instance_key, *sender))
    {
        logging::print("[DerivedCurrentSendAll] FAILED: Derived wallet not owned by current contract", true);
        return WasmEdge_Result_Terminate;
    }

    // Decode wallets
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

    std::vector<uint8_t> derived_wallet_decode = base58_decode(derived_wallet_base58);
    std::string derived_wallet_raw(derived_wallet_decode.begin(), derived_wallet_decode.end());

    // Get token lookup for derived wallet
    std::string wallet_lookup = "TOKEN_LOOKUP_" + derived_wallet_raw;
    std::string lookup_data;
    if (!db_wallet_lookup::get_single(wallet_lookup, lookup_data))
    {
        std::string result = "No tokens found for derived wallet";
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
        logging::print("[DerivedCurrentSendAll] FAILED: Did not parse token lookup", true);
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
        if (db_wallets::get_single(derived_wallet_raw + token, amount))
        {
            std::string status = derived_current_create_transfer(*sender, token, amount, wallet_string, derived_wallet_raw);
            transfer_message += token + std::string(": ") + status + std::string(", ");
        }
    }

    std::string amount;

    if (db_processed_wallets::get_single(derived_wallet_raw + NETWORK_CONTRACT, amount) || db_wallets::get_single(derived_wallet_raw + NETWORK_CONTRACT, amount))
    {
        std::string status = derived_current_create_transfer(*sender, NETWORK_CONTRACT, amount, wallet_string, derived_wallet_raw, true);
        transfer_message += std::string(NETWORK_CONTRACT + " :") + status;
    }

    std::string result = transfer_message;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}
