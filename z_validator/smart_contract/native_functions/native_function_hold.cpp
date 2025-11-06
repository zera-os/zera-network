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
        if(!zera_fees::get_cur_equiv(fee_id, fee_equiv))
        {
            fee_equiv = ONE_DOLLAR;
        }
        uint256_t priority_equiv;
        if(!zera_fees::get_cur_equiv(contract.contract_id(), priority_equiv))
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
        if(!zera_fees::get_cur_equiv(fee_id, fee_equiv))
        {
            fee_equiv = ONE_DOLLAR;
        }
        uint256_t txn_equiv;
        if(!zera_fees::get_cur_equiv(fee_id, fee_equiv))
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
            if (id == "$ZRA+0000")
            {
                break;
            }

            return false;
        }

        txn->set_contract_fee_id("$ZRA+0000");

        uint256_t contract_fee(contract.contract_fees().fee());
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t contract_equiv;
        if(!zera_fees::get_cur_equiv(contract.contract_id(), contract_equiv))
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
            if(!zera_fees::get_cur_equiv(txn->contract_fee_id(), fee_equiv))
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

    void calc_fee(zera_txn::CoinTXN *txn)
    {
        uint256_t equiv;
        zera_fees::get_cur_equiv("$ZRA+0000", equiv);
        zera_txn::InstrumentContract fee_contract;
        block_process::get_contract("$ZRA+0000", fee_contract);

        uint256_t fee_per_byte(get_txn_fee(zera_txn::TRANSACTION_TYPE::COIN_TYPE));
        int byte_size = txn->ByteSize() + 64;
        std::string denomination_str = fee_contract.coin_denomination().amount();
        int256_t txn_fee_amount;
        uint256_t fee = fee_per_byte * byte_size;
        uint256_t denomination(denomination_str);
        txn_fee_amount = (fee * denomination)  / equiv;

        for (auto public_key : txn->auth().public_key())
        {
            uint256_t key_fee = get_key_fee(public_key);
            txn_fee_amount += (key_fee * denomination) / equiv;
        }
        txn->mutable_base()->set_fee_amount(txn_fee_amount.str());
    }

    void set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
    {
        std::string sc_auth = "sc_" + sender.smart_contract_instance;
        base->mutable_public_key()->set_smart_contract_auth(sc_auth);

        base->set_fee_amount("100000000000");
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        base->mutable_timestamp()->set_seconds(sender.block_time);
    }

    void current_set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
    {
        std::string sc_auth = "sc_" + sender.current_smart_contract_instance;
        base->mutable_public_key()->set_smart_contract_auth(sc_auth);

        base->set_fee_amount("100000000000");
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        base->mutable_timestamp()->set_seconds(sender.block_time);
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
        
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::COIN_TYPE, false, fee_address, true);

        if (status.ok())
        {
            sender.txn_hashes.push_back(txn.base().hash());
            block_txns.add_coin_txns()->CopyFrom(txn);
            txn_hash_tracker::add_sc_hash(txn.base().hash());
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

        calc_fee(&txn);
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

        calc_fee(&txn);
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
    SenderDataType sender = *(SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> AmountKey(AmountSize);

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
            std::string result = "[Hold] FAILED: Invalid uint256";
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

    std::string status = create_transfer(sender, contract_id, amount);
    std::string fee_address = sender.fee_address;
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
    SenderDataType sender = *(SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> AmountKey(AmountSize);

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
            std::string result = "[Hold] FAILED: Invalid uint256";
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

    std::string status = current_create_transfer(sender, contract_id, amount);
    std::string result = status;
    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}
