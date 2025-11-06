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

namespace
{
    // Function to validate if seconds_temp is a valid uint32_t
    bool isValidUint32(const std::string &seconds_temp)
    {
        try
        {
            // Convert string to unsigned long long
            unsigned long long value = std::stoull(seconds_temp);

            // Check if the value is within the range of uint32_t
            if (value <= std::numeric_limits<uint32_t>::max())
            {
                return true;
            }
        }
        catch (const std::invalid_argument &e)
        {
            // Handle non-numeric input
            return false;
        }
        catch (const std::out_of_range &e)
        {
            // Handle values out of range
            return false;
        }

        return false;
    }

    void calc_fee(zera_txn::AllowanceTXN *txn)
    {
        uint256_t txn_fee_amount;

        uint256_t equiv;
        zera_fees::get_cur_equiv("$ZRA+0000", equiv);

        zera_txn::InstrumentContract fee_contract;
        block_process::get_contract("$ZRA+0000", fee_contract);

        uint256_t fee_per_byte(get_txn_fee(zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE));
        int byte_size = txn->ByteSize() + 64;
        std::string denomination_str = fee_contract.coin_denomination().amount();

        uint256_t fee = fee_per_byte * byte_size;
        uint256_t denomination(denomination_str);
        txn_fee_amount = (fee * denomination) / equiv;

        txn->mutable_base()->set_fee_amount(txn_fee_amount.str());
    }

    void set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
    {
        std::string sc_auth = "sc_" + sender.smart_contract_instance;
        base->mutable_public_key()->set_smart_contract_auth(sc_auth);

        base->set_nonce(sender.sc_nonce);
        sender.sc_nonce++;

        base->set_fee_amount("1000000000000");
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        base->mutable_timestamp()->set_seconds(sender.block_time);
    }

    void sender_set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
    {
        if (smart_contract_service::gov_key(sender.pub_key))
        {
            base->mutable_public_key()->set_governance_auth(sender.pub_key);
        }
        else
        {
            base->mutable_public_key()->set_single(sender.pub_key);
        }

        base->set_nonce(sender.sc_nonce);
        sender.sc_nonce++;

        base->set_fee_amount("1000000000000");
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        base->mutable_timestamp()->set_seconds(sender.block_time);
    }

    std::string delegate_set_base(zera_txn::BaseTXN *base, SenderDataType &sender, const std::string &delegate_wallet)
    {
        std::string sc_auth = "";

        int x = 0;
        for (auto &wallet : sender.wallet_chain)
        {
            if (delegate_wallet == wallet)
            {
                sc_auth = "sc_" + sender.call_chain[x];
                break;
            }
            x++;
        }

        if (sc_auth == "")
        {
            return sc_auth;
        }

        base->mutable_public_key()->set_smart_contract_auth(sc_auth);

        base->set_fee_amount("1000000000000");
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        base->mutable_timestamp()->set_seconds(sender.block_time);

        return sc_auth;
    }

    std::string current_set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
    {
        std::string sc_auth = "sc_" + sender.current_smart_contract_instance;
        base->mutable_public_key()->set_smart_contract_auth(sc_auth);

        base->set_fee_amount("100000000000");
        base->set_fee_id("$ZRA+0000");
        base->set_safe_send(false);
        base->mutable_timestamp()->set_seconds(sender.block_time);

        return sc_auth;
    }

    std::string process_txn(SenderDataType &sender, const zera_txn::AllowanceTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);

        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE, false, sender.fee_address, true);

        if (status.ok())
        {
            sender.txn_hashes.push_back(txn.base().hash());
            block_txns.add_allowance_txns()->CopyFrom(txn);
            txn_hash_tracker::add_sc_hash(txn.base().hash());
        }

        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    std::string create_allowance(SenderDataType &sender, const std::string &contract_id, const std::string &wallet, const std::string &delegate_wallet, const std::string &allowed_currency_equiv,
                                 const std::string &allowed_amount, const std::string &months, const std::string &seconds, const std::string &start_time, bool authorize, const int code)
    {
        zera_txn::AllowanceTXN txn;

        txn.set_authorize(authorize);
        txn.set_wallet_address(wallet);
        txn.set_contract_id(contract_id);

        if (authorize)
        {
            if (allowed_currency_equiv != "N/A")
            {
                txn.set_allowed_currency_equivalent(allowed_currency_equiv);
            }
            else if (allowed_amount != "N/A")
            {
                txn.set_allowed_amount(allowed_amount);
            }
            else
            {
                return "FAILED: Invalid parameters - allowed_currency_equiv or allowed_amount not provided";
            }

            if (months != "N/A")
            {
                txn.set_period_months(std::stoull(months));
            }
            else if (seconds != "N/A")
            {
                txn.set_period_seconds(std::stoull(seconds));
            }
            else
            {
                return "FAILED: Invalid parameters - months or seconds not provided";
            }

            if (start_time != "N/A")
            {
                txn.mutable_start_time()->set_seconds(std::stoull(start_time));
            }
            else
            {
                return "FAILED: Invalid parameters - start_time not provided";
            }
        }

        zera_txn::BaseTXN *base = txn.mutable_base();

        if (code == 0)
        {
            set_base(base, sender);
        }
        else if (code == 1)
        {
            sender_set_base(base, sender);
        }
        else if (code == 2)
        {
            std::string sc_auth = current_set_base(base, sender);

            if (sc_auth == "")
            {
                return "FAILED: Delegate wallet not found";
            }
        }
        else if (code == 3)
        {
            std::string sc_auth = delegate_set_base(base, sender, delegate_wallet);

            if (sc_auth == "")
            {
                return "FAILED: Delegate wallet not found";
            }
        }

        txn.set_contract_id(contract_id);

        calc_fee(&txn);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }
}

WasmEdge_Result Allowance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out)
{

    logging::print("[Allowance] START");
    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t CurrencyPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t CurrencySize = WasmEdge_ValueGetI32(In[5]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t MonthsPointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t MonthsSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t SecondsPointer = WasmEdge_ValueGetI32(In[10]);
    uint32_t SecondsSize = WasmEdge_ValueGetI32(In[11]);

    uint32_t StartPointer = WasmEdge_ValueGetI32(In[12]);
    uint32_t StartSize = WasmEdge_ValueGetI32(In[13]);

    uint32_t AuthorizePointer = WasmEdge_ValueGetI32(In[14]);
    uint32_t AuthorizeSize = WasmEdge_ValueGetI32(In[15]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[16]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> WalletKey(WalletSize);
    std::vector<unsigned char> CurrencyKey(CurrencySize);
    std::vector<unsigned char> AmountKey(AmountSize);
    std::vector<unsigned char> MonthsKey(MonthsSize);
    std::vector<unsigned char> SecondsKey(SecondsSize);
    std::vector<unsigned char> StartKey(StartSize);
    std::vector<unsigned char> AuthorizeKey(AuthorizeSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    logging::print("[Allowance] Res");
    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    bool authorize;

    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        contract_id = contract_id_temp;
        logging::print("[Allowance] Contract ID:", contract_id);
    }
    else
    {
        return Res;
    }

    logging::print("[Allowance] Res2");
    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
    if (WasmEdge_ResultOK(Res2))
    {
        std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
        auto wallet_vec = base58_decode(wallet_temp);
        wallet = std::string(wallet_vec.begin(), wallet_vec.end());
        logging::print("[Allowance] Wallet:", wallet_temp, true);
    }
    else
    {
        return Res2;
    }

    logging::print("[Allowance] Res3");
    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, CurrencyKey.data(), CurrencyPointer, CurrencySize);
    if (WasmEdge_ResultOK(Res3))
    {
        std::string currency_temp(reinterpret_cast<char *>(CurrencyKey.data()), CurrencySize);
        currency = currency_temp;
        logging::print("[Allowance] Currency:", currency, true);
    }
    else
    {
        return Res3;
    }

    logging::print("[Allowance] Res4");
    WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, AmountKey.data(), AmountPointer, AmountSize);
    if (WasmEdge_ResultOK(Res4))
    {
        std::string amount_temp(reinterpret_cast<char *>(AmountKey.data()), AmountSize);
        amount = amount_temp;
        logging::print("[Allowance] Amount:", amount, true);
    }
    else
    {
        return Res4;
    }

    logging::print("[Allowance] Res5");
    WasmEdge_Result Res5 = WasmEdge_MemoryInstanceGetData(MemCxt, MonthsKey.data(), MonthsPointer, MonthsSize);
    if (WasmEdge_ResultOK(Res5))
    {
        std::string months_temp(reinterpret_cast<char *>(MonthsKey.data()), MonthsSize);
        if (months_temp != "N/A" && !isValidUint32(months_temp))
        {
            logging::print("[Allowance] Res5 FAILED: Invalid uint32_t for months", months_temp, true);

            std::string result = "[Allowance] FAILED: Invalid uint32_t for months";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        months = months_temp;

        logging::print("[Allowance] Months:", months, true);
    }
    else
    {
        return Res5;
    }

    logging::print("[Allowance] Res 6");
    WasmEdge_Result Res6 = WasmEdge_MemoryInstanceGetData(MemCxt, SecondsKey.data(), SecondsPointer, SecondsSize);
    if (WasmEdge_ResultOK(Res6))
    {
        std::string seconds_temp(reinterpret_cast<char *>(SecondsKey.data()), SecondsSize);
        if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
        {
            std::string result = "[Allowance] FAILED: Invalid uint32_t for seconds";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        // Convert string to uint32_t
        seconds = seconds_temp;

        logging::print("[Allowance] Seconds:", seconds, true);
    }
    else
    {
        return Res6;
    }

    logging::print("[Allowance] Res 7");
    WasmEdge_Result Res7 = WasmEdge_MemoryInstanceGetData(MemCxt, StartKey.data(), StartPointer, StartSize);
    if (WasmEdge_ResultOK(Res7))
    {
        std::string start_temp(reinterpret_cast<char *>(StartKey.data()), StartSize);
        if (start_temp != "N/A" && !isValidUint32(start_temp))
        {
            std::string result = "[Allowance] FAILED: Invalid uint32_t for start time";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        start = start_temp;
        logging::print("[Allowance] Start Time:", start, true);
    }
    else
    {
        return Res7;
    }

    logging::print("[Allowance] Res8");
    WasmEdge_Result Res8 = WasmEdge_MemoryInstanceGetData(MemCxt, AuthorizeKey.data(), AuthorizePointer, AuthorizeSize);
    if (WasmEdge_ResultOK(Res8))
    {
        std::string authorize_temp(reinterpret_cast<char *>(AuthorizeKey.data()), AuthorizeSize);
        authorize = (authorize_temp == "true");
        logging::print("[Allowance] Authorize:", authorize_temp, true);
    }
    else
    {
        return Res8;
    }

    SenderDataType sender;
    sender = *(SenderDataType *)Data;
    logging::print("[Allowance] create_allowance");
    std::string result = create_allowance(sender, contract_id, wallet, "", currency, amount, months, seconds, start, authorize, 0);

    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result AllowanceSender(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                const WasmEdge_Value *In, WasmEdge_Value *Out)
{

    logging::print("[AllowanceSender] START");
    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t CurrencyPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t CurrencySize = WasmEdge_ValueGetI32(In[5]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t MonthsPointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t MonthsSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t SecondsPointer = WasmEdge_ValueGetI32(In[10]);
    uint32_t SecondsSize = WasmEdge_ValueGetI32(In[11]);

    uint32_t StartPointer = WasmEdge_ValueGetI32(In[12]);
    uint32_t StartSize = WasmEdge_ValueGetI32(In[13]);

    uint32_t AuthorizePointer = WasmEdge_ValueGetI32(In[14]);
    uint32_t AuthorizeSize = WasmEdge_ValueGetI32(In[15]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[16]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> WalletKey(WalletSize);
    std::vector<unsigned char> CurrencyKey(CurrencySize);
    std::vector<unsigned char> AmountKey(AmountSize);
    std::vector<unsigned char> MonthsKey(MonthsSize);
    std::vector<unsigned char> SecondsKey(SecondsSize);
    std::vector<unsigned char> StartKey(StartSize);
    std::vector<unsigned char> AuthorizeKey(AuthorizeSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    logging::print("[AllowanceSender] Res");
    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    bool authorize;

    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        contract_id = contract_id_temp;
        logging::print("[AllowanceSender] Contract ID:", contract_id);
    }
    else
    {
        return Res;
    }

    logging::print("[AllowanceSender] Res2");
    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
    if (WasmEdge_ResultOK(Res2))
    {
        std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
        auto wallet_vec = base58_decode(wallet_temp);
        wallet = std::string(wallet_vec.begin(), wallet_vec.end());
        logging::print("[AllowanceSender] Wallet:", wallet_temp, true);
    }
    else
    {
        return Res2;
    }

    logging::print("[AllowanceSender] Res3");
    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, CurrencyKey.data(), CurrencyPointer, CurrencySize);
    if (WasmEdge_ResultOK(Res3))
    {
        std::string currency_temp(reinterpret_cast<char *>(CurrencyKey.data()), CurrencySize);
        currency = currency_temp;
        logging::print("[AllowanceSender] Currency:", currency, true);
    }
    else
    {
        return Res3;
    }

    logging::print("[AllowanceSender] Res4");
    WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, AmountKey.data(), AmountPointer, AmountSize);
    if (WasmEdge_ResultOK(Res4))
    {
        std::string amount_temp(reinterpret_cast<char *>(AmountKey.data()), AmountSize);
        amount = amount_temp;
        logging::print("[AllowanceSender] Amount:", amount, true);
    }
    else
    {
        return Res4;
    }

    logging::print("[AllowanceSender] Res5");
    WasmEdge_Result Res5 = WasmEdge_MemoryInstanceGetData(MemCxt, MonthsKey.data(), MonthsPointer, MonthsSize);
    if (WasmEdge_ResultOK(Res5))
    {
        std::string months_temp(reinterpret_cast<char *>(MonthsKey.data()), MonthsSize);
        if (months_temp != "N/A" && !isValidUint32(months_temp))
        {
            logging::print("[AllowanceSender] Res5 FAILED: Invalid uint32_t for months", months_temp, true);

            std::string result = "[AllowanceSender] FAILED: Invalid uint32_t for months";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        months = months_temp;

        logging::print("[AllowanceSender] Months:", months, true);
    }
    else
    {
        return Res5;
    }

    logging::print("[AllowanceSender] Res 6");
    WasmEdge_Result Res6 = WasmEdge_MemoryInstanceGetData(MemCxt, SecondsKey.data(), SecondsPointer, SecondsSize);
    if (WasmEdge_ResultOK(Res6))
    {
        std::string seconds_temp(reinterpret_cast<char *>(SecondsKey.data()), SecondsSize);
        if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
        {
            std::string result = "[AllowanceSender] FAILED: Invalid uint32_t for seconds";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        // Convert string to uint32_t
        seconds = seconds_temp;

        logging::print("[AllowanceSender] Seconds:", seconds, true);
    }
    else
    {
        return Res6;
    }

    logging::print("[AllowanceSender] Res 7");
    WasmEdge_Result Res7 = WasmEdge_MemoryInstanceGetData(MemCxt, StartKey.data(), StartPointer, StartSize);
    if (WasmEdge_ResultOK(Res7))
    {
        std::string start_temp(reinterpret_cast<char *>(StartKey.data()), StartSize);
        if (start_temp != "N/A" && !isValidUint32(start_temp))
        {
            std::string result = "[AllowanceSender] FAILED: Invalid uint32_t for start time";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        start = start_temp;
        logging::print("[AllowanceSender] Start Time:", start, true);
    }
    else
    {
        return Res7;
    }

    logging::print("[AllowanceSender] Res8");
    WasmEdge_Result Res8 = WasmEdge_MemoryInstanceGetData(MemCxt, AuthorizeKey.data(), AuthorizePointer, AuthorizeSize);
    if (WasmEdge_ResultOK(Res8))
    {
        std::string authorize_temp(reinterpret_cast<char *>(AuthorizeKey.data()), AuthorizeSize);
        authorize = (authorize_temp == "true");
        logging::print("[AllowanceSender] Authorize:", authorize_temp, true);
    }
    else
    {
        return Res8;
    }

    SenderDataType sender;
    sender = *(SenderDataType *)Data;
    logging::print("[Allowance] create_allowance");
    std::string result = create_allowance(sender, contract_id, wallet, "", currency, amount, months, seconds, start, authorize, 1);

    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result AllowanceCurrent(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                 const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    logging::print("[AllowanceCurrent] START");
    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t CurrencyPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t CurrencySize = WasmEdge_ValueGetI32(In[5]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t MonthsPointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t MonthsSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t SecondsPointer = WasmEdge_ValueGetI32(In[10]);
    uint32_t SecondsSize = WasmEdge_ValueGetI32(In[11]);

    uint32_t StartPointer = WasmEdge_ValueGetI32(In[12]);
    uint32_t StartSize = WasmEdge_ValueGetI32(In[13]);

    uint32_t AuthorizePointer = WasmEdge_ValueGetI32(In[14]);
    uint32_t AuthorizeSize = WasmEdge_ValueGetI32(In[15]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[16]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> WalletKey(WalletSize);
    std::vector<unsigned char> CurrencyKey(CurrencySize);
    std::vector<unsigned char> AmountKey(AmountSize);
    std::vector<unsigned char> MonthsKey(MonthsSize);
    std::vector<unsigned char> SecondsKey(SecondsSize);
    std::vector<unsigned char> StartKey(StartSize);
    std::vector<unsigned char> AuthorizeKey(AuthorizeSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    logging::print("[AllowanceCurrent] Res");
    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    bool authorize;

    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        contract_id = contract_id_temp;
        logging::print("[AllowanceCurrent] Contract ID:", contract_id);
    }
    else
    {
        return Res;
    }

    logging::print("[AllowanceCurrent] Res2");
    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
    if (WasmEdge_ResultOK(Res2))
    {
        std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
        auto wallet_vec = base58_decode(wallet_temp);
        wallet = std::string(wallet_vec.begin(), wallet_vec.end());
        logging::print("[AllowanceCurrent] Wallet:", wallet_temp, true);
    }
    else
    {
        return Res2;
    }

    logging::print("[AllowanceCurrent] Res3");
    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, CurrencyKey.data(), CurrencyPointer, CurrencySize);
    if (WasmEdge_ResultOK(Res3))
    {
        std::string currency_temp(reinterpret_cast<char *>(CurrencyKey.data()), CurrencySize);
        currency = currency_temp;
        logging::print("[AllowanceCurrent] Currency:", currency, true);
    }
    else
    {
        return Res3;
    }

    logging::print("[AllowanceCurrent] Res4");
    WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, AmountKey.data(), AmountPointer, AmountSize);
    if (WasmEdge_ResultOK(Res4))
    {
        std::string amount_temp(reinterpret_cast<char *>(AmountKey.data()), AmountSize);
        amount = amount_temp;
        logging::print("[AllowanceSender] Amount:", amount, true);
    }
    else
    {
        return Res4;
    }

    logging::print("[AllowanceCurrent] Res5");
    WasmEdge_Result Res5 = WasmEdge_MemoryInstanceGetData(MemCxt, MonthsKey.data(), MonthsPointer, MonthsSize);
    if (WasmEdge_ResultOK(Res5))
    {
        std::string months_temp(reinterpret_cast<char *>(MonthsKey.data()), MonthsSize);
        if (months_temp != "N/A" && !isValidUint32(months_temp))
        {
            logging::print("[AllowanceSender] Res5 FAILED: Invalid uint32_t for months", months_temp, true);

            std::string result = "[AllowanceSender] FAILED: Invalid uint32_t for months";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        months = months_temp;

        logging::print("[AllowanceCurrent] Months:", months, true);
    }
    else
    {
        return Res5;
    }

    logging::print("[AllowanceCurrent] Res 6");
    WasmEdge_Result Res6 = WasmEdge_MemoryInstanceGetData(MemCxt, SecondsKey.data(), SecondsPointer, SecondsSize);
    if (WasmEdge_ResultOK(Res6))
    {
        std::string seconds_temp(reinterpret_cast<char *>(SecondsKey.data()), SecondsSize);
        if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
        {
            std::string result = "[AllowanceCurrent] FAILED: Invalid uint32_t for seconds";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        // Convert string to uint32_t
        seconds = seconds_temp;

        logging::print("[AllowanceCurrent] Seconds:", seconds, true);
    }
    else
    {
        return Res6;
    }

    logging::print("[AllowanceCurrent] Res 7");
    WasmEdge_Result Res7 = WasmEdge_MemoryInstanceGetData(MemCxt, StartKey.data(), StartPointer, StartSize);
    if (WasmEdge_ResultOK(Res7))
    {
        std::string start_temp(reinterpret_cast<char *>(StartKey.data()), StartSize);
        if (start_temp != "N/A" && !isValidUint32(start_temp))
        {
            std::string result = "[AllowanceSender] FAILED: Invalid uint32_t for start time";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        start = start_temp;
        logging::print("[AllowanceCurrent] Start Time:", start, true);
    }
    else
    {
        return Res7;
    }

    logging::print("[AllowanceCurrent] Res8");
    WasmEdge_Result Res8 = WasmEdge_MemoryInstanceGetData(MemCxt, AuthorizeKey.data(), AuthorizePointer, AuthorizeSize);
    if (WasmEdge_ResultOK(Res8))
    {
        std::string authorize_temp(reinterpret_cast<char *>(AuthorizeKey.data()), AuthorizeSize);
        authorize = (authorize_temp == "true");
        logging::print("[AllowanceSender] Authorize:", authorize_temp, true);
    }
    else
    {
        return Res8;
    }

    SenderDataType sender;
    sender = *(SenderDataType *)Data;
    logging::print("[AllowanceCurrent] create_allowance");
    std::string result = create_allowance(sender, contract_id, wallet, "", currency, amount, months, seconds, start, authorize, 2);

    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}

WasmEdge_Result AllowanceDelegate(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                  const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    logging::print("[AllowanceDelegate] START");
    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t WalletPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t WalletSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t CurrencyPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t CurrencySize = WasmEdge_ValueGetI32(In[5]);

    uint32_t AmountPointer = WasmEdge_ValueGetI32(In[6]);
    uint32_t AmountSize = WasmEdge_ValueGetI32(In[7]);

    uint32_t MonthsPointer = WasmEdge_ValueGetI32(In[8]);
    uint32_t MonthsSize = WasmEdge_ValueGetI32(In[9]);

    uint32_t SecondsPointer = WasmEdge_ValueGetI32(In[10]);
    uint32_t SecondsSize = WasmEdge_ValueGetI32(In[11]);

    uint32_t StartPointer = WasmEdge_ValueGetI32(In[12]);
    uint32_t StartSize = WasmEdge_ValueGetI32(In[13]);

    uint32_t AuthorizePointer = WasmEdge_ValueGetI32(In[14]);
    uint32_t AuthorizeSize = WasmEdge_ValueGetI32(In[15]);

    uint32_t DelegatePointer = WasmEdge_ValueGetI32(In[16]);
    uint32_t DelegateSize = WasmEdge_ValueGetI32(In[17]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[18]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> WalletKey(WalletSize);
    std::vector<unsigned char> CurrencyKey(CurrencySize);
    std::vector<unsigned char> AmountKey(AmountSize);
    std::vector<unsigned char> MonthsKey(MonthsSize);
    std::vector<unsigned char> SecondsKey(SecondsSize);
    std::vector<unsigned char> StartKey(StartSize);
    std::vector<unsigned char> AuthorizeKey(AuthorizeSize);
    std::vector<unsigned char> DelegateKey(DelegateSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    logging::print("[AllowanceDelegate] Res");
    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    std::string delegate_wallet;
    bool authorize;

    if (WasmEdge_ResultOK(Res))
    {
        std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
        contract_id = contract_id_temp;
        logging::print("[AllowanceDelegate] Contract ID:", contract_id);
    }
    else
    {
        return Res;
    }

    logging::print("[AllowanceDelegate] Res2");
    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
    if (WasmEdge_ResultOK(Res2))
    {
        std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
        auto wallet_vec = base58_decode(wallet_temp);
        wallet = std::string(wallet_vec.begin(), wallet_vec.end());
        logging::print("[AllowanceDelegate] Wallet:", wallet_temp, true);
    }
    else
    {
        return Res2;
    }

    logging::print("[AllowanceDelegate] Res3");
    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, CurrencyKey.data(), CurrencyPointer, CurrencySize);
    if (WasmEdge_ResultOK(Res3))
    {
        std::string currency_temp(reinterpret_cast<char *>(CurrencyKey.data()), CurrencySize);
        currency = currency_temp;
        logging::print("[AllowanceCurrent] Currency:", currency, true);
    }
    else
    {
        return Res3;
    }

    logging::print("[AllowanceDelegate] Res4");
    WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, AmountKey.data(), AmountPointer, AmountSize);
    if (WasmEdge_ResultOK(Res4))
    {
        std::string amount_temp(reinterpret_cast<char *>(AmountKey.data()), AmountSize);
        amount = amount_temp;
        logging::print("[AllowanceDelegate] Amount:", amount, true);
    }
    else
    {
        return Res4;
    }

    logging::print("[AllowanceDelegate] Res5");
    WasmEdge_Result Res5 = WasmEdge_MemoryInstanceGetData(MemCxt, MonthsKey.data(), MonthsPointer, MonthsSize);
    if (WasmEdge_ResultOK(Res5))
    {
        std::string months_temp(reinterpret_cast<char *>(MonthsKey.data()), MonthsSize);
        if (months_temp != "N/A" && !isValidUint32(months_temp))
        {
            logging::print("[AllowanceSender] Res5 FAILED: Invalid uint32_t for months", months_temp, true);

            std::string result = "[AllowanceSender] FAILED: Invalid uint32_t for months";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        months = months_temp;

        logging::print("[AllowanceDelegate] Months:", months, true);
    }
    else
    {
        return Res5;
    }

    logging::print("[AllowanceDelegate] Res 6");
    WasmEdge_Result Res6 = WasmEdge_MemoryInstanceGetData(MemCxt, SecondsKey.data(), SecondsPointer, SecondsSize);
    if (WasmEdge_ResultOK(Res6))
    {
        std::string seconds_temp(reinterpret_cast<char *>(SecondsKey.data()), SecondsSize);
        if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
        {
            std::string result = "[AllowanceDelegate] FAILED: Invalid uint32_t for seconds";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        // Convert string to uint32_t
        seconds = seconds_temp;

        logging::print("[AllowanceDelegate] Seconds:", seconds, true);
    }
    else
    {
        return Res6;
    }

    logging::print("[AllowanceDelegate] Res 7");
    WasmEdge_Result Res7 = WasmEdge_MemoryInstanceGetData(MemCxt, StartKey.data(), StartPointer, StartSize);
    if (WasmEdge_ResultOK(Res7))
    {
        std::string start_temp(reinterpret_cast<char *>(StartKey.data()), StartSize);
        if (start_temp != "N/A" && !isValidUint32(start_temp))
        {
            std::string result = "[AllowanceDelegate] FAILED: Invalid uint32_t for start time";
            const char *val = result.c_str();
            const size_t len = result.length();
            WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
            Out[0] = WasmEdge_ValueGenI32(len);
            return WasmEdge_Result_Success;
        }

        start = start_temp;
        logging::print("[AllowanceDelegate] Start Time:", start, true);
    }
    else
    {
        return Res7;
    }

    logging::print("[AllowanceDelegate] Res8");
    WasmEdge_Result Res8 = WasmEdge_MemoryInstanceGetData(MemCxt, AuthorizeKey.data(), AuthorizePointer, AuthorizeSize);
    if (WasmEdge_ResultOK(Res8))
    {
        std::string authorize_temp(reinterpret_cast<char *>(AuthorizeKey.data()), AuthorizeSize);
        authorize = (authorize_temp == "true");
        logging::print("[AllowanceDelegate] Authorize:", authorize_temp, true);
    }
    else
    {
        return Res8;
    }

    WasmEdge_Result Res9 = WasmEdge_MemoryInstanceGetData(MemCxt, DelegateKey.data(), DelegatePointer, DelegateSize);

    if (WasmEdge_ResultOK(Res9))
    {
        std::string delegate_temp(reinterpret_cast<char *>(DelegateKey.data()), DelegateSize);
        auto delegate_vec = base58_decode(delegate_temp);
        delegate_wallet = std::string(delegate_vec.begin(), delegate_vec.end());
        logging::print("[AllowanceDelegate] delegate_wallet:", delegate_temp, true);
    }
    else
    {
        return Res9;
    }

    SenderDataType sender;
    sender = *(SenderDataType *)Data;
    logging::print("[AllowanceDelegate] create_allowance");
    std::string result = create_allowance(sender, contract_id, wallet, delegate_wallet, currency, amount, months, seconds, start, authorize, 3);

    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}