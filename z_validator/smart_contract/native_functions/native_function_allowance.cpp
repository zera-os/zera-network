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


    std::string process_txn(SenderDataType &sender, const zera_txn::AllowanceTXN &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);

        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE, false, sender.fee_address, true, sender.txn_hash, sender.fee_smart_contract_wallet);

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
            std::string sc_auth;
            if (!delegate_set_base(base, sender, delegate_wallet, sc_auth))
            {
                return "FAILED: Delegate wallet not found";
            }
        }

        txn.set_contract_id(contract_id);

        calc_fee(txn.mutable_base(), sender.fee_id, txn.ByteSize(), zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE);

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

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    bool authorize;

    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[Allowance] Contract ID:", contract_id);

    std::string wallet_temp;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    auto wallet_vec = base58_decode(wallet_temp);
    wallet = std::string(wallet_vec.begin(), wallet_vec.end());
    logging::print("[Allowance] Wallet:", wallet_temp, true);

    if (!read_wasm_param(MemCxt, CurrencyPointer, CurrencySize, currency))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[Allowance] Currency:", currency, true);

    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[Allowance] Amount:", amount, true);

    std::string months_temp;
    if (!read_wasm_param(MemCxt, MonthsPointer, MonthsSize, months_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string seconds_temp;
    if (!read_wasm_param(MemCxt, SecondsPointer, SecondsSize, seconds_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
    {
        std::string result = "[Allowance] FAILED: Invalid uint32_t for seconds";
        const char *val = result.c_str();
        const size_t len = result.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        return WasmEdge_Result_Success;
    }
    seconds = seconds_temp;
    logging::print("[Allowance] Seconds:", seconds, true);

    std::string start_temp;
    if (!read_wasm_param(MemCxt, StartPointer, StartSize, start_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string authorize_temp;
    if (!read_wasm_param(MemCxt, AuthorizePointer, AuthorizeSize, authorize_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    authorize = (authorize_temp == "true");
    logging::print("[Allowance] Authorize:", authorize_temp, true);

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

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    bool authorize;

    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceSender] Contract ID:", contract_id);

    std::string wallet_temp;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    auto wallet_vec = base58_decode(wallet_temp);
    wallet = std::string(wallet_vec.begin(), wallet_vec.end());
    logging::print("[AllowanceSender] Wallet:", wallet_temp, true);

    if (!read_wasm_param(MemCxt, CurrencyPointer, CurrencySize, currency))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceSender] Currency:", currency, true);

    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceSender] Amount:", amount, true);

    std::string months_temp;
    if (!read_wasm_param(MemCxt, MonthsPointer, MonthsSize, months_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string seconds_temp;
    if (!read_wasm_param(MemCxt, SecondsPointer, SecondsSize, seconds_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
    {
        std::string result = "[AllowanceSender] FAILED: Invalid uint32_t for seconds";
        const char *val = result.c_str();
        const size_t len = result.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        return WasmEdge_Result_Success;
    }
    seconds = seconds_temp;
    logging::print("[AllowanceSender] Seconds:", seconds, true);

    std::string start_temp;
    if (!read_wasm_param(MemCxt, StartPointer, StartSize, start_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string authorize_temp;
    if (!read_wasm_param(MemCxt, AuthorizePointer, AuthorizeSize, authorize_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    authorize = (authorize_temp == "true");
    logging::print("[AllowanceSender] Authorize:", authorize_temp, true);

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

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    bool authorize;

    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceCurrent] Contract ID:", contract_id);

    std::string wallet_temp;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    auto wallet_vec = base58_decode(wallet_temp);
    wallet = std::string(wallet_vec.begin(), wallet_vec.end());
    logging::print("[AllowanceCurrent] Wallet:", wallet_temp, true);

    if (!read_wasm_param(MemCxt, CurrencyPointer, CurrencySize, currency))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceCurrent] Currency:", currency, true);

    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceSender] Amount:", amount, true);

    std::string months_temp;
    if (!read_wasm_param(MemCxt, MonthsPointer, MonthsSize, months_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string seconds_temp;
    if (!read_wasm_param(MemCxt, SecondsPointer, SecondsSize, seconds_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
    {
        std::string result = "[AllowanceCurrent] FAILED: Invalid uint32_t for seconds";
        const char *val = result.c_str();
        const size_t len = result.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        return WasmEdge_Result_Success;
    }
    seconds = seconds_temp;
    logging::print("[AllowanceCurrent] Seconds:", seconds, true);

    std::string start_temp;
    if (!read_wasm_param(MemCxt, StartPointer, StartSize, start_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string authorize_temp;
    if (!read_wasm_param(MemCxt, AuthorizePointer, AuthorizeSize, authorize_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    authorize = (authorize_temp == "true");
    logging::print("[AllowanceSender] Authorize:", authorize_temp, true);

    SenderDataType* sender = (SenderDataType *)Data;

    logging::print("[AllowanceCurrent] create_allowance");
    std::string result = create_allowance(*sender, contract_id, wallet, "", currency, amount, months, seconds, start, authorize, 2);

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

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string contract_id;
    std::string wallet;
    std::string currency;
    std::string amount;
    std::string months;
    std::string seconds;
    std::string start;
    std::string delegate_wallet;
    bool authorize;

    if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceDelegate] Contract ID:", contract_id);

    std::string wallet_temp;
    if (!read_wasm_param(MemCxt, WalletPointer, WalletSize, wallet_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    auto wallet_vec = base58_decode(wallet_temp);
    wallet = std::string(wallet_vec.begin(), wallet_vec.end());
    logging::print("[AllowanceDelegate] Wallet:", wallet_temp, true);

    if (!read_wasm_param(MemCxt, CurrencyPointer, CurrencySize, currency))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceCurrent] Currency:", currency, true);

    if (!read_wasm_param(MemCxt, AmountPointer, AmountSize, amount))
    {
        return WasmEdge_Result_Terminate;
    }
    logging::print("[AllowanceDelegate] Amount:", amount, true);

    std::string months_temp;
    if (!read_wasm_param(MemCxt, MonthsPointer, MonthsSize, months_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string seconds_temp;
    if (!read_wasm_param(MemCxt, SecondsPointer, SecondsSize, seconds_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    if (seconds_temp != "N/A" && !isValidUint32(seconds_temp))
    {
        std::string result = "[AllowanceDelegate] FAILED: Invalid uint32_t for seconds";
        const char *val = result.c_str();
        const size_t len = result.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);
        return WasmEdge_Result_Success;
    }
    seconds = seconds_temp;
    logging::print("[AllowanceDelegate] Seconds:", seconds, true);

    std::string start_temp;
    if (!read_wasm_param(MemCxt, StartPointer, StartSize, start_temp))
    {
        return WasmEdge_Result_Terminate;
    }
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

    std::string authorize_temp;
    if (!read_wasm_param(MemCxt, AuthorizePointer, AuthorizeSize, authorize_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    authorize = (authorize_temp == "true");
    logging::print("[AllowanceDelegate] Authorize:", authorize_temp, true);

    std::string delegate_temp;
    if (!read_wasm_param(MemCxt, DelegatePointer, DelegateSize, delegate_temp))
    {
        return WasmEdge_Result_Terminate;
    }
    auto delegate_vec = base58_decode(delegate_temp);
    delegate_wallet = std::string(delegate_vec.begin(), delegate_vec.end());
    logging::print("[AllowanceDelegate] delegate_wallet:", delegate_temp, true);

    SenderDataType* sender = (SenderDataType *)Data;

    logging::print("[AllowanceDelegate] create_allowance");
    std::string result = create_allowance(*sender, contract_id, wallet, delegate_wallet, currency, amount, months, seconds, start, authorize, 3);

    const char *val = result.c_str();
    const size_t len = result.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
}