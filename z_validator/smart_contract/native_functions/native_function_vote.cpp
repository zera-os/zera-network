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

namespace
{

    std::string process_txn(SenderDataType &sender, const zera_txn::GovernanceVote &txn)
    {
        std::string value;
        db_smart_contracts::get_single(sender.block_txns_key, value);
        zera_txn::TXNS block_txns;
        block_txns.ParseFromString(value);

        std::string fee_address = sender.fee_address;
        ZeraStatus status = proposing::unpack_process_wrapper(&txn, &block_txns, zera_txn::TRANSACTION_TYPE::VOTE_TYPE, false, fee_address, true);

        if (status.ok())
        {
            sender.txn_hashes.push_back(txn.base().hash());
            block_txns.add_governance_votes()->CopyFrom(txn);
            txn_hash_tracker::add_sc_hash(txn.base().hash());
        }
        db_smart_contracts::store_single(sender.block_txns_key, block_txns.SerializeAsString());

        return zera_txn::TXN_STATUS_Name(status.txn_status());
    }

    std::string create_vote(SenderDataType &sender, zera_txn::GovernanceVote &txn)
    {
        zera_txn::BaseTXN *base = txn.mutable_base();

        set_base(base, sender);
        calc_fee(base, sender.fee_id, txn.ByteSize(), zera_txn::TRANSACTION_TYPE::VOTE_TYPE);

        auto hash_vec = Hashing::sha256_hash(txn.SerializeAsString());
        std::string hash(hash_vec.begin(), hash_vec.end());
        base->set_hash(hash);

        return process_txn(sender, txn);
    }

}
WasmEdge_Result Vote(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    SenderDataType* sender = (SenderDataType *)Data;

    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

    uint32_t ProposalPointer = WasmEdge_ValueGetI32(In[2]);
    uint32_t ProposalSize = WasmEdge_ValueGetI32(In[3]);

    uint32_t OptionPointer = WasmEdge_ValueGetI32(In[4]);
    uint32_t OptionSize = WasmEdge_ValueGetI32(In[5]);

    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

    std::vector<unsigned char> ContractKey(ContractSize);
    std::vector<unsigned char> ProposalKey(ProposalSize);
    std::vector<unsigned char> OptionKey(OptionSize);

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

    WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, ProposalKey.data(), ProposalPointer, ProposalSize);
    std::string proposal_id;
    if (WasmEdge_ResultOK(Res2))
    {
        std::string prop_temp(reinterpret_cast<char *>(ProposalKey.data()), ProposalSize);
        proposal_id = prop_temp;
    }
    else
    {
        return Res2;
    }

    WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, OptionKey.data(), OptionPointer, OptionSize);
    std::string option;
    if (WasmEdge_ResultOK(Res3))
    {
        std::string option_temp(reinterpret_cast<char *>(OptionKey.data()), OptionSize);
        option = option_temp;
    }
    else
    {
        return Res3;
    }

    zera_txn::GovernanceVote txn;

    if (option == "true" || option == "false")
    {
        txn.set_support(option == "true" ? true : false);
    }
    else if (std::all_of(option.begin(), option.end(), ::isdigit)) // Check if the option is a uint
    {
        try
        {
            uint64_t numeric_option = std::stoull(option); // Convert the string to uint64_t

            // Check if the value is within the range of uint32_t
            if (numeric_option > std::numeric_limits<uint32_t>::max())
            {
                return WasmEdge_Result_Terminate; // Fail if the value is out of range
            }

            txn.set_support_option(static_cast<uint32_t>(numeric_option)); // Safe to cast now
        }
        catch (const std::exception &e)
        {
            return WasmEdge_Result_Terminate; // Fail if conversion throws an exception
        }
    }
    else
    {
        return WasmEdge_Result_Terminate; // Fail the native function if the option is invalid
    }

    txn.set_contract_id(contract_id);
    auto hex_id = hex_conversion::hex_to_bytes(proposal_id);
    std::string proposal_id_str(hex_id.begin(), hex_id.end());

    std::string status = create_vote(*sender, txn);

    const char *val = status.c_str();
    const size_t len = status.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
}