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
#include "sc_base64.h"
#include "nt_helpers.h"

WasmEdge_Result SubmitTXN(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out)
{

    SenderDataType *sender = (SenderDataType *)Data;
    uint32_t TXNPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t TXNSize = WasmEdge_ValueGetI32(In[1]);
    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

    std::string network_txn_string;
    if (!read_wasm_param(MemCxt, TXNPointer, TXNSize, network_txn_string))
    {
        return WasmEdge_Result_Terminate;
    }

    NetworkTXN network_txn = decode_network_txn(network_txn_string);

    std::string result = nt_process_network_txn(sender, network_txn);
    logging::print("[SubmitTXN] result:", result, true);

    if (result != "OK")
    {
        logging::print("[SubmitTXN] ERROR: ", result, true);
        return WasmEdge_Result_Terminate;
    }

    const char *val = result.c_str();
    const size_t len = result.length();
    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
}