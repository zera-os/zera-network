#include "native_function_get_ace.h"
#include "smart_contract_service.h"
#include "db_base.h"
#include "smart_contract_sender_data.h"
#include "../../logging/logging.h"
#include "fees.h"

WasmEdge_Result GetACEData(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
    logging::print("[GetACEData] START");
    /*
     * Params: {i32, i32, i32}
     * Returns: {i32}
     */
    uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
    uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);
    uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

    std::vector<unsigned char> ContractKey(ContractSize);

    WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
    // read data
    WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);
    if (WasmEdge_ResultOK(Res))
    {
        // retrieve Value by ContractID
        //
        std::string contract_id(reinterpret_cast<char *>(ContractKey.data()), ContractSize);

        std::string qualified = "true";
        std::string rate_str;
        uint256_t cur_equiv;
        if(!zera_fees::get_cur_equiv(contract_id, cur_equiv))
        {
            qualified = "false";
            rate_str = "0";
        }
        else
        {
            rate_str = cur_equiv.str();
        }

        std::string return_data = qualified + "," + rate_str;

        logging::print("[GetACEData] Return data: ", return_data, true);

        const char *val = return_data.c_str();
        const size_t len = return_data.length();
        WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
        Out[0] = WasmEdge_ValueGenI32(len);

        return WasmEdge_Result_Success;
    }
    else
    {
        return Res;
    }
}