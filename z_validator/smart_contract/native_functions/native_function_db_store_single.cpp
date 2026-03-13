#include "native_function_db_store_single.h"
#include "smart_contract_service.h"
#include "db_base.h"
#include "smart_contract_sender_data.h"
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>
#include "nf_helpers.h"

WasmEdge_Result DBStoreSingle(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t ValuePointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t ValueSize = WasmEdge_ValueGetI32(In[3]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  std::string keyString;
  if (!read_wasm_param(MemCxt, KeyPointer, KeySize, keyString))
  {
    return WasmEdge_Result_Terminate;
  }

  std::string valueString;
  if (!read_wasm_param(MemCxt, ValuePointer, ValueSize, valueString))
  {
    return WasmEdge_Result_Terminate;
  }

  db_smart_contracts::store_single(keyString, valueString);

  return WasmEdge_Result_Success;
}