#include "native_function_db_store_single.h"
#include "smart_contract_service.h"
#include "db_base.h"
#include "smart_contract_sender_data.h"
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

WasmEdge_Result DBStoreSingle(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32, i32}
   */

  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t ValuePointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t ValueSize = WasmEdge_ValueGetI32(In[3]);

  std::vector<unsigned char> Key(KeySize);
  std::vector<unsigned char> Value(ValueSize);

  // https://wasmedge.org/docs/embed/c/host_function/#calling-frame-context
  // https://www.secondstate.io/articles/extend-webassembly/
  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Key.data(), KeyPointer, KeySize);
  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, Value.data(), ValuePointer, ValueSize);
  if (WasmEdge_ResultOK(Res))
  {
    if (WasmEdge_ResultOK(Res2))
    {
      // store Key and Value
      //
      std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);
      std::string valueString(reinterpret_cast<char *>(Value.data()), ValueSize);

      db_smart_contracts::store_single(keyString, valueString);

      return WasmEdge_Result_Success;
    }
    else
    {
      return Res2;
    }
  }
  else
  {
    return Res;
  }
}