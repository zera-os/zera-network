#include "native_function_db_get_data.h"
#include "smart_contract_service.h"
#include "db_base.h"
#include "txn.pb.h"
#include "smart_contract_sender_data.h"
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>
#include "nf_helpers.h"

namespace
{
  std::string get_db_data(const std::string &db_key, const std::string &key)
  {
    std::string raw_data;
    if (db_key == "db_wallets")
    {
      if (!db_wallets_temp::get_single(key, raw_data) && !db_wallets::get_single(key, raw_data))
      {
        raw_data = "";
      }
    }
    else if(db_key == "db_wallet_nonce")
    {
      db_wallet_nonce::get_single(key, raw_data);
    }
    else
    {
      raw_data = "";
    }

    return raw_data;
  }
}

WasmEdge_Result DBGetAnyData(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

  uint32_t DBKeyPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t DBKeySize = WasmEdge_ValueGetI32(In[3]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  std::string keyString;
  if (!read_wasm_param(MemCxt, KeyPointer, KeySize, keyString))
  {
    return WasmEdge_Result_Terminate;
  }

  std::string dbKeyString;
  if (!read_wasm_param(MemCxt, DBKeyPointer, DBKeySize, dbKeyString))
  {
    return WasmEdge_Result_Terminate;
  }

  std::string raw_data;
  raw_data = get_db_data(dbKeyString, keyString);

  const char *val = raw_data.c_str();
  const size_t len = raw_data.length();

  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result DBGetData(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  std::string keyString;
  if (!read_wasm_param(MemCxt, KeyPointer, KeySize, keyString))
  {
    return WasmEdge_Result_Terminate;
  }

  std::string raw_data;
  db_smart_contracts::get_single(keyString, raw_data);

  const char *val = raw_data.c_str();
  const size_t len = raw_data.length();

  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}