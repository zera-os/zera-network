#include "native_function_db_get_data.h"
#include "smart_contract_service.h"
#include "db_base.h"
#include "txn.pb.h"
#include "smart_contract_sender_data.h"
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

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
  /*
   * Params: {i32, i32, i32}
   * Returns: {i32}
   */

  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

  uint32_t DBKeyPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t DBKeySize = WasmEdge_ValueGetI32(In[3]);

  std::vector<unsigned char> Key(KeySize);
  std::vector<unsigned char> DBKey(DBKeySize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Key.data(), KeyPointer, KeySize);
  std::string keyString;
  if (WasmEdge_ResultOK(Res))
  {
    // retrieve Value by Key
    std::string tempKeyString(reinterpret_cast<char *>(Key.data()), KeySize);
    keyString = tempKeyString;
  }
  else
  {
    return Res;
  }

  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, DBKey.data(), DBKeyPointer, DBKeySize);

  if(WasmEdge_ResultOK(Res))
  {
    std::string dbKeyString(reinterpret_cast<char *>(DBKey.data()), DBKeySize);

    std::string raw_data;
    raw_data = get_db_data(dbKeyString, keyString);

    const char *val = raw_data.c_str();
    const size_t len = raw_data.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res2;
  }
}

WasmEdge_Result DBGetData(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32}
   * Returns: {i32}
   */
  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> Key(KeySize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Key.data(), KeyPointer, KeySize);
  if (WasmEdge_ResultOK(Res))
  {
    // retrieve Value by Key
    //
    std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);

    std::string raw_data;
    db_smart_contracts::get_single(keyString, raw_data);

    const char *val = raw_data.c_str();
    const size_t len = raw_data.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}