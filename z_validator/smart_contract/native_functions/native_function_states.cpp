#include "native_function_states.h"
#include "smart_contract_service.h"
#include "db_base.h"
#include "../../temp_data/temp_data.h"
#include "zera_status.h"
#include "const.h"
#include "../../block_process/block_process.h"
#include "smart_contract_sender_data.h"
#include "fees.h"
#include "validators.h"
#include "logging.h"
#include "nf_helpers.h"

namespace
{

  bool is_valid_smart_contract_key(const std::string &key)
  {
    if (key.empty())
    {
      return false;
    }

    for (char c : key)
    {
      if(c == '<' || c == '>')
      {
        return false;
      }
    }

    return true;
  }

}
WasmEdge_Result StoreState(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
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
      SenderDataType *sender = (SenderDataType *)Data;
      std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);
      if (!is_valid_smart_contract_key(keyString))
      {
        logging::print("Invalid smart contract key: " + keyString, true);
        return WasmEdge_Result_Terminate;
      }

      std::string storeKey = sender->current_smart_contract_instance + "<>" + keyString;
      std::string storage_data;

      if (!db_smart_contract_states::get_single(storeKey, storage_data))
      {
        std::string original_store_key = sender->current_smart_contract_instance + "_" + keyString;
        if (db_smart_contracts::get_single(original_store_key, storage_data))
        {
          db_smart_contracts::remove_single(original_store_key);
          db_smart_contract_states::store_single(storeKey, storage_data);
        }
      }
      uint64_t size = KeySize + ValueSize;
      uint64_t storage_fee;

      if (size > storage_data.length())
      {
        storage_fee = size - storage_data.length();
      }
      else
      {
        storage_fee = 0;
      }

      if (storage_fee > 0 && !storage_fees(*sender, storage_fee))
      {
        logging::print("Storage fees check failed for sender: " + storeKey, true);
        return WasmEdge_Result_Terminate;
      }
      // store Key and Value
      std::string valueString(reinterpret_cast<char *>(Value.data()), ValueSize);

      if (!db_sc_temp::exist(storeKey))
      {
        std::string original_data;
        // db_smart_contracts::get_single(storeKey, original_data);
        db_smart_contract_states::store_single(storeKey, original_data);
        db_sc_temp::store_single(storeKey, original_data);
      }
      logging::print("[StoreState] Storing key: ", storeKey, true);
      logging::print("[StoreState] Value: ", valueString, true);
      db_smart_contract_states::store_single(storeKey, valueString);

      int value = 1;
      Out[0] = WasmEdge_ValueGenI32(value);
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

WasmEdge_Result DelegateStoreState(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                   const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32, i32}
   */

  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t ValuePointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t ValueSize = WasmEdge_ValueGetI32(In[3]);
  uint32_t DelegateKeyPointer = WasmEdge_ValueGetI32(In[4]);
  uint32_t DelegateKeySize = WasmEdge_ValueGetI32(In[5]);

  std::vector<unsigned char> DelegateKey(DelegateKeySize);
  std::vector<unsigned char> Key(KeySize);
  std::vector<unsigned char> Value(ValueSize);

  // https://wasmedge.org/docs/embed/c/host_function/#calling-frame-context
  // https://www.secondstate.io/articles/extend-webassembly/
  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Key.data(), KeyPointer, KeySize);
  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, Value.data(), ValuePointer, ValueSize);
  WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, DelegateKey.data(), DelegateKeyPointer, DelegateKeySize);
  if (WasmEdge_ResultOK(Res))
  {
    if (WasmEdge_ResultOK(Res2))
    {
      if (WasmEdge_ResultOK(Res3))
      {
        SenderDataType *sender = (SenderDataType *)Data;

        std::string delegate_keyString(reinterpret_cast<char *>(DelegateKey.data()), DelegateKeySize);
        std::string delegate_key = delegate_keyString;

        std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);

        if (!is_valid_smart_contract_key(keyString))
        {
          logging::print("Invalid delegate smart contract key: " + keyString, true);
          return WasmEdge_Result_Terminate;
        }

        bool in_call_chain = false;
        for (auto &call : sender->call_chain)
        {
          if (call == delegate_key)
          {
            in_call_chain = true;
            break;
          }
        }

        if (!in_call_chain)
        {
          return WasmEdge_Result_Terminate;
        }

        std::string storeKey = delegate_key + "<>" + keyString;
        std::string storage_data;

        if (!db_smart_contract_states::get_single(storeKey, storage_data))
        {
          std::string original_store_key = delegate_key + "_" + keyString;
          if (db_smart_contracts::get_single(original_store_key, storage_data))
          {
            db_smart_contracts::remove_single(original_store_key);
            db_smart_contract_states::store_single(storeKey, storage_data);
          }
        }

        uint64_t size = KeySize + ValueSize;
        uint64_t storage_fee;

        if (size > storage_data.length())
        {
          storage_fee = size - storage_data.length();
        }
        else
        {
          storage_fee = 0;
        }

        if (storage_fee > 0 && !storage_fees(*sender, storage_fee))
        {
          logging::print("Storage fees check failed for sender: " + storeKey, true);
          return WasmEdge_Result_Terminate;
        }
        // store Key and Value
        std::string valueString(reinterpret_cast<char *>(Value.data()), ValueSize);

        if (!db_sc_temp::exist(storeKey))
        {
          std::string original_data;
          db_smart_contract_states::get_single(storeKey, original_data);
          db_sc_temp::store_single(storeKey, original_data);
        }
        logging::print("[DelegateStoreState] Storing key: ", storeKey, true);
        logging::print("[DelegateStoreState] Value: ", valueString, true);

        db_smart_contract_states::store_single(storeKey, valueString);

        int value = 1;
        Out[0] = WasmEdge_ValueGenI32(value);
        return WasmEdge_Result_Success;
      }
      else
      {
        return Res3;
      }
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

WasmEdge_Result RetrieveState(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
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
    SenderDataType *sender = (SenderDataType *)Data;

    // retrieve Value by Key
    //
    std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);

    std::string storeKey = sender->current_smart_contract_instance + "<>" + keyString;
    std::string raw_data;

    if (!db_smart_contract_states::get_single(storeKey, raw_data))
    {
      std::string original_store_key = sender->current_smart_contract_instance + "_" + keyString;
      if (db_smart_contracts::get_single(original_store_key, raw_data))
      {
        db_smart_contracts::remove_single(original_store_key);
        db_smart_contract_states::store_single(storeKey, raw_data);
      }
    }

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

WasmEdge_Result DelegateRetrieveState(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                      const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32}
   * Returns: {i32}
   */

  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t DelegateKeyPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t DelegateKeySize = WasmEdge_ValueGetI32(In[3]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

  std::vector<unsigned char> Key(KeySize);
  std::vector<unsigned char> DelegateKey(DelegateKeySize);
  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Key.data(), KeyPointer, KeySize);
  std::string key;
  if (WasmEdge_ResultOK(Res))
  {
    SenderDataType *sender = (SenderDataType *)Data;

    std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);

    key = keyString;
  }
  else
  {
    return Res;
  }

  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, DelegateKey.data(), DelegateKeyPointer, DelegateKeySize);
  std::string delegate_key;
  if (WasmEdge_ResultOK(Res2))
  {
    std::string delegate_keyString(reinterpret_cast<char *>(DelegateKey.data()), DelegateKeySize);
    delegate_key = delegate_keyString;
  }
  else
  {
    return Res2;
  }

  std::string storeKey = delegate_key + "<>" + key;
  std::string raw_data;

  if (!db_smart_contract_states::get_single(storeKey, raw_data))
  {
    std::string original_store_key = delegate_key + "_" + key;
    if (db_smart_contracts::get_single(original_store_key, raw_data))
    {
      db_smart_contracts::remove_single(original_store_key);
      db_smart_contract_states::store_single(storeKey, raw_data);
    }
  }

  const char *val = raw_data.c_str();
  const size_t len = raw_data.length();

  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result ClearState(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                           const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32, i32}
   */

  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);

  std::vector<unsigned char> Key(KeySize);

  // https://wasmedge.org/docs/embed/c/host_function/#calling-frame-context
  // https://www.secondstate.io/articles/extend-webassembly/
  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Key.data(), KeyPointer, KeySize);
  if (WasmEdge_ResultOK(Res))
  {
    SenderDataType *sender = (SenderDataType *)Data;
    // store Key and Value
    std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);
    std::string originalstoreKey = sender->current_smart_contract_instance + "_" + keyString;
    std::string storeKey = sender->current_smart_contract_instance + "<>" + keyString;

    if (!db_sc_temp::exist(storeKey))
    {
      std::string original_data;
      db_smart_contract_states::get_single(storeKey, original_data);
      db_sc_temp::store_single(storeKey, original_data);
    }

    if (!db_sc_temp::exist(originalstoreKey))
    {
      std::string original_data;
      db_smart_contracts::get_single(originalstoreKey, original_data);
      db_sc_temp::store_single(originalstoreKey, original_data);
    }

    db_smart_contracts::remove_single(originalstoreKey);
    db_smart_contract_states::remove_single(storeKey);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}

WasmEdge_Result DelegateClearState(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                   const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32, i32}
   */

  uint32_t KeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t KeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t DelegateKeyPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t DelegateKeySize = WasmEdge_ValueGetI32(In[3]);

  std::vector<unsigned char> Key(KeySize);
  std::vector<unsigned char> DelegateKey(DelegateKeySize);

  // https://wasmedge.org/docs/embed/c/host_function/#calling-frame-context
  // https://www.secondstate.io/articles/extend-webassembly/
  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Key.data(), KeyPointer, KeySize);
  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, DelegateKey.data(), DelegateKeyPointer, DelegateKeySize);
  if (WasmEdge_ResultOK(Res))
  {
    if (WasmEdge_ResultOK(Res2))
    {

      SenderDataType *sender = (SenderDataType *)Data;

      std::string delegate_keyString(reinterpret_cast<char *>(DelegateKey.data()), DelegateKeySize);
      std::string delegate_key = delegate_keyString;
      std::string keyString(reinterpret_cast<char *>(Key.data()), KeySize);

      bool in_call_chain = false;

      for (auto &call : sender->call_chain)
      {
        if (call == delegate_key)
        {
          in_call_chain = true;
          break;
        }
      }

      if (!in_call_chain)
      {
        return WasmEdge_Result_Terminate;
      }

      std::string storeKey = delegate_key + "<>" + keyString;
      std::string originalstoreKey = delegate_key + "_" + keyString;

      if (!db_sc_temp::exist(storeKey))
      {
        std::string original_data;
        db_smart_contract_states::get_single(storeKey, original_data);
        db_sc_temp::store_single(storeKey, original_data);
      }

      if (!db_sc_temp::exist(originalstoreKey))
      {
        std::string original_data;
        db_smart_contracts::get_single(originalstoreKey, original_data);
        db_sc_temp::store_single(originalstoreKey, original_data);
      }

      db_smart_contracts::remove_single(originalstoreKey);
      db_smart_contract_states::remove_single(storeKey);

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

WasmEdge_Result GetAllStates(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt, const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t DelegateKeyPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t DelegateKeySize = WasmEdge_ValueGetI32(In[1]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> DelegateKey(DelegateKeySize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, DelegateKey.data(), DelegateKeyPointer, DelegateKeySize);
  std::string delegate_key;
  if (WasmEdge_ResultOK(Res))
  {
    std::string delegate_keyString(reinterpret_cast<char *>(DelegateKey.data()), DelegateKeySize);
    delegate_key = delegate_keyString;
  }
  else
  {
    return Res;
  }

  std::vector<std::string> keys;
  std::vector<std::string> values;
  std::string return_data;

  std::string smart_contract_key = delegate_key + "<>";
  if(db_smart_contract_states::find_by_prefix(smart_contract_key, keys, values) < 1)
  {
    return_data = "";
  }
  else
  {
    for(size_t i = 0; i < keys.size(); i++)
    {
      return_data += keys[i].substr(smart_contract_key.length()) + "\n" + values[i] + "\n";
    }
  }

  const char *val = return_data.c_str();
  const size_t len = return_data.length();

  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}