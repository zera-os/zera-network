#include "native_function_utils.h"

#include "db_base.h"
#include "txn.pb.h"
#include "smart_contract_sender_data.h"
#include "nf_helpers.h"

WasmEdge_Result ContractName(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32}
   * Returns: {i32}
   *
   * Looks up a contract by id (e.g. "$ZRA+0000") and writes its name
   * to WASM memory at TargetPointer. Returns the length of the name,
   * or 0 if the contract was not found / could not be parsed.
   */

  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  std::string contract_id;
  if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
  {
    return WasmEdge_Result_Terminate;
  }

  std::string value;
  zera_txn::InstrumentContract contract;

  if (!db_contracts::get_single(contract_id, value) || !contract.ParseFromString(value))
  {
    Out[0] = WasmEdge_ValueGenI32(0);
    return WasmEdge_Result_Success;
  }

  const std::string &name = contract.name();

  const char *val = name.c_str();
  const size_t len = name.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result ContractSymbol(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                               const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32, i32}
   * Returns: {i32}
   *
   * Looks up a contract by id (e.g. "$ZRA+0000") and writes its symbol
   * to WASM memory at TargetPointer. Returns the length of the symbol,
   * or 0 if the contract was not found / could not be parsed.
   */

  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  std::string contract_id;
  if (!read_wasm_param(MemCxt, ContractPointer, ContractSize, contract_id))
  {
    return WasmEdge_Result_Terminate;
  }

  std::string value;
  zera_txn::InstrumentContract contract;

  if (!db_contracts::get_single(contract_id, value) || !contract.ParseFromString(value))
  {
    Out[0] = WasmEdge_ValueGenI32(0);
    return WasmEdge_Result_Success;
  }

  const std::string &symbol = contract.symbol();

  const char *val = symbol.c_str();
  const size_t len = symbol.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}
