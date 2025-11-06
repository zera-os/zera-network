#include <iostream>
#include <stdio.h>
#include <string>
#include <sstream>
#include <vector>

#include "smart_contract_sender_data.h"
#include "smart_contract_service.h"
#include "native_function_states.h"
#include "native_function_db_get_data.h"
#include "native_function_db_store_single.h"
#include "native_function_get_ace.h"
#include "native_function_utils.h"
#include "native_function_txns.h"
#include "db_base.h"
#include "base58.h"

#include "../temp_data/temp_data.h"
#include "../block_process/block_process.h"
#include "../logging/logging.h"
#include "validators.h"
#include "fees.h"

using namespace std;

const int exit_error_code = 1;
const int exit_success_code = 0;

SenderDataType sender;

enum RetTypes
{
  U8 = 1,
  I8 = 2,
  U16 = 3,
  I16 = 4,
  U32 = 5,
  I32 = 6,
  U64 = 7,
  I64 = 8,
  F32 = 9,
  F64 = 10,
  Bool = 11,
  Char = 12,
  U8Array = 21,
  I8Array = 22,
  U16Array = 23,
  I16Array = 24,
  U32Array = 25,
  I32Array = 26,
  U64Array = 27,
  I64Array = 28,
  String = 31,
};

namespace
{

  uint64_t deterministicUint64FromString(const std::string &seed)
  {
    // FNV-1a 64-bit
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : seed)
    {
      h ^= c;
      h *= 1099511628211ull;
    }
    // SplitMix64 finalizer
    h += 0x9e3779b97f4a7c15ull;
    h = (h ^ (h >> 30)) * 0xbf58476d1ce4e5b9ull;
    h = (h ^ (h >> 27)) * 0x94d049bb133111ebull;
    h ^= (h >> 31);

    // Constrain to [0, UINT64_MAX - 1'000'000]
    const uint64_t max_allowed = std::numeric_limits<uint64_t>::max() - 1000000ull;
    return h % (max_allowed + 1ull);
  }
  bool storage_fees(const SenderDataType &sender, const uint64_t &storage_size)
  {
    uint256_t storage_fee = get_fee("STORAGE_FEE") * storage_size;
    uint256_t usd_equiv;

    if(!zera_fees::get_cur_equiv("$ZRA+0000", usd_equiv))
    {
      return false;
    }
    storage_fee = (storage_fee * 1000000000) / usd_equiv;

    ZeraStatus status = balance_tracker::subtract_txn_balance(sender.fee_smart_contract_wallet, "$ZRA+0000", storage_fee, sender.txn_hash);

    if (!status.ok())
    {
      return false;
    }

    std::string storage_key = "STORAGE_FEE_" + sender.fee_smart_contract_instance;

    std::string fee_data;

    if (db_smart_contracts::get_single(storage_key, fee_data))
    {
      uint256_t fee(fee_data);
      storage_fee += fee;
    }

    db_smart_contracts::store_single(storage_key, storage_fee.str());

    return true;
  }
}

void splice(const unsigned char *array, int start, int end, unsigned char *spliced_array)
{
  for (int i = start; i < end; ++i)
  {
    *spliced_array++ = array[i];
  }
}

void printBytes(unsigned char *vec, int len, char *name)
{
  for (int i = 0; i < len; ++i)
  {
    std::cout << "[" << name << "] Byte: " << i << ": " << static_cast<int>(vec[i]) << std::endl;
  }
}

void printAnyVector(std::vector<std::any> vec, std::string label)
{
  logging::print(label, ":");
  for (int i = 0; i < vec.size(); ++i)
  {
    std::any inp = vec[i];
    if (inp.type() == typeid(int))
    {
      int val = std::any_cast<int>(inp);
      logging::print(std::to_string(i), "-", std::to_string(val));
    }
    else if (inp.type() == typeid(float))
    {
      float val = std::any_cast<float>(inp);
      logging::print(std::to_string(i), "-", std::to_string(val));
    }
    else if (inp.type() == typeid(double))
    {
      double val = std::any_cast<double>(inp);
      logging::print(std::to_string(i), "-", std::to_string(val));
    }
    else if (inp.type() == typeid(const char *))
    {
      const char *val = std::any_cast<const char *>(inp);
      std::string val_str(val);
      logging::print(std::to_string(i), "-", val_str);
    }
    else if (inp.type() == typeid(std::string))
    {
      std::string val = std::any_cast<std::string>(inp);
      logging::print(std::to_string(i), "-", val);
    }
    else
    {
      logging::print(std::to_string(i));
    }
  }
}

int allocate(WasmEdge_VMContext *VMCxt, int length)
{
  WasmEdge_Value P[1], R[1];
  WasmEdge_String FuncName;
  WasmEdge_Result Res;

  // alloc a space for input args
  P[0] = WasmEdge_ValueGenI32(length);
  FuncName = WasmEdge_StringCreateByCString("allocate");
  Res = WasmEdge_VMExecute(VMCxt, FuncName, P, 1, R, 1);
  WasmEdge_StringDelete(FuncName);

  if (WasmEdge_ResultOK(Res))
  {
    return WasmEdge_ValueGetI32(R[0]);
  }
  else
  {
    return exit_error_code;
  }
}

int deallocate(WasmEdge_VMContext *VMCxt, int pointer, int size)
{
  WasmEdge_Value P[2], R[0];
  WasmEdge_String FuncName;
  WasmEdge_Result Res;

  P[0] = WasmEdge_ValueGenI32(pointer);
  P[1] = WasmEdge_ValueGenI32(size);
  FuncName = WasmEdge_StringCreateByCString("deallocate");
  Res = WasmEdge_VMExecute(VMCxt, FuncName, P, 2, R, 0);
  WasmEdge_StringDelete(FuncName);

  if (WasmEdge_ResultOK(Res))
  {
    return exit_success_code;
  }
  else
  {
    return exit_error_code;
  }
}

// https://stackoverflow.com/questions/27687769/use-different-parameter-data-types-in-same-function-c
std::vector<int> settle(WasmEdge_VMContext *VMCxt, WasmEdge_MemoryInstanceContext *MemoryCxt, std::string input)
{
  const char *cInput = input.c_str();

  int length_of_input = input.length();
  int pointer = allocate(VMCxt, length_of_input);

  WasmEdge_MemoryInstanceSetData(MemoryCxt, (unsigned char *)cInput, pointer, length_of_input);

  std::vector<int> res;
  res.push_back(pointer);
  res.push_back(length_of_input);

  return res;
}

std::vector<int> settle(WasmEdge_VMContext *VMCxt, WasmEdge_MemoryInstanceContext *MemoryCxt, int input)
{
  int length_of_input = 1;
  int pointer = allocate(VMCxt, length_of_input * 4);

  unsigned char bytes[sizeof(int)];
  std::memcpy(bytes, &input, sizeof(int));

  WasmEdge_MemoryInstanceSetData(MemoryCxt, bytes, pointer, 4);

  std::vector<int> res;
  res.push_back(pointer);
  res.push_back(length_of_input);

  return res;
}

std::vector<int> settle(WasmEdge_VMContext *VMCxt, WasmEdge_MemoryInstanceContext *MemoryCxt, float input)
{
  int length_of_input = 1;
  int pointer = allocate(VMCxt, length_of_input * 4);

  unsigned char bytes[sizeof(float)];
  std::memcpy(bytes, &input, sizeof(float));

  WasmEdge_MemoryInstanceSetData(MemoryCxt, bytes, pointer, 4);

  std::vector<int> res;
  res.push_back(pointer);
  res.push_back(length_of_input);

  return res;
}

std::vector<int> settle(WasmEdge_VMContext *VMCxt, WasmEdge_MemoryInstanceContext *MemoryCxt, std::vector<uint8_t> input)
{
  int length_of_input = input.size();
  int pointer = allocate(VMCxt, length_of_input);

  WasmEdge_MemoryInstanceSetData(MemoryCxt, input.data(), pointer, length_of_input);

  std::vector<int> res;
  res.push_back(pointer);
  res.push_back(length_of_input);

  return res;
}

std::vector<std::any> parse_result(WasmEdge_VMContext *VMCxt, WasmEdge_MemoryInstanceContext *MemoryCxt, unsigned char *ret_pointer, unsigned char *ret_len)
{
  int size = static_cast<int>(*ret_len);

  int retPointer;
  std::memcpy(&retPointer, ret_pointer, sizeof(int));

  int p_data_len = size * 3 * 4;
  unsigned char p_data[p_data_len];
  WasmEdge_MemoryInstanceGetData(MemoryCxt, p_data, retPointer, p_data_len);
  deallocate(VMCxt, retPointer, p_data_len);

  std::vector<int> p_values;

  for (int i = 0; i < (size * 3); ++i)
  {
    unsigned char p_data_slice[4];
    splice(p_data, i * 4, (i + 1) * 4, p_data_slice);

    int p_data_slice_int;
    std::memcpy(&p_data_slice_int, p_data_slice, sizeof(int));
    p_values.push_back(p_data_slice_int);
  }

  std::vector<std::any> results;
  // results.reserve(size);
  for (int i = 0; i < size; ++i)
  {
    const int len = p_values[i * 3 + 2];
    unsigned char bytes[len];
    WasmEdge_MemoryInstanceGetData(MemoryCxt, bytes, p_values[i * 3], len);
    deallocate(VMCxt, p_values[i * 3], len);

    const int retType = p_values[i * 3 + 1];

    switch (retType)
    {
    case RetTypes::String:
    {
      std::string bytesString((const char *)bytes);
      results.push_back(bytesString);
      break;
    }
    case RetTypes::I32:
    {
      int val;
      std::memcpy(&val, bytes, sizeof(int));
      results.push_back(val);
      break;
    }
    case RetTypes::F32:
    {
      float val;
      std::memcpy(&val, bytes, sizeof(float));
      results.push_back(val);
      break;
    }
    case RetTypes::Bool:
    {
      bool val;
      std::memcpy(&val, bytes, sizeof(bool));
      results.push_back(val);
      break;
    }
    }
  }

  return results;
}

std::vector<std::any> read_and_parse_result(WasmEdge_VMContext *VMCxt, WasmEdge_MemoryInstanceContext *MemoryCxt, uint32_t resultsPointer)
{
  uint32_t size = 9;
  unsigned char rvec[size];

  WasmEdge_MemoryInstanceGetData(MemoryCxt, rvec, resultsPointer, size);
  deallocate(VMCxt, resultsPointer, size);

  unsigned char flag = rvec[0];
  if (flag == 0)
  {
    unsigned char ret_pointer[4];
    splice(rvec, 1, 5, ret_pointer);

    unsigned char ret_len[4];
    splice(rvec, 5, 9, ret_len);

    std::vector<std::any> results = parse_result(VMCxt, MemoryCxt, ret_pointer, ret_len);
    printAnyVector(results, "results");

    return results;
  }
  else
  {
    throw std::runtime_error("Error: parsing result failed\n");
  }
}

int parse_and_store_inputs(WasmEdge_VMContext *VMCxt, WasmEdge_MemoryInstanceContext *MemoryCxt, std::vector<std::any> func_params)
{
  int inputs_count = func_params.size();
  // alloc a space for input args
  int pointer_of_pointers = -1;
  if (inputs_count > 0)
  {
    pointer_of_pointers = allocate(VMCxt, inputs_count * 4 * 2);
    if (pointer_of_pointers == exit_error_code)
    {
      throw std::runtime_error("[allocate] Error\n");
    }

    int pos = 0;
    for (auto &inp : func_params)
    {
      std::vector<int> sr;
      if (inp.type() == typeid(int))
      {
        sr = settle(VMCxt, MemoryCxt, std::any_cast<int>(inp));
      }
      else if (inp.type() == typeid(const char *))
      {
        const char *val = std::any_cast<const char *>(inp);
        sr = settle(VMCxt, MemoryCxt, std::string(val));
      }
      else if (inp.type() == typeid(std::string))
      {
        std::string val = std::any_cast<std::string>(inp);
        sr = settle(VMCxt, MemoryCxt, val);
      }
      else if (inp.type() == typeid(std::vector<uint8_t>))
      {
        std::vector<uint8_t> val = std::any_cast<std::vector<uint8_t>>(inp);
        sr = settle(VMCxt, MemoryCxt, val);
      }
      else
      {
        throw std::runtime_error("Error: unhandled func_params type\n");
      }

      int pointer = sr[0];
      //
      unsigned char *ucPointerLittleEndian = reinterpret_cast<unsigned char *>(&pointer);
      //
      WasmEdge_MemoryInstanceSetData(MemoryCxt, ucPointerLittleEndian, pointer_of_pointers + pos * 4 * 2, sizeof(ucPointerLittleEndian));

      int length_of_input = sr[1];
      //
      unsigned char *ucLenghtOfInputLittleEndian = reinterpret_cast<unsigned char *>(&length_of_input);
      WasmEdge_MemoryInstanceSetData(MemoryCxt, ucLenghtOfInputLittleEndian, pointer_of_pointers + pos * 4 * 2 + 4, sizeof(ucLenghtOfInputLittleEndian));
      ++pos;
    }
  }

  return pointer_of_pointers;
}

// Function to generate a random string
char *generate_random_string(int length)
{
  // Define the characters that can be included in the random string
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  // Calculate the size of the charset
  int charset_size = sizeof(charset) - 1;

  // Seed the random number generator
  srand((unsigned int)time(NULL));

  // Allocate memory for the random string (including the null terminator)
  char *random_string = (char *)malloc((length + 1) * sizeof(char));

  // Generate the random string
  for (int i = 0; i < length; ++i)
  {
    int random_index = rand() % charset_size;
    random_string[i] = charset[random_index];
  }

  // Null-terminate the string
  random_string[length] = '\0';

  return random_string;
}

std::vector<std::string> getWords(std::string s, std::string delim)
{
  std::vector<std::string> tokens;
  size_t start = 0;
  size_t end = s.find(delim);
  while (end != std::string::npos)
  {
    tokens.push_back(s.substr(start, end - start));
    start = end + delim.length();
    end = s.find(delim, start);
  }
  tokens.push_back(s.substr(start));
  return tokens;
}

std::vector<std::any> wasmInstantiateAndExecute(WasmEdge_VMContext *VMCxt, const char *function_name, std::vector<std::any> &func_params, WasmEdge_Result &Res, WasmEdge_String &FuncName)
{
  /* Step 3: Instantiate the WASM module. */
  Res = WasmEdge_VMInstantiate(VMCxt);
  /*
   * Developers can load, validate, and instantiate another WASM module to
   * replace the instantiated one. In this case, the old module will be
   * cleared, but the registered modules are still kept.
   */
  if (!WasmEdge_ResultOK(Res))
  {
    logging::print("Error: Instantiation phase failed:", WasmEdge_ResultGetMessage(Res));
    throw std::runtime_error("Error: Instantiation phase failed");
  }
  //
  // https://github.com/second-state/wasmedge-bindgen/blob/main/host/rust/src/lib.rs#L329
  //

  // get active module
  const WasmEdge_ModuleInstanceContext *ActiveModuleCxt = WasmEdge_VMGetActiveModule(VMCxt);
  if (ActiveModuleCxt == NULL)
  {
    throw std::runtime_error("Error: no active module found\n");
  }
  //
  // get active module's memory
  WasmEdge_String MemoryName = WasmEdge_StringCreateByCString("memory");
  WasmEdge_MemoryInstanceContext *MemoryCxt = WasmEdge_ModuleInstanceFindMemory(ActiveModuleCxt, MemoryName);
  WasmEdge_StringDelete(MemoryName);

  if (MemoryCxt == NULL)
  {
    throw std::runtime_error("Error: no memory found\n");
  }

  int inputs_count = func_params.size();
  int pointer_of_pointers = parse_and_store_inputs(VMCxt, MemoryCxt, func_params);

  // /*
  //  * Step 4: Execute WASM functions. You can execute functions repeatedly
  //  * after instantiation.
  //  */
  logging::print("[Execute function]:", function_name, true);
  WasmEdge_Value P[2], rets[1];
  FuncName = WasmEdge_StringCreateByCString(function_name);
  P[0] = WasmEdge_ValueGenI32(inputs_count > 0 ? pointer_of_pointers : 0); // params_pointer: *mut u32
  P[1] = WasmEdge_ValueGenI32(inputs_count);                               // params_count: i32
  Res = WasmEdge_VMExecute(VMCxt, FuncName, P, 2, rets, 1);

  if (WasmEdge_ResultOK(Res))
  {
    logging::print("[Execute function] Ok\n");
  }
  else
  {
    std::string error_message = WasmEdge_ResultGetMessage(Res);

    if (error_message == "cost limit exceeded")
    {
      logging::print("[Execute function] Error:", error_message);
      throw std::runtime_error("[Execute function] Error\n");
    }

    throw std::runtime_error("[Execute function] Error\n");
  }

  // Don't need to deallocate 'pointer_of_pointers' because the memory will be loaded and free in the wasm
  //

  uint32_t resultsPointer = WasmEdge_ValueGetI32(rets[0]);
  std::vector<std::any> results = read_and_parse_result(VMCxt, MemoryCxt, resultsPointer);

  return results;
}

WasmEdge_Result Call(void *, const WasmEdge_CallingFrameContext *CallFrameCxt,
                     const WasmEdge_Value *In, WasmEdge_Value *Out)
{

  if (sender.current_depth >= sender.max_depth)
  {
    return WasmEdge_Result_Fail;
  }
  /*
   * Params: {i32, i32, i32, i32, i32, i32, i32, i32, i32, i32}
   * Returns: {i32}
   */

  uint32_t ContractNamePointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractNameLength = WasmEdge_ValueGetI32(In[1]);
  //
  uint32_t InstancePointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t InstanceLength = WasmEdge_ValueGetI32(In[3]);
  //
  uint32_t FunctionNamePointer = WasmEdge_ValueGetI32(In[4]);
  uint32_t FunctionNameLength = WasmEdge_ValueGetI32(In[5]);
  //
  uint32_t ParametersPointer = WasmEdge_ValueGetI32(In[6]);
  uint32_t ParametersLength = WasmEdge_ValueGetI32(In[7]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

  unsigned char ContractName[ContractNameLength + 1];
  unsigned char Instance[InstanceLength + 1];
  unsigned char FunctionName[FunctionNameLength + 1];
  unsigned char Parameters[ParametersLength];

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractName, ContractNamePointer, ContractNameLength);
  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, Instance, InstancePointer, InstanceLength);
  WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, FunctionName, FunctionNamePointer, FunctionNameLength);
  WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, Parameters, ParametersPointer, ParametersLength);

  ContractName[ContractNameLength] = '\0'; // Ensure it's null-terminated
  FunctionName[FunctionNameLength] = '\0'; // Ensure it's null-terminated
  Instance[InstanceLength] = '\0';
  // Sometimes, when we pass 'retrieve' as function name, it results in 'retrieve??' here.
  // In C++, unsigned char FunctionName[8]; defines an array of 8 characters,
  // but when you use the %s format specifier in printf,
  // it expects a null-terminated string.
  // If your FunctionName array is not null-terminated,
  // printf will continue reading memory beyond the 8 characters,
  // leading to the inclusion of extra characters (in your case, ??)
  // until it happens to encounter a null byte (\0).

  if (WasmEdge_ResultOK(Res) && WasmEdge_ResultOK(Res2) && WasmEdge_ResultOK(Res3) && WasmEdge_ResultOK(Res4))
  {
    std::string ContractNameString1((char *)ContractName);
    std::string InstanceString1((char *)Instance);
    std::string FunctionNameString((char *)FunctionName);

    logging::print("[Call] ContractName:", ContractNameString1);
    logging::print("[Call] Instance:", InstanceString1);
    logging::print("[Call] FunctionName:", FunctionNameString);

    // split Parameters string into array of strings
    //
    const size_t array_size = sizeof(Parameters) / sizeof(unsigned char);
    std::string input_string(reinterpret_cast<const char *>(Parameters), array_size);
    std::vector<std::string> parametersVecString = getWords(input_string, "##");
    std::vector<std::any> parametersVec;

    if (!input_string.empty())
    {
      for (auto &element : parametersVecString)
      {
        parametersVec.push_back(element);
      }
    }

    // read dependant instance contract
    //
    std::string ContractNameString((char *)ContractName);
    std::string InstanceString((char *)Instance);
    std::string instance_name = ContractNameString + "_" + InstanceString;
    //
    std::string raw_data;
    db_smart_contracts::get_single(instance_name, raw_data);
    //
    if (raw_data.empty())
    {
      return WasmEdge_Result_Fail;
    }
    //
    zera_txn::SmartContractTXN db_contract;
    db_contract.ParseFromString(raw_data);

    sender.current_depth++;

    zera_txn::PublicKey smart_contract_pub_key;
    smart_contract_pub_key.set_smart_contract_auth("sc_" + instance_name);
    std::string smart_contract_wallet = wallets::generate_wallet(smart_contract_pub_key);

    SenderDataType sender_copy = sender;

    sender.pub_key = "";
    sender.wallet_address = "";
    sender.smart_contract_instance = instance_name;
    sender.smart_contract_wallet = smart_contract_wallet;
    sender.call_chain.clear();
    sender.wallet_chain.clear();
    sender.call_chain.push_back(instance_name);
    sender.wallet_chain.push_back(smart_contract_wallet);
    sender.current_smart_contract_instance = instance_name;
    sender.emited.clear();

    // call
    //
    // run(const char *wasmFileLocation, std::string wasmFileContent, std::string wasm_function, std::vector<std::any> func_params, int preopenLen, const char *const *preopens, int argc, const char *const *argv, const uint64_t& limit, uint64_t& used_gas);
    std::vector<std::any> results;

    try
    {
      // JS/Python
      if (db_contract.language() == zera_txn::LANGUAGE::JAVASCRIPT || db_contract.language() == zera_txn::LANGUAGE::PYTHON)
      {
        const char *wasmFile = db_contract.language() == zera_txn::LANGUAGE::JAVASCRIPT ? "../smart_contract/wasmedge_quickjs.wasm" : "../smart_contract/python-3.11.3-wasmedge.wasm";
        // wasm_function will be _start
        results = smart_contract_service::runCallScriptingLang(instance_name, wasmFile, db_contract.binary_code(), (const char *)FunctionName, parametersVec);
      }
      else
      {
        // compiled langs
        results = smart_contract_service::runCall(instance_name, NULL, db_contract.binary_code(), (const char *)FunctionName, parametersVec, 0, NULL, 0, NULL);
      }
    }
    catch (std::exception &e)
    {
      return WasmEdge_Result_Fail;
    }

    std::string resultsString = "";

    for (int i = 0; i < results.size(); i++)
    {
      std::string val = std::any_cast<std::string>(results[i]);
      logging::print("result", std::to_string(i), ":", val);
      resultsString += "[res]" + val + "[end]";
    }

    for (auto emit : sender.emited)
    {
      resultsString += "[res]" + emit + "[end]";
    }

    sender_copy.gas_used = sender.gas_used;
    sender_copy.gas_available = sender.gas_available;
    sender_copy.current_depth = sender.current_depth;

    sender = sender_copy;

    const char *val = resultsString.c_str();
    const size_t len = resultsString.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}

WasmEdge_Result DelegateCall(void *, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out)
{

  if (sender.current_depth >= sender.max_depth)
  {
    logging::print("Error: current depth exceeded max depth");
    return WasmEdge_Result_Fail;
  }

  /*
   * Params: {i32, i32, i32, i32, i32, i32, i32, i32, i32, i32}
   * Returns: {i32}
   */

  uint32_t ContractNamePointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractNameLength = WasmEdge_ValueGetI32(In[1]);
  //
  uint32_t InstancePointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t InstanceLength = WasmEdge_ValueGetI32(In[3]);
  //
  uint32_t FunctionNamePointer = WasmEdge_ValueGetI32(In[4]);
  uint32_t FunctionNameLength = WasmEdge_ValueGetI32(In[5]);
  //
  uint32_t ParametersPointer = WasmEdge_ValueGetI32(In[6]);
  uint32_t ParametersLength = WasmEdge_ValueGetI32(In[7]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[8]);

  unsigned char ContractName[ContractNameLength + 1];
  unsigned char Instance[InstanceLength + 1];
  unsigned char FunctionName[FunctionNameLength + 1];
  unsigned char Parameters[ParametersLength];

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractName, ContractNamePointer, ContractNameLength);
  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, Instance, InstancePointer, InstanceLength);
  WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, FunctionName, FunctionNamePointer, FunctionNameLength);
  WasmEdge_Result Res4 = WasmEdge_MemoryInstanceGetData(MemCxt, Parameters, ParametersPointer, ParametersLength);

  ContractName[ContractNameLength] = '\0'; // Ensure it's null-terminated
  FunctionName[FunctionNameLength] = '\0'; // Ensure it's null-terminated
  Instance[InstanceLength] = '\0';
  // Sometimes, when we pass 'retrieve' as function name, it results in 'retrieve??' here.
  // In C++, unsigned char FunctionName[8]; defines an array of 8 characters,
  // but when you use the %s format specifier in printf,
  // it expects a null-terminated string.
  // If your FunctionName array is not null-terminated,
  // printf will continue reading memory beyond the 8 characters,
  // leading to the inclusion of extra characters (in your case, ??)
  // until it happens to encounter a null byte (\0).

  if (WasmEdge_ResultOK(Res) && WasmEdge_ResultOK(Res2) && WasmEdge_ResultOK(Res3) && WasmEdge_ResultOK(Res4))
  {
    std::string ContractNameString1((char *)ContractName);
    std::string InstanceString1((char *)Instance);
    std::string FunctionNameString((char *)FunctionName);
    // split Parameters string into array of strings
    //
    const size_t array_size = sizeof(Parameters) / sizeof(unsigned char);
    std::string input_string(reinterpret_cast<const char *>(Parameters), array_size);

    std::vector<std::string> parametersVecString = getWords(input_string, "##");
    std::vector<std::any> parametersVec;

    if (!input_string.empty())
    {
      for (auto &element : parametersVecString)
      {
        logging::print("Parameter:", std::any_cast<std::string>(element), true);
        parametersVec.push_back(element);
      }
    }

    // read dependant instance contract
    //
    std::string ContractNameString((char *)ContractName);
    std::string InstanceString((char *)Instance);
    std::string instance_name = ContractNameString + "_" + InstanceString;
    //
    std::string raw_data;
    db_smart_contracts::get_single(instance_name, raw_data);
    //
    if (raw_data.empty())
    {
      return WasmEdge_Result_Fail;
    }
    //
    zera_txn::SmartContractTXN db_contract;
    db_contract.ParseFromString(raw_data);
    sender.current_depth++;
    zera_txn::PublicKey smart_contract_pub_key;
    smart_contract_pub_key.set_smart_contract_auth("sc_" + instance_name);
    std::string smart_contract_wallet = wallets::generate_wallet(smart_contract_pub_key);
    std::string old_smart_contract_instance = sender.current_smart_contract_instance;
    sender.call_chain.push_back(instance_name);
    sender.wallet_chain.push_back(smart_contract_wallet);
    sender.current_smart_contract_instance = instance_name;
    std::vector<std::string> sender_copy_emited;

    sender_copy_emited = sender.emited;
    sender.emited.clear();

    // call
    //
    // run(const char *wasmFileLocation, std::string wasmFileContent, std::string wasm_function, std::vector<std::any> func_params, int preopenLen, const char *const *preopens, int argc, const char *const *argv, const uint64_t& limit, uint64_t& used_gas);
    std::vector<std::any> results;

    try
    {
      // JS/Python
      if (db_contract.language() == zera_txn::LANGUAGE::JAVASCRIPT || db_contract.language() == zera_txn::LANGUAGE::PYTHON)
      {
        const char *wasmFile = db_contract.language() == zera_txn::LANGUAGE::JAVASCRIPT ? "../smart_contract/wasmedge_quickjs.wasm" : "../smart_contract/python-3.11.3-wasmedge.wasm";
        // wasm_function will be _start
        results = smart_contract_service::runCallScriptingLang(instance_name, wasmFile, db_contract.binary_code(), (const char *)FunctionName, parametersVec);
      }
      else
      {
        // compiled langs
        results = smart_contract_service::runCall(instance_name, NULL, db_contract.binary_code(), FunctionNameString, parametersVec, 0, NULL, 0, NULL);
      }
    }
    catch (std::exception &e)
    {
      logging::print("[DelegateCall] FAILED!", e.what(), true);
      return WasmEdge_Result_Fail;
    }

    std::string resultsString = "";

    for (int i = 0; i < results.size(); i++)
    {
      std::string val = std::any_cast<std::string>(results[i]);
      logging::print("result", std::to_string(i), ":", val);
      resultsString += "[res]" + val + "[end]";
    }

    for (auto emit : sender.emited)
    {
      resultsString += "[res]" + emit + "[end]";
    }
    sender.emited = sender_copy_emited;

    sender.call_chain.pop_back();
    sender.wallet_chain.pop_back();
    sender.current_smart_contract_instance = old_smart_contract_instance;

    const char *val = resultsString.c_str();
    const size_t len = resultsString.length();

    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}
WasmEdge_Result Emit(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                     const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
   * Params: {i32, i32}
   */

  uint32_t ValuePointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ValueSize = WasmEdge_ValueGetI32(In[1]);

  std::vector<unsigned char> Value(ValueSize);

  // https://wasmedge.org/docs/embed/c/host_function/#calling-frame-context
  // https://www.secondstate.io/articles/extend-webassembly/
  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  // read data
  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, Value.data(), ValuePointer, ValueSize);
  if (WasmEdge_ResultOK(Res))
  {
    // SenderDataType sender = *(SenderDataType *)Data;

    std::string valueString(reinterpret_cast<char *>(Value.data()), ValueSize);

    uint64_t storage_fee = ValueSize;

    if (!storage_fees(sender, storage_fee))
    {
      logging::print("[Emit] no storage fees Value: ", valueString, true);
      int value = 0;
      Out[0] = WasmEdge_ValueGenI32(value);
      return WasmEdge_Result_Success;
    }

    logging::print("[Emit] Value: ", valueString, true);
    // emit
    sender.emited.push_back(valueString);
    int value = 1;
    Out[0] = WasmEdge_ValueGenI32(value);
    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}
WasmEdge_Result Randomish(void *, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
  * Params: {i32}
    Returns: {i32}
  */

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  // return random value

  int len = 10;
  char *random_str = generate_random_string(len);

  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)random_str, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  // Don't forget to free the allocated memory
  free(random_str);

  return WasmEdge_Result_Success;
}

WasmEdge_Result Version(void *, const WasmEdge_CallingFrameContext *CallFrameCxt,
                        const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
    Returns: {i32}
  */

  int version = 21;
  Out[0] = WasmEdge_ValueGenI32(version);

  return WasmEdge_Result_Success;
}

void CreateHostFunction(WasmEdge_ModuleInstanceContext *HostModCxt,
                        enum WasmEdge_ValType *ParamList, size_t ParamListSize,
                        enum WasmEdge_ValType *ReturnList, size_t ReturnListSize,
                        WasmEdge_HostFunc_t Func, const char *FuncName)
{
  WasmEdge_FunctionTypeContext *HostFType = WasmEdge_FunctionTypeCreate(ParamList, ParamListSize, ReturnList, ReturnListSize);
  //
  WasmEdge_FunctionInstanceContext *HostFuncCtx = WasmEdge_FunctionInstanceCreate(HostFType, Func, (void *)(&sender), 0);
  WasmEdge_String HostFuncName = WasmEdge_StringCreateByCString(FuncName);
  WasmEdge_ModuleInstanceAddFunction(HostModCxt, HostFuncName, HostFuncCtx);
  //
  WasmEdge_StringDelete(HostFuncName);
  WasmEdge_FunctionTypeDelete(HostFType);
}

WasmEdge_ModuleInstanceContext *CreateExternModule()
{
  // 1. Module Instance Creation
  WasmEdge_String HostModuleName = WasmEdge_StringCreateByCString("native_functions");
  WasmEdge_ModuleInstanceContext *HostModCxt = WasmEdge_ModuleInstanceCreate(HostModuleName);
  WasmEdge_StringDelete(HostModuleName);

  // 2. Create functions:
  //
  // add "store_state" function
  enum WasmEdge_ValType ParamList_StoreState[4] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_StoreState[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_StoreState, sizeof(ParamList_StoreState) / sizeof(ParamList_StoreState[0]),
                     ReturnList_StoreState, sizeof(ReturnList_StoreState) / sizeof(ReturnList_StoreState[0]),
                     StoreState, "store_state");

  enum WasmEdge_ValType ParamList_DelegateStoreState[6] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DelegateStoreState[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DelegateStoreState, sizeof(ParamList_DelegateStoreState) / sizeof(ParamList_DelegateStoreState[0]),
                     ReturnList_DelegateStoreState, sizeof(ReturnList_DelegateStoreState) / sizeof(ReturnList_DelegateStoreState[0]),
                     DelegateStoreState, "delegate_store_state");
  //
  // add "retrieve_state" function
  enum WasmEdge_ValType ParamList_RetrieveState[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_RetrieveState[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_RetrieveState, sizeof(ParamList_RetrieveState) / sizeof(ParamList_RetrieveState[0]),
                     ReturnList_RetrieveState, sizeof(ReturnList_RetrieveState) / sizeof(ReturnList_RetrieveState[0]),
                     RetrieveState, "retrieve_state");

  enum WasmEdge_ValType ParamList_DelegateRetrieveState[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DelegateRetrieveState[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DelegateRetrieveState, sizeof(ParamList_DelegateRetrieveState) / sizeof(ParamList_DelegateRetrieveState[0]),
                     ReturnList_DelegateRetrieveState, sizeof(ReturnList_DelegateRetrieveState) / sizeof(ReturnList_DelegateRetrieveState[0]),
                     DelegateRetrieveState, "delegate_retrieve_state");
  

  // add "clear_state" function
  enum WasmEdge_ValType ParamList_ClearState[2] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_ClearState[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_ClearState, sizeof(ParamList_ClearState) / sizeof(ParamList_ClearState[0]),
                     ReturnList_ClearState, sizeof(ReturnList_ClearState) / sizeof(ReturnList_ClearState[0]),
                     ClearState, "clear_state");

  enum WasmEdge_ValType ParamList_DelegateClearState[4] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DelegateClearState[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DelegateClearState, sizeof(ParamList_DelegateClearState) / sizeof(ParamList_DelegateClearState[0]),
                     ReturnList_DelegateClearState, sizeof(ReturnList_DelegateClearState) / sizeof(ReturnList_DelegateClearState[0]),
                     DelegateClearState, "delegate_clear_state");

  // add "send" function
  enum WasmEdge_ValType ParamList_Send[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Send[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Send, sizeof(ParamList_Send) / sizeof(ParamList_Send[0]),
                     ReturnList_Send, sizeof(ReturnList_ClearState) / sizeof(ReturnList_ClearState[0]),
                     Send, "send");

  enum WasmEdge_ValType ParamList_SendAll[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_SendAll[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_SendAll, sizeof(ParamList_SendAll) / sizeof(ParamList_SendAll[0]),
                     ReturnList_SendAll, sizeof(ReturnList_SendAll) / sizeof(ReturnList_SendAll[0]),
                     SendAll, "send_all");

  enum WasmEdge_ValType ParamList_Mint[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Mint[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Mint, sizeof(ParamList_Mint) / sizeof(ParamList_Mint[0]),
                     ReturnList_Mint, sizeof(ReturnList_Mint) / sizeof(ReturnList_Mint[0]),
                     Mint, "mint");

  enum WasmEdge_ValType ParamList_Hold[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Hold[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Hold, sizeof(ParamList_Hold) / sizeof(ParamList_Hold[0]),
                     ReturnList_Hold, sizeof(ReturnList_Hold) / sizeof(ReturnList_Hold[0]),
                     Hold, "hold");

  // add "send" function
  enum WasmEdge_ValType ParamList_DelegateSend[9] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DelegateSend[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DelegateSend, sizeof(ParamList_DelegateSend) / sizeof(ParamList_DelegateSend[0]),
                     ReturnList_DelegateSend, sizeof(ReturnList_DelegateSend) / sizeof(ReturnList_DelegateSend[0]),
                     DelegateSend, "delegate_send");

  enum WasmEdge_ValType ParamList_DelegateSendAll[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DelegateSendAll[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DelegateSendAll, sizeof(ParamList_DelegateSendAll) / sizeof(ParamList_DelegateSendAll[0]),
                     ReturnList_DelegateSendAll, sizeof(ReturnList_DelegateSendAll) / sizeof(ReturnList_DelegateSendAll[0]),
                     DelegateSendAll, "delegate_send_all");

  enum WasmEdge_ValType ParamList_DelegateMint[9] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DelegateMint[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DelegateMint, sizeof(ParamList_DelegateMint) / sizeof(ParamList_DelegateMint[0]),
                     ReturnList_DelegateMint, sizeof(ReturnList_DelegateMint) / sizeof(ReturnList_DelegateMint[0]),
                     DelegateMint, "delegate_mint");

  ///////////////////////////////////////////////////////////
  enum WasmEdge_ValType ParamList_CurrentHold[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CurrentHold[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CurrentHold, sizeof(ParamList_CurrentHold) / sizeof(ParamList_CurrentHold[0]),
                     ReturnList_CurrentHold, sizeof(ReturnList_CurrentHold) / sizeof(ReturnList_CurrentHold[0]),
                     CurrentHold, "current_hold");

  enum WasmEdge_ValType ParamList_CurrentSend[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CurrentSend[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CurrentSend, sizeof(ParamList_CurrentSend) / sizeof(ParamList_CurrentSend[0]),
                     ReturnList_CurrentSend, sizeof(ReturnList_CurrentSend) / sizeof(ReturnList_CurrentSend[0]),
                     CurrentSend, "current_send");

  enum WasmEdge_ValType ParamList_CurrentSendAll[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CurrentSendAll[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CurrentSendAll, sizeof(ParamList_CurrentSendAll) / sizeof(ParamList_CurrentSendAll[0]),
                     ReturnList_CurrentSendAll, sizeof(ReturnList_CurrentSendAll) / sizeof(ReturnList_CurrentSendAll[0]),
                     CurrentSendAll, "current_send_all");

  enum WasmEdge_ValType ParamList_CurrentMint[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CurrentMint[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CurrentMint, sizeof(ParamList_CurrentMint) / sizeof(ParamList_CurrentMint[0]),
                     ReturnList_CurrentMint, sizeof(ReturnList_CurrentMint) / sizeof(ReturnList_CurrentMint[0]),
                     CurrentMint, "current_mint");

  enum WasmEdge_ValType ParamList_Transfer[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Transfer[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Transfer, sizeof(ParamList_Transfer) / sizeof(ParamList_Transfer[0]),
                     ReturnList_Transfer, sizeof(ReturnList_Transfer) / sizeof(ReturnList_Transfer[0]),
                     Transfer, "transfer");

  enum WasmEdge_ValType ParamList_DBGetData[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DBGetData[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DBGetData, sizeof(ParamList_DBGetData) / sizeof(ParamList_DBGetData[0]),
                     ReturnList_DBGetData, sizeof(ReturnList_DBGetData) / sizeof(ReturnList_DBGetData[0]),
                     DBGetData, "db_get_data");

  // add "get_ace_data" function
  //////////////////////////////////////
  enum WasmEdge_ValType ParamList_GetACEData[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_GetACEData[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_GetACEData, sizeof(ParamList_GetACEData) / sizeof(ParamList_GetACEData[0]),
                     ReturnList_GetACEData, sizeof(ReturnList_GetACEData) / sizeof(ReturnList_GetACEData[0]),
                     GetACEData, "get_ace_data");

  // add "db_get_data" function
  enum WasmEdge_ValType ParamList_DBGetAnyData[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_DBGetAnyData[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_DBGetAnyData, sizeof(ParamList_DBGetAnyData) / sizeof(ParamList_DBGetAnyData[0]),
                     ReturnList_DBGetAnyData, sizeof(ReturnList_DBGetAnyData) / sizeof(ReturnList_DBGetAnyData[0]),
                     DBGetAnyData, "db_get_any_data");

  enum WasmEdge_ValType ParamList_CirculatingSupply[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CirculatingSupply[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CirculatingSupply, sizeof(ParamList_CirculatingSupply) / sizeof(ParamList_CirculatingSupply[0]),
                     ReturnList_CirculatingSupply, sizeof(ReturnList_CirculatingSupply) / sizeof(ReturnList_CirculatingSupply[0]),
                     CirculatingSupply, "circulating_supply");

  //
  // add "wallet_address" function
  enum WasmEdge_ValType ParamList_WalletAddress[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_WalletAddress[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_WalletAddress, sizeof(ParamList_WalletAddress) / sizeof(ParamList_WalletAddress[0]),
                     ReturnList_WalletAddress, sizeof(ReturnList_WalletAddress) / sizeof(ReturnList_WalletAddress[0]),
                     WalletAddress, "wallet_address");

  // add "public_key" function
  enum WasmEdge_ValType ParamList_PublicKey[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_PublicKey[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_PublicKey, sizeof(ParamList_PublicKey) / sizeof(ParamList_PublicKey[0]),
                     ReturnList_PublicKey, sizeof(ReturnList_PublicKey) / sizeof(ReturnList_PublicKey[0]),
                     PublicKey, "public_key");

  // add "public_key" function
  enum WasmEdge_ValType ParamList_TXNHash[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_TXNHash[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_TXNHash, sizeof(ParamList_TXNHash) / sizeof(ParamList_TXNHash[0]),
                     ReturnList_TXNHash, sizeof(ReturnList_TXNHash) / sizeof(ReturnList_TXNHash[0]),
                     TXNHash, "txn_hash");

  enum WasmEdge_ValType ParamList_WalletTokens[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_WalletTokens[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_WalletTokens, sizeof(ParamList_WalletTokens) / sizeof(ParamList_WalletTokens[0]),
                     ReturnList_WalletTokens, sizeof(ReturnList_WalletTokens) / sizeof(ReturnList_WalletTokens[0]),
                     WalletTokens, "wallet_tokens");

  // add "last_block_time" function
  enum WasmEdge_ValType ParamList_LastBlockTime[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_LastBlockTime[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_LastBlockTime, sizeof(ParamList_LastBlockTime) / sizeof(ParamList_LastBlockTime[0]),
                     ReturnList_LastBlockTime, sizeof(ReturnList_LastBlockTime) / sizeof(ReturnList_LastBlockTime[0]),
                     LastBlockTime, "last_block_time");

  // add "last_block_time" function
  enum WasmEdge_ValType ParamList_ContractExists[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_ContractExists[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_ContractExists, sizeof(ParamList_ContractExists) / sizeof(ParamList_ContractExists[0]),
                     ReturnList_ContractExists, sizeof(ReturnList_ContractExists) / sizeof(ReturnList_ContractExists[0]),
                     ContractExists, "contract_exists");

  // add "last_block_time" function
  enum WasmEdge_ValType ParamList_ContractDenomination[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_ContractDenomination[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_ContractDenomination, sizeof(ParamList_ContractDenomination) / sizeof(ParamList_ContractDenomination[0]),
                     ReturnList_ContractDenomination, sizeof(ReturnList_ContractDenomination) / sizeof(ReturnList_ContractDenomination[0]),
                     ContractDenomination, "contract_denomination");

  enum WasmEdge_ValType ParamList_WalletBalance[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_WalletBalance[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_WalletBalance, sizeof(ParamList_WalletBalance) / sizeof(ParamList_WalletBalance[0]),
                     ReturnList_WalletBalance, sizeof(ReturnList_WalletBalance) / sizeof(ReturnList_WalletBalance[0]),
                     WalletBalance, "wallet_balance");

  enum WasmEdge_ValType ParamList_SmartContractBalance[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_SmartContractBalance[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_SmartContractBalance, sizeof(ParamList_SmartContractBalance) / sizeof(ParamList_SmartContractBalance[0]),
                     ReturnList_SmartContractBalance, sizeof(ReturnList_SmartContractBalance) / sizeof(ReturnList_SmartContractBalance[0]),
                     SmartContractBalance, "smart_contract_balance");

  enum WasmEdge_ValType ParamList_SmartContractWallet[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_SmartContractWallet[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_SmartContractWallet, sizeof(ParamList_SmartContractWallet) / sizeof(ParamList_SmartContractWallet[0]),
                     ReturnList_SmartContractWallet, sizeof(ReturnList_SmartContractWallet) / sizeof(ReturnList_SmartContractWallet[0]),
                     SmartContractWallet, "smart_contract_wallet");

  enum WasmEdge_ValType ParamList_CurrentSmartContractBalance[3] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CurrentSmartContractBalance[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CurrentSmartContractBalance, sizeof(ParamList_CurrentSmartContractBalance) / sizeof(ParamList_CurrentSmartContractBalance[0]),
                     ReturnList_CurrentSmartContractBalance, sizeof(ReturnList_CurrentSmartContractBalance) / sizeof(ReturnList_CurrentSmartContractBalance[0]),
                     CurrentSmartContractBalance, "current_smart_contract_balance");

  enum WasmEdge_ValType ParamList_CurrentSmartContractWallet[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CurrentSmartContractWallet[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CurrentSmartContractWallet, sizeof(ParamList_CurrentSmartContractWallet) / sizeof(ParamList_CurrentSmartContractWallet[0]),
                     ReturnList_CurrentSmartContractWallet, sizeof(ReturnList_CurrentSmartContractWallet) / sizeof(ReturnList_CurrentSmartContractWallet[0]),
                     CurrentSmartContractWallet, "current_smart_contract_wallet");

  enum WasmEdge_ValType ParamList_CalledSmartContractWallet[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_CalledSmartContractWallet[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_CalledSmartContractWallet, sizeof(ParamList_CalledSmartContractWallet) / sizeof(ParamList_CalledSmartContractWallet[0]),
                     ReturnList_CalledSmartContractWallet, sizeof(ReturnList_CalledSmartContractWallet) / sizeof(ReturnList_CalledSmartContractWallet[0]),
                     CalledSmartContractWallet, "called_smart_contract_wallet");

  // //
  // // add "delegatecall" function
  enum WasmEdge_ValType ParamList_Delegatecall[9] = {
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Delegatecall[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Delegatecall, sizeof(ParamList_Delegatecall) / sizeof(ParamList_Delegatecall[0]),
                     ReturnList_Delegatecall, sizeof(ReturnList_Delegatecall) / sizeof(ReturnList_Delegatecall[0]),
                     DelegateCall, "delegatecall");
  //
  // add "call" function
  enum WasmEdge_ValType ParamList_Call[9] = {
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32,
      WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Call[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Call, sizeof(ParamList_Call) / sizeof(ParamList_Call[0]),
                     ReturnList_Call, sizeof(ReturnList_Call) / sizeof(ReturnList_Call[0]),
                     Call, "call");

  // add "randomish" function
  enum WasmEdge_ValType ParamList_Randomish[1] = {WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Randomish[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Randomish, sizeof(ParamList_Randomish) / sizeof(ParamList_Randomish[0]),
                     ReturnList_Randomish, sizeof(ReturnList_Randomish) / sizeof(ReturnList_Randomish[0]),
                     Randomish, "randomish");

  // add "version" function
  enum WasmEdge_ValType ParamList_Version[0];
  enum WasmEdge_ValType ReturnList_Version[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Version, 0,
                     ReturnList_Version, sizeof(ReturnList_Version) / sizeof(ReturnList_Version[0]),
                     Version, "version");
  //

  enum WasmEdge_ValType ParamList_Emit[2] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Emit[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Emit, sizeof(ParamList_Emit) / sizeof(ParamList_Emit[0]),
                     ReturnList_Emit, sizeof(ReturnList_Emit) / sizeof(ReturnList_Emit[0]),
                     Emit, "emit");

  enum WasmEdge_ValType ParamList_Compliance[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Compliance[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Compliance, sizeof(ParamList_Compliance) / sizeof(ParamList_Compliance[0]),
                     ReturnList_Compliance, sizeof(ReturnList_Compliance) / sizeof(ReturnList_Compliance[0]),
                     Compliance, "compliance");

  enum WasmEdge_ValType ParamList_ComplianceLevels[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_ComplianceLevels[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Compliance, sizeof(ParamList_ComplianceLevels) / sizeof(ParamList_ComplianceLevels[0]),
                     ReturnList_Compliance, sizeof(ReturnList_ComplianceLevels) / sizeof(ReturnList_ComplianceLevels[0]),
                     ComplianceLevels, "compliance_levels");

  enum WasmEdge_ValType ParamList_Vote[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Vote[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Vote, sizeof(ParamList_Vote) / sizeof(ParamList_Vote[0]),
                     ReturnList_Vote, sizeof(ReturnList_Vote) / sizeof(ReturnList_Vote[0]),
                     Vote, "vote");

  enum WasmEdge_ValType ParamList_ExpenseRatio[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_ExpenseRatio[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_ExpenseRatio, sizeof(ParamList_ExpenseRatio) / sizeof(ParamList_ExpenseRatio[0]),
                     ReturnList_ExpenseRatio, sizeof(ReturnList_ExpenseRatio) / sizeof(ReturnList_ExpenseRatio[0]),
                     ExpenseRatio, "expense_ratio");

  // ALLOWANCE
  enum WasmEdge_ValType ParamList_Allowance[17] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                   WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                   WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                   WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                   WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                   WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                   WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                   WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Allowance[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Allowance, sizeof(ParamList_Allowance) / sizeof(ParamList_Allowance[0]),
                     ReturnList_Allowance, sizeof(ReturnList_Allowance) / sizeof(ReturnList_Allowance[0]),
                     Allowance, "allowance");

  // ALLOWANCE SENDER
  enum WasmEdge_ValType ParamList_AllowanceSender[17] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                         WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                         WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                         WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                         WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                         WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                         WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                         WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_AllowanceSender[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_AllowanceSender, sizeof(ParamList_AllowanceSender) / sizeof(ParamList_AllowanceSender[0]),
                     ReturnList_AllowanceSender, sizeof(ReturnList_AllowanceSender) / sizeof(ReturnList_AllowanceSender[0]),
                     AllowanceSender, "allowance_sender");

  // ALLOWANCE CURRENT
  enum WasmEdge_ValType ParamList_AllowanceCurrent[17] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                          WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                          WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                          WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                          WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                          WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                          WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                          WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_AllowanceCurrent[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_AllowanceCurrent, sizeof(ParamList_AllowanceCurrent) / sizeof(ParamList_AllowanceCurrent[0]),
                     ReturnList_AllowanceCurrent, sizeof(ReturnList_AllowanceCurrent) / sizeof(ReturnList_AllowanceCurrent[0]),
                     AllowanceCurrent, "allowance_current");

  // ALLOWANCE DELEGATE
  enum WasmEdge_ValType ParamList_AllowanceDelegate[19] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                           WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_AllowanceDelegate[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_AllowanceDelegate, sizeof(ParamList_AllowanceDelegate) / sizeof(ParamList_AllowanceDelegate[0]),
                     ReturnList_AllowanceDelegate, sizeof(ReturnList_AllowanceDelegate) / sizeof(ReturnList_AllowanceDelegate[0]),
                     AllowanceDelegate, "allowance_delegate");

  // Instrument Contract Bridge
  enum WasmEdge_ValType ParamList_InstrumentContractBridge[19] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32,
                                                                  WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_InstrumentContractBridge[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_InstrumentContractBridge, sizeof(ParamList_InstrumentContractBridge) / sizeof(ParamList_InstrumentContractBridge[0]),
                     ReturnList_InstrumentContractBridge, sizeof(ReturnList_InstrumentContractBridge) / sizeof(ReturnList_InstrumentContractBridge[0]),
                     InstrumentContractBridge, "instrument_contract_bridge");

  enum WasmEdge_ValType ParamList_VerifySignature[7] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_VerifySignature[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_VerifySignature, sizeof(ParamList_VerifySignature) / sizeof(ParamList_VerifySignature[0]),
                     ReturnList_VerifySignature, sizeof(ReturnList_VerifySignature) / sizeof(ReturnList_VerifySignature[0]),
                     VerifySignature, "verify_signature");

  enum WasmEdge_ValType ParamList_Hash[5] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_Hash[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_Hash, sizeof(ParamList_Hash) / sizeof(ParamList_Hash[0]),
                     ReturnList_Hash, sizeof(ReturnList_Hash) / sizeof(ReturnList_Hash[0]),
                     Hash, "hash");
                
  // Send Multi
  enum WasmEdge_ValType ParamList_SendMulti[9] = {WasmEdge_ValType_I32, WasmEdge_ValType_I32, 
    WasmEdge_ValType_I32, WasmEdge_ValType_I32, 
    WasmEdge_ValType_I32, WasmEdge_ValType_I32, 
    WasmEdge_ValType_I32, WasmEdge_ValType_I32, WasmEdge_ValType_I32};
  enum WasmEdge_ValType ReturnList_SendMulti[1] = {WasmEdge_ValType_I32};
  CreateHostFunction(HostModCxt,
                     ParamList_SendMulti, sizeof(ParamList_SendMulti) / sizeof(ParamList_SendMulti[0]),
                     ReturnList_SendMulti, sizeof(ReturnList_SendMulti) / sizeof(ReturnList_SendMulti[0]),
                     SendMulti, "send_multi");

  return HostModCxt;
}

std::vector<std::any> smart_contract_service::runCall(std::string smart_contract_instance, const char *wasmFileLocation, std::string wasmFileContent, std::string wasm_function, std::vector<std::any> func_params, int preopenLen, const char *const *preopens, int argc, const char *const *argv)
{

  int stats_size = sender.Stats.size() - 1;
  uint64_t gas_used = WasmEdge_StatisticsGetTotalCost(sender.Stats[stats_size]);
  sender.gas_available -= gas_used;

  // Create store context
  WasmEdge_ConfigureContext *ConfCxt = WasmEdge_ConfigureCreate();

  // Create store context
  WasmEdge_StoreContext *StoreCxt = WasmEdge_StoreCreate();

  if (!ValidatorConfig::get_dev_mode())
  {
    WasmEdge_LogOff();
  }

  // enable stats
  WasmEdge_ConfigureStatisticsSetCostMeasuring(ConfCxt, true);

  // Create VM context
  WasmEdge_VMContext *VMCxt = WasmEdge_VMCreate(ConfCxt, StoreCxt);

  // Create statistics context
  WasmEdge_StatisticsContext *StatCxt = WasmEdge_VMGetStatisticsContext(VMCxt);

  // Set cost limit
  WasmEdge_StatisticsSetCostLimit(StatCxt, sender.gas_available);

  sender.Stats.push_back(StatCxt);

  const char *function_name = wasm_function.c_str();

  /* Result.*/
  WasmEdge_Result Res;

  WasmEdge_ModuleInstanceContext *HostModCxt = CreateExternModule();

  // 4. Register Host Modules to WasmEdge
  /* Register the module instance into the store. */

  Res = WasmEdge_VMRegisterModuleFromImport(VMCxt, HostModCxt);

  /* Step 1: Load WASM file. */
  if (wasmFileLocation)
  {
    Res = WasmEdge_VMLoadWasmFromFile(VMCxt, wasmFileLocation);
  }
  else
  {
    int len = wasmFileContent.length();
    // https://stackoverflow.com/a/7664596/574475
    const uint8_t *p = reinterpret_cast<const uint8_t *>(wasmFileContent.c_str());
    Res = WasmEdge_VMLoadWasmFromBuffer(VMCxt, p, len);
  }

  /*
   * Developers can load the WASM binary from buffer with the
   * `WasmEdge_VMLoadWasmFromBuffer()` API, or from
   * `WasmEdge_ASTModuleContext` object with the
   * `WasmEdge_VMLoadWasmFromASTModule()` API.
   */
  if (!WasmEdge_ResultOK(Res))
  {
    throw std::runtime_error("Error: Loading phase failed");
  }

  /* Step 2: Validate the WASM module. */
  Res = WasmEdge_VMValidate(VMCxt);

  if (!WasmEdge_ResultOK(Res))
  {
    logging::print("Error: Validation phase failed:", WasmEdge_ResultGetMessage(Res));
    throw std::runtime_error("Error: Validation phase failed");
  }

  WasmEdge_String FuncName;
  std::vector<std::any> results;
  try
  {
    results = wasmInstantiateAndExecute(VMCxt, function_name, func_params, Res, FuncName);
  }
  catch (...)
  {
    gas_used = WasmEdge_StatisticsGetTotalCost(StatCxt);
    sender.gas_available -= gas_used;
    sender.Stats.pop_back();
    stats_size = sender.Stats.size() - 1;
    WasmEdge_StatisticsSetCostLimit(sender.Stats[stats_size], sender.gas_available);
    sender.gas_used += gas_used;
    logging::print("[run] TotalCosts + sender.gas_available", std::to_string(sender.gas_available), true);
    logging::print("[run] TotalCost (GasCosts):", std::to_string(gas_used), true);
    logging::print("[run] TotalCosts + sender.gas_used:", std::to_string(sender.gas_used), true);
    throw std::runtime_error("Error: wasmInstantiateAndExecute");
  }

  gas_used = WasmEdge_StatisticsGetTotalCost(StatCxt);
  sender.gas_available -= gas_used;
  sender.Stats.pop_back();
  stats_size = sender.Stats.size() - 1;

  WasmEdge_StatisticsSetCostLimit(sender.Stats[stats_size], sender.gas_available);

  sender.gas_used += gas_used;

  WasmEdge_StringDelete(FuncName);
  WasmEdge_VMDelete(VMCxt);
  WasmEdge_StoreDelete(StoreCxt);
  WasmEdge_ConfigureDelete(ConfCxt);

  return results;
}

std::vector<std::any> smart_contract_service::run(std::string smart_contract_instance, const char *wasmFileLocation, std::string wasmFileContent, std::string func, std::vector<std::any> func_params, int preopenLen, const char *const *preopens, int argc, const char *const *argv, const uint64_t &limit, uint64_t &used_gas, std::vector<std::string> &txn_hashes)
{
  const char *function_name = func.c_str();
  logging::print("[run] function_name:", func);

  // store additional sender's data
  sender.function = func;
  // Create configure context
  /* This step is not necessary unless you need WASI support. */
  WasmEdge_ConfigureContext *ConfCxt = WasmEdge_ConfigureCreate();
  // WasmEdge_ConfigureAddHostRegistration(ConfCxt, WasmEdge_HostRegistration_Wasi);
  // Create store context
  WasmEdge_StoreContext *StoreCxt = WasmEdge_StoreCreate();

  if (!ValidatorConfig::get_dev_mode())
  {
    WasmEdge_LogOff();
  }
  // enable stats
  // WasmEdge_ConfigureStatisticsSetInstructionCounting(ConfCxt, true);
  WasmEdge_ConfigureStatisticsSetCostMeasuring(ConfCxt, true);

  logging::print("[run] limit:", std::to_string(limit));
  // Create VM context
  sender.VMCxt = WasmEdge_VMCreate(ConfCxt, StoreCxt);
  WasmEdge_StatisticsContext *StatCxt = WasmEdge_VMGetStatisticsContext(sender.VMCxt);

  WasmEdge_StatisticsSetCostLimit(StatCxt, limit);

  sender.Stats.push_back(StatCxt);

  /* Result.*/
  WasmEdge_Result Res;
  // Add host module
  //

  WasmEdge_ModuleInstanceContext *HostModCxt = CreateExternModule();

  // 4. Register Host Modules to WasmEdge
  /* Register the module instance into the store. */

  Res = WasmEdge_VMRegisterModuleFromImport(sender.VMCxt, HostModCxt);
  //
  if (!WasmEdge_ResultOK(Res))
  {
    logging::print("Error: Host module registration failed:", WasmEdge_ResultGetMessage(Res));
    throw std::runtime_error("Error: Host module registration failed");
  }
  /* Step 1: Load WASM file. */
  if (wasmFileLocation)
  {
    Res = WasmEdge_VMLoadWasmFromFile(sender.VMCxt, wasmFileLocation);
  }
  else
  {
    int len = wasmFileContent.length();
    // https://stackoverflow.com/a/7664596/574475
    const uint8_t *p = reinterpret_cast<const uint8_t *>(wasmFileContent.c_str());
    Res = WasmEdge_VMLoadWasmFromBuffer(sender.VMCxt, p, len);
  }
  /*
   * Developers can load the WASM binary from buffer with the
   * `WasmEdge_VMLoadWasmFromBuffer()` API, or from
   * `WasmEdge_ASTModuleContext` object with the
   * `WasmEdge_VMLoadWasmFromASTModule()` API.
   */
  if (!WasmEdge_ResultOK(Res))
  {
    logging::print("Error: Loading phase failed:", WasmEdge_ResultGetMessage(Res));
    throw std::runtime_error("Error: Loading phase failed");
  }
  /* Step 2: Validate the WASM module. */
  Res = WasmEdge_VMValidate(sender.VMCxt);
  if (!WasmEdge_ResultOK(Res))
  {
    logging::print("Error: Validation phase failed:", WasmEdge_ResultGetMessage(Res));
    throw std::runtime_error("Error: Validation phase failed");
  }

  WasmEdge_String FuncName;
  std::vector<std::any> results;
  try
  {
    results = wasmInstantiateAndExecute(sender.VMCxt, function_name, func_params, Res, FuncName);
  }
  catch (...)
  {
    for (auto hash : sender.txn_hashes)
    {
      txn_hashes.push_back(hash);
    }

    uint64_t TotalCosts = WasmEdge_StatisticsGetTotalCost(StatCxt);
    used_gas = TotalCosts + sender.gas_used;
    logging::print("[run] TotalCost (GasCosts):", std::to_string(TotalCosts), true);
    logging::print("[run] TotalCosts + sender.gas_used:", std::to_string(used_gas), true);
    throw std::runtime_error("Error: wasmInstantiateAndExecute");
  }

  uint64_t TotalCosts = WasmEdge_StatisticsGetTotalCost(StatCxt);

  logging::print("[run] TotalCost (GasCosts):", std::to_string(TotalCosts), true);
  used_gas = TotalCosts + sender.gas_used;

  logging::print("[run] TotalCosts + sender.gas_used:", std::to_string(used_gas), true);

  // Resources deallocations
  WasmEdge_StringDelete(FuncName);
  WasmEdge_VMDelete(sender.VMCxt);
  WasmEdge_StoreDelete(StoreCxt);
  WasmEdge_ConfigureDelete(ConfCxt);
  return results;
}

std::vector<std::any> smart_contract_service::runScriptingLang(std::string smart_contract_instance, const char *wasmFile, std::string binary_code, std::string wasm_function, std::vector<std::any> func_params, const uint64_t &limit, uint64_t &used_gas, std::vector<std::string> &txn_hashes)
{
  const char *Preopens[] = {
      ".:.",
      // "../../smart_contract/modules:/modules",
      "usr/local/lib/python3.11:usr/local/lib/python3.11"};
  const char *argv[] = {"", binary_code.c_str()};

  return smart_contract_service::run(smart_contract_instance, wasmFile, binary_code, wasm_function, func_params, 2, Preopens, 2, argv, limit, used_gas, txn_hashes);
}

std::vector<std::any> smart_contract_service::runCallScriptingLang(std::string smart_contract_instance, const char *wasmFile, std::string binary_code, std::string wasm_function, std::vector<std::any> func_params)
{
  const char *Preopens[] = {
      ".:.",
      // "../../smart_contract/modules:/modules",
      "usr/local/lib/python3.11:usr/local/lib/python3.11"};
  const char *argv[] = {"", binary_code.c_str()};

  return smart_contract_service::runCall(smart_contract_instance, wasmFile, binary_code, wasm_function, func_params, 2, Preopens, 2, argv);
}

std::vector<std::any> smart_contract_service::eval(
    const std::string sender_pub_key,
    const std::string sender_wallet_address,
    const std::string smart_contract_instance,
    const std::string binary_code,
    const zera_txn::LANGUAGE language,
    const std::string func,
    std::vector<std::any> func_params,
    const std::vector<std::string> &dependencies,
    const std::string txn_hash,
    const uint64_t timestamp,
    const std::string block_txns_key,
    const std::string fee_address,
    const std::string smart_contract_wallet,
    const uint64_t &gas_limit,
    uint64_t &used_gas,
    std::vector<std::string> &txn_hashes)
{
  // store sender's data
  sender.pub_key = sender_pub_key;
  sender.wallet_address = sender_wallet_address;
  sender.smart_contract_instance = smart_contract_instance;
  sender.current_smart_contract_instance = smart_contract_instance;
  sender.fee_smart_contract_instance = smart_contract_instance;
  sender.txn_hash = txn_hash;
  sender.timestamp = timestamp;
  sender.block_txns_key = block_txns_key;
  sender.fee_address = fee_address;
  sender.smart_contract_wallet = smart_contract_wallet;
  sender.fee_smart_contract_wallet = smart_contract_wallet;
  sender.max_depth = 50;
  sender.current_depth = 0;
  sender.emited.clear();
  sender.call_chain.clear();
  sender.wallet_chain.clear();
  sender.call_chain.push_back(smart_contract_instance);
  sender.wallet_chain.push_back(smart_contract_wallet);
  sender.gas_available = gas_limit;
  sender.gas_used = 0;
  sender.txn_hashes.clear();

  zera_validator::BlockHeader block_header;
  std::string key;
  db_headers_tag::get_last_data(block_header, key);
  sender.block_time = block_header.timestamp().seconds();

  sender.sc_nonce = deterministicUint64FromString(txn_hash);

  logging::print("[eval] sender:", base58_encode(smart_contract_wallet), true);

  std::vector<std::any> results;

  // JS/Python
  if (language == zera_txn::LANGUAGE::JAVASCRIPT || language == zera_txn::LANGUAGE::PYTHON)
  {
    const char *wasmFile = language == zera_txn::LANGUAGE::JAVASCRIPT ? "../smart_contract/wasmedge_quickjs.wasm" : "../smart_contract/python-3.11.3-wasmedge.wasm";
    // wasm_function will be _start
    results = smart_contract_service::runScriptingLang(smart_contract_instance, wasmFile, binary_code, func, func_params, gas_limit, used_gas, txn_hashes);
  }
  else
  {
    // compiled langs
    results = smart_contract_service::run(smart_contract_instance, NULL, binary_code, func, func_params, 0, NULL, 0, NULL, gas_limit, used_gas, txn_hashes);
  }

  logging::print("[eval] results:", std::to_string(results.size()));
  logging::print("[eval] emited:", std::to_string(sender.emited.size()));
  for (int i = 0; i < sender.emited.size(); ++i)
  {
    results.insert(results.begin(), sender.emited[i]);
  }

  return results;
}