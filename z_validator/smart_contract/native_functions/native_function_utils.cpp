#include "native_function_utils.h"

#include <algorithm>

#include "smart_contract_service.h"
#include "base58.h"
#include "db_base.h"
#include "zera_status.h"
#include "../../temp_data/temp_data.h"
#include "../../block_process/block_process.h"
#include "hex_conversion.h"
#include "smart_contract_sender_data.h"
#include "../compliance/compliance.h"
#include "../../logging/logging.h"
#include "hashing.h"
#include "utils.h"

WasmEdge_Result WalletAddress(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
  * Params: {i32}
    Returns: {i32}
  */

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  SenderDataType sender = *(SenderDataType *)Data;

  // return caller address ...
  std::string base58_wallet_address = base58_encode(sender.wallet_address);
  const char *address = base58_wallet_address.c_str();
  const size_t len = base58_wallet_address.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)address, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result PublicKey(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
  * Params: {i32}
    Returns: {i32}
  */

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  SenderDataType sender = *(SenderDataType *)Data;

  // return caller address ...
  std::string base58_pub_key = base58_encode_public_key(sender.pub_key);
  const char *pub_key = base58_pub_key.c_str();
  const size_t len = strlen(pub_key);
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)pub_key, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result TXNHash(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                        const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
  * Params: {i32}
    Returns: {i32}
  */

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  SenderDataType sender = *(SenderDataType *)Data;

  // return caller address ...
  std::string hex_hash = hex_conversion::bytes_to_hex(sender.txn_hash);
  const char *hash = hex_hash.c_str();
  const size_t len = strlen(hash);
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)hash, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result LastBlockTime(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out)
{

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  SenderDataType sender = *(SenderDataType *)Data;

  std::string block_time_str = std::to_string(sender.block_time);

  const char *time = block_time_str.c_str();
  const size_t len = strlen(time);
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)time, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result ContractExists(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                               const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> ContractKey(ContractSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
    std::string exist;

    if (db_contracts::exist(contract_id))
    {
      exist = "true";
    }
    else
    {
      exist = "false";
    }

    const char *val = exist.c_str();
    const size_t len = exist.length();
    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}

WasmEdge_Result ContractDenomination(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                     const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  logging::print("[ContractDenomination] START");
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> ContractKey(ContractSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id(reinterpret_cast<char *>(ContractKey.data()), ContractSize);

    std::string value;
    zera_txn::InstrumentContract contract;
    db_contracts::get_single(contract_id, value);
    contract.ParseFromString(value);

    std::string denomination = contract.coin_denomination().amount();

    logging::print("[ContractDenomination] Denomination: ", denomination, true);

    const char *val = denomination.c_str();
    const size_t len = denomination.length();
    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}

WasmEdge_Result WalletTokens(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t WalletPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t WalletSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> WalletKey(WalletSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);

  if (WasmEdge_ResultOK(Res))
  {
    std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);

    auto wallet = base58_decode(wallet_temp);
    std::string wallet_str(wallet.begin(), wallet.end());
    std::string wallet_key = "TOKEN_LOOKUP_" + wallet_str;
    std::string data;
    zera_validator::TokenLookup token_lookup;
    db_wallet_lookup::get_single(wallet_key, data);
    token_lookup.ParseFromString(data);
    std::string token_str = "";
    for (auto token : token_lookup.tokens())
    {
      token_str += token + ",";
    }

    if (!token_str.empty())
    {
      token_str.pop_back();
    }

    const char *val = token_str.c_str();
    const size_t len = token_str.length();
    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);

    Out[0] = WasmEdge_ValueGenI32(len);

    return WasmEdge_Result_Success;
  }
  else
  {
    return Res;
  }
}

WasmEdge_Result SmartContractBalance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                     const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[3]);

  std::vector<unsigned char> ContractKey(ContractSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  std::string contract_id;
  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
    contract_id = contract_id_temp;
  }
  else
  {
    return Res;
  }

  SenderDataType sender = *(SenderDataType *)Data;

  std::string balance_data;
  std::string wallet_key = sender.smart_contract_wallet + contract_id;

  if (!db_processed_wallets::get_single(wallet_key, balance_data) && !db_wallets::get_single(wallet_key, balance_data))
  {
    balance_data = "0";
  }

  const char *val = balance_data.c_str();
  const size_t len = balance_data.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result WalletBalance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  logging::print("[WalletBalance] START");
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t WalletPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t WalletSize = WasmEdge_ValueGetI32(In[3]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

  std::vector<unsigned char> ContractKey(ContractSize);
  std::vector<unsigned char> WalletKey(WalletSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  std::string contract_id;
  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
    contract_id = contract_id_temp;
  }
  else
  {
    return Res;
  }

  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);
  std::string wallet;
  if (WasmEdge_ResultOK(Res2))
  {
    std::string wallet_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
    auto wal_vec = base58_decode(wallet_temp);
    wallet = std::string(wal_vec.begin(), wal_vec.end());
  }
  else
  {
    return Res2;
  }
  std::string wallet_key = wallet + contract_id;
  std::string balance_data;

  if (!db_processed_wallets::get_single(wallet_key, balance_data) && !db_wallets::get_single(wallet_key, balance_data))
  {
    balance_data = "0";
  }

  logging::print("[WalletBalance] Balance: ", balance_data, true);

  const char *val = balance_data.c_str();
  const size_t len = balance_data.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result CirculatingSupply(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                  const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  /*
  * Params: {i32}
    Returns: {i32}
  */

  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> ContractKey(ContractSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  std::string contract_id;
  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
    contract_id = contract_id_temp;
  }
  else
  {
    return Res;
  }


  uint256_t circ_supply = get_circulating_supply(contract_id);

  if(circ_supply == 0)
  {
    std::string circulation = "0";
    const char *val = circulation.c_str();
    const size_t len = strlen(val);
    WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
    Out[0] = WasmEdge_ValueGenI32(len);
    return WasmEdge_Result_Success;
  }


  // return caller address ...
  std::string circulation = circ_supply.str();
  const char *val = circulation.c_str();
  const size_t len = strlen(val);
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result CurrentSmartContractBalance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                            const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[3]);

  std::vector<unsigned char> ContractKey(ContractSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  std::string contract_id;
  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
    contract_id = contract_id_temp;
  }
  else
  {
    return Res;
  }

  SenderDataType sender = *(SenderDataType *)Data;

  std::string balance_data;
  size_t call_size = sender.wallet_chain.size();
  int call_index = call_size - 1;

  std::string wallet_key = sender.wallet_chain[call_index] + contract_id;

  if (!db_processed_wallets::get_single(wallet_key, balance_data) && !db_wallets::get_single(wallet_key, balance_data))
  {
    balance_data = "0";
  }

  const char *val = balance_data.c_str();
  const size_t len = balance_data.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result SmartContractWallet(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                    const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  SenderDataType sender = *(SenderDataType *)Data;

  std::string wallet = base58_encode(sender.smart_contract_wallet);
  const char *val = wallet.c_str();
  const size_t len = wallet.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result CurrentSmartContractWallet(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                           const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  SenderDataType sender = *(SenderDataType *)Data;

  size_t call_size = sender.wallet_chain.size();
  int call_index = call_size - 1;

  std::string wallet = base58_encode(sender.wallet_chain[call_index]);

  const char *val = wallet.c_str();
  const size_t len = wallet.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}
WasmEdge_Result CalledSmartContractWallet(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                          const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[0]);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  SenderDataType sender = *(SenderDataType *)Data;

  size_t call_size = sender.wallet_chain.size();
  int call_index = call_size - 1;

  if (sender.wallet_chain.size() > 1)
  {
    // If the call chain is longer than 1, we return the wallet of the last call
    call_index = call_size - 2;
  }

  std::string wallet = base58_encode(sender.wallet_chain[call_index]);

  const char *val = wallet.c_str();
  const size_t len = wallet.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result Compliance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                           const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t WalletPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t WalletSize = WasmEdge_ValueGetI32(In[3]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

  std::vector<unsigned char> ContractKey(ContractSize);
  std::vector<unsigned char> WalletKey(WalletSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  std::string contract_id;
  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
    contract_id = contract_id_temp;
  }
  else
  {
    return Res;
  }

  WasmEdge_Result Res1 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);

  std::string wallet_adr;
  if (WasmEdge_ResultOK(Res1))
  {
    std::string wallet_adr_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
    wallet_adr = wallet_adr_temp;
  }
  else
  {
    return Res1;
  }

  auto wallet_vec = base58_decode(wallet_adr);
  std::string wallet(wallet_vec.begin(), wallet_vec.end());

  std::string contract_data;
  zera_txn::InstrumentContract contract;
  std::string return_string = "false";

  if (db_contracts::get_single(contract_id, contract_data) && contract.ParseFromString(contract_data))
  {
    if (compliance::check_compliance(wallet, contract))
    {
      return_string = "true";
    }
  }

  const char *val = return_string.c_str();
  const size_t len = return_string.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result ComplianceLevels(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                 const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t WalletPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t WalletSize = WasmEdge_ValueGetI32(In[3]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

  std::vector<unsigned char> ContractKey(ContractSize);
  std::vector<unsigned char> WalletKey(WalletSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

  std::string contract_id;
  if (WasmEdge_ResultOK(Res))
  {
    std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
    contract_id = contract_id_temp;
  }
  else
  {
    return Res;
  }

  WasmEdge_Result Res1 = WasmEdge_MemoryInstanceGetData(MemCxt, WalletKey.data(), WalletPointer, WalletSize);

  std::string wallet_adr;
  if (WasmEdge_ResultOK(Res1))
  {
    std::string wallet_adr_temp(reinterpret_cast<char *>(WalletKey.data()), WalletSize);
    wallet_adr = wallet_adr_temp;
  }
  else
  {
    return Res1;
  }

  auto wallet_vec = base58_decode(wallet_adr);
  std::string wallet(wallet_vec.begin(), wallet_vec.end());
  std::string contract_data;
  zera_txn::InstrumentContract contract;
  std::string return_string = "";

  std::vector<uint32_t> levels;

  compliance::get_levels(wallet, contract_id, levels);

  if (levels.size() > 0)
  {
    std::sort(levels.begin(), levels.end());

    for (auto level : levels)
    {
      return_string += std::to_string(level) + ",";
    }
  }
  else
  {
    return_string = "0";
  }

  logging::print("Compliance levels", return_string, true);

  const char *val = return_string.c_str();
  const size_t len = return_string.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result VerifySignature(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                const WasmEdge_Value *In, WasmEdge_Value *Out)
{

  uint32_t MessagePointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t MessageSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t SignaturePointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t SignatureSize = WasmEdge_ValueGetI32(In[3]);

  uint32_t PublicKeyPointer = WasmEdge_ValueGetI32(In[4]);
  uint32_t PublicKeySize = WasmEdge_ValueGetI32(In[5]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

  std::vector<unsigned char> MessageKey(MessageSize);
  std::vector<unsigned char> SignatureKey(SignatureSize);
  std::vector<unsigned char> PublicKeyKey(PublicKeySize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, MessageKey.data(), MessagePointer, MessageSize);

  std::string message;
  if (WasmEdge_ResultOK(Res))
  {
    std::string MessageKey_temp(reinterpret_cast<char *>(MessageKey.data()), MessageSize);
    message = MessageKey_temp;

    logging::print("[VerifySignature] Message", message, true);
  }
  else
  {
    return Res;
  }

  WasmEdge_Result Res1 = WasmEdge_MemoryInstanceGetData(MemCxt, SignatureKey.data(), SignaturePointer, SignatureSize);
  std::string signature;
  if (WasmEdge_ResultOK(Res1))
  {
    std::string SignatureKey_temp(reinterpret_cast<char *>(SignatureKey.data()), SignatureSize);
    signature = SignatureKey_temp;

    logging::print("[VerifySignature] Signature", signature, true);
  }
  else
  {
    return Res1;
  }

  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, PublicKeyKey.data(), PublicKeyPointer, PublicKeySize);
  std::string public_key;
  if (WasmEdge_ResultOK(Res2))
  {
    std::string PublicKeyKey_temp(reinterpret_cast<char *>(PublicKeyKey.data()), PublicKeySize);
    public_key = PublicKeyKey_temp;

    logging::print("[VerifySignature] Public Key", public_key, true);
  }

  std::string return_string = "false";
  if (signatures::verify_message(message, signature, public_key))
  {
    return_string = "true";
  }

  const char *val = return_string.c_str();
  const size_t len = return_string.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}

WasmEdge_Result Hash(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                     const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t DataPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t DataSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t HashPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t HashSize = WasmEdge_ValueGetI32(In[3]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[4]);

  std::vector<unsigned char> DataKey(DataSize);
  std::vector<unsigned char> HashKey(HashSize);

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, DataKey.data(), DataPointer, DataSize);
  std::string data;
  if (WasmEdge_ResultOK(Res))
  {
    std::string DataKey_temp(reinterpret_cast<char *>(DataKey.data()), DataSize);
    data = DataKey_temp;
    logging::print("[Hash] Data", data, true);
  }
  else
  {
    return Res;
  }

  WasmEdge_Result Res1 = WasmEdge_MemoryInstanceGetData(MemCxt, HashKey.data(), HashPointer, HashSize);
  std::string hash;
  if (WasmEdge_ResultOK(Res1))
  {
    std::string HashKey_temp(reinterpret_cast<char *>(HashKey.data()), HashSize);
    hash = HashKey_temp;
    logging::print("[Hash] Hash", hash, true);
  }

  std::vector<uint8_t> data_vec(data.begin(), data.end());
  std::vector<uint8_t> hash_vec;
  std::string hash_str;

  if(hash == "sha256")
  {
    hash_vec = Hashing::sha256_hash(data_vec);
  }
  else if(hash == "sha512")
  {
    hash_vec = Hashing::sha512_hash(data_vec);
  }
  else if(hash == "blake3_256")
  {
    hash_vec = Hashing::blake3_hash(data_vec);
  }
  else if(hash == "blake3_512")
  {
    hash_vec = Hashing::blake3_hash(data_vec, Blake3HashLength::Bits_512);
  }
  else if(hash == "blake3_1024")
  {
    hash_vec = Hashing::blake3_hash(data_vec, Blake3HashLength::Bits_1024);
  }
  else if(hash == "blake3_2048")
  {
    hash_vec = Hashing::blake3_hash(data_vec, Blake3HashLength::Bits_2048);
  }
  else if(hash == "blake3_4096")
  {
    hash_vec = Hashing::blake3_hash(data_vec, Blake3HashLength::Bits_4096);
  }
  else if(hash == "blake3_9001")
  {
    hash_vec = Hashing::blake3_hash(data_vec, Blake3HashLength::Bits_9001);
  }
  else if(hash == "shake_1024")
  {
    hash_vec = Hashing::shake_hash(data_vec, SHAKEHashLength::Bits_1024);
  }
  else if(hash == "shake_2048")
  {
    hash_vec = Hashing::shake_hash(data_vec, SHAKEHashLength::Bits_2048);
  }
  else if(hash == "shake_4096")
  {
    hash_vec = Hashing::shake_hash(data_vec, SHAKEHashLength::Bits_4096);
  }
  else
  {
    hash_str = "error";
  }

  if (hash_str != "error")
  {
    hash_str = hex_conversion::bytes_to_hex(hash_vec);
  }

  logging::print("[Hash] Hash String", hash_str, true);

  const char *val = hash_str.c_str();
  const size_t len = hash_str.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);

  return WasmEdge_Result_Success;
}
// WasmEdge_Result ContractWallets(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
//                                 const WasmEdge_Value *In, WasmEdge_Value *Out)
// {
//   uint32_t ContractPointer = WasmEdge_ValueGetI32(In[0]);
//   uint32_t ContractSize = WasmEdge_ValueGetI32(In[1]);

//   uint32_t TargetPointer = WasmEdge_ValueGetI32(In[3]);

//   std::vector<unsigned char> ContractKey(ContractSize);

//   WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

//   WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);

//   std::string contract_id;
//   if (WasmEdge_ResultOK(Res))
//   {
//     std::string contract_id_temp(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
//     contract_id = contract_id_temp;
//   }
//   else
//   {
//     return Res;
//   }

//   SenderDataType sender = *(SenderDataType *)Data;

//   std::string balance_data;
//   size_t call_size = sender.wallet_chain.size();
//   int call_index = call_size - 1;

//   std::string wallet_key = sender.wallet_chain[call_index] + contract_id;

//   if (!db_processed_wallets::get_single(wallet_key, balance_data) && !db_wallets::get_single(wallet_key, balance_data))
//   {
//     balance_data = "0";
//   }

//   const char *val = balance_data.c_str();
//   const size_t len = balance_data.length();
//   WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
//   Out[0] = WasmEdge_ValueGenI32(len);

//   return WasmEdge_Result_Success;
// }