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
#include "wallet.pb.h"

WasmEdge_Result DeriveWalletCurrent(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t SeedPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t SeedSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> SeedKey(SeedSize);

  SenderDataType* sender = (SenderDataType *)Data;

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, SeedKey.data(), SeedPointer, SeedSize);
  std::string seed;
  if (WasmEdge_ResultOK(Res))
  {
    std::string SeedKey_temp(reinterpret_cast<char *>(SeedKey.data()), SeedSize);
    seed = SeedKey_temp;
  }
  else
  {
    return Res;
  }

  auto seed_vec = Hashing::sha256_hash(seed);
  std::string seed_str = std::string(seed_vec.begin(), seed_vec.end());
  
  // Get the current smart contract instance (last one in the call chain)
  size_t call_size = sender->call_chain.size();
  int call_index = call_size - 1;
  std::string current_instance = sender->call_chain[call_index];
  
  std::string full_seed = current_instance + seed_str;
  auto derived_wallet = Hashing::sha256_hash(full_seed);

  // Convert derived wallet to base58 for storage and user-facing operations
  std::string base58_wallet = base58_encode(derived_wallet);

  zera_wallets::DerivedWallets derived_wallets;
  std::string derived_wallets_data;
  std::string derived_wallets_key = "derived_wallets<>" + current_instance;
  
  // Load existing derived wallets if they exist
  if(db_smart_contract_states::get_single(derived_wallets_key, derived_wallets_data))
  {
    if (!derived_wallets.ParseFromString(derived_wallets_data))
    {
      logging::print("[DerivePublicKeyCurrent] Failed to parse existing derived wallets", true);
      return WasmEdge_Result_Fail;
    }
  }

  // Check if wallet already exists (O(1) or O(log n) lookup with map)
  auto wallets_map = derived_wallets.mutable_wallets();
  if (wallets_map->count(base58_wallet) > 0)
  {
    // Wallet already exists, return it
    logging::print("[DerivePublicKeyCurrent] Wallet already exists: " + base58_wallet, true);
  }
  else
  {
    sender->derived_wallets[base58_wallet] = derived_wallets_key;
  }

  // Return base58-encoded wallet address to the user
  const char *val = base58_wallet.c_str();
  const size_t len = base58_wallet.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);
  
  return WasmEdge_Result_Success;
}

WasmEdge_Result DeriveWalletDelegate(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t SeedPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t SeedSize = WasmEdge_ValueGetI32(In[1]);
  uint32_t ContractPointer = WasmEdge_ValueGetI32(In[2]);
  uint32_t ContractSize = WasmEdge_ValueGetI32(In[3]);
  uint32_t InstancePointer = WasmEdge_ValueGetI32(In[4]);
  uint32_t InstanceSize = WasmEdge_ValueGetI32(In[5]);
  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[6]);

  std::vector<unsigned char> SeedKey(SeedSize);
  std::vector<unsigned char> ContractKey(ContractSize);
  std::vector<unsigned char> InstanceKey(InstanceSize);

  SenderDataType* sender = (SenderDataType *)Data;

  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, SeedKey.data(), SeedPointer, SeedSize);
  WasmEdge_Result Res2 = WasmEdge_MemoryInstanceGetData(MemCxt, ContractKey.data(), ContractPointer, ContractSize);
  WasmEdge_Result Res3 = WasmEdge_MemoryInstanceGetData(MemCxt, InstanceKey.data(), InstancePointer, InstanceSize);

  if (!WasmEdge_ResultOK(Res))
  {
    return Res;
  }
  if (!WasmEdge_ResultOK(Res2))
  {
    return Res2;
  }
  if (!WasmEdge_ResultOK(Res3))
  {
    return Res3;
  }

  std::string seed(reinterpret_cast<char *>(SeedKey.data()), SeedSize);
  std::string contract_name(reinterpret_cast<char *>(ContractKey.data()), ContractSize);
  std::string instance_temp(reinterpret_cast<char *>(InstanceKey.data()), InstanceSize);

  std::string contract_key = contract_name + "_" + instance_temp;
  // Validate that delegate wallet is in the call chain
  std::string contract_instance = "";
  int x = 0;
  for (auto &contract_temp : sender->call_chain)
  {
    if (contract_temp == contract_key)
    {
      contract_instance = contract_temp;
      break;
    }
    x++;
  }

  if (contract_instance == "")
  {
    // Delegate wallet not found in call chain - no access
    logging::print("[DeriveWalletDelegate] Delegate wallet not found in call chain", true);
    return WasmEdge_Result_Terminate;
  }

  auto seed_vec = Hashing::sha256_hash(seed);
  std::string seed_str = std::string(seed_vec.begin(), seed_vec.end());
  std::string full_seed = contract_instance + seed_str;
  auto derived_wallet = Hashing::sha256_hash(full_seed);

  // Convert derived wallet to base58 for storage and user-facing operations
  std::string base58_wallet = base58_encode(derived_wallet);

  zera_wallets::DerivedWallets derived_wallets;
  std::string derived_wallets_data;
  std::string derived_wallets_key = "derived_wallets<>" + contract_name + "_" + instance_temp;
  
  // Load existing derived wallets if they exist
  if(db_smart_contract_states::get_single(derived_wallets_key, derived_wallets_data))
  {
    if (!derived_wallets.ParseFromString(derived_wallets_data))
    {
      logging::print("[DeriveWalletDelegate] Failed to parse existing derived wallets", true);
      return WasmEdge_Result_Fail;
    }
  }

  // Check if wallet already exists (O(1) or O(log n) lookup with map)
  auto wallets_map = derived_wallets.mutable_wallets();
  if (wallets_map->count(base58_wallet) > 0)
  {
    // Wallet already exists, return it
    logging::print("[DeriveWalletDelegate] Wallet already exists: " + base58_wallet, true);
  }
  else
  {
    (*wallets_map)[base58_wallet] = true;
    logging::print("[DeriveWalletDelegate] Added new derived wallet: " + base58_wallet, true);
    
    // Store updated derived wallets back to database
    db_smart_contract_states::store_single(derived_wallets_key, derived_wallets.SerializeAsString());
  }

  const char *val = base58_wallet.c_str();
  const size_t len = base58_wallet.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);
  
  return WasmEdge_Result_Success;
}

WasmEdge_Result DeriveWallet(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                const WasmEdge_Value *In, WasmEdge_Value *Out)
{
  uint32_t SeedPointer = WasmEdge_ValueGetI32(In[0]);
  uint32_t SeedSize = WasmEdge_ValueGetI32(In[1]);

  uint32_t TargetPointer = WasmEdge_ValueGetI32(In[2]);

  std::vector<unsigned char> SeedKey(SeedSize);

  SenderDataType* sender = (SenderDataType *)Data;


  WasmEdge_MemoryInstanceContext *MemCxt = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);

  WasmEdge_Result Res = WasmEdge_MemoryInstanceGetData(MemCxt, SeedKey.data(), SeedPointer, SeedSize);
  std::string seed;
  if (WasmEdge_ResultOK(Res))
  {
    std::string SeedKey_temp(reinterpret_cast<char *>(SeedKey.data()), SeedSize);
    seed = SeedKey_temp;
  }

  auto seed_vec = Hashing::sha256_hash(seed);
  std::string seed_str = std::string(seed_vec.begin(), seed_vec.end());
  std::string full_seed = sender->smart_contract_instance + seed_str;
  auto derived_wallet = Hashing::sha256_hash(full_seed);

  // Convert derived wallet to base58 for storage and user-facing operations
  std::string base58_wallet = base58_encode(derived_wallet);

  zera_wallets::DerivedWallets derived_wallets;
  std::string derived_wallets_data;
  std::string derived_wallets_key = "derived_wallets<>" + sender->smart_contract_instance;
  
  // Load existing derived wallets if they exist
  if(db_smart_contract_states::get_single(derived_wallets_key, derived_wallets_data))
  {
    if (!derived_wallets.ParseFromString(derived_wallets_data))
    {
      logging::print("[DeriveWallet] Failed to parse existing derived wallets", true);
      return WasmEdge_Result_Fail;
    }
  }

  // Check if wallet already exists (O(1) or O(log n) lookup with map)
  auto wallets_map = derived_wallets.mutable_wallets();
  if (wallets_map->count(base58_wallet) > 0)
  {
    // Wallet already exists, return it
    logging::print("[DeriveWallet] Wallet already exists: " + base58_wallet, true);
  }
  else
  {
    logging::print("[DeriveWallet] Adding new derived wallet: " + base58_wallet, true);
    sender->derived_wallets[base58_wallet] = derived_wallets_key;
  }

  logging::print("[DeriveWallet] Derived wallet: " + base58_wallet, true);
  
  // Return base58-encoded wallet address to the user
  const char *val = base58_wallet.c_str();
  const size_t len = base58_wallet.length();
  WasmEdge_MemoryInstanceSetData(MemCxt, (unsigned char *)val, TargetPointer, len);
  Out[0] = WasmEdge_ValueGenI32(len);
  
  logging::print("[DeriveWallet] Derived wallets size:", std::to_string(sender->derived_wallets.size()), true);

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

//   SenderDataType* sender = (SenderDataType *)Data;

//   std::string balance_data;
//   size_t call_size = sender->wallet_chain.size();
//   int call_index = call_size - 1;

//   std::string wallet_key = sender->wallet_chain[call_index] + contract_id;

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