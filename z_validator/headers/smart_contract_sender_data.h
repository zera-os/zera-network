#pragma once

#include <wasmedge/wasmedge.h>
#include <any>
#include <string>
#include <vector>

struct SenderDataType
{
  std::string pub_key;                            // Public key of the sender (Temp removed on Call) - DONE
  std::string wallet_address;                     // Wallet address of the sender (Temp removed on Call) - DONE
  std::string smart_contract_instance;            // Smart contract instance name (Temp changed on Call)
  std::string function;                           // Function name (Never changes)
  std::string txn_hash;                           // Transaction hash (Never changes)
  int max_depth;                                  // Max depth of the call chain (Static Number)
  int current_depth;                              // Current depth of the call chain (increases on each Call/DelegateCall)
  std::vector<std::string> emited;                // Emited results (Can add on Call/DelegateCall)
  uint64_t timestamp;                             // Timestamp of the transaction (Never changes)
  std::string block_txns_key;                     // Block transactions key (Never changes)
  std::string fee_address;                        // Fee address (Never changes)
  std::string smart_contract_wallet;              // Smart contract wallet (Temp change on Call)
  std::vector<std::string> call_chain;            // Call chain (Temp remove/reset on Call | Add on DelegateCall)
  std::vector<std::string> wallet_chain;          // Wallet chain (Temp remove/reset on Call | Add on DelegateCall)
  std::string current_smart_contract_instance;    // Current smart contract instance (Changes every Call/DelegateCall)
  std::string fee_smart_contract_instance;        // Fee smart contract instance (Never changes)
  std::string fee_smart_contract_wallet;          // Fee smart contract wallet (Never changes)
  std::vector<std::string> txn_hashes;            // Transaction hashes made by the smart contract (is not effected by Call/DelegateCall)
  uint64_t block_time;                            // Block time (Never changes)

  uint64_t gas_used;                              // Used gas for all calls (increases after every Call/DelegateCall)
  uint64_t gas_available;                         // Available gas for next call (reduces after ever Call/DelegateCall)
  WasmEdge_VMContext *VMCxt;                      // Original VM context
  std::vector<WasmEdge_StatisticsContext*> Stats; 
  uint64_t sc_nonce;                               // Smart contract nonce (Increases after every txn)
};