#pragma once

#include "txn.grpc.pb.h"
#include <any>
#include <string>
#include <vector>



class smart_contract_service
{
public:
  static std::vector<std::any> eval(
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
      const uint64_t& gas_limit,
      uint64_t& used_gas,
      std::vector<std::string>& txn_hashes);
  static std::vector<std::any> runCall(std::string smart_contract_instance,const char *wasmFileLocation, std::string wasmFileContent, std::string wasm_function, std::vector<std::any> func_params, int preopenLen, const char *const *preopens, int argc, const char *const *argv);
  static std::vector<std::any> run(std::string smart_contract_instance, const char *wasmFileLocation, std::string wasmFileContent, std::string wasm_function, std::vector<std::any> func_params, int preopenLen, const char *const *preopens, int argc, const char *const *argv, const uint64_t& limit, uint64_t& used_gas, std::vector<std::string>& txn_hashes);
  static std::vector<std::any> runScriptingLang(std::string smart_contract_instance, const char *wasmFile, std::string binary_code, std::string wasm_function, std::vector<std::any> func_params, const uint64_t& limit, uint64_t& used_gas, std::vector<std::string>& txn_hashes);
  static std::vector<std::any> runCallScriptingLang(std::string smart_contract_instance, const char *wasmFile, std::string binary_code, std::string wasm_function, std::vector<std::any> func_params);
  static bool gov_key(const std::string &str) {
    return str.rfind("gov_", 0) == 0; // Check if "gov_" is at the start of the string
  }

};
