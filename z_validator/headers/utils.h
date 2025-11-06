#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <string>

#include "txn.pb.h"

using namespace boost::multiprecision;

uint256_t get_key_fee(const zera_txn::PublicKey &pk);
bool is_valid_uint256(const std::string &s);
void set_explorer_config();
std::string get_seconds_key(const std::time_t &t);

uint256_t get_txn_fee_contract(const zera_txn::TRANSACTION_TYPE &txn_type, const zera_txn::InstrumentContract *txn);
uint256_t get_fee(const std::string& fee_type);
uint256_t get_txn_fee(const zera_txn::TRANSACTION_TYPE &txn_type);
std::string get_txn_key(uint64_t nonce, std::string hash);
uint256_t get_circulating_supply(const std::string &contract_id);
bool is_restricted_symbol(const std::string &symbol);