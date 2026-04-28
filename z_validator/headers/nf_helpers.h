#pragma once

#include <string>
#include <vector>
#include <wasmedge/wasmedge.h>
#include "txn.pb.h"
#include "smart_contract_sender_data.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

using uint256_t = boost::multiprecision::uint256_t;

inline bool read_wasm_param(WasmEdge_MemoryInstanceContext *MemCxt,
                            uint32_t pointer, uint32_t size,
                            std::string &out)
{
    if (size == 0) return false;
    std::vector<unsigned char> buf(size);
    WasmEdge_Result res = WasmEdge_MemoryInstanceGetData(MemCxt, buf.data(), pointer, size);
    if (!WasmEdge_ResultOK(res)) return false;
    out.assign(reinterpret_cast<char *>(buf.data()), size);
    return true;
}

void calc_fee(zera_txn::BaseTXN *base, const std::string &fee_id, const uint64_t &txn_size, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &wallet_address = "", const std::string &contract_id = "");
void calc_fee_coin_txn(zera_txn::CoinTXN *txn, const std::string &fee_id, uint256_t &txn_fee_amount);
void calc_fee_contract_txn(zera_txn::InstrumentContract *txn, const std::string &fee_id, uint256_t &txn_fee_amount);
bool storage_fees(const SenderDataType &sender, const uint64_t &storage_size);

void set_base(zera_txn::BaseTXN *base, SenderDataType &sender);
std::string current_set_base(zera_txn::BaseTXN *base, SenderDataType &sender);
bool delegate_set_base(zera_txn::BaseTXN *base, SenderDataType &sender, const std::string &delegate_wallet, std::string &sc_auth);
bool delegate_set_base_from_auth(zera_txn::BaseTXN *base, SenderDataType &sender, std::string &sc_auth);
void sender_set_base(zera_txn::BaseTXN *base, SenderDataType &sender);

bool in_call_chain(const std::string &instance_name, SenderDataType &sender);