#pragma once

#include <string>
#include <vector>
#include <wasmedge/wasmedge.h>
#include "txn.pb.h"
#include "smart_contract_sender_data.h"
#include "const.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

using uint256_t = boost::multiprecision::uint256_t;

// Copy a (pointer, size) parameter out of contract Wasm memory. Both values are
// attacker-controlled, so BEFORE any host-side allocation we (1) cap size at
// MAX_WASM_PARAM_BYTES and (2) ask WasmEdge to bounds-check the [pointer, size)
// range (GetPointerConst returns NULL on any out-of-range/overflowing range).
// Only after both checks pass do we allocate, and then at most `size` bytes that
// provably exist inside the module's own linear memory (CWE-400 guard).
inline bool read_wasm_param(WasmEdge_MemoryInstanceContext *MemCxt,
                            uint32_t pointer, uint32_t size,
                            std::string &out)
{
    if (size == 0 || size > MAX_WASM_PARAM_BYTES) return false;
    const unsigned char *data = WasmEdge_MemoryInstanceGetPointerConst(MemCxt, pointer, size);
    if (data == nullptr) return false;
    out.assign(reinterpret_cast<const char *>(data), size);
    return true;
}

void calc_fee(zera_txn::BaseTXN *base, const std::string &fee_id, const uint64_t &txn_size, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &wallet_address = "", const std::string &contract_id = "");
void calc_fee_coin_txn(zera_txn::CoinTXN *txn, const std::string &fee_id, uint256_t &txn_fee_amount);
void calc_fee_contract_txn(zera_txn::InstrumentContract *txn, const std::string &fee_id, uint256_t &txn_fee_amount);
// Charge a storage (emit) fee as gas drawn from the contract's approved gas budget.
// Converts the storage size to gas, verifies there is enough remaining run-room on
// the active WasmEdge frame, shrinks that frame's cost limit, and accumulates the gas
// into sender.storage_gas (settled only on success). Returns false if it cannot be
// afforded, in which case the caller should terminate execution.
bool consume_storage_gas(SenderDataType &sender, const uint64_t &storage_size);

// NOTE: consume_sc_txn_fee_gas (internal txn network fees as gas) is declared in
// block_process/fees.h so block_process callers don't have to include wasmedge.h.

// ---------------------------------------------------------------------------
// Smart contract outflow allowance enforcement
// ---------------------------------------------------------------------------
// Apply the user-signed per-execution outflow budget for `token` against an
// `outflow` amount of raw parts leaving the user's wallet. On success the
// remaining budget for that token is decremented in place. Returns "" to allow,
// or a non-empty error string when the cap is exceeded (or when default-deny is
// active and there is no entry) — the caller must terminate the whole execution.
std::string sc_apply_outflow_budget(SenderDataType *sender, const std::string &token, const uint256_t &outflow);

// Enforce the outflow budget for a synthesized CoinTXN. Only coin txns authorized
// by the executing user (auth public key == user, not a smart-contract/derived
// auth) are bounded; contract/derived-funded transfers return "" (allowed). The
// outflow is the sum of input_transfers (single user auth key). Returns "" to
// allow or an error string to terminate the execution.
std::string sc_check_user_outflow_allowance(SenderDataType *sender, const zera_txn::CoinTXN &txn);

void set_base(zera_txn::BaseTXN *base, SenderDataType &sender);
std::string current_set_base(zera_txn::BaseTXN *base, SenderDataType &sender);
bool delegate_set_base(zera_txn::BaseTXN *base, SenderDataType &sender, const std::string &delegate_wallet, std::string &sc_auth);
bool delegate_set_base_from_auth(zera_txn::BaseTXN *base, SenderDataType &sender, std::string &sc_auth);
void sender_set_base(zera_txn::BaseTXN *base, SenderDataType &sender);

bool in_call_chain(const std::string &instance_name, SenderDataType &sender);