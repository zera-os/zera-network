#include "nf_helpers.h"
#include "utils.h"
#include "fees.h"
#include "block_process.h"
#include "temp_data.h"
#include "const.h"
#include "logging.h"
#include <limits>

std::string sc_apply_outflow_budget(SenderDataType *sender, const std::string &token, const uint256_t &outflow)
{
    // Explicit user opt-in: unlimited outflow for this token.
    if (sender->allowance_unlimited.count(token))
    {
        return "";
    }

    auto it = sender->allowance_remaining.find(token);
    if (it != sender->allowance_remaining.end())
    {
        uint256_t remaining = is_valid_uint256(it->second) ? uint256_t(it->second) : uint256_t(0);
        if (remaining < outflow)
        {
            return "ERROR: smart contract outflow allowance exceeded for " + token;
        }
        it->second = (remaining - outflow).str();
        return "";
    }

    // No allowance entry for this token.
    if (SC_ALLOWANCE_DEFAULT_DENY)
    {
        return "ERROR: no outflow allowance for " + token;
    }

    // Legacy behavior (this build): no entry => allow, so the ecosystem can adopt
    // allowances gracefully before the default flips to deny.
    return "";
}

std::string sc_check_user_outflow_allowance(SenderDataType *sender, const zera_txn::CoinTXN &txn)
{
    if (txn.auth().public_key_size() == 0 || sender->pub_key.empty())
    {
        return "";
    }

    const zera_txn::PublicKey &pk = txn.auth().public_key(0);

    // Contract/derived-authorized outflow is out of scope (not the user's wallet).
    if (pk.has_smart_contract_auth())
    {
        return "";
    }

    const bool is_user = (pk.single() == sender->pub_key) || (pk.governance_auth() == sender->pub_key);
    if (!is_user)
    {
        return "";
    }

    // Single user auth key => every input belongs to the user. Sum the gross outflow.
    uint256_t outflow = 0;
    for (const auto &input : txn.input_transfers())
    {
        if (!is_valid_uint256(input.amount()))
        {
            return "ERROR: invalid input amount for outflow allowance check";
        }
        outflow += uint256_t(input.amount());
    }

    return sc_apply_outflow_budget(sender, txn.contract_id(), outflow);
}

void calc_fee(zera_txn::BaseTXN *base, const std::string &fee_id, const uint64_t &txn_size, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &wallet_address, const std::string &contract_id)
{
    uint256_t txn_fee_amount;

    uint256_t equiv;
    zera_fees::get_cur_equiv(fee_id, equiv);

    zera_txn::InstrumentContract fee_contract;
    block_process::get_contract(fee_id, fee_contract);

    uint256_t fee_per_byte(get_txn_fee(txn_type));
    int byte_size = txn_size + 128;
    std::string denomination_str = fee_contract.coin_denomination().amount();

    uint256_t fee = fee_per_byte * byte_size;
    uint256_t denomination(denomination_str);
    txn_fee_amount = (fee * denomination) / equiv;

    uint256_t key_fee = get_key_fee(base->public_key());
    txn_fee_amount += (key_fee * denomination) / equiv;


    if(wallet_address != "")
    {
        std::string wallet_key = wallet_address + contract_id;
        if(!db_wallets::exist(wallet_key))
        {
            uint256_t first_time_wallet_fee = get_fee(FIRST_TIME_WALLET_FEE);
            txn_fee_amount += (first_time_wallet_fee * denomination) / equiv;
        }
    }

    if (fee_id != NETWORK_CONTRACT)
    {
        uint256_t token_multiplier = get_fee(TOKEN_MULTIPLIER);
        txn_fee_amount *= token_multiplier;
    }

    base->set_fee_amount(txn_fee_amount.str());
}

void calc_fee_coin_txn(zera_txn::CoinTXN *txn, const std::string &fee_id, uint256_t &txn_fee_amount)
{
    uint256_t equiv;
    zera_fees::get_cur_equiv(fee_id, equiv);
    zera_txn::InstrumentContract fee_contract;
    block_process::get_contract(fee_id, fee_contract);

    uint256_t fee_per_byte(get_txn_fee(zera_txn::TRANSACTION_TYPE::COIN_TYPE));
    int byte_size = txn->ByteSize() + 128;
    std::string denomination_str = fee_contract.coin_denomination().amount();

    uint256_t fee = fee_per_byte * byte_size;
    uint256_t denomination(denomination_str);
    txn_fee_amount = (fee * denomination) / equiv;

    for (auto public_key : txn->auth().public_key())
    {
        uint256_t key_fee = get_key_fee(public_key);
        txn_fee_amount += (key_fee * denomination) / equiv;
    }

    uint256_t normalized_fee = 0;
    for (auto output : txn->output_transfers())
    {
        std::string wallet_key = output.wallet_address() + txn->contract_id();
        if (!db_wallets::exist(wallet_key))
        {
            if (normalized_fee == 0)
            {
                uint256_t first_time_wallet_fee = get_fee(FIRST_TIME_WALLET_FEE);
                normalized_fee = (first_time_wallet_fee * denomination) / equiv;
            }

            txn_fee_amount += normalized_fee;
        }
    }

    if (fee_id != NETWORK_CONTRACT)
    {
        uint256_t token_multiplier = get_fee(TOKEN_MULTIPLIER);
        txn_fee_amount *= token_multiplier;
    }

    txn->mutable_base()->set_fee_amount(txn_fee_amount.str());
}

void calc_fee_contract_txn(zera_txn::InstrumentContract *txn, const std::string &fee_id, uint256_t &txn_fee_amount)
{
    uint256_t equiv;
    zera_fees::get_cur_equiv(fee_id, equiv);
    zera_txn::InstrumentContract fee_contract;
    block_process::get_contract(fee_id, fee_contract);
    uint256_t fee_per_byte = get_txn_fee_contract(zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE, txn);
    int byte_size = txn->ByteSize() + 128;
    std::string denomination_str = fee_contract.coin_denomination().amount();

    uint256_t fee = fee_per_byte * byte_size;
    uint256_t denomination(denomination_str);
    txn_fee_amount = (fee * denomination) / equiv;



    uint256_t key_fee = get_key_fee(txn->base().public_key());
    txn_fee_amount += (key_fee * denomination) / equiv;


    int x = 0;
    uint256_t normalized_fee = 0;
    while (x < txn->premint_wallets_size())
    {
        if(normalized_fee == 0)
        {
            uint256_t first_time_wallet_fee = get_fee(FIRST_TIME_WALLET_FEE);
            normalized_fee = (first_time_wallet_fee * denomination) / equiv;
        }

        txn_fee_amount += normalized_fee;
        x++;
    }


    if (fee_id != NETWORK_CONTRACT)
    {
        uint256_t token_multiplier = get_fee(TOKEN_MULTIPLIER);
        txn_fee_amount *= token_multiplier;
    }
    txn->mutable_base()->set_fee_amount(txn_fee_amount.str());
}

// Live execution context (defined in smart_contract_service.cpp). Needed so the
// central fee-processing code can pull internal txn fees from the running
// contract's gas budget without plumbing SenderDataType through block_process.
extern SenderDataType sender;

namespace
{
  // Pull `gas` from the contract's approved budget: verify the active WasmEdge
  // frame has enough run-room left, shrink its cost limit, and accumulate the
  // amount into the given bucket (settled only on success / refunded on crash).
  bool consume_budget_gas(SenderDataType &sender_data, const uint64_t &gas, uint64_t &accumulator, const char *tag)
  {
    if (sender_data.Stats.empty())
    {
      return false;
    }

    WasmEdge_StatisticsContext *top = sender_data.Stats.back();
    uint64_t total_cost = WasmEdge_StatisticsGetTotalCost(top);

    if (total_cost > sender_data.current_cost_limit)
    {
      return false;
    }

    uint64_t headroom = sender_data.current_cost_limit - total_cost;

    if (gas > headroom)
    {
      // Cannot afford the fee within the approved budget -> out of gas.
      return false;
    }

    sender_data.current_cost_limit -= gas;

    if (sender_data.gas_available > gas)
    {
      sender_data.gas_available -= gas;
    }
    else
    {
      sender_data.gas_available = 0;
    }

    WasmEdge_StatisticsSetCostLimit(top, sender_data.current_cost_limit);

    accumulator += gas;


    return true;
  }

  uint64_t usd_fee_to_gas(const uint256_t &usd_fee)
  {
    uint256_t gas_fee = get_fee("GAS_FEE");

    if (gas_fee == 0)
    {
      return std::numeric_limits<uint64_t>::max();
    }

    uint256_t gas_256 = usd_fee / gas_fee;

    return gas_256 > std::numeric_limits<uint64_t>::max()
               ? std::numeric_limits<uint64_t>::max()
               : static_cast<uint64_t>(gas_256);
  }
}


bool consume_storage_gas(SenderDataType &sender_data, const uint64_t &storage_size)
{
  // Storage fee expressed directly in gas units. The gas->currency conversion at
  // settlement (gas_fees) re-applies GAS_FEE, denomination, equiv and TOKEN_MULTIPLIER,
  // so the emit-time conversion is simply STORAGE_FEE * size / GAS_FEE.
  uint64_t storage_gas = usd_fee_to_gas(get_fee("STORAGE_FEE") * storage_size);

  return consume_budget_gas(sender_data, storage_gas, sender_data.storage_gas, "consume_storage_gas");
}

bool consume_sc_txn_fee_gas(const uint256_t &usd_fee)
{
  // Internal txn network fee expressed in gas units. Same reasoning as storage:
  // settlement's gas_fees re-applies the full currency conversion, so here we
  // only divide the USD fee-units by GAS_FEE.
  uint64_t fee_gas = usd_fee_to_gas(usd_fee);


  return consume_budget_gas(sender, fee_gas, sender.txn_fee_gas, "consume_sc_txn_fee_gas");
}