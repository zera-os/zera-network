#include "nf_helpers.h"
#include "utils.h"
#include "fees.h"
#include "block_process.h"
#include "temp_data.h"

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

    logging::print("FEE PER BYTE!!!", fee_per_byte.str(), true);
    logging::print("BYTE SIZE!!!", std::to_string(byte_size), true);
    logging::print("DENOMINATION!!!", denomination_str, true);
    logging::print("EQUIV!!!", equiv.str(), true);

    uint256_t fee = fee_per_byte * byte_size;
    uint256_t denomination(denomination_str);
    txn_fee_amount = (fee * denomination) / equiv;

    logging::print("FEE!!!", fee.str(), true);


    uint256_t key_fee = get_key_fee(txn->base().public_key());
    logging::print("KEY FEE!!!", key_fee.str(), true);
    txn_fee_amount += (key_fee * denomination) / equiv;

    logging::print("TXN FEE AMOUNT!!!", txn_fee_amount.str(), true);

    int x = 0;
    uint256_t normalized_fee = 0;
    while (x < txn->premint_wallets_size())
    {
        if(normalized_fee == 0)
        {
            uint256_t first_time_wallet_fee = get_fee(FIRST_TIME_WALLET_FEE);
            normalized_fee = (first_time_wallet_fee * denomination) / equiv;
            logging::print("NORMALIZED FEE!!!", normalized_fee.str(), true);
        }

        txn_fee_amount += normalized_fee;
        x++;
    }


    logging::print("TXN FEE AMOUNT!!!", txn_fee_amount.str(), true);
    if (fee_id != NETWORK_CONTRACT)
    {
        uint256_t token_multiplier = get_fee(TOKEN_MULTIPLIER);
        txn_fee_amount *= token_multiplier;
    }
    logging::print("TXN FEE AMOUNT!!!", txn_fee_amount.str(), true);
    txn->mutable_base()->set_fee_amount(txn_fee_amount.str());
}

bool storage_fees(const SenderDataType &sender, const uint64_t &storage_size)
{
  uint256_t storage_fee = get_fee("STORAGE_FEE") * storage_size;

  zera_txn::InstrumentContract fee_contract;
  block_process::get_contract(sender.fee_id, fee_contract);
  std::string denomination_str = fee_contract.coin_denomination().amount();
  uint256_t denomination(denomination_str);
  uint256_t usd_equiv;

  if(!zera_fees::get_cur_equiv(sender.fee_id, usd_equiv))
  {
    return false;
  }

  storage_fee = (storage_fee * denomination) / usd_equiv;

  if(sender.fee_id != NETWORK_CONTRACT)
  {
    uint256_t token_multiplier = get_fee(TOKEN_MULTIPLIER);
    storage_fee *= token_multiplier;

    if(!fee_token_tracker::add_temp_fee_token(sender.fee_id, storage_fee, denomination))
    {
        return false;
    }
  }

  ZeraStatus status = balance_tracker::subtract_txn_balance(sender.wallet_address, sender.fee_id, storage_fee, sender.txn_hash);

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