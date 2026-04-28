#include "nt_helpers.h"
#include "nf_helpers.h"
#include "base58.h"
#include "txn.pb.h"

namespace
{
    std::string decode_wallet(const std::string &b58_wallet)
    {
        if (b58_wallet == ":fire:")
        {
            return b58_wallet;
        }

        auto decoded = base58_decode(b58_wallet);
        return std::string(decoded.begin(), decoded.end());
    }

    // The SDK leaves CoinTXN.auth at Default and expects the network to
    // populate it from the TxnSender context. The base is always the current
    // smart contract (who submits/pays), but the auth reflects whoever the
    // network_txn.sender says is sending the coins.
    bool populate_auth(zera_txn::CoinTXN *txn, SenderDataType *sender, const Sender &sender_data)
    {
        zera_txn::TransferAuthentication *auth = txn->mutable_auth();
        zera_txn::PublicKey *pk = auth->add_public_key();

        if (!set_sender_public_key(pk, sender, sender_data))
        {
            return false;
        }

        auth->add_nonce(sender->sc_nonce);
        sender->sc_nonce++;
        return true;
    }

    void fill_input(zera_txn::InputTransfers *dst, const InputTransfers &src)
    {
        dst->set_index(src.index);
        dst->set_amount(src.amount);
        dst->set_fee_percent(src.fee_percent);
        if (src.contract_fee_percent.has_value())
            dst->set_contract_fee_percent(src.contract_fee_percent.value());
    }

    void fill_output(zera_txn::OutputTransfers *dst, const OutputTransfers &src)
    {
        dst->set_wallet_address(decode_wallet(src.wallet_address));
        dst->set_amount(src.amount);
        if (src.memo.has_value())
            dst->set_memo(src.memo.value());
    }
}

std::string nt_process_coin(SenderDataType *sender, const NetworkTXN &network_txn)
{
    CoinTXN coin_txn = decode_coin_txn(network_txn.payload);

    zera_txn::CoinTXN txn;

    zera_txn::BaseTXN base = create_current_sc_base(sender);

    txn.mutable_base()->CopyFrom(base);
    txn.set_contract_id(coin_txn.contract_id);

    if (!populate_auth(&txn, sender, network_txn.sender))
    {
        return "ERROR: Failed to populate auth for coin (invalid TxnSender)";
    }

    for (const auto &input : coin_txn.input_transfers)
        fill_input(txn.add_input_transfers(), input);

    for (const auto &output : coin_txn.output_transfers)
        fill_output(txn.add_output_transfers(), output);

    if (coin_txn.contract_fee_id.has_value())
        txn.set_contract_fee_id(coin_txn.contract_fee_id.value());

    if (coin_txn.contract_fee_amount.has_value())
        txn.set_contract_fee_amount(coin_txn.contract_fee_amount.value());

    uint256_t txn_fee_amount;
    calc_fee_coin_txn(&txn, sender->fee_id, txn_fee_amount);

    set_txn_hash<zera_txn::CoinTXN>(&txn);

    if (!txn.IsInitialized())
    {
        return "ERROR: Failed to initialize coin transaction";
    }

    std::string value;
    db_smart_contracts::get_single(sender->block_txns_key, value);
    zera_txn::TXNS block_txns;
    block_txns.ParseFromString(value);

    ZeraStatus status = process_txn<zera_txn::CoinTXN>(&txn, block_txns, zera_txn::TRANSACTION_TYPE::COIN_TYPE, sender);

    if (status.ok() && status.txn_status() == zera_txn::TXN_STATUS::OK)
    {
        block_txns.add_coin_txns()->CopyFrom(txn);
    }
    else
    {
        logging::print("[nt_process_coin] Failed to process coin transaction", true);
        logging::print(status.read_status(), true);
        logging::print(zera_txn::TXN_STATUS_Name(status.txn_status()), true);
    }

    db_smart_contracts::store_single(sender->block_txns_key, block_txns.SerializeAsString());

    return zera_txn::TXN_STATUS_Name(status.txn_status());
}
