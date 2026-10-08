#include "nt_helpers.h"
#include "nf_helpers.h"
#include "base58.h"

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
}

std::string nt_process_mint(SenderDataType *sender, const NetworkTXN &network_txn)
{

    MintTXN mint_txn = decode_mint_txn(network_txn.payload);

    zera_txn::MintTXN txn;

    zera_txn::BaseTXN base = create_base(sender, network_txn.sender);

    if (!base.IsInitialized())
    {
        return "ERROR: Failed to create base for mint";
    }

    txn.mutable_base()->CopyFrom(base);

    std::string recipient = decode_wallet(mint_txn.recipient_address);

    txn.set_contract_id(mint_txn.contract_id);
    txn.set_amount(mint_txn.amount);
    txn.set_recipient_address(recipient);

    calc_fee(txn.mutable_base(), sender->fee_id, txn.ByteSizeLong(), zera_txn::TRANSACTION_TYPE::MINT_TYPE, recipient, mint_txn.contract_id);

    set_txn_hash<zera_txn::MintTXN>(&txn);

    if (!txn.IsInitialized())
    {
        return "ERROR: Failed to initialize mint transaction";
    }

    std::string value;
    db_smart_contracts::get_single(sender->block_txns_key, value);
    zera_txn::TXNS block_txns;
    block_txns.ParseFromString(value);

    ZeraStatus status = process_txn<zera_txn::MintTXN>(&txn, block_txns, zera_txn::TRANSACTION_TYPE::MINT_TYPE, sender);

    if (status.ok() && status.txn_status() == zera_txn::TXN_STATUS::OK)
    {
        block_txns.add_mint_txns()->CopyFrom(txn);
    }
    else
    {
        logging::print("[nt_process_mint] Failed to process mint transaction", true);
        logging::print(status.read_status(), true);
        logging::print(zera_txn::TXN_STATUS_Name(status.txn_status()), true);
    }

    db_smart_contracts::store_single(sender->block_txns_key, block_txns.SerializeAsString());

    return zera_txn::TXN_STATUS_Name(status.txn_status());
}
