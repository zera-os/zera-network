#pragma once

#include <string>
#include "sc_base64.h"
#include "smart_contract_sender_data.h"
#include "txn.pb.h"
#include "db_base.h"
#include "proposer.h"
#include "zera_status.h"

std::string nt_process_network_txn(SenderDataType *sender, const NetworkTXN &network_txn);

std::string nt_process_contract_update(SenderDataType *sender, const NetworkTXN &network_txn);

std::string nt_process_contract(SenderDataType *sender, const NetworkTXN &network_txn);

std::string nt_process_coin(SenderDataType *sender, const NetworkTXN &network_txn);

std::string nt_process_mint(SenderDataType *sender, const NetworkTXN &network_txn);

zera_txn::BaseTXN create_base(SenderDataType *sender, const Sender &sender_data);

zera_txn::BaseTXN create_current_sc_base(SenderDataType *sender);

bool set_sender_public_key(zera_txn::PublicKey *pk, SenderDataType *sender, const Sender &sender_data);

template <typename TXType>
void set_txn_hash(TXType *txn)
{
    auto hash_vec = Hashing::sha256_hash(txn->SerializeAsString());
    std::string hash(hash_vec.begin(), hash_vec.end());
    txn->mutable_base()->set_hash(hash);
}

template <typename TXType>
ZeraStatus process_txn(TXType *txn, zera_txn::TXNS &block_txns, const zera_txn::TRANSACTION_TYPE &txn_type, SenderDataType *sender)
{
    std::string fee_address = sender->fee_address;
    ZeraStatus status = proposing::unpack_process_wrapper(txn, &block_txns, txn_type, false, fee_address, true, sender->txn_hash, sender->fee_smart_contract_wallet);
    if (status.ok())
    {
        if (status.txn_status() == zera_txn::TXN_STATUS::OK)
        {
            sender->txn_hashes.push_back(txn->base().hash());
            txn_hash_tracker::add_sc_hash(txn->base().hash());
        }
        else
        {
            balance_tracker::remove_txn_balance(txn->base().hash());
        }
    }

    return status;
}
