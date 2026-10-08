#include "nt_helpers.h"
#include "smart_contract_service.h"


std::string nt_process_network_txn(SenderDataType *sender, const NetworkTXN &network_txn)
{
    if (network_txn.txn_type == TransactionType::UpdateContractType)
    {
        return nt_process_contract_update(sender, network_txn);
    }
    else if (network_txn.txn_type == TransactionType::ContractTxnType)
    {
        return nt_process_contract(sender, network_txn);
    }
    else if (network_txn.txn_type == TransactionType::CoinType)
    {
        return nt_process_coin(sender, network_txn);
    }
    else if (network_txn.txn_type == TransactionType::MintType)
    {
        return nt_process_mint(sender, network_txn);
    }
    else{
        return "ERROR: Invalid transaction type";
    }

}

bool set_sender_public_key(zera_txn::PublicKey *pk, SenderDataType *sender, const Sender &sender_data)
{
    switch (sender_data.type)
    {
    case SenderType::Delegate:
    {
        std::string sender_auth = sender_data.sc_name + "_" + sender_data.sc_instance;

        for (auto &call : sender->call_chain)
        {
            if (call == sender_auth)
            {
                pk->set_smart_contract_auth("sc_" + call);
                return true;
            }
        }

        return false;
    }
    case SenderType::Current:
    {
        pk->set_smart_contract_auth("sc_" + sender->current_smart_contract_instance_name);
        return true;
    }
    case SenderType::ContractBefore:
    {
        if (sender->call_chain.size() > 1)
        {
            pk->set_smart_contract_auth("sc_" + sender->call_chain[sender->call_chain.size() - 2]);
            return true;
        }
        return false;
    }
    case SenderType::OriginalContract:
    {
        pk->set_smart_contract_auth("sc_" + sender->smart_contract_instance);
        return true;
    }
    case SenderType::User:
    {
        if (smart_contract_service::gov_key(sender->pub_key))
        {
            pk->set_governance_auth(sender->pub_key);
        }
        else
        {
            pk->set_single(sender->pub_key);
        }
        return true;
    }
    default:
        return false;
    }
}

zera_txn::BaseTXN create_base(SenderDataType *sender, const Sender &sender_data)
{
    zera_txn::BaseTXN base;

    if (!set_sender_public_key(base.mutable_public_key(), sender, sender_data))
    {
        return base;
    }

    base.set_nonce(sender->sc_nonce);
    sender->sc_nonce++;
    base.set_fee_amount("1000000000000");
    base.set_fee_id(sender->fee_id);
    base.set_safe_send(false);
    base.mutable_timestamp()->set_seconds(sender->block_time);

    return base;
}

zera_txn::BaseTXN create_current_sc_base(SenderDataType *sender)
{
    zera_txn::BaseTXN base;

    base.mutable_public_key()->set_smart_contract_auth("sc_" + sender->current_smart_contract_instance_name);
    base.set_nonce(sender->sc_nonce);
    sender->sc_nonce++;
    base.set_fee_amount("1000000000000");
    base.set_fee_id(sender->fee_id);
    base.set_safe_send(false);
    base.mutable_timestamp()->set_seconds(sender->block_time);

    return base;
}

