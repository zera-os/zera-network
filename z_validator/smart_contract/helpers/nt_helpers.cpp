#include "nt_helpers.h"
#include "smart_contract_service.h"


std::string nt_process_network_txn(SenderDataType *sender, const NetworkTXN &network_txn)
{
    if (network_txn.txn_type == TransactionType::UpdateContractType)
    {
        return nt_process_contract_update(sender, network_txn);
    }
    else{
        return "ERROR: Invalid transaction type";
    }

}

zera_txn::BaseTXN create_base(SenderDataType *sender, const Sender &sender_data)
{
    zera_txn::BaseTXN base;

    switch(sender_data.type)
    {
        case SenderType::Delegate:
        {
            bool found = false;
            std::string sender_auth = "sc_" + sender_data.sc_name + "_" + sender_data.sc_instance;

            for (auto &call : sender->call_chain)
            {
                if(call == sender_auth)
                {
                    std::string sc_auth = "sc_" + call;
                    base.mutable_public_key()->set_smart_contract_auth(sc_auth);
                    found = true;
                    break;
                }
            }

            if(!found)
            {
                return base;
            }
            break;
        }
        case SenderType::Current:
        {
            std::string sc_auth = "sc_" + sender->current_smart_contract_instance_name;
            base.mutable_public_key()->set_smart_contract_auth(sc_auth);
            break;
        }
        case SenderType::ContractBefore:
        {
            if(sender->call_chain.size() > 1)
            {
                std::string sc_auth = "sc_" + sender->call_chain[sender->call_chain.size() - 2];
                base.mutable_public_key()->set_smart_contract_auth(sc_auth);
            }
            else
            {
                return base;
            }
            break;
        }
        case SenderType::OriginalContract:
        {
            std::string sc_auth = "sc_" + sender->smart_contract_instance;
            base.mutable_public_key()->set_smart_contract_auth(sc_auth);
            break;
        }
        case SenderType::User:
        {
            if (smart_contract_service::gov_key(sender->pub_key))
            {
                base.mutable_public_key()->set_governance_auth(sender->pub_key);
            }
            else
            {
                base.mutable_public_key()->set_single(sender->pub_key);
            }
            break;
        }

        default:
        {
            return base;
        }
    }

    base.set_nonce(sender->sc_nonce);
    sender->sc_nonce++;
    base.set_fee_amount("1000000000000");
    base.set_fee_id(sender->fee_id);
    base.set_safe_send(false);
    base.mutable_timestamp()->set_seconds(sender->block_time);

    return base;
}

