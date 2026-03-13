#include "nf_helpers.h"
#include "smart_contract_service.h"

void set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
{
    std::string sc_auth = "sc_" + sender.smart_contract_instance;
    base->mutable_public_key()->set_smart_contract_auth(sc_auth);

    base->set_nonce(sender.sc_nonce);
    sender.sc_nonce++;

    base->set_fee_amount("1000000000000");
    base->set_fee_id(sender.fee_id);
    base->set_safe_send(false);
    base->mutable_timestamp()->set_seconds(sender.block_time);
}

std::string current_set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
{
    std::string sc_auth = "sc_" + sender.current_smart_contract_instance_name;
    base->mutable_public_key()->set_smart_contract_auth(sc_auth);
    base->set_nonce(sender.sc_nonce);
    sender.sc_nonce++;

    base->set_fee_amount("100000000000");
    base->set_fee_id(sender.fee_id);
    base->set_safe_send(false);
    base->mutable_timestamp()->set_seconds(sender.block_time);

    return sc_auth;
}

bool delegate_set_base_from_auth(zera_txn::BaseTXN *base, SenderDataType &sender, std::string &sc_auth)
{
    bool found = false;
    for (auto &call : sender.call_chain)
    {
        if(call == sc_auth)
        {
            sc_auth = "sc_" + call;
            found = true;
            break;
        }
    }

    if(!found)
    {
        return false;
    }

    base->mutable_public_key()->set_smart_contract_auth(sc_auth);

    base->set_fee_amount("1000000000000");
    base->set_fee_id(sender.fee_id);
    base->set_safe_send(false);
    base->mutable_timestamp()->set_seconds(sender.block_time);
    base->set_nonce(sender.sc_nonce);
    sender.sc_nonce++;

    return true;
}

bool delegate_set_base(zera_txn::BaseTXN *base, SenderDataType &sender, const std::string &delegate_wallet, std::string &sc_auth)
{
    sc_auth = "";
    int x = 0;
    for (auto &wallet : sender.wallet_chain)
    {
        if (delegate_wallet == wallet)
        {
            sc_auth = "sc_" + sender.call_chain[x];
            break;
        }
        x++;
    }

    if (sc_auth == "")
    {
        return false;
    }

    base->mutable_public_key()->set_smart_contract_auth(sc_auth);

    base->set_fee_amount("1000000000000");
    base->set_fee_id(sender.fee_id);
    base->set_safe_send(false);
    base->mutable_timestamp()->set_seconds(sender.block_time);
    base->set_nonce(sender.sc_nonce);
    sender.sc_nonce++;

    return true;
}

void sender_set_base(zera_txn::BaseTXN *base, SenderDataType &sender)
{
    if (smart_contract_service::gov_key(sender.pub_key))
    {
        base->mutable_public_key()->set_governance_auth(sender.pub_key);
    }
    else
    {
        base->mutable_public_key()->set_single(sender.pub_key);
    }

    base->set_nonce(sender.sc_nonce);
    sender.sc_nonce++;

    base->set_fee_amount("1000000000000");
    base->set_fee_id(sender.fee_id);
    base->set_safe_send(false);
    base->mutable_timestamp()->set_seconds(sender.block_time);
}