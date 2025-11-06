#include "../block_process.h"

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

#include "db_base.h"
#include "../../temp_data/temp_data.h"

namespace
{
    ZeraStatus check_wrapper(zera_txn::TXNWrapper wrapper, const zera_txn::InstrumentContract &contract)
    {
        std::vector<std::string> txn_contract_id;
        zera_txn::PublicKey public_key;
        google::protobuf::Timestamp txn_timestamp;

        if (wrapper.has_coin_txn())
        {
            std::string contract_id = wrapper.coin_txn().contract_id();
            txn_contract_id.push_back(contract_id);
            public_key.CopyFrom(wrapper.coin_txn().auth().public_key(0));
            txn_timestamp.CopyFrom(wrapper.coin_txn().base().timestamp());
        }
        else if (wrapper.has_mint_txn())
        {
            txn_contract_id.push_back(*wrapper.mutable_mint_txn()->mutable_contract_id());
            public_key.CopyFrom(wrapper.mint_txn().base().public_key());
            txn_timestamp.CopyFrom(wrapper.mint_txn().base().timestamp());
        }
        else if (wrapper.has_item_mint_txn())
        {
            txn_contract_id.push_back(*wrapper.mutable_item_mint_txn()->mutable_contract_id());
            public_key.CopyFrom(wrapper.item_mint_txn().base().public_key());
            txn_timestamp.CopyFrom(wrapper.item_mint_txn().base().timestamp());
        }
        else if (wrapper.has_governance_proposal())
        {
            txn_contract_id.push_back(*wrapper.mutable_governance_proposal()->mutable_contract_id());
            public_key.CopyFrom(wrapper.governance_proposal().base().public_key());
            txn_timestamp.CopyFrom(wrapper.governance_proposal().base().timestamp());
        }
        else if (wrapper.has_expense_ratios())
        {
            txn_contract_id.push_back(*wrapper.mutable_expense_ratios()->mutable_contract_id());
            public_key.CopyFrom(wrapper.expense_ratios().base().public_key());
            txn_timestamp.CopyFrom(wrapper.expense_ratios().base().timestamp());
        }
        else if (wrapper.has_nft_txn())
        {
            txn_contract_id.push_back(*wrapper.mutable_nft_txn()->mutable_contract_id());
            public_key.CopyFrom(wrapper.nft_txn().base().public_key());
            txn_timestamp.CopyFrom(wrapper.nft_txn().base().timestamp());
        }
        else if (wrapper.has_contract_update_txn())
        {
            txn_contract_id.push_back(*wrapper.mutable_contract_update_txn()->mutable_contract_id());
            public_key.CopyFrom(wrapper.contract_update_txn().base().public_key());
            txn_timestamp.CopyFrom(wrapper.contract_update_txn().base().timestamp());
        }
        else
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_quash.cpp: check_wrapper: TXN is not a quash txn", zera_txn::TXN_STATUS::INVALID_TXN_TYPE);
        }

        bool cur_match = false;
        if (txn_contract_id.size() == 1)
        {
            for (auto id : txn_contract_id)
            {
                if (id != contract.contract_id())
                {
                    return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_quash.cpp: check_wrapper: TXN contract id does not match contract id", zera_txn::TXN_STATUS::INVALID_CONTRACT);
                }
            }
            cur_match = true;
        }
        else
        {
            for (auto id : txn_contract_id)
            {
                if (id == contract.contract_id())
                {
                    cur_match = true;
                }
            }
        }

        if (!cur_match)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_quash.cpp: check_wrapper: TXN contract id does not match contract id", zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        uint64_t time_delay = 0;
        for (auto key : contract.restricted_keys())
        {
            std::string res_pub_key = wallets::get_public_key_string(key.public_key());
            std::string pub_key_str = wallets::get_public_key_string(public_key);
            if (res_pub_key == pub_key_str)
            {
                time_delay = key.time_delay();
                break;
            }
        }
        if (!time_delay)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_quash.cpp: check_wrapper: TXN public key not found in contract", zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        zera_validator::BlockHeader new_header;
        std::string new_key;
        db_headers_tag::get_last_data(new_header, new_key);
        google::protobuf::Timestamp timestamp = new_header.timestamp();
        google::protobuf::Timestamp delay_timestamp;

        delay_timestamp.set_seconds(txn_timestamp.seconds() + time_delay);

        if (timestamp.seconds() >= delay_timestamp.seconds())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_quash.cpp: check_wrapper: TXN timestamp is not valid", zera_txn::TXN_STATUS::TIME_DELAY_EXPIRED);
        }

        return ZeraStatus();
    }
}

template <>
ZeraStatus block_process::check_parameters<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    zera_txn::InstrumentContract contract;
    block_process::get_contract(txn->contract_id(), contract);
    ZeraStatus status;

    std::string txn_data;
    zera_txn::TXNWrapper wrapper;
    if (!db_timed_txns::get_single(txn->txn_hash(), txn_data) || !wrapper.ParseFromString(txn_data))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_quash.cpp: check_parameters: Timed txn does not exist", zera_txn::TXN_STATUS::INVALID_TXN_HASH);
    }

    status = check_wrapper(wrapper, contract);

    if (!status.ok())
    {
        return status;
    }

    std::string quash_data;
    zera_validator::QuashLookup quash_lookup;
    db_quash_lookup::get_single(txn->txn_hash(), quash_data);

    quash_lookup.ParseFromString(quash_data);

    for (auto keys : quash_lookup.quash_keys())
    {
        std::string quash_pub_key = wallets::get_public_key_string(keys);
        std::string base_pub_key = wallets::get_public_key_string(txn->base().public_key());
        if (quash_pub_key == base_pub_key )
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_quash.cpp: check_parameters: TXN public key already exists in quash lookup", zera_txn::TXN_STATUS::DUPLICATE_AUTH_KEY);
        }
    }

    if (quash_lookup.quash_keys_size() >= contract.quash_threshold())
    {
        quash_tracker::add_quash(txn->txn_hash());
    }

    quash_tracker::add_quash_keys(txn->txn_hash(), txn->base().public_key());

    return status;
}
