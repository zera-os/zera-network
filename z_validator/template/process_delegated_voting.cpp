#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

#include "../block_process.h"
#include "wallets.h"
#include "../../temp_data/temp_data.h"
#include "utils.h"

namespace
{
    ZeraStatus process_delegated_fees(const zera_txn::DelegatedTXN *txn)
    {
        ZeraStatus status;
        std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());

        for (auto fee : txn->delegate_fees())
        {
            if (!is_valid_uint256(fee.auth_amount()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_delegated_voting.cpp: process_delegated_fees: Invalid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
            }
            std::string contract_id = fee.contract_id();
            uint256_t amount(fee.auth_amount());
            std::string voting_wallet = "v_" + wallet_adr + contract_id;
            std::string balance_str;

            if (!db_processed_wallets::get_single(voting_wallet, balance_str) && !db_wallets::get_single(voting_wallet, balance_str))
            {
                balance_str = "0";
            }

            uint256_t voting_balance(balance_str);
            uint256_t add_amount = 0;
            uint256_t sub_amount = 0;

            if (amount > voting_balance)
            {
                sub_amount = amount - voting_balance;
            }
            else if (amount < voting_balance)
            {
                add_amount = voting_balance - amount;
            }

            if (add_amount == 0 && sub_amount == 0)
            {
                continue;
            }
            else if (add_amount > 0)
            {
                status = balance_tracker::subtract_txn_balance("v_" + wallet_adr, contract_id, add_amount, txn->base().hash());
                if (!status.ok())
                {
                    status.prepend_message("process_delegated_voting.cpp: process_delegated_fees: add_balance:");
                    return status;
                }
                balance_tracker::add_txn_balance(wallet_adr, contract_id, add_amount, txn->base().hash());
            }
            else if (sub_amount > 0)
            {
                status = balance_tracker::subtract_txn_balance(wallet_adr, contract_id, sub_amount, txn->base().hash());
                if (!status.ok())
                {
                    status.prepend_message("process_delegated_voting.cpp: process_delegated_fees: sub balance: wallet_adr: " + base58_encode(wallet_adr) + " contract_id: " + contract_id);
                    return status;
                }
                balance_tracker::add_txn_balance("v_" + wallet_adr, contract_id, sub_amount, txn->base().hash());
            }
        }

        return ZeraStatus();
    }
}
template <>
ZeraStatus block_process::check_parameters<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    if (txn->delegate_fees_size() <= 0)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "No fees to delegate", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }
    for(auto vote : txn->delegate_votes()){
       
       if(vote.address() == wallets::generate_wallet(txn->base().public_key()))
       {
           return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_delegated_voting.cpp: check_parameters: Cannot delegate to self", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
       }
    }

    ZeraStatus status = process_delegated_fees(txn);

    return status;
}