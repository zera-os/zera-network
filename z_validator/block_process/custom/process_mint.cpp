// Standard library headers

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

// Project-specific headers
#include "const.h"
#include "../block_process.h"
#include "wallets.h"
#include "validators.h"
#include "db_base.h"
#include "proposer.h"
#include "base58.h"
#include "utils.h"
#include "../../temp_data/temp_data.h"
#include "../../compliance/compliance.h"
#include "../../logging/logging.h"
#include "fees.h"

namespace
{
    ZeraStatus check_max_supply(const std::string &contract_id, const uint256_t &mint_amount)
    {
        std::string supply_data;
        zera_wallets::MaxSupply supply;

        if (!db_contract_supply::get_single(contract_id, supply_data) || !supply.ParseFromString(supply_data))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp: mint_process: This will never happen. Invalid max supply data.", zera_txn::TXN_STATUS::EXCEEDED_MAX_SUPPLY);
        }

        uint256_t circulation(supply.circulation());
        uint256_t max_supply(supply.max_supply());

        if ((circulation + mint_amount) > max_supply)
        {

            if (supply.release_size() > 0)
            {
                std::string key;
                zera_validator::BlockHeader header;
                db_headers_tag::get_last_data(header, key);
                int remove = 0;
                for (auto release : supply.release())
                {
                    if (header.timestamp().seconds() >= release.release_date().seconds())
                    {
                        uint256_t release_amount(release.amount());
                        max_supply += release_amount;
                        remove++;
                    }
                    else
                    {
                        break;
                    }
                }

                if (remove > 0)
                {
                    for (int x = 0; x < remove; x++)
                    {
                        supply.mutable_release()->DeleteSubrange(0, 1);
                    }

                    supply.set_max_supply(max_supply.str());
                    db_contract_supply::store_single(contract_id, supply.SerializeAsString());

                    if ((circulation + mint_amount) <= max_supply)
                    {
                        return ZeraStatus();
                    }
                }
            }
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp: mint_process: This mint would cause circulation to go over max supply.", zera_txn::TXN_STATUS::EXCEEDED_MAX_SUPPLY);
        }

        return ZeraStatus();
    }

    ZeraStatus mint(const zera_txn::MintTXN *txn, zera_txn::InstrumentContract &contract)
    {

        //TODO - inspect this
        std::string contract_id = txn->contract_id();
        if(contract_id.substr(0, 5) == "$sol-")
        {
            std::string public_key = wallets::get_public_key_string(txn->base().public_key());

            if(public_key != "sc_bridge_proxy_1")
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp: mint: Only bridge smart contract can mint.", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
            }
        }

        if (contract.type() != zera_txn::CONTRACT_TYPE::TOKEN)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp: qualified_mint: Invalid contract type.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        if (!is_valid_uint256(txn->amount()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp: qualified_mint: Invalid uint256_t", zera_txn::TXN_STATUS::INVALID_UINT256);
        }

        // check to see if the contract has enough supply to cover mint
        uint256_t mint_amount(txn->amount());
        ZeraStatus status = check_max_supply(txn->contract_id(), mint_amount);

        if (!status.ok())
        {
            return status;
        }

        if (!check_safe_send(txn->base(), txn->recipient_address()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp : qualified_mint : cannot safe send", zera_txn::TXN_STATUS::INVALID_SAFE_SEND);
        }

        if (!compliance::check_compliance(txn->recipient_address(), contract))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
        }

        balance_tracker::add_txn_balance(txn->recipient_address(), txn->contract_id(), mint_amount, txn->base().hash());
        supply_tracker::store_supply(contract, mint_amount);

        return ZeraStatus();
    }
}

template <>
ZeraStatus block_process::process_txn<zera_txn::MintTXN>(const zera_txn::MintTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{
    uint64_t nonce = txn->base().nonce();
    ZeraStatus status;

    if (!timed)
    {
        status = block_process::check_nonce(txn->base().public_key(), nonce, txn->base().hash(), sc_txn);

        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, status.message(), status.txn_status());
        }
    }

    status = zera_fees::process_simple_fees(txn, status_fees, zera_txn::TRANSACTION_TYPE::MINT_TYPE, fee_address);
    if (!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, status.message(), status.txn_status());
    }

    zera_txn::InstrumentContract contract;

    status = block_process::get_contract(txn->contract_id(), contract);
    if (!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, status.message(), status.txn_status());
    }

    status = zera_fees::process_interface_fees(txn->base(), status_fees);

    if (status.ok())
    {
        status = restricted_keys_check::check_restricted_keys(txn, contract, txn_type, timed);
    }

    if (status.ok())
    {
        status = mint(txn, contract);
    }

    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());
    if(!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }

    status_fees.set_status(status.txn_status());

    if (status.code() != ZeraStatus::Code::OK)
    {
        logging::print(status.read_status());
    }

    return ZeraStatus();
}