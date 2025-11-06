#include "../block_process.h"
#include "wallets.h"
#include "../../temp_data/temp_data.h"
#include "utils.h"
#include "../compliance/compliance.h"
#include "../logging/logging.h"
#include "fees.h"


namespace
{
    ZeraStatus check_max_supply(const zera_txn::ItemizedMintTXN *txn)
    {
        std::string supply_data;
        zera_wallets::MaxSupply supply;

        if (!db_contract_supply::get_single(txn->contract_id(), supply_data) || !supply.ParseFromString(supply_data))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_item_mint.cpp: mint_process: This will never happen. Invalid max supply data.");
        }

        if (!is_valid_uint256(supply.circulation()) || !is_valid_uint256(supply.max_supply()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_item_mint.cpp: mint_process: This mint would cause circulation to go over max supply.");
        }
        uint256_t circulation(supply.circulation());
        uint256_t max_supply(supply.max_supply());
        uint256_t one = 1;

        if ((circulation + one) > max_supply)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp: mint_process: This mint would cause circulation to go over max supply.");
        }

        return ZeraStatus();
    }
    ZeraStatus item_mint(const zera_txn::ItemizedMintTXN *txn, zera_txn::InstrumentContract &contract, bool timed, zera_txn::TXNStatusFees &status_fees)
    {
        ZeraStatus status = zera_fees::process_interface_fees(txn->base(), status_fees);

        if (!status.ok())
        {
            return status;
        }

        if (!compliance::check_compliance(txn->recipient_address(), contract))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
        }

        if(!check_safe_send(txn->base(), txn->recipient_address()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp : qualified_mint : cannot safe send", zera_txn::TXN_STATUS::INVALID_SAFE_SEND);
        }

        status = block_process::get_contract(txn->contract_id(), contract);
        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_item_mint.cpp: item_mint: NFT/SBT Contract does not exist.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }
        if (db_contract_items::exist(txn->item_id() + txn->contract_id()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_mint.cpp: item_mint: This item id already exists.", zera_txn::TXN_STATUS::INVALID_NFT);
        }
        status = item_tracker::add_item(txn->item_id() + txn->contract_id());
        if (!status.ok())
        {
            return status;
        }

        // check the the public key to see if its authorized to mint
        // get the contract aswell

        status = restricted_keys_check::check_restricted_keys(txn, contract, zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE, timed);

        if (!status.ok())
        {
            return status;
        }

        if (contract.has_max_supply())
        {
            status = check_max_supply(txn);
            if (!status.ok() && status.code())
            {
                return status;
            }
        }

        if (contract.type() != zera_txn::CONTRACT_TYPE::NFT && contract.type() != zera_txn::CONTRACT_TYPE::SBT)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_item_mint.cpp: item_mint: Cannot item mint a token contract type.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        if (!is_valid_uint256(txn->item_id()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_item_mint.cpp: item_mint: Item_id is not valid: " + txn->item_id(), zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        if (txn->has_expiry() && contract.type() == zera_txn::CONTRACT_TYPE::NFT)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_item_mint.cpp: item_mint: NFT cannot have an expiry", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        if (txn->has_contract_fees())
        {
            if (!is_valid_uint256(txn->contract_fees().burn()) || !is_valid_uint256(txn->contract_fees().fee()) || !is_valid_uint256(txn->contract_fees().validator()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_item_mint.cpp: item_mint: NFT cannot have an expiry", zera_txn::TXN_STATUS::INVALID_UINT256);
            }
        }

        return ZeraStatus();
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::ItemizedMintTXN>(const zera_txn::ItemizedMintTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{
    uint64_t nonce = txn->base().nonce();
    ZeraStatus status;

    if (!timed)
    {
        status = block_process::check_nonce(txn->base().public_key(), nonce, txn->base().hash(), sc_txn);

        if (!status.ok())
        {
            return status;
        }
    }

    zera_txn::InstrumentContract fee_contract;
    status = block_process::get_contract(txn->base().fee_id(), fee_contract);
    if (!status.ok())
    {
        return status;
    }

    // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
    uint256_t usd_equiv;
    std::string fee_id = txn->base().fee_id();

    if(!zera_fees::get_cur_equiv(fee_id, usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_item_mint.cpp: process_txn: invalid token for fees: " + fee_id);
    }

    uint256_t byte_multiplier(get_txn_fee(zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE));
    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, byte_multiplier, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, fee_contract.coin_denomination().amount(), txn->base().public_key());

    if (!status.ok())
    {
        return status;
    }
    std::string sender_adr = wallets::generate_wallet(txn->base().public_key());
    zera_txn::InstrumentContract contract;
    status = zera_fees::process_fees(contract, txn_fee_amount, sender_adr, fee_id, true, status_fees, txn->base().hash(), fee_address);

    if (!status.ok())
    {
        return status;
    }

    status_fees.set_base_contract_id(txn->base().fee_id());
    status_fees.set_base_fees(boost::lexical_cast<std::string>(txn_fee_amount));

    status = item_mint(txn, contract, timed, status_fees);

    if (status.ok())
    {
        if (contract.has_max_supply())
        {
            uint256_t one = 1;
            status = supply_tracker::store_supply(contract, one);
        }
    }
    else
    {
        logging::print(status.read_status());
    }

    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());
    status_fees.set_status(status.txn_status());
    if(!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }


    return ZeraStatus();
}