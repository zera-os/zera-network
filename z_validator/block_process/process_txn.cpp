#include "block_process.h"
#include "zera_status.h"
#include "../temp_data/temp_data.h"
#include "utils.h"
#include "wallets.h"
#include <thread>
#include "../logging/logging.h"
#include "fees.h"

ZeraStatus block_process::check_nonce(const zera_txn::PublicKey &public_key, const uint64_t &txn_nonce, const std::string &txn_hash, bool sc_txn)
{
    std::string wallet_adr = wallets::generate_wallet(public_key);
    uint64_t wallet_nonce;

    if (public_key.has_governance_auth())
    {
        if (db_gov_txn::exist(txn_hash) || sc_txn)
        {
            return ZeraStatus();
        }
        else
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_txn.cpp: check_nonce: Did not find txn_hash in db_gov_txn.");
        }
    }
    if(sc_txn)
    {
        return ZeraStatus();
    }

    if (!nonce_tracker::get_nonce(wallet_adr, wallet_nonce))
    {
        std::string nonce_str;
        if (!db_wallet_nonce::get_single(wallet_adr, nonce_str))
        {
            if (txn_nonce == 1)
            {
                return ZeraStatus();
            }
            return ZeraStatus(ZeraStatus::Code::NONCE_ERROR, "process_txn.cpp: check_nonce: Did not find nonce in wallet_nonce. " + std::to_string(txn_nonce));
        }
        wallet_nonce = std::stoull(nonce_str);
    };

    uint64_t nonce_diff = txn_nonce - wallet_nonce;

    if (txn_nonce <= wallet_nonce)
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_txn.cpp: check_nonce: Nonce has already been used. wallet nonce: " + std::to_string(wallet_nonce) + " txn nonce: " + std::to_string(txn_nonce) + " wallet address: " + base58_encode(wallet_adr));
    }

    if (nonce_diff != 1)
    {
        return ZeraStatus(ZeraStatus::Code::NONCE_ERROR, "process_txn.cpp: check_nonce: Nonce is not correct. wallet nonce: " + std::to_string(wallet_nonce) + " txn nonce: " + std::to_string(txn_nonce) + " wallet address: " + base58_encode(wallet_adr));
    }

    return ZeraStatus();
}

ZeraStatus block_process::check_nonce_adr(const std::string &wallet_adr, const uint64_t &txn_nonce, const std::string &txn_hash)
{
    uint64_t wallet_nonce;

    if (!nonce_tracker::get_nonce(wallet_adr, wallet_nonce))
    {
        std::string nonce_str;
        if (!db_wallet_nonce::get_single(wallet_adr, nonce_str))
        {
            if (txn_nonce == 1)
            {
                return ZeraStatus();
            }
            return ZeraStatus(ZeraStatus::Code::NONCE_ERROR, "process_txn.cpp: check_nonce: ALLOWANCE Did not find nonce in wallet_nonce. " + std::to_string(txn_nonce));
        }
        wallet_nonce = std::stoull(nonce_str);
    };

    uint64_t nonce_diff = txn_nonce - wallet_nonce;

    if (txn_nonce <= wallet_nonce)
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_txn.cpp: check_nonce: ALLOWANCE Nonce has already been used. wallet nonce: " + std::to_string(wallet_nonce) + " txn nonce: " + std::to_string(txn_nonce) + " wallet address: " + base58_encode(wallet_adr));
    }

    if (nonce_diff != 1)
    {
        return ZeraStatus(ZeraStatus::Code::NONCE_ERROR, "process_txn.cpp: check_nonce: ALLOWANCE Nonce is not correct. wallet nonce: " + std::to_string(wallet_nonce) + " txn nonce: " + std::to_string(txn_nonce) + " wallet address: " + base58_encode(wallet_adr));
    }

    return ZeraStatus();
}

template <typename TXType>
ZeraStatus block_process::restricted_check(const TXType *txn, const zera_txn::TRANSACTION_TYPE &txn_type)
{

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

    if (!status.ok())
    {
        return status;
    }

    status = restricted_keys_check::check_restricted_keys(txn, contract, txn_type);

    if (!status.ok())
    {
        return status;
    }

    std::string pub_key = wallets::get_public_key_string(txn->base().public_key());
    return block_process::check_validator(pub_key, txn_type);
}
template ZeraStatus block_process::restricted_check<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type);
template ZeraStatus block_process::restricted_check<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type);
template ZeraStatus block_process::restricted_check<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type);
template ZeraStatus block_process::restricted_check<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn, const zera_txn::TRANSACTION_TYPE &txn_type);
template ZeraStatus block_process::restricted_check<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type);
template ZeraStatus block_process::restricted_check<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type);
template ZeraStatus block_process::restricted_check<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type);
template ZeraStatus block_process::restricted_check<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type);

template <>
ZeraStatus block_process::restricted_check<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *txn, const zera_txn::TRANSACTION_TYPE &txn_type)
{
    std::string public_key = wallets::get_public_key_string(txn->base().public_key());

    return block_process::check_validator(public_key, txn_type);
}
template <>
ZeraStatus block_process::restricted_check<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type)
{
    std::string public_key = wallets::get_public_key_string(txn->base().public_key());

    return block_process::check_validator(public_key, txn_type);
}
template <>
ZeraStatus block_process::restricted_check<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *txn, const zera_txn::TRANSACTION_TYPE &txn_type)
{
    std::string public_key = wallets::get_public_key_string(txn->base().public_key());

    return block_process::check_validator(public_key, txn_type);
}
template <>
ZeraStatus block_process::restricted_check<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *txn, const zera_txn::TRANSACTION_TYPE &txn_type)
{
    return ZeraStatus();
}
template <typename TXType>
ZeraStatus block_process::process_txn(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
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
    uint256_t fee_amount;
    status = zera_fees::process_simple_fees(txn, status_fees, txn_type, fee_address);

    if (!status.ok())
    {
        return status;
    }

    status = zera_fees::process_interface_fees(txn->base(), status_fees);
    
    if (status.ok())
    {
        if (!timed)
        {
            status = restricted_check(txn, txn_type);
        }
    }

    if (status.ok())
    {
        status = check_parameters(txn, status_fees, fee_address);
    }

    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());
    status_fees.set_status(status.txn_status());

    if(!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }

    if (!status.ok())
    {
        logging::print(status.read_status());
    }

    return ZeraStatus();
}
template ZeraStatus block_process::process_txn<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
template ZeraStatus block_process::process_txn<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn);
