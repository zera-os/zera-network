#include "../block_process.h"
#include "utils.h"
#include "fees.h"

namespace
{
    ZeraStatus process_heartbeat_fees(const zera_txn::ValidatorHeartbeat *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const zera_txn::PublicKey &public_key, const std::string& fee_address)
    {
        uint256_t fee_type = get_txn_fee(txn_type);

        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_heartbeat.cpp: process_fees: invalid contract for fees: " + txn->base().fee_id());
        }

        // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
        uint256_t usd_equiv;

        if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_heartbeat.cpp: process_fees: invalid token for fees: " + contract.contract_id());
        }
        
        // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
        uint256_t txn_fee_amount;
        status = zera_fees::calculate_fees_heartbeat(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), public_key);

        if (!status.ok())
        {
            return status;
        }

        std::string wallet_key = wallets::generate_wallet(public_key);

        status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);

        return status;
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{
    zera_txn::Validator validator;
    std::string validator_str;

    if (!db_validators::get_single(wallets::get_public_key_string(txn->base().public_key()), validator_str))
    {
        return ZeraStatus(ZeraStatus::TXN_FAILED, "Validator not registered", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
    }

    if (!validator.ParseFromString(validator_str))
    {
        return ZeraStatus(ZeraStatus::TXN_FAILED, "Validator not registered v2", zera_txn::TXN_STATUS::VALIDATOR_ADDRESS);
    }

    uint64_t nonce = txn->base().nonce();
    ZeraStatus status;

    status = block_process::check_nonce(validator.public_key(), nonce, txn->base().hash(), sc_txn);

    if (!status.ok())
    {
        return status;
    }

    status = process_heartbeat_fees(txn, status_fees, txn_type, validator.public_key(), fee_address);

    if (!status.ok())
    {
        return status;
    }

    status = zera_fees::process_interface_fees(txn->base(), status_fees);

    std::string wallet_adr = wallets::generate_wallet(validator.public_key());
    status_fees.set_status(status.txn_status());
    if(!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }

    return ZeraStatus();
}