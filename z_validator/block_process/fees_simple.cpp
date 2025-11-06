#include "fees.h"
#include "const.h"
#include "block_process.h"
#include "wallets.h"
#include "validators.h"
#include "db_base.h"
#include "hashing.h"
#include "proposer.h"
#include "signatures.h"
#include "../temp_data/temp_data.h"
#include "../compliance/compliance.h"
#include "utils.h"
#include "../logging/logging.h"

template <typename TXType>
ZeraStatus zera_fees::process_simple_fees(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address)
{
    uint256_t fee_type = get_txn_fee(txn_type);

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
    if (!status.ok())
    {
        return status;
    }

    // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
    uint256_t usd_equiv;

    if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: invalid token for fees: " + contract.contract_id());
    }
    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), txn->base().public_key());

    if (!status.ok())
    {
        return status;
    }
    std::string wallet_key = wallets::generate_wallet(txn->base().public_key());

    status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);
    return status;
}
template ZeraStatus zera_fees::process_simple_fees<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ValidatorRegistration>(const zera_txn::ValidatorRegistration *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::MintTXN>(const zera_txn::MintTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address);

template <>
ZeraStatus zera_fees::process_simple_fees<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address)
{
    uint256_t fee_type = get_txn_fee_contract(txn_type, txn);

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
    if (!status.ok())
    {
        return status;
    }

    // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
    uint256_t usd_equiv;

    if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: invalid token for fees Instrument_Contract: " + contract.contract_id());
    }

    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), txn->base().public_key());

    if (!status.ok())
    {
        return status;
    }
    std::string wallet_key = wallets::generate_wallet(txn->base().public_key());

    status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);
    return status;
}

template <typename TXType>
ZeraStatus zera_fees::process_simple_fees_gas(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address)
{
    uint256_t fee_type = get_txn_fee(txn_type);

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
    if (!status.ok())
    {
        return status;
    }

    // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
    uint256_t usd_equiv;

    if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees_gas: invalid token for fees: " + contract.contract_id());
    }
    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), txn->base().public_key());
    fee_amount = txn_fee_amount;
    
    if (!status.ok())
    {
        return status;
    }
    std::string wallet_key = wallets::generate_wallet(txn->base().public_key());

    status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);
    return status;
}
template ZeraStatus zera_fees::process_simple_fees_gas<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address);
template ZeraStatus zera_fees::process_simple_fees_gas<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address);
