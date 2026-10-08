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
#include "fee_payer.h"

template <typename TXType>
ZeraStatus zera_fees::process_simple_fees(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_txn, const std::string &sc_fee_address)
{
    uint256_t fee_type = get_txn_fee(txn_type);

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
    if (!status.ok())
    {
        return status;
    }

    // Internal smart contract txn: the network fee is metered as gas drawn from the
    // contract's approved budget instead of being charged in currency. It gets
    // settled (or refunded on crash) with the root smart contract txn's gas.
    if (sc_txn)
    {
        uint256_t usd_fee = fee_type * txn->ByteSize();
        usd_fee += get_key_fee(txn->base().public_key());

        if (!consume_sc_txn_fee_gas(usd_fee))
        {
            // Also mark the status fee record, since unpack_process_wrapper
            // overwrites the ZeraStatus txn_status with status_fees.status().
            status_fees.set_status(zera_txn::TXN_STATUS::OUT_OF_GAS);
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "fees_simple.cpp: process_simple_fees: insufficient gas for internal txn network fee", zera_txn::TXN_STATUS::OUT_OF_GAS);
        }

        status_fees.set_base_contract_id(contract.contract_id());
        status_fees.set_base_fees("0");
        return ZeraStatus();
    }

    // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
    uint256_t usd_equiv;

    if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: invalid token for fees: " + contract.contract_id());
    }
    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), txn->base().public_key(), contract.contract_id());

    if (!status.ok())
    {
        return status;
    }

    std::string wallet_key = fee_payer::source_wallet(txn->base());

    status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);
    return status;
}
template ZeraStatus zera_fees::process_simple_fees<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ValidatorRegistration>(const zera_txn::ValidatorRegistration *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees<zera_txn::ProposalCancelTXN>(const zera_txn::ProposalCancelTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);

template <>
ZeraStatus zera_fees::process_simple_fees<zera_txn::MintTXN>(const zera_txn::MintTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_txn, const std::string &sc_fee_address)
{
    
    uint256_t fee_type = get_txn_fee(txn_type);

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
    if (!status.ok())
    {
        return status;
    }

    std::string first_wallet_key = txn->recipient_address() + txn->contract_id();

    // Internal smart contract txn: the network fee is metered as gas drawn from the
    // contract's approved budget instead of being charged in currency. It gets
    // settled (or refunded on crash) with the root smart contract txn's gas.
    if (sc_txn)
    {
        uint256_t usd_fee = fee_type * txn->ByteSize();
        usd_fee += get_key_fee(txn->base().public_key());

        if (!db_wallets::exist(first_wallet_key))
        {
            usd_fee += get_fee(FIRST_TIME_WALLET_FEE);
        }

        if (!consume_sc_txn_fee_gas(usd_fee))
        {
            // Also mark the status fee record, since unpack_process_wrapper
            // overwrites the ZeraStatus txn_status with status_fees.status().
            status_fees.set_status(zera_txn::TXN_STATUS::OUT_OF_GAS);
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "fees_simple.cpp: process_simple_fees<MintTXN>: insufficient gas for internal txn network fee", zera_txn::TXN_STATUS::OUT_OF_GAS);
        }

        status_fees.set_base_contract_id(contract.contract_id());
        status_fees.set_base_fees("0");
        return ZeraStatus();
    }

    // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
    uint256_t usd_equiv;

    if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: invalid token for fees: " + contract.contract_id());
    }
    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), txn->base().public_key(), contract.contract_id());

    if (!status.ok())
    {
        return status;
    }

    uint256_t authorized_fees_uint(txn->base().fee_amount());

    if(!db_wallets::exist(first_wallet_key))
    {
        uint256_t first_time_wallet_fee = get_fee(FIRST_TIME_WALLET_FEE);
        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t normalized_fee = (first_time_wallet_fee * denomination) / usd_equiv;
        txn_fee_amount += normalized_fee;
    }

    if (txn_fee_amount > authorized_fees_uint)
    {
        logging::print("process_simple_fees<zera_txn::MintTXN> The sender did not authorize enough fees.", txn_fee_amount.str(), true);
        logging::print("process_simple_fees<zera_txn::MintTXN> authorized_fees_uint: ", authorized_fees_uint.str(), true);
        return ZeraStatus(ZeraStatus::Code::COIN_TXN_ERROR, "process_simple_fees<zera_txn::MintTXN>: The sender did not authorize enough fees.", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
    }

    std::string wallet_key = fee_payer::source_wallet(txn->base());

    status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);
    return status;    
}

template <>
ZeraStatus zera_fees::process_simple_fees<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address)
{
    uint256_t fee_type = get_txn_fee_contract(txn_type, txn);

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->base().fee_id(), contract);
    if (!status.ok())
    {
        return status;
    }

    // Internal smart contract txn: the network fee is metered as gas drawn from the
    // contract's approved budget instead of being charged in currency. It gets
    // settled (or refunded on crash) with the root smart contract txn's gas.
    if (sc_fees)
    {
        uint256_t usd_fee = fee_type * txn->ByteSize();
        usd_fee += get_key_fee(txn->base().public_key());
        usd_fee += get_fee(FIRST_TIME_WALLET_FEE) * txn->premint_wallets_size();

        if (!consume_sc_txn_fee_gas(usd_fee))
        {
            // Also mark the status fee record, since unpack_process_wrapper
            // overwrites the ZeraStatus txn_status with status_fees.status().
            status_fees.set_status(zera_txn::TXN_STATUS::OUT_OF_GAS);
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "fees_simple.cpp: process_simple_fees<InstrumentContract>: insufficient gas for internal txn network fee", zera_txn::TXN_STATUS::OUT_OF_GAS);
        }

        status_fees.set_base_contract_id(contract.contract_id());
        status_fees.set_base_fees("0");
        return ZeraStatus();
    }

    // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
    uint256_t usd_equiv;

    if(!zera_fees::get_cur_equiv(contract.contract_id(), usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees: invalid token for fees Instrument_Contract: " + contract.contract_id());
    }

    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), txn->base().public_key(), contract.contract_id());

    if (!status.ok())
    {
        return status;
    }

    uint256_t authorized_fees_uint(txn->base().fee_amount());

    //add first time wallet fee
    int x = 0;
    uint256_t normalized_fee = 0;
    while(x < txn->premint_wallets_size())
    {
        if(normalized_fee == 0)
        {
            uint256_t denomination(contract.coin_denomination().amount());
            uint256_t first_time_wallet_fee = get_fee(FIRST_TIME_WALLET_FEE);
            normalized_fee = (first_time_wallet_fee * denomination) / usd_equiv;
        }

        txn_fee_amount += normalized_fee;
        x++;
    }

    if (txn_fee_amount > authorized_fees_uint)
    {
        logging::print("process_coin.cpp: calculate_fees: The sender did not authorize enough fees.", txn_fee_amount.str(), true);
        logging::print("authorized_fees_uint: ", authorized_fees_uint.str(), true);
        return ZeraStatus(ZeraStatus::Code::COIN_TXN_ERROR, "process_coin.cpp: calculate_fees: The sender did not authorize enough fees.", zera_txn::TXN_STATUS::INSUFFICIENT_AMOUNT);
    }

    std::string wallet_key = fee_payer::source_wallet(txn->base());

    status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);
    return status;
}

template <typename TXType>
ZeraStatus zera_fees::process_simple_fees_gas(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address)
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

    if(!zera_fees::get_cur_equiv(txn->base().fee_id(), usd_equiv))
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_utils.cpp: process_simple_fees_gas: invalid token for fees: " + contract.contract_id());
    }
    // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
    uint256_t txn_fee_amount;
    status = zera_fees::calculate_fees(usd_equiv, fee_type, txn->ByteSize(), txn->base().fee_amount(), txn_fee_amount, contract.coin_denomination().amount(), txn->base().public_key(), contract.contract_id());
    fee_amount = txn_fee_amount;
    
    if (!status.ok())
    {
        return status;
    }
    std::string wallet_key = fee_payer::source_wallet(txn->base());

    status = zera_fees::process_fees(contract, txn_fee_amount, wallet_key, contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);
    return status;
}
template ZeraStatus zera_fees::process_simple_fees_gas<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
template ZeraStatus zera_fees::process_simple_fees_gas<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address, const bool &sc_fees, const std::string &sc_fee_address);
