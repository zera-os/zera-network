#include "verify_process_txn.h"

#include <set>

template ZeraStatus verify_txns::verify_txn<zera_txn::MintTXN>(const zera_txn::MintTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::ItemizedMintTXN>(const zera_txn::ItemizedMintTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::CoinTXN>(const zera_txn::CoinTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::RequiredVersion>(const zera_txn::RequiredVersion *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn);
template ZeraStatus verify_txns::verify_txn<zera_txn::ProposalCancelTXN>(const zera_txn::ProposalCancelTXN *txn);

template <>
void verify_txns::store_wrapper<zera_txn::MintTXN>(const zera_txn::MintTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_mint_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::MINT_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::ItemizedMintTXN>(const zera_txn::ItemizedMintTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_item_mint_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_contract_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_governance_vote()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::VOTE_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_governance_proposal()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_smart_contract()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_smart_contract_execute()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_expense_ratios()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_nft_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::NFT_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_contract_update_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_validator_heartbeat_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::VALIDATOR_HEARTBEAT_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_delegated_voting_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::DELEGATED_VOTING_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::QuashTXN>(const zera_txn::QuashTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_quash_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::QUASH_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_fast_quorum_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::FAST_QUORUM_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_revoke_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::REVOKE_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_compliance_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::COMPLIANCE_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_burn_sbt_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::SBT_BURN_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::CoinTXN>(const zera_txn::CoinTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_coin_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::COIN_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::ValidatorRegistration>(const zera_txn::ValidatorRegistration *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_validator_registration_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::VALIDATOR_REGISTRATION_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_smart_contract_instantiate_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE);
}
template <>
void verify_txns::store_wrapper<zera_txn::RequiredVersion>(const zera_txn::RequiredVersion *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_required_version_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::REQUIRED_VERSION);
}
template <>
void verify_txns::store_wrapper<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_allowance_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE);
}

template <>
void verify_txns::store_wrapper<zera_txn::ProposalCancelTXN>(const zera_txn::ProposalCancelTXN *txn, zera_txn::TXNWrapper &wrapper)
{
    wrapper.mutable_proposal_cancel_txn()->CopyFrom(*txn);
    wrapper.set_txn_type(zera_txn::TRANSACTION_TYPE::PROPOSAL_CANCEL_TYPE);
}

template <typename TXType>
ZeraStatus verify_txns::verify_identity(TXType *txn)
{
    try
    {

        TXType txn_copy;
        txn_copy.CopyFrom(*txn);

        if (!signatures::verify_txns(txn_copy))
        {
            return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "verify_process.h: verify_identity: signature verification failed.");
        }
        zera_txn::BaseTXN *base = txn_copy.mutable_base();
        // Copy + clear instead of release_hash(): release returns nullptr when the
        // field is unset, and a txn submitted without a hash would crash on the
        // dereference (segfaults are not catchable by the try/catch below).
        std::string original_hash_str = base->hash();
        base->clear_hash();
        std::vector<uint8_t> original_hash(original_hash_str.begin(), original_hash_str.end());
        std::vector<uint8_t> new_hash = Hashing::sha256_hash(txn_copy.SerializeAsString());

        // if hashes do not match, txn cannot be made
        if (!Hashing::compare_hash(original_hash, new_hash))
        {
            return ZeraStatus(ZeraStatus::Code::HASH_ERROR, "verify_process.h: verify_identity: txn hash did not match");
        }

        return ZeraStatus(ZeraStatus::Code::OK);
    }
    catch (...)
    {
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "verify_process.h: verify_identity: signature verification failed. CRASH");
    }
}


template <>
ZeraStatus verify_txns::verify_identity<zera_txn::SmartContractExecuteTXN>(zera_txn::SmartContractExecuteTXN *txn)
{
    try
    {
        zera_txn::SmartContractExecuteTXN txn_copy;
        txn_copy.CopyFrom(*txn);

        if (!signatures::verify_txns(txn_copy))
        {
            return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "verify_process.h: verify_identity: signature verification failed.");
        }
        zera_txn::BaseTXN *base = txn_copy.mutable_base();
        // Copy + clear instead of release_hash() (see generic verify_identity above).
        std::string original_hash_str = base->hash();
        base->clear_hash();
        std::vector<uint8_t> original_hash(original_hash_str.begin(), original_hash_str.end());
        std::vector<uint8_t> new_hash = Hashing::sha256_hash(txn_copy.SerializeAsString());

        // if hashes do not match, txn cannot be made
        if (!Hashing::compare_hash(original_hash, new_hash))
        {
            return ZeraStatus(ZeraStatus::Code::HASH_ERROR, "verify_process.h: verify_identity: txn hash did not match");
        }

        return ZeraStatus(ZeraStatus::Code::OK);
    }
    catch (...)
    {
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "verify_process.h: verify_identity: signature verification failed. Smart Contract Execute CRASH");
    }
}

template <>
ZeraStatus verify_txns::verify_identity<zera_txn::ValidatorRegistration>(zera_txn::ValidatorRegistration *txn)
{
    try
    {
        /* code */
        zera_txn::ValidatorRegistration txn_copy;
        txn_copy.CopyFrom(*txn);

        if (!signatures::verify_txns(txn_copy))
        {
            return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "verify_process.h: verify_identity: signature verification failed. Validator Registration");
        }
        zera_txn::BaseTXN *base = txn_copy.mutable_base();
        // Copy + clear instead of release_hash() (see generic verify_identity above).
        std::string original_hash_str = base->hash();
        base->clear_hash();
        std::vector<uint8_t> original_hash(original_hash_str.begin(), original_hash_str.end());

        if (txn_copy.register_())
        {
            txn_copy.clear_generated_signature();
        }

        std::vector<uint8_t> new_hash = Hashing::sha256_hash(txn_copy.SerializeAsString());

        // if hashes do not match, txn cannot be made
        if (!Hashing::compare_hash(original_hash, new_hash))
        {
            return ZeraStatus(ZeraStatus::Code::HASH_ERROR, "verify_process.h: verify_identity: txn hash did not match");
        }

        return ZeraStatus(ZeraStatus::Code::OK);
    }
    catch (...)
    {
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "verify_process.h: verify_identity: crash - signature verification failed. Validator Registration CRASH");
    }
}

ZeraStatus verify_txns::verify_block_txns(const zera_validator::Block &block)
{
    const zera_txn::TXNS &txns = block.transactions();
    std::set<std::string> seen_hashes;

    // Verifies every txn in a repeated field. Skips internally-generated txns
    // (smart contract / governance child txns) which carry no user signature and
    // are reproduced during block reconstruction, and rejects duplicate hashes.
    auto verify_field = [&seen_hashes](const auto &repeated_field) -> ZeraStatus
    {
        for (const auto &txn : repeated_field)
        {
            if (txn.base().public_key().has_smart_contract_auth() ||
                txn.base().public_key().has_governance_auth())
            {
                continue;
            }

            if (!seen_hashes.insert(txn.base().hash()).second)
            {
                return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "verify_process.cpp: verify_block_txns: duplicate txn hash in block");
            }

            auto txn_copy = txn;
            ZeraStatus status = verify_identity(&txn_copy);

            if (!status.ok())
            {
                status.prepend_message("verify_process.cpp: verify_block_txns");
                return status;
            }
        }

        return ZeraStatus(ZeraStatus::Code::OK);
    };

    ZeraStatus status;

    if (!(status = verify_field(txns.coin_txns())).ok()) return status;
    if (!(status = verify_field(txns.contract_txns())).ok()) return status;
    if (!(status = verify_field(txns.mint_txns())).ok()) return status;
    if (!(status = verify_field(txns.item_mint_txns())).ok()) return status;
    if (!(status = verify_field(txns.governance_votes())).ok()) return status;
    if (!(status = verify_field(txns.governance_proposals())).ok()) return status;
    if (!(status = verify_field(txns.smart_contracts())).ok()) return status;
    if (!(status = verify_field(txns.smart_contract_executes())).ok()) return status;
    if (!(status = verify_field(txns.smart_contract_instantiate_txns())).ok()) return status;
    if (!(status = verify_field(txns.expense_ratios())).ok()) return status;
    if (!(status = verify_field(txns.nft_txns())).ok()) return status;
    if (!(status = verify_field(txns.contract_update_txns())).ok()) return status;
    if (!(status = verify_field(txns.validator_registration_txns())).ok()) return status;
    if (!(status = verify_field(txns.validator_heartbeat_txns())).ok()) return status;
    if (!(status = verify_field(txns.delegated_voting_txns())).ok()) return status;
    if (!(status = verify_field(txns.quash_txns())).ok()) return status;
    if (!(status = verify_field(txns.fast_quorum_txns())).ok()) return status;
    if (!(status = verify_field(txns.revoke_txns())).ok()) return status;
    if (!(status = verify_field(txns.compliance_txns())).ok()) return status;
    if (!(status = verify_field(txns.burn_sbt_txns())).ok()) return status;
    if (!(status = verify_field(txns.allowance_txns())).ok()) return status;

    return ZeraStatus(ZeraStatus::Code::OK);
}