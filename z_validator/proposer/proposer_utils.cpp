#include "proposer.h"
#include "../governance/gov_process.h"
#include "../logging/logging.h"

void proposing::add_used_new_coin_nonce(const zera_txn::CoinTXN &txn, const zera_txn::TXNStatusFees &status_fees, bool timed)
{
    int x = 0;
    for (auto public_key : txn.auth().public_key())
    {
        std::string wallet_adr = wallets::generate_wallet(public_key);
        uint64_t nonce = txn.auth().nonce(x);

        nonce_tracker::add_used_nonce(wallet_adr, nonce);
        x++;
    }

    if (status_fees.status() == zera_txn::TXN_STATUS::OK)
    {
        x = 0;
        for (auto wallet_adr : txn.auth().allowance_address())
        {
            uint64_t nonce = txn.auth().allowance_nonce(x);
            nonce_tracker::add_used_nonce(wallet_adr, nonce);
            x++;
        }
    }
}

ZeraStatus proposing::processTransaction(zera_txn::TXNWrapper &wrapper, zera_txn::TXNS *block_txns, bool timed, const std::string &fee_address)
{
    ZeraStatus status;

    if (wrapper.has_coin_txn())
    {   
        status = proposing::unpack_process_wrapper(wrapper.mutable_coin_txn(), block_txns, wrapper.txn_type(), timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_allowance_hash(wrapper.coin_txn().base().hash());
            txn_hash_tracker::add_hash(wrapper.coin_txn().base().hash());
            block_txns->add_coin_txns()->CopyFrom(wrapper.coin_txn());
            auto size = block_txns->txn_fees_and_status_size() - 1;
            add_used_new_coin_nonce(wrapper.coin_txn(), block_txns->txn_fees_and_status(size));
        }
        if (!status.ok())
        {
            logging::print(status.read_status());
        }
    }
    else if (wrapper.has_contract_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_contract_txn(), block_txns, zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.contract_txn().base().hash());
            block_txns->add_contract_txns()->CopyFrom(wrapper.contract_txn());
            add_used_nonce(wrapper.contract_txn());
        }
    }
    else if (wrapper.has_governance_proposal())
    {  
        status = proposing::unpack_process_wrapper(wrapper.mutable_governance_proposal(), block_txns, zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.governance_proposal().base().hash());
            block_txns->add_governance_proposals()->CopyFrom(wrapper.governance_proposal());
            add_used_nonce(wrapper.governance_proposal());
        }
    }
    else if (wrapper.has_governance_vote())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_governance_vote(), block_txns, zera_txn::TRANSACTION_TYPE::VOTE_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.governance_vote().base().hash());
            block_txns->add_governance_votes()->CopyFrom(wrapper.governance_vote());
            add_used_nonce(wrapper.governance_vote());
        }
    }
    else if (wrapper.has_mint_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_mint_txn(), block_txns, zera_txn::TRANSACTION_TYPE::MINT_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.mint_txn().base().hash());
            block_txns->add_mint_txns()->CopyFrom(wrapper.mint_txn());
            add_used_nonce(wrapper.mint_txn());
        }
    }
    else if (wrapper.has_item_mint_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_item_mint_txn(), block_txns, zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.item_mint_txn().base().hash());
            block_txns->add_item_mint_txns()->CopyFrom(wrapper.item_mint_txn());
            add_used_nonce(wrapper.item_mint_txn());
        }
    }
    else if (wrapper.has_nft_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_nft_txn(), block_txns, zera_txn::TRANSACTION_TYPE::NFT_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.nft_txn().base().hash());
            block_txns->add_nft_txns()->CopyFrom(wrapper.nft_txn());
            add_used_nonce(wrapper.nft_txn());
        }
    }
    else if (wrapper.has_contract_update_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_contract_update_txn(), block_txns, zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.contract_update_txn().base().hash());
            block_txns->add_contract_update_txns()->CopyFrom(wrapper.contract_update_txn());
            add_used_nonce(wrapper.contract_update_txn());
        }
    }
    else if (wrapper.has_smart_contract())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_smart_contract(), block_txns, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.smart_contract().base().hash());
            block_txns->add_smart_contracts()->CopyFrom(wrapper.smart_contract());
            add_used_nonce(wrapper.smart_contract());
        }
    }
    else if (wrapper.has_smart_contract_execute())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_smart_contract_execute(), block_txns, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            logging::print("[ProposerUtils] Smart Contract Execute: Passed", true);
            txn_hash_tracker::add_hash(wrapper.smart_contract_execute().base().hash());
            block_txns->add_smart_contract_executes()->CopyFrom(wrapper.smart_contract_execute());
            add_used_nonce(wrapper.smart_contract_execute());
        }
    }
    else if (wrapper.has_expense_ratios())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_expense_ratios(), block_txns, true, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.expense_ratios().base().hash());
            block_txns->add_expense_ratios()->CopyFrom(wrapper.expense_ratios());
            add_used_nonce(wrapper.expense_ratios());
        }
    }
    else if (wrapper.has_delegated_voting_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_delegated_voting_txn(), block_txns, zera_txn::TRANSACTION_TYPE::DELEGATED_VOTING_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.delegated_voting_txn().base().hash());
            block_txns->add_delegated_voting_txns()->CopyFrom(wrapper.delegated_voting_txn());
            add_used_nonce(wrapper.delegated_voting_txn());
        }
    }
    else if (wrapper.has_quash_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_quash_txn(), block_txns, zera_txn::TRANSACTION_TYPE::QUASH_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.quash_txn().base().hash());
            block_txns->add_quash_txns()->CopyFrom(wrapper.quash_txn());
            add_used_nonce(wrapper.quash_txn());
        }
    }
    else if (wrapper.has_fast_quorum_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_fast_quorum_txn(), block_txns, zera_txn::TRANSACTION_TYPE::FAST_QUORUM_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.fast_quorum_txn().base().hash());
            block_txns->add_fast_quorum_txns()->CopyFrom(wrapper.fast_quorum_txn());
            add_used_nonce(wrapper.fast_quorum_txn());
        }
    }
    else if (wrapper.has_revoke_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_revoke_txn(), block_txns, zera_txn::TRANSACTION_TYPE::REVOKE_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.revoke_txn().base().hash());
            block_txns->add_revoke_txns()->CopyFrom(wrapper.revoke_txn());
            add_used_nonce(wrapper.revoke_txn());
        }
    }
    else if (wrapper.has_compliance_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_compliance_txn(), block_txns, zera_txn::TRANSACTION_TYPE::COMPLIANCE_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.compliance_txn().base().hash());
            block_txns->add_compliance_txns()->CopyFrom(wrapper.compliance_txn());
            add_used_nonce(wrapper.compliance_txn());
        }
    }
    else if (wrapper.proposal_result_txn())
    {
        status = gov_process::process_ledgers(block_txns, wrapper, fee_address);
    }
    else if (wrapper.has_burn_sbt_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_burn_sbt_txn(), block_txns, zera_txn::TRANSACTION_TYPE::SBT_BURN_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.burn_sbt_txn().base().hash());
            block_txns->add_burn_sbt_txns()->CopyFrom(wrapper.burn_sbt_txn());
            add_used_nonce(wrapper.burn_sbt_txn());
        }
    }
    else if (wrapper.has_validator_heartbeat_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_validator_heartbeat_txn(), block_txns, zera_txn::TRANSACTION_TYPE::VALIDATOR_HEARTBEAT_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.validator_heartbeat_txn().base().hash());
            block_txns->add_validator_heartbeat_txns()->CopyFrom(wrapper.validator_heartbeat_txn());
            add_used_nonce(wrapper.validator_heartbeat_txn());
        }
    }
    else if (wrapper.has_validator_registration_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_validator_registration_txn(), block_txns, zera_txn::TRANSACTION_TYPE::VALIDATOR_REGISTRATION_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.validator_registration_txn().base().hash());
            block_txns->add_validator_registration_txns()->CopyFrom(wrapper.validator_registration_txn());
            add_used_nonce(wrapper.validator_registration_txn());
        }
    }
    else if (wrapper.has_smart_contract_instantiate_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_smart_contract_instantiate_txn(), block_txns, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.smart_contract_instantiate_txn().base().hash());
            block_txns->add_smart_contract_instantiate_txns()->CopyFrom(wrapper.smart_contract_instantiate_txn());
            add_used_nonce(wrapper.smart_contract_instantiate_txn());
        }
    }
    else if (wrapper.has_required_version_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_required_version_txn(), block_txns, zera_txn::TRANSACTION_TYPE::REQUIRED_VERSION, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            logging::print("Required version txn is passed and stored");
            txn_hash_tracker::add_hash(wrapper.required_version_txn().base().hash());
            block_txns->mutable_required_version_txn()->CopyFrom(wrapper.required_version_txn());
        }
    }
    else if (wrapper.has_allowance_txn())
    {
        status = proposing::unpack_process_wrapper(wrapper.mutable_allowance_txn(), block_txns, zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE, timed, fee_address, wrapper.smart_contract_txn());
        if (status.ok())
        {
            txn_hash_tracker::add_hash(wrapper.allowance_txn().base().hash());
            block_txns->add_allowance_txns()->CopyFrom(wrapper.allowance_txn());
        }
    }
    else
    {

        std::string a_thing = zera_txn::TRANSACTION_TYPE_Name(wrapper.txn_type());
        logging::print("No transaction type found: ", a_thing, true);
        status = ZeraStatus(ZeraStatus::Code::TXN_FAILED, "No transaction type found", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }

    return status;
}