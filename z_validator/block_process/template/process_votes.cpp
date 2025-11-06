#include "../block_process.h"
#include "../../temp_data/temp_data.h"
#include "const.h"
#include "../../governance/time_calc.h"
#include "wallets.h"
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>
#include "base58.h"
#include "../compliance/compliance.h"
#include "hex_conversion.h"
#include "../../logging/logging.h"
#include "fees.h"
#include "utils.h"

namespace
{

    ZeraStatus process_fees(const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, std::string &fee_contract_id, std::string &wallet_adr, std::string &auth_fees, const std::string &fee_address, bool delegated = false)
    {
        uint256_t fee_type = get_fee("DELEGATED_FEE");

        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(fee_contract_id, contract);

        if (!status.ok())
        {
            return status;
        }

        // check to see if token is qualified and get usd_equiv if it is, or send back zra usd equiv if it is not qualified
        uint256_t usd_equiv;

        if(!zera_fees::get_cur_equiv(fee_contract_id, usd_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_votes.cpp: process_fees: invalid token for fees: " + fee_contract_id);
        }
        uint256_t txn_fee_amount;
        int byte_size = contract.coin_denomination().amount().size() + wallet_adr.size() + contract.contract_id().size();

        // calculate the fees that need to be paid, and verify they have authorized enough coin to pay it
        status = zera_fees::calculate_fees(usd_equiv, fee_type, byte_size, auth_fees, txn_fee_amount, contract.coin_denomination().amount());

        if (!status.ok())
        {
            return status;
        }

        status = zera_fees::process_fees(contract, txn_fee_amount, wallet_adr, fee_contract_id, true, status_fees, txn->base().hash(), fee_address);

        if(delegated)
        {
            std::string modified_wallet_adr = wallet_adr.substr(2);
            zera_txn::DelegatedData* delegated_data = status_fees.add_delegated_data();
            delegated_data->set_address(modified_wallet_adr);
            zera_txn::Token* fee = delegated_data->mutable_fee();
            fee->set_contract_id(fee_contract_id);
            fee->set_amount(txn_fee_amount.str());
        }
        return status;
    }

    bool process_delegated_fees(const zera_txn::PublicKey &public_key, const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        std::string vote_data;
        zera_validator::DelegatedFees fee;
        std::string wallet_addr = wallets::generate_wallet(public_key);

        if (!db_delegate_vote::get_single(wallet_addr, vote_data) || !fee.ParseFromString(vote_data))
        {
            return false;
        }

        ZeraStatus status;

        for (auto contract_id : fee.contract_ids())
        {
            std::string voting_wallet = "v_" + wallet_addr;
            std::string wallet_key = voting_wallet + contract_id;
            std::string amount_str;
            if (!db_processed_wallets::get_single(wallet_key, amount_str) && !db_wallets::get_single(wallet_key, amount_str))
            {
                return false;
            }
        
            logging::print("process_delegated_fees: ", amount_str);
            status = process_fees(txn, status_fees, contract_id, voting_wallet, amount_str, fee_address, true);

            if (status.ok())
            {
                return true;
            }
        }

        return false;
    }

    // recursive function to check if you have any voters that are delegated to this wallet
    bool check_delegates(std::string wallet_adr, std::vector<std::string> &delegatees, std::vector<std::string> &failed_delegatees, std::vector<std::string> &processed_delegatees, const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        // if wallet has already been processed return false, becuase of duplicate
        if (std::find(processed_delegatees.begin(), processed_delegatees.end(), wallet_adr) != processed_delegatees.end())
        {
            return false;
        }

        processed_delegatees.push_back(wallet_adr);

        std::string recip_data;
        zera_validator::DelegatedRecipient recipient;

        // if no delegatees found return true (no extra processing needed)
        if (!db_delegate_recipient::get_single(wallet_adr, recip_data))
        {
            return true;
        }
        else
        {
            if (!recipient.ParseFromString(recip_data))
            {
                return true;
            }
        }

        // if no delegations found return true (no extra processing needed)
        if (recipient.delegations().count(txn->contract_id()) <= 0)
        {
            return true;
        }

        // get the list of delegates for this contract
        auto delegator = recipient.mutable_delegations()->at(txn->contract_id());

        std::string proposal_id = base58_encode(txn->proposal_id());
        // process each delegatee for this contract
        for (auto single_delegator : delegator.delegator())
        {
            // check any recursive delegates
            check_delegates(wallets::generate_wallet(single_delegator.public_key()), delegatees, failed_delegatees, processed_delegatees, txn, status_fees, fee_address);

            std::string proposal_data;
            zera_validator::Delegated delegated;
            std::string del_wallet = wallets::generate_wallet(single_delegator.public_key());

            if (db_voted_proposals::get_single(del_wallet, proposal_data) && delegated.ParseFromString(proposal_data))
            {
                auto proposals = delegated.mutable_proposals();
                auto it = proposals->find(proposal_id);

                if (it != proposals->end())
                {
                    auto &priority = it->second;
                    if (priority <= single_delegator.priority())
                    {
                        failed_delegatees.push_back(del_wallet);
                        continue;
                    }
                }
            }
            else

            // process fees for this delegatee
            if (!process_delegated_fees(single_delegator.public_key(), txn, status_fees, fee_address))
            {
                std::string pub_key = wallets::get_public_key_string(single_delegator.public_key());
                recipient.mutable_delegations()->erase(pub_key);
                failed_delegatees.push_back(del_wallet);
            }
            else
            {
                delegatees.push_back(del_wallet);
            }
        }

        return true;
    }
    // initial function to process delegated votes
    void process_delegated(const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
    {
        // get the wallet address of the sender
        std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());

        // get the list of delegates so we do not process multiples (infinate loop)
        std::vector<std::string> delegatees;
        std::vector<std::string> failed_delegatees;
        std::vector<std::string> processed_delegatees;

        // check to see if what delegates are delegated to this wallet and process the fees
        check_delegates(wallet_adr, delegatees, failed_delegatees, processed_delegatees, txn, status_fees, fee_address);

        zera_validator::DelegateWallets delegate_wallets;

        // never had to do this before to process own vote? why now WHAT DID I CHANGE?
        for (auto wallets : delegatees)
        {
            delegate_wallets.add_wallets(wallets);
        }

        db_delegate_wallets::store_single(txn->base().hash(), delegate_wallets.SerializeAsString());
    }
}
template <>
ZeraStatus block_process::check_parameters<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    std::string proposal_data;
    zera_validator::Proposal proposal;
    
    if (!db_proposals::get_single(txn->proposal_id(), proposal_data) || !proposal.ParseFromString(proposal_data))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_votes.cpp: check_parameters: Proposal does not exist.", zera_txn::TXN_STATUS::INVALID_PROPOSAL_ID);
    }

    if (proposal.options_set() && !txn->has_support_option())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_votes.cpp: check_parameters: Proposal does not have support option.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }
    else if (!proposal.options_set() && txn->has_support_option())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_votes.cpp: check_parameters: Proposal has support option.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }

    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

    if (!status.ok())
    {
        return status;
    }

    if(proposal.contract_id() != txn->contract_id())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_votes.cpp: check_parameters: Proposal contract id does not match txn contract id.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }

    auto wallet_address = wallets::generate_wallet(txn->base().public_key());

    if (!compliance::check_compliance(wallet_address, contract))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
    }

    if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::ADAPTIVE || contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGGERED)
    {
        zera_validator::BlockHeader new_header;
        std::string new_key;
        db_headers_tag::get_last_data(new_header, new_key);
        google::protobuf::Timestamp now;
        now.CopyFrom(new_header.timestamp());

        if (now.seconds() >= proposal.end_date().seconds())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_votes.cpp: check_parameters: Proposal voting period has ended.", zera_txn::TXN_STATUS::PROPOSAL_NOT_IN_VOTING_PERIOD);
        }

        if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::ADAPTIVE || contract.governance().type() == zera_txn::GOVERNANCE_TYPE::STAGGERED)
        {
            if (now.seconds() < proposal.start_date().seconds())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_votes.cpp: check_parameters: Proposal voting period has not begun.", zera_txn::TXN_STATUS::PROPOSAL_NOT_IN_VOTING_PERIOD);
            }
        }
    }

    process_delegated(txn, status_fees, fee_address);

    return ZeraStatus();
}
