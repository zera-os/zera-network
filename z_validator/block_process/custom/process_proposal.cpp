#include "../block_process.h"
#include <boost/lexical_cast.hpp>
#include <set>
#include <algorithm>

#include "../../temp_data/temp_data.h"
#include "const.h"
#include "wallets.h"
#include "base58.h"
#include "proposer.h"
#include "utils.h"
#include "../compliance/compliance.h"
#include "../../logging/logging.h"
#include "fees.h"
#include "base64.h"

namespace
{
    ZeraStatus check_auth(const zera_txn::BaseTXN &base, const std::string &contract_auth)
    {

        if (base.public_key().has_governance_auth() && base.public_key().governance_auth() != contract_auth)
        {
            zera_txn::InstrumentContract contract;

            // Remove the first 4 characters from contract_auth
            if (contract_auth.length() > 4)
            {
                std::string auth = contract_auth.substr(4);
                std::string contract_data;
                if (!db_contracts::get_single(auth, contract_data) || !contract.ParseFromString(contract_data))
                {
                    return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: Contract does not exist.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
                }
            }
            else
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: Contract does not have governance auth.", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
            }

            std::string auth_id = base.public_key().governance_auth();
            zera_txn::InstrumentContract gov_contract;

            // Remove the first 4 characters from contract_auth
            if (auth_id.length() > 4)
            {
                std::string auth = auth_id.substr(4);
                std::string contract_data;
                // TODO - remove this

                if (!db_contracts::get_single(auth, contract_data) || !gov_contract.ParseFromString(contract_data))
                {
                    return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: Contract does not exist.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
                }
            }
            else
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: Contract does not have governance auth.", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
            }

            bool found_key = false;
            std::string gov_auth_key = "gov_" + gov_contract.contract_id();

            for (auto key : contract.restricted_keys())
            {
                std::string own_r_key = wallets::get_public_key_string(key.public_key());
                if (own_r_key == gov_auth_key)
                {

                    for (auto gov_key : gov_contract.restricted_keys())
                    {

                        std::string gov_r_key = wallets::get_public_key_string(gov_key.public_key());

                        if (gov_r_key == gov_auth_key)
                        {
                            found_key = true;
                            break;
                        }
                    }
                }
                if (found_key)
                {
                    break;
                }
            }

            if (!found_key)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: BaseTXN does not have governance auth. did not find key", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
            }
        }

        if (!base.public_key().has_governance_auth())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: BaseTXN does not have governance auth.", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
        }
        else if (!base.has_timestamp())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: BaseTXN does not have timestamp.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
        else if (!base.has_hash())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_auth: BaseTXN does not have hash.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        return ZeraStatus();
    }

    bool contains_forbidden_words(const std::string &text)
    {
        // Convert to lowercase for case-insensitive comparison
        std::string lower_text = text;
        std::transform(lower_text.begin(), lower_text.end(), lower_text.begin(), ::tolower);

        std::vector<std::string> forbidden_words;
        std::string option_blacklist_data;
        if(db_smart_contract_states::get_single(OPTION_BLACKLIST, option_blacklist_data) && option_blacklist_data != "")
        {
            NetworkValues network_values = decode_network_values(option_blacklist_data);
            forbidden_words = network_values.values;
        }
        else
        {
            forbidden_words = {
                "against", "fail", "no", "reject", "oppose", "negative",
                "decline", "deny", "veto", "refuse", "nay", "cancel",
                "abort", "stop", "block", "disapprove", "dissent", "nothing"
            };
        }


        // Check if any forbidden word is found in the text
        for (const auto &word : forbidden_words)
        {
            if (lower_text.find(word) != std::string::npos)
            {
                return true;
            }
        }
        return false;
    }

    template <typename TXType>
    ZeraStatus parse_validate(TXType &txn, const std::string &serialized_txn, std::string contract_adr, std::string txn_hash)
    {
        // check to see if txn can prse into the correct type
        if (!txn.ParseFromString(serialized_txn))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: parse_validate: Failed to parse txn.", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
        }

        if (txn.base().has_interface_fee())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: parse_validate: Interface fee is not allowed in governance proposal.", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
        }

        // check the governance_auth key is correct for the contract_id (all contracts have a governance_auth key that is used to authenticate txns for that contract_id)
        ZeraStatus status = check_auth(txn.base(), contract_adr);

        if (!status.ok())
        {
            return status;
        }
        TXType txn_copy;
        txn_copy.CopyFrom(txn);

        // check the hash of the txn is correct
        auto hash_vec = txn_copy.mutable_base()->release_hash();
        std::vector<uint8_t> hash(hash_vec->begin(), hash_vec->end());

        auto man_hash = Hashing::sha256_hash(txn_copy.SerializeAsString());

        if (!Hashing::compare_hash(hash, man_hash))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: parse_validate: Hashes do not match.", zera_txn::TXN_STATUS::INVALID_TXN_HASH);
        }

        // check the hash given in the outer layer is correct
        std::vector<uint8_t> txn_hash_vec(txn_hash.begin(), txn_hash.end());
        if (!Hashing::compare_hash(hash, txn_hash_vec))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: parse_validate: Hashes do not match.", zera_txn::TXN_STATUS::INVALID_TXN_HASH);
        }

        return ZeraStatus();
    }

    ZeraStatus check_txns(const zera_txn::GovernanceTXN &gov_txn, const std::string &contract_adr)
    {
        ZeraStatus status;
        switch (gov_txn.txn_type())
        {
        case zera_txn::TRANSACTION_TYPE::COIN_TYPE:
        {
            zera_txn::CoinTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::MINT_TYPE:
        {
            zera_txn::MintTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE:
        {
            zera_txn::ItemizedMintTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE:
        {
            zera_txn::InstrumentContract net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::VOTE_TYPE:
        {
            zera_txn::GovernanceVote net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE:
        {
            zera_txn::GovernanceProposal net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE:
        {
            zera_txn::SmartContractTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE:
        {
            zera_txn::SmartContractExecuteTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE:
        {
            zera_txn::ExpenseRatioTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::NFT_TYPE:
        {
            zera_txn::NFTTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE:
        {
            zera_txn::ContractUpdateTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::DELEGATED_VOTING_TYPE:
        {
            zera_txn::DelegatedTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::REVOKE_TYPE:
        {
            zera_txn::RevokeTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::FAST_QUORUM_TYPE:
        {
            zera_txn::FastQuorumTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::COMPLIANCE_TYPE:
        {
            zera_txn::ComplianceTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SBT_BURN_TYPE:
        {
            zera_txn::BurnSBTTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::REQUIRED_VERSION:
        {
            zera_txn::RequiredVersion req_txn;
            status = parse_validate(req_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE:
        {
            zera_txn::SmartContractInstantiateTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::QUASH_TYPE:
        {
            zera_txn::QuashTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE:
        {
            zera_txn::AllowanceTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }

            break;
        }
        case zera_txn::TRANSACTION_TYPE::PROPOSAL_CANCEL_TYPE:
        {
            zera_txn::ProposalCancelTXN net_txn;
            status = parse_validate(net_txn, gov_txn.serialized_txn(), contract_adr, gov_txn.txn_hash());
            if (!status.ok())
            {
                return status;
            }
        }
        case zera_txn::TRANSACTION_TYPE::UKNOWN_TYPE:
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: Unknown Transaction Type", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
            break;
        }
        default:
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: Unknown Transaction Type", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
            break;
        }

        return ZeraStatus();
    }

    ZeraStatus check_option_txns(const zera_txn::GovernanceProposal *txn)
    {

        ZeraStatus status;

        if (txn->governance_option_txns_size() > txn->options_size() - 1 || txn->governance_txn_size() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: GovernanceOptionTXNS size is greater than options size.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        std::string contract_adr = "gov_" + txn->contract_id();
        if (txn->options(0) != "against")
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: First option must be 'against'", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        int x = 0;
        for(auto option : txn->options())
        {
            if(x == 0)
            {
                x++;
                continue;
            }

            // Check if option contains forbidden words that could mislead users
            if(contains_forbidden_words(option))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: Option contains forbidden words that could mislead users", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }

            x++;
        }

        std::set<uint32_t> seen_option_indexes;
        for (auto option_txn : txn->governance_option_txns())
        {
            if (option_txn.option_index() >= txn->options_size() || option_txn.option_index() == 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: Option index is greater than options size or is 0", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }

            // Check for duplicate option indexes
            if (seen_option_indexes.count(option_txn.option_index()) > 0)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: Duplicate option index found", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }

            seen_option_indexes.insert(option_txn.option_index());

            for (auto gov_txn : option_txn.governance_txn())
            {
                status = check_txns(gov_txn, contract_adr);
                if (!status.ok())
                {
                    return status;
                }
            }
        }

        return ZeraStatus();
    }

    ZeraStatus check_txn(const zera_txn::GovernanceProposal *txn)
    {
        if (txn->governance_txn_size() > 0 && txn->options_size() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_txn: GovernanceProposal cannot have both governance_txn and options.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        if (txn->governance_option_txns_size() > 0 && txn->options_size() > 0)
        {
            return check_option_txns(txn);
        }

        if (txn->governance_txn_size() > 0)
        {

            ZeraStatus status;
            auto gov_txns = txn->governance_txn();

            std::string contract_adr = "gov_" + txn->contract_id();
            logging::print("contract_adr: " + contract_adr, true);
            logging::print("gov_txns size: " + std::to_string(gov_txns.size()), true);

            for (auto gov_txn : gov_txns)
            {
                status = check_txns(gov_txn, contract_adr);
                if (!status.ok())
                {
                    return status;
                }
            }

            return ZeraStatus();
        }
    }

    ZeraStatus calculate_fee(const zera_txn::InstrumentContract &contract, const zera_txn::GovernanceProposal *txn, uint256_t &fee_amount)
    {
        zera_fees::ALLOWED_CONTRACT_FEE allowed_fee;

        if (!zera_fees::check_qualified(txn->base().fee_id()))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: calculate_contract_fee: Contract requires qualified token fees", zera_txn::TXN_STATUS::INVALID_BASE_FEE_ID);
        }
        uint256_t multiplier = get_txn_fee(zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE);

        uint256_t fee_equiv;
        if (!zera_fees::get_cur_equiv(txn->base().fee_id(), fee_equiv))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: calculate_fee: Invalid fee id", zera_txn::TXN_STATUS::INVALID_BASE_FEE_ID);
        }

        return zera_fees::calculate_fees(fee_equiv, multiplier, txn->ByteSize(), txn->base().fee_amount(), fee_amount, contract.coin_denomination().amount(), txn->base().public_key(), contract.contract_id());
    }

    ZeraStatus process_proposal_fees(const zera_txn::GovernanceProposal *txn, zera_txn::InstrumentContract &contract, zera_txn::TXNStatusFees &status_fees, uint256_t &fee_remainder, const std::string &fee_address, const bool &sc_txn)
    {

        // CHANGELOG: added sc_fee address for sc_txns
        std::string wallet_adr;
        if (sc_txn)
        {
            wallet_adr = txn->base().sc_fee_address();
        }
        else
        {
            wallet_adr = wallets::generate_wallet(txn->base().public_key());
        }
        std::string contract_data;
        if (!db_contracts::get_single(txn->contract_id(), contract_data) || !contract.ParseFromString(contract_data))
        {
            return ZeraStatus(ZeraStatus::Code::CONTRACT_ERROR, "process_proposal.cpp: process_fees: " + txn->contract_id() + " Contract does not exist.");
        }

        auto wallet_address = wallets::generate_wallet(txn->base().public_key());

        if (!compliance::check_compliance(wallet_address, contract))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
        }

        std::string fee_contract_data;
        zera_txn::InstrumentContract fee_contract;

        if (!db_contracts::get_single(txn->base().fee_id(), fee_contract_data) || !fee_contract.ParseFromString(fee_contract_data))
        {
            return ZeraStatus(ZeraStatus::Code::CONTRACT_ERROR, "process_proposal.cpp: process_fees: " + txn->base().fee_id() + " Fee Contract does not exist.");
        }

        uint256_t fee_amount;
        ZeraStatus status = calculate_fee(fee_contract, txn, fee_amount);

        if (!status.ok())
        {
            return status;
        }

        auto length_size = contract.governance().stage_length_size();
        int stage_size = (length_size > 0) ? (length_size + 1) : 2;

        uint256_t divided_fee = fee_amount / stage_size;
        fee_remainder = fee_amount - divided_fee;

        // store the remainder of the fee in temp wallet address (which is proposal hash)
        std::string proposal_wallet = "p_" + txn->base().hash();

        status = balance_tracker::subtract_txn_balance(wallet_adr, fee_contract.contract_id(), fee_remainder, txn->base().hash());

        if (!status.ok())
        {
            return status;
        }

        balance_tracker::add_txn_balance(proposal_wallet, fee_contract.contract_id(), fee_remainder, txn->base().hash());
        proposing::set_txn_token_fees(txn->base().hash(), fee_contract.contract_id(), proposal_wallet, fee_remainder);
        status = zera_fees::process_fees(fee_contract, divided_fee, wallet_adr, fee_contract.contract_id(), true, status_fees, txn->base().hash(), fee_address);

        if (status.ok())
        {
            std::string fee_amount_str = boost::lexical_cast<std::string>(fee_amount);
            status_fees.set_base_fees(fee_amount_str);
        }

        return status;
    }

    ZeraStatus check_parameters_prop(const zera_txn::GovernanceProposal *txn, zera_txn::InstrumentContract &contract, bool timed, zera_txn::TXNStatusFees &status_fees)
    {
        ZeraStatus status = zera_fees::process_interface_fees(txn->base(), status_fees);

        if (!status.ok())
        {
            return status;
        }

        status = restricted_keys_check::check_restricted_keys(txn, contract, zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE, timed);

        if (!status.ok())
        {
            return status;
        }

        if (!contract.has_governance())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_parameters: Contract does not have governance.", zera_txn::TXN_STATUS::CONTRACT_HAS_NO_GOVERNANCE);
        }

        if (contract.governance().type() == zera_txn::GOVERNANCE_TYPE::ADAPTIVE)
        {
            if (!txn->has_start_timestamp() || !txn->has_end_timestamp())
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_parameters: Adaptive governance requires start and end timestamp", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }

            uint64_t start = txn->start_timestamp().seconds();
            uint64_t end = txn->end_timestamp().seconds();

            if (start > end)
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_parameters: Adaptive governance start timestamp is greater than end timestamp", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
            }
        }
        if (!contract.governance().allow_multi() && txn->options_size() > 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_parameters: Governance doesn not allow multi", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        bool has_instrument = false;
        for (auto instrument : contract.governance().allowed_proposal_instrument())
        {
            auto wallet = wallets::generate_wallet(txn->base().public_key());
            std::string amount;
            if (db_wallets::get_single(wallet + instrument, amount))
            {
                uint256_t amount_int(amount);
                if (amount_int > 0)
                {
                    has_instrument = true;
                    break;
                }
            }
        }

        if (!has_instrument)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_proposal.cpp: check_parameters: Sender does not have allowed proposal instrument.", zera_txn::TXN_STATUS::INVALID_WALLET_ADDRESS);
        }

        return ZeraStatus();
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
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
    status = check_txn(txn);
    if (!status.ok())
    {
        return status;
    }
    zera_txn::InstrumentContract contract;
    uint256_t fee_remainder;
    status = process_proposal_fees(txn, contract, status_fees, fee_remainder, fee_address, sc_txn);

    if (!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, status.read_status());
    }

    status = check_parameters_prop(txn, contract, timed, status_fees);
    status_fees.set_status(status.txn_status());

    if (status.code() != ZeraStatus::Code::OK)
    {
        logging::print(status.read_status());
    }
    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());
    status_fees.set_status(status.txn_status());

    if (!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }

    return ZeraStatus();
}
