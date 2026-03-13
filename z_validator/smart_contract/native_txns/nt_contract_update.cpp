#include "nt_helpers.h"
#include "nf_helpers.h"

namespace
{
    std::string bytes_to_proto(const std::vector<uint8_t> &bytes)
    {
        return std::string(bytes.begin(), bytes.end());
    }

    zera_txn::GOVERNANCE_TYPE to_proto_governance_type(GovernanceType type)
    {
        switch (type)
        {
        case GovernanceType::Staged:
            return zera_txn::STAGED;
        case GovernanceType::Cycle:
            return zera_txn::CYCLE;
        case GovernanceType::Staggered:
            return zera_txn::STAGGERED;
        case GovernanceType::Adaptive:
            return zera_txn::ADAPTIVE;
        case GovernanceType::Remove:
            return zera_txn::REMOVE;
        default:
            return zera_txn::ADAPTIVE;
        }
    }

    zera_txn::CONTRACT_FEE_TYPE to_proto_fee_type(ContractFeeType type)
    {
        switch (type)
        {
        case ContractFeeType::Fixed:
            return zera_txn::FIXED;
        case ContractFeeType::CurEquivalent:
            return zera_txn::CUR_EQUIVALENT;
        case ContractFeeType::Percentage:
            return zera_txn::PERCENTAGE;
        case ContractFeeType::None:
            return zera_txn::NONE;
        default:
            return zera_txn::NONE;
        }
    }

    zera_txn::PROPOSAL_PERIOD to_proto_proposal_period(ProposalPeriod period)
    {
        switch (period)
        {
        case ProposalPeriod::Days:
            return zera_txn::DAYS;
        case ProposalPeriod::Months:
            return zera_txn::MONTHS;
        default:
            return zera_txn::DAYS;
        }
    }

    void fill_multi_patterns(zera_txn::MultiPatterns *dst, const MultiPatterns &src)
    {
        for (uint32_t val : src.pattern_class)
            dst->add_class_(val);
        for (uint32_t val : src.required)
            dst->add_required(val);
    }

    void fill_multi_key(zera_txn::MultiKey *dst, const MultiKey &src)
    {
        for (const auto &pk : src.public_keys)
            dst->add_public_keys(bytes_to_proto(pk));
        for (const auto &sig : src.signatures)
            dst->add_signatures(bytes_to_proto(sig));
        for (const auto &mp : src.multi_patterns)
            fill_multi_patterns(dst->add_multi_patterns(), mp);
        for (const auto &ht : src.hash_tokens)
            dst->add_hash_tokens(ht);
    }

    void fill_public_key(zera_txn::PublicKey *dst, const PublicKey &src)
    {
        dst->set_single(bytes_to_proto(src.single));
        if (src.multi.has_value())
            fill_multi_key(dst->mutable_multi(), src.multi.value());
        if (src.smart_contract_auth.has_value())
            dst->set_smart_contract_auth(bytes_to_proto(src.smart_contract_auth.value()));
        if (src.governance_auth.has_value())
            dst->set_governance_auth(bytes_to_proto(src.governance_auth.value()));
    }

    void fill_restricted_key(zera_txn::RestrictedKey *dst, const RestrictedKey &src)
    {
        fill_public_key(dst->mutable_public_key(), src.public_key);
        dst->set_time_delay(src.time_delay);
        dst->set_global(src.global);
        dst->set_update_contract(src.update_contract);
        dst->set_transfer(src.transfer);
        dst->set_quash(src.quash);
        dst->set_mint(src.mint);
        dst->set_vote(src.vote);
        dst->set_propose(src.propose);
        dst->set_compliance(src.compliance);
        dst->set_expense_ratio(src.expense_ratio);
        dst->set_revoke(src.revoke);
        dst->set_key_weight(src.key_weight);
    }

    void fill_contract_fees(zera_txn::ContractFees *dst, const ContractFees &src)
    {
        dst->set_fee(src.fee);
        if (src.fee_address.has_value())
            dst->set_fee_address(bytes_to_proto(src.fee_address.value()));
        dst->set_burn(src.burn);
        dst->set_validator(src.validator);
        for (const auto &fi : src.allowed_fee_instrument)
            dst->add_allowed_fee_instrument(fi);
        dst->set_contract_fee_type(to_proto_fee_type(src.contract_fee_type));
    }

    void fill_governance(zera_txn::Governance *dst, const Governance &src)
    {
        dst->set_type(to_proto_governance_type(src.governance_type));
        dst->set_regular_quorum(src.regular_quorum);
        if (src.fast_quorum.has_value())
            dst->set_fast_quorum(src.fast_quorum.value());
        for (const auto &vi : src.voting_instrument)
            dst->add_voting_instrument(vi);
        dst->set_threshold(src.threshold);
        if (src.chicken_dinner.has_value())
            dst->set_chicken_dinner(src.chicken_dinner.value());
        dst->set_allow_multi(src.allow_multi);
        if (src.voting_period.has_value())
            dst->set_voting_period(src.voting_period.value());
        for (const auto &api : src.allowed_proposal_instrument)
            dst->add_allowed_proposal_instrument(api);
        if (src.proposal_period.has_value())
            dst->set_proposal_period(to_proto_proposal_period(src.proposal_period.value()));
        for (const auto &stage : src.stage_length)
        {
            auto *s = dst->add_stage_length();
            s->set_length(stage.length);
            s->set_period(to_proto_proposal_period(stage.period));
            s->set_break_(stage.break_stage);
            s->set_max_approved(stage.max_approved);
        }
        if (src.start_timestamp.has_value())
        {
            auto *ts = dst->mutable_start_timestamp();
            ts->set_seconds(src.start_timestamp.value().seconds);
            ts->set_nanos(src.start_timestamp.value().nanos);
        }
        if (src.max_approved.has_value())
            dst->set_max_approved(src.max_approved.value());
    }

    void fill_contract_update_txn(zera_txn::ContractUpdateTXN *dst, const ContractUpdateTXN &src)
    {
        dst->set_contract_id(src.contract_id);
        dst->set_contract_version(src.contract_version);

        if (src.name.has_value())
            dst->set_name(src.name.value());

        if (src.governance.has_value())
            fill_governance(dst->mutable_governance(), src.governance.value());

        for (const auto &rk : src.restricted_keys)
            fill_restricted_key(dst->add_restricted_keys(), rk);

        if (src.contract_fees.has_value())
            fill_contract_fees(dst->mutable_contract_fees(), src.contract_fees.value());

        for (const auto &kv : src.custom_parameters)
        {
            auto *param = dst->add_custom_parameters();
            param->set_key(kv.key);
            param->set_value(kv.value);
        }

        for (const auto &er : src.expense_ratio)
        {
            auto *ratio = dst->add_expense_ratio();
            ratio->set_day(er.day);
            ratio->set_month(er.month);
            ratio->set_percent(er.percent);
        }

        for (const auto &tc : src.token_compliance)
        {
            auto *proto_tc = dst->add_token_compliance();
            for (const auto &ce : tc.compliance)
            {
                auto *proto_ce = proto_tc->add_compliance();
                proto_ce->set_contract_id(ce.contract_id);
                proto_ce->set_compliance_level(ce.compliance_level);
            }
        }

        if (src.kyc_status.has_value())
            dst->set_kyc_status(src.kyc_status.value());

        if (src.immutable_kyc_status.has_value())
            dst->set_immutable_kyc_status(src.immutable_kyc_status.value());

        if (src.quash_threshold.has_value())
            dst->set_quash_threshold(src.quash_threshold.value());
    }
}

std::string nt_process_contract_update(SenderDataType *sender, const NetworkTXN &network_txn)
{

    ContractUpdateTXN contract_update_txn = decode_contract_update_txn(network_txn.payload);

    zera_txn::ContractUpdateTXN txn;

    fill_contract_update_txn(&txn, contract_update_txn);

    zera_txn::BaseTXN base = create_base(sender, network_txn.sender);

    if(!base.IsInitialized())
    {
        return "ERROR: Failed to create base for contract update";
    }

    txn.mutable_base()->CopyFrom(base);

    calc_fee(&base, sender->fee_id, txn.ByteSizeLong(), zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE);

    set_txn_hash<zera_txn::ContractUpdateTXN>(&txn);

    if(!txn.IsInitialized())
    {
        return "ERROR: Failed to initialize contract update transaction";
    }

    std::string value;
    db_smart_contracts::get_single(sender->block_txns_key, value);
    zera_txn::TXNS block_txns;
    block_txns.ParseFromString(value);

    ZeraStatus status = process_txn<zera_txn::ContractUpdateTXN>(&txn, block_txns, zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE, sender);

    if(status.ok())
    {
        block_txns.add_contract_update_txns()->CopyFrom(txn);
    }

    db_smart_contracts::store_single(sender->block_txns_key, block_txns.SerializeAsString());

    return zera_txn::TXN_STATUS_Name(status.txn_status());;
}
