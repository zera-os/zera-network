#include "../block_process.h"

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

#include "db_base.h"
#include "../../temp_data/temp_data.h"
#include "utils.h"
#include "fees.h"
#include "wallets.h"

template <>
ZeraStatus block_process::check_parameters<zera_txn::ProposalCancelTXN>(const zera_txn::ProposalCancelTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

    if (!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Contract not found: " + txn->contract_id(), zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }

    if (txn->proposal_id().empty())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "proposal_id is empty", zera_txn::TXN_STATUS::INVALID_PROPOSAL_ID);
    }

    std::string proposal_data;
    zera_validator::Proposal proposal;
    if (!db_proposals::get_single(txn->proposal_id(), proposal_data) || !proposal.ParseFromString(proposal_data))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "proposal_id is not found", zera_txn::TXN_STATUS::INVALID_PROPOSAL_ID);
    }

    std::string prop_pub_key = wallets::get_public_key_string(proposal.public_key());
    std::string base_pub_key = wallets::get_public_key_string(txn->base().public_key());
    if(prop_pub_key != base_pub_key)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "proposal does not belong to sender", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
    }


    return ZeraStatus();
}