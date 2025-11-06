#include "../block_process.h"

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

#include "db_base.h"
#include "../../temp_data/temp_data.h"


template <>
ZeraStatus block_process::check_parameters<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    std::string proposal_data;
    zera_validator::Proposal proposal;

    if (!db_proposals_temp::get_single(txn->proposal_id(), proposal_data) && !db_proposals::get_single(txn->proposal_id(), proposal_data))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_fast_quorum.cpp: check_parameters: Proposal does not exist.", zera_txn::TXN_STATUS::INVALID_PROPOSAL);
    }
    if(!proposal.ParseFromString(proposal_data)){
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_fast_quorum.cpp: check_parameters: Proposal could not parse.", zera_txn::TXN_STATUS::INVALID_PROPOSAL);
    }
    std::string prop_pub_key = wallets::get_public_key_string(proposal.public_key());
    std::string base_pub_key = wallets::get_public_key_string(txn->base().public_key());
    if (prop_pub_key != base_pub_key)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_fast_quorum.cpp: check_parameters: Proposal does not belong to sender.", zera_txn::TXN_STATUS::PROPOSAL_DOES_NOT_BELONG_TO_SENDER);
    }

    db_fast_quorum::store_single(txn->proposal_id(), proposal.SerializeAsString());

    return ZeraStatus();
}