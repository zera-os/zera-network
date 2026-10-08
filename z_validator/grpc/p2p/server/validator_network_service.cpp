#include "validator_network_service_grpc.h"

RateLimiter ValidatorServiceImpl::rate_limiter;

// Deprecated direct validator-to-validator transaction RPCs.
//
// These predate the gossip protocol: they are the original ("v1") P2P mechanism
// where each txn type had its own RPC that fed straight into preprocessing. That
// role was fully superseded by the batched Gossip RPC (TXNGossip -> ProcessGossip
// -> ProcessGossipTXN), which verifies every txn before processing. No live caller
// sends individual txns through these RPCs anymore, so they are now hard-disabled
// (UNIMPLEMENTED) to remove the exposed, unauthenticated ingress surface.
//
// ValidatorRegistration and ValidatorHeartbeat are intentionally NOT disabled:
// validator bootstrap (StartRegisterSeeds / StartHeartBeatSeeds in startup_config)
// still sends those directly to seed validators, since a joining validator is not
// yet in any peer's gossip set. The Gossip RPC also stays live.
namespace
{
    const grpc::Status DEPRECATED_TXN_RPC(grpc::StatusCode::UNIMPLEMENTED,
                                          "Direct validator txn RPC is deprecated; transactions propagate via the Gossip RPC.");
}

grpc::Status ValidatorServiceImpl::ValidatorMint(grpc::ServerContext *context, const zera_txn::MintTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorItemMint(grpc::ServerContext *context, const zera_txn::ItemizedMintTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorContract(grpc::ServerContext *context, const zera_txn::InstrumentContract *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorGovernProposal(grpc::ServerContext *context, const zera_txn::GovernanceProposal *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorGovernVote(grpc::ServerContext *context, const zera_txn::GovernanceVote *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorSmartContract(grpc::ServerContext *context, const zera_txn::SmartContractTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorSmartContractExecute(grpc::ServerContext *context, const zera_txn::SmartContractExecuteTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorExpenseRatio(grpc::ServerContext *context, const zera_txn::ExpenseRatioTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorNFT(grpc::ServerContext *context, const zera_txn::NFTTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorContractUpdate(grpc::ServerContext *context, const zera_txn::ContractUpdateTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorHeartbeat(grpc::ServerContext *context, const zera_txn::ValidatorHeartbeat *request, google::protobuf::Empty *response)
{
    // Still live: used for validator heartbeat to seed validators (bootstrap path).
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorDelegatedVoting(grpc::ServerContext *context, const zera_txn::DelegatedTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorQuash(grpc::ServerContext *context, const zera_txn::QuashTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}   
grpc::Status ValidatorServiceImpl::ValidatorRevoke(grpc::ServerContext *context, const zera_txn::RevokeTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorFastQuorum(grpc::ServerContext *context, const zera_txn::FastQuorumTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorCompliance(grpc::ServerContext *context, const zera_txn::ComplianceTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorBurnSBT(grpc::ServerContext *context, const zera_txn::BurnSBTTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorCoin(grpc::ServerContext *context, const zera_txn::CoinTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}
grpc::Status ValidatorServiceImpl::ValidatorRegistration(grpc::ServerContext *context, const zera_txn::ValidatorRegistration *request, google::protobuf::Empty *response)
{
    // Still live: used for validator registration to seed validators (bootstrap path).
    return RecieveRequest(context, request, response);
}

grpc::Status ValidatorServiceImpl::ValidatorSmartContractInstantiate(grpc::ServerContext *context, const zera_txn::SmartContractInstantiateTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}

grpc::Status ValidatorServiceImpl::Gossip(grpc::ServerContext *context, const zera_validator::TXNGossip *request, google::protobuf::Empty *response)
{
    return RecieveGossip(context, request, response);
}

grpc::Status ValidatorServiceImpl::ValidatorAllowance(grpc::ServerContext *context, const zera_txn::AllowanceTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}

grpc::Status ValidatorServiceImpl::ValidatorProposalCancel(grpc::ServerContext *context, const zera_txn::ProposalCancelTXN *request, google::protobuf::Empty *response)
{
    return DEPRECATED_TXN_RPC;
}