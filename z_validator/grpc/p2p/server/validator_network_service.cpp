#include "validator_network_service_grpc.h"

RateLimiter ValidatorServiceImpl::rate_limiter;

grpc::Status ValidatorServiceImpl::ValidatorMint(grpc::ServerContext *context, const zera_txn::MintTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorItemMint(grpc::ServerContext *context, const zera_txn::ItemizedMintTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorContract(grpc::ServerContext *context, const zera_txn::InstrumentContract *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorGovernProposal(grpc::ServerContext *context, const zera_txn::GovernanceProposal *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorGovernVote(grpc::ServerContext *context, const zera_txn::GovernanceVote *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorSmartContract(grpc::ServerContext *context, const zera_txn::SmartContractTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorSmartContractExecute(grpc::ServerContext *context, const zera_txn::SmartContractExecuteTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorExpenseRatio(grpc::ServerContext *context, const zera_txn::ExpenseRatioTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorNFT(grpc::ServerContext *context, const zera_txn::NFTTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorContractUpdate(grpc::ServerContext *context, const zera_txn::ContractUpdateTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorHeartbeat(grpc::ServerContext *context, const zera_txn::ValidatorHeartbeat *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorDelegatedVoting(grpc::ServerContext *context, const zera_txn::DelegatedTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorQuash(grpc::ServerContext *context, const zera_txn::QuashTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}   
grpc::Status ValidatorServiceImpl::ValidatorRevoke(grpc::ServerContext *context, const zera_txn::RevokeTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorFastQuorum(grpc::ServerContext *context, const zera_txn::FastQuorumTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorCompliance(grpc::ServerContext *context, const zera_txn::ComplianceTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorBurnSBT(grpc::ServerContext *context, const zera_txn::BurnSBTTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorCoin(grpc::ServerContext *context, const zera_txn::CoinTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ValidatorServiceImpl::ValidatorRegistration(grpc::ServerContext *context, const zera_txn::ValidatorRegistration *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}

grpc::Status ValidatorServiceImpl::ValidatorSmartContractInstantiate(grpc::ServerContext *context, const zera_txn::SmartContractInstantiateTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}

grpc::Status ValidatorServiceImpl::Gossip(grpc::ServerContext *context, const zera_validator::TXNGossip *request, google::protobuf::Empty *response)
{
    return RecieveGossip(context, request, response);
}

grpc::Status ValidatorServiceImpl::ValidatorAllowance(grpc::ServerContext *context, const zera_txn::AllowanceTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}