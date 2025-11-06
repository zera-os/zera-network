#include "client_network_service.h"
#include "validator_network_client.h"
#include "verify_process_txn.h"
#include <thread>

RateLimiter ClientNetworkServiceImpl::rate_limiter;

grpc::Status ClientNetworkServiceImpl::Mint(grpc::ServerContext *context, const zera_txn::MintTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::NFT(grpc::ServerContext *context, const zera_txn::NFTTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::ItemMint(grpc::ServerContext *context, const zera_txn::ItemizedMintTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::Contract(grpc::ServerContext *context, const zera_txn::InstrumentContract *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::GovernProposal(grpc::ServerContext *context, const zera_txn::GovernanceProposal *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::GovernVote(grpc::ServerContext *context, const zera_txn::GovernanceVote *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::SmartContract(grpc::ServerContext *context, const zera_txn::SmartContractTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::SmartContractExecute(grpc::ServerContext *context, const zera_txn::SmartContractExecuteTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::ExpenseRatio(grpc::ServerContext *context, const zera_txn::ExpenseRatioTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::ContractUpdate(grpc::ServerContext *context, const zera_txn::ContractUpdateTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::DelegatedVoting(grpc::ServerContext *context, const zera_txn::DelegatedTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::Quash(grpc::ServerContext *context, const zera_txn::QuashTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::Revoke(grpc::ServerContext *context, const zera_txn::RevokeTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::FastQuorum(grpc::ServerContext *context, const zera_txn::FastQuorumTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::Compliance(grpc::ServerContext *context, const zera_txn::ComplianceTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::BurnSBT(grpc::ServerContext *context, const zera_txn::BurnSBTTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::Coin(grpc::ServerContext *context, const zera_txn::CoinTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}
grpc::Status ClientNetworkServiceImpl::SmartContractInstantiate(grpc::ServerContext *context, const zera_txn::SmartContractInstantiateTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}

grpc::Status ClientNetworkServiceImpl::Allowance(grpc::ServerContext *context, const zera_txn::AllowanceTXN *request, google::protobuf::Empty *response)
{
    return RecieveRequest(context, request, response);
}


