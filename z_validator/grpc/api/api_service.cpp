#include "validator_api_service.h"

RateLimiter APIImpl::rate_limiter;

grpc::Status APIImpl::Balance(grpc::ServerContext *context, const zera_api::BalanceRequest *request, zera_api::BalanceResponse *response)
{
    return RecieveRequestBalance(context, request, response);
}
grpc::Status APIImpl::Nonce(grpc::ServerContext *context, const zera_api::NonceRequest *request, zera_api::NonceResponse *response)
{
    return RecieveRequestNonce(context, request, response);
}
grpc::Status APIImpl::ContractFee(grpc::ServerContext *context, const zera_api::ContractFeeRequest *request, zera_api::ContractFeeResponse *response)
{
    return RecieveRequestContractFee(context, request, response);
}
grpc::Status APIImpl::BaseFee(grpc::ServerContext *context, const zera_api::BaseFeeRequest *request, zera_api::BaseFeeResponse *response)
{
    return RecieveRequestBaseFee(context, request, response);
}
grpc::Status APIImpl::GetTokenFeeInfo(grpc::ServerContext *context, const zera_api::TokenFeeInfoRequest *request, zera_api::TokenFeeInfoResponse*response)
{
    return RecieveGetTokenFeeInfo(context, request, response);
}
grpc::Status APIImpl::Items(grpc::ServerContext *context, const zera_api::ItemRequest *request, zera_api::ItemResponse *response)
{
    return RecieveRequestItems(context, request, response);
}
grpc::Status APIImpl::Denomination(grpc::ServerContext *context, const zera_api::DenominationRequest *request, zera_api::DenominationResponse *response)
{
    return RecieveRequestDenomination(context, request, response);
}
grpc::Status APIImpl::Database(grpc::ServerContext *context, const zera_api::DatabaseRequest *request, zera_api::DatabaseResponse *response) 
{
    return RecieveRequestDatabase(context, request, response);
}
grpc::Status APIImpl::Block(grpc::ServerContext *context, const zera_api::BlockRequest *request, zera_api::BlockResponse *response)
{
    return RecieveRequestBlock(context, request, response);
}
grpc::Status APIImpl::ProposalLedger(grpc::ServerContext *context, const zera_api::ProposalLedgerRequest *request, zera_api::ProposalLedgerResponse *response)
{
    return RecieveRequestProposalLedger(context, request, response);
}
grpc::Status APIImpl::SmartContractActivityRequest(grpc::ServerContext *context, const zera_api::ActivityRequest *request, google::protobuf::Empty *response)
{
    return RecieveSmartContractActivityRequest(context, request, response);
}
grpc::Status APIImpl::Contract(grpc::ServerContext *context, const zera_api::ContractRequest *request, zera_api::ContractResponse *response)
{
    return RecieveRequestContract(context, request, response);
}

grpc::Status APIImpl::SmartContractEventsSearch(grpc::ServerContext *context, const zera_api::SmartContractEventsSearchRequest *request, zera_api::SmartContractEventsSearchResponse *response)
{
    return RecieveSmartContractEventsSearch(context, request, response);
}


