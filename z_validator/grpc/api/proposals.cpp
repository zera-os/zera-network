
#include "validator_api_service.h"

#include "db_base.h"
#include "base58.h"

grpc::Status APIImpl::RecieveRequestProposalLedger(grpc::ServerContext *context, const zera_api::ProposalLedgerRequest *request, zera_api::ProposalLedgerResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    std::vector<std::string> temp_keys;
    std::vector<std::string> temp_values;

    db_proposal_ledger::get_all_data(temp_keys, temp_values);

    for (size_t i = 0; i < temp_keys.size(); ++i)
    {
        response->add_ledger_keys(base58_encode(temp_keys[i]));
        response->add_ledger_values(base58_encode(temp_values[i]));
    }
    
    temp_keys.clear();
    temp_values.clear();

    db_proposals::get_all_data(temp_keys, temp_values);

    for (size_t i = 0; i < temp_keys.size(); ++i)
    {
        response->add_proposal_keys(base58_encode(temp_keys[i]));
        response->add_proposal_values(base58_encode(temp_values[i]));
    }
    temp_keys.clear();
    temp_values.clear();


    db_proposal_wallets::get_all_data(temp_keys, temp_values);

    for (size_t i = 0; i < temp_keys.size(); ++i)
    {
        response->add_wallets_keys(base58_encode(temp_keys[i]));
        response->add_wallets_values(base58_encode(temp_values[i]));
    }
    temp_keys.clear();
    temp_values.clear();

    db_proposals_temp::get_all_data(temp_keys, temp_values);

    for (size_t i = 0; i < temp_keys.size(); ++i)
    {
        response->add_temp_keys(base58_encode(temp_keys[i]));
        response->add_temp_values(base58_encode(temp_values[i]));
    }
    temp_keys.clear();
    temp_values.clear();

    db_voted_proposals::get_all_data(temp_keys, temp_values);

    for (size_t i = 0; i < temp_keys.size(); ++i)
    {
        response->add_voted_keys(base58_encode(temp_keys[i]));
        response->add_voted_values(base58_encode(temp_values[i]));
    }
    temp_keys.clear();
    temp_values.clear();

    return grpc::Status::OK;
}
