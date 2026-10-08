
#include "validator_api_service.h"

#include "db_base.h"
#include "base58.h"
#include "const.h"

namespace
{
    // Appends encoded key/value pairs until the shared response byte budget is
    // spent. Returns false once the budget is exhausted so the handler can skip
    // scanning the remaining tables entirely (the cap bounds both the response
    // size and the encode work behind it).
    bool append_within_budget(const std::vector<std::string> &keys,
                              const std::vector<std::string> &values,
                              google::protobuf::RepeatedPtrField<std::string> *out_keys,
                              google::protobuf::RepeatedPtrField<std::string> *out_values,
                              size_t &bytes_used)
    {
        for (size_t i = 0; i < keys.size(); ++i)
        {
            std::string encoded_key = base58_encode(keys[i]);
            std::string encoded_value = base58_encode(values[i]);

            if (bytes_used + encoded_key.size() + encoded_value.size() > MAX_PROPOSAL_LEDGER_RESPONSE_BYTES)
            {
                return false;
            }

            bytes_used += encoded_key.size() + encoded_value.size();
            out_keys->Add(std::move(encoded_key));
            out_values->Add(std::move(encoded_value));
        }

        return true;
    }
}

grpc::Status APIImpl::RecieveRequestProposalLedger(grpc::ServerContext *context, const zera_api::ProposalLedgerRequest *request, zera_api::ProposalLedgerResponse *response)
{
    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    size_t bytes_used = 0;
    std::vector<std::string> temp_keys;
    std::vector<std::string> temp_values;

    db_proposal_ledger::get_all_data(temp_keys, temp_values);

    if (!append_within_budget(temp_keys, temp_values, response->mutable_ledger_keys(), response->mutable_ledger_values(), bytes_used))
    {
        return grpc::Status::OK;
    }

    temp_keys.clear();
    temp_values.clear();

    db_proposals::get_all_data(temp_keys, temp_values);

    if (!append_within_budget(temp_keys, temp_values, response->mutable_proposal_keys(), response->mutable_proposal_values(), bytes_used))
    {
        return grpc::Status::OK;
    }

    temp_keys.clear();
    temp_values.clear();

    db_proposal_wallets::get_all_data(temp_keys, temp_values);

    if (!append_within_budget(temp_keys, temp_values, response->mutable_wallets_keys(), response->mutable_wallets_values(), bytes_used))
    {
        return grpc::Status::OK;
    }

    temp_keys.clear();
    temp_values.clear();

    db_proposals_temp::get_all_data(temp_keys, temp_values);

    if (!append_within_budget(temp_keys, temp_values, response->mutable_temp_keys(), response->mutable_temp_values(), bytes_used))
    {
        return grpc::Status::OK;
    }

    temp_keys.clear();
    temp_values.clear();

    db_voted_proposals::get_all_data(temp_keys, temp_values);

    append_within_budget(temp_keys, temp_values, response->mutable_voted_keys(), response->mutable_voted_values(), bytes_used);

    return grpc::Status::OK;
}
