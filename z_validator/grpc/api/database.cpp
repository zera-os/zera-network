#include "validator_api_service.h"

#include "db_base.h"
#include "fees.h"


grpc::Status APIImpl::RecieveRequestDatabase(grpc::ServerContext *context, const zera_api::DatabaseRequest *request, zera_api::DatabaseResponse *response)
{

    if (!check_rate_limit(context))
    {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }
    
    std::string data = "";
    switch(request->type())
    {
        case zera_api::DATABASE_TYPE::CONTRACTS:
            {
                zera_txn::InstrumentContract contract;
                std::string contract_data;
                db_contracts::get_single(request->key(), contract_data);
                contract.ParseFromString(contract_data);
                data = contract.DebugString();
                break;
            }
            case zera_api::DATABASE_TYPE::HASH_INDEX:
            {
                db_hash_index::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::CONTRACT_SUPPLY:
            {
                db_contract_supply::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::SMART_CONTRACTS:
            {
                db_smart_contracts::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::VALIDATORS:
            {
                db_validators::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::BLOCKS:
            {
                db_blocks::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::HEADERS:
            {
                db_headers::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::TRANSACTIONS:
            {
                db_transactions::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::CONTRACT_ITEMS:
            {
                db_contract_items::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::VALIDATOR_UNBONDING:
            {
                db_validator_unbond::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::PROPOSAL_LEDGER:
            {
                db_proposal_ledger::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::PROPOSALS:
            {
                db_proposals::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::CURRENCY_EQUIVALENTS:
            {
                uint256_t cur_data;
                if(!zera_fees::get_cur_equiv(request->key(), cur_data))
                {
                    data = "0";
                }
                else
                {
                    data = cur_data.str();
                }
                break;
            }
            case zera_api::DATABASE_TYPE::EXPENSE_RATIO:
            {
                db_expense_ratio::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::ATTESTATION:
            {
                db_attestation::get_single(request->key(), data);
                break;
            }
            case zera_api::DATABASE_TYPE::CONFIRMED_BLOCKS:
            {
                db_confirmed_blocks::get_single(request->key(), data);
                break;
            }
        default:
            return grpc::Status(grpc::NOT_FOUND, "Invalid Database Type");
    }


    if(data == "")
    {
        return grpc::Status(grpc::NOT_FOUND, "No data found for this key");
    }

    response->set_value(data);

    return grpc::Status::OK;
}