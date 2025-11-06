#include "validator_network_service_grpc.h"
#include "db_base.h"

namespace
{
    ZeraStatus unchunk_gossip(std::vector<zera_validator::DataChunk> *responses, zera_validator::TXNGossip *gossip)
    {
        // Step 1: Sort the chunks based on chunk_number
        std::sort(responses->begin(), responses->end(),
                  [](const zera_validator::DataChunk &a, const zera_validator::DataChunk &b)
                  {
                      return a.chunk_number() < b.chunk_number();
                  });

        // Step 2: Concatenate the chunk_data
        std::string concatenated_data;
        for (const auto &chunk : *responses)
        {
            concatenated_data += chunk.chunk_data();
        }

        // Step 3: Deserialize into BlockBatch
        if (!gossip->ParseFromString(concatenated_data))
        {
            // Handle the error, if the data cannot be parsed
            return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "Failed to parse BlockBatch from concatenated chunks.");
        }
        return ZeraStatus();
    }

    void ProcessGossip(zera_validator::TXNGossip *gossip, std::string client_ip)
    {

        std::string public_key = wallets::get_public_key_string(gossip->public_key());

        if(!db_validator_lookup::exist(public_key))
        {
            ValidatorServiceImpl::rate_limiter.processUpdate(client_ip, true);
            return;
        }

        if(!signatures::verify_txn_gossip(gossip))
        {
            ValidatorServiceImpl::rate_limiter.processUpdate(client_ip, true);
            return;
        }

        for (auto value : gossip->txns())
        {
            switch (value.txn_type())
            {
            case zera_txn::TRANSACTION_TYPE::COIN_TYPE:
            {
                // Handle COIN_TYPE
                zera_txn::CoinTXN coin_txn;
                if (coin_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&coin_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::MINT_TYPE:
            {
                // Handle MINT_TYPE
                zera_txn::MintTXN mint_txn;
                if (mint_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&mint_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::ITEM_MINT_TYPE:
            {
                // Handle ITEM_MINT_TYPE
                zera_txn::ItemizedMintTXN item_mint_txn;
                if (item_mint_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&item_mint_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE:
            {
                // Handle CONTRACT_TXN_TYPE
                zera_txn::InstrumentContract contract_txn;
                if (contract_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&contract_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::VOTE_TYPE:
            {
                // Handle VOTE_TYPE
                zera_txn::GovernanceVote vote_txn;
                if (vote_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&vote_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::PROPOSAL_TYPE:
            {
                // Handle PROPOSAL_TYPE
                zera_txn::GovernanceProposal proposal_txn;
                if (proposal_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&proposal_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE:
            {
                // Handle SMART_CONTRACT_TYPE
                zera_txn::SmartContractTXN smart_contract_txn;
                if (smart_contract_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&smart_contract_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_EXECUTE_TYPE:
            {
                // Handle SMART_CONTRACT_EXECUTE_TYPE
                zera_txn::SmartContractExecuteTXN smart_contract_execute_txn;
                if (smart_contract_execute_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&smart_contract_execute_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE:
            {
                // Handle EXPENSE_RATIO_TYPE
                zera_txn::ExpenseRatioTXN expense_ratio_txn;
                if (expense_ratio_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&expense_ratio_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::NFT_TYPE:
            {
                // Handle NFT_TYPE
                zera_txn::NFTTXN nft_txn;
                if (nft_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&nft_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::UPDATE_CONTRACT_TYPE:
            {
                // Handle UPDATE_CONTRACT_TYPE
                zera_txn::ContractUpdateTXN update_contract_txn;
                if (update_contract_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&update_contract_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::VALIDATOR_REGISTRATION_TYPE:
            {
                // Handle VALIDATOR_REGISTRATION_TYPE
                zera_txn::ValidatorRegistration validator_registration_txn;
                if (validator_registration_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&validator_registration_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::VALIDATOR_HEARTBEAT_TYPE:
            {
                // Handle VALIDATOR_HEARTBEAT_TYPE
                zera_txn::ValidatorHeartbeat validator_heartbeat_txn;
                if (validator_heartbeat_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&validator_heartbeat_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::DELEGATED_VOTING_TYPE:
            {
                // Handle DELEGATED_VOTING_TYPE
                zera_txn::DelegatedTXN delegated_voting_txn;
                if (delegated_voting_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&delegated_voting_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::REVOKE_TYPE:
            {
                // Handle REVOKE_TYPE
                zera_txn::RevokeTXN revoke_txn;
                if (revoke_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&revoke_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::QUASH_TYPE:
            {
                // Handle QUASH_TYPE
                zera_txn::QuashTXN quash_txn;
                if (quash_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&quash_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::FAST_QUORUM_TYPE:
            {
                // Handle FAST_QUORUM_TYPE
                zera_txn::FastQuorumTXN fast_quorum_txn;
                if (fast_quorum_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&fast_quorum_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::COMPLIANCE_TYPE:
            {
                // Handle COMPLIANCE_TYPE
                zera_txn::ComplianceTXN compliance_txn;
                if (compliance_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&compliance_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::SBT_BURN_TYPE:
            {
                // Handle SBT_BURN_TYPE
                zera_txn::BurnSBTTXN sbt_burn_txn;
                if (sbt_burn_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&sbt_burn_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_INSTANTIATE_TYPE:
            {
                // Handle SMART_CONTRACT_INSTANTIATE_TYPE
                zera_txn::SmartContractInstantiateTXN smart_contract_instantiate_txn;
                if (smart_contract_instantiate_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&smart_contract_instantiate_txn, client_ip);
                }
                break;
            }
            case zera_txn::TRANSACTION_TYPE::ALLOWANCE_TYPE:
            {
                // Handle SMART_CONTRACT_INSTANTIATE_TYPE
                zera_txn::AllowanceTXN allowance_txn;
                if (allowance_txn.ParseFromString(value.serialized_txn()))
                {
                    ValidatorServiceImpl::ProcessGossipTXN(&allowance_txn, client_ip);
                }
                break;
            }
            default:
                break;
            }
        }
    }
}

template <typename TXType>
void ValidatorServiceImpl::ProcessGossipTXN(const TXType *request, std::string client_ip)
{

    // Start asynchronous processing of the request
    TXType *txn = new TXType();
    txn->CopyFrom(*request);
    if (recieved_txn_tracker::check_txn(txn->base().hash()))
    {
        logging::print("TXN already recieved");
        delete txn;
        return;
    }

    recieved_txn_tracker::add_txn(txn->base().hash());

    try
    {
        // Enqueue the task into the thread pool
        ValidatorThreadPool::enqueueTask([txn, client_ip]()
                                         { 
                ValidatorServiceImpl::ProcessRequest<TXType>(txn, client_ip);
                delete txn; });
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to enqueue task: " << e.what() << std::endl;
    }
}

grpc::Status ValidatorServiceImpl::RecieveGossip(grpc::ServerContext *context, const zera_validator::TXNGossip *request, google::protobuf::Empty *response)
{
     // Get the client's IP address
     std::string peer_info = context->peer();
     std::string client_ip;
 
     // Extract the IP address from the peer info
     size_t pos = peer_info.find(":");
     if (pos != std::string::npos)
     {
         client_ip = peer_info.substr(0, pos); // Extract everything before the first colon
     }
     else
     {
         client_ip = peer_info; // Fallback if no colon is found
     }
     
     if(!rate_limiter.canProceed(client_ip))
     {
        logging::print("Rate limit exceeded for IP: " + client_ip, true);
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
     }

    zera_validator::TXNGossip *gossip = new zera_validator::TXNGossip();
    gossip->CopyFrom(*request);

    // Enqueue the task into the thread pool
    ValidatorThreadPool::enqueueTask([gossip, client_ip](){ 
        ProcessGossip(gossip, client_ip);
        delete gossip; });

    return grpc::Status::OK;
}

grpc::Status ValidatorServiceImpl::StreamGossip(grpc::ServerContext *context, grpc::ServerReader<zera_validator::DataChunk> *reader, google::protobuf::Empty *response)
{
    // Get the client's IP address
    std::string peer_info = context->peer();
    std::string client_ip;

    // Extract the IP address from the peer info
    size_t pos = peer_info.find(":");
    if (pos != std::string::npos)
    {
        client_ip = peer_info.substr(0, pos); // Extract everything before the first colon
    }
    else
    {
        client_ip = peer_info; // Fallback if no colon is found
    }

    if(!rate_limiter.canProceed(client_ip))
    {
        std::cerr << "Rate limit exceeded for IP: " << client_ip << std::endl;
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }


    zera_validator::TXNGossip *txn = new zera_validator::TXNGossip();

    zera_validator::DataChunk chunk;
    std::vector<zera_validator::DataChunk> chunks;
    while (reader->Read(&chunk))
    {
        chunks.push_back(chunk);
    }

    ZeraStatus status = unchunk_gossip(&chunks, txn);

    if (!status.ok())
    {
        delete txn;
        return grpc::Status::CANCELLED;
    }

    // Enqueue the task into the thread pool
    ValidatorThreadPool::enqueueTask([txn, client_ip](){ 
		ProcessGossip(txn, client_ip);
		delete txn; });

    return grpc::Status::OK;
}
