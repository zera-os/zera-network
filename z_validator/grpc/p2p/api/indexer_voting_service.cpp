// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"
#include "validator_network_service_grpc.h"

// Project-specific headers (from the current directory)
#include "db_base.h"

grpc::Status ValidatorServiceImpl::IndexerVoting(grpc::ServerContext *context, const zera_validator::IndexerVotingRequest *request, zera_validator::IndexerVotingResponse *response)
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

    if (!rate_limiter.canProceed(client_ip))
    {
        std::cerr << "Rate limit exceeded for IP: " << client_ip << std::endl;
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded");
    }

    rate_limiter.processUpdate(client_ip, false);
    
    std::string proposal_data;
    zera_validator::Proposal proposal;

    if(!db_proposals::get_single(request->proposal_id(), proposal_data)){
        return grpc::Status(grpc::StatusCode::CANCELLED, "Proposal does not exist.");
    }
    if(!proposal.ParseFromString(proposal_data)){
        return grpc::Status(grpc::StatusCode::CANCELLED, "Failed to parse Proposal. (this should never happen)");
    }
    for(auto yes_vote : proposal.yes()){
        zera_validator::IndexerVote* vote = response->add_support();
        vote->set_amount(yes_vote.second);
        vote->set_contract_id(yes_vote.first);
    }
    for(auto no_vote : proposal.no()){
        zera_validator::IndexerVote* vote = response->add_against();
        vote->set_amount(no_vote.second);
        vote->set_contract_id(no_vote.first);
    }
    for(auto options : proposal.options()){
        zera_validator::IndexerOption* option = response->add_options();
        option->set_index(options.first);
        for(auto option_vote : options.second.vote()){
            zera_validator::IndexerVote* vote = option->add_votes();
            vote->set_amount(option_vote.second);
            vote->set_contract_id(option_vote.first);
        }
    }

    response->set_stage(proposal.stage());
    return grpc::Status::OK;
}