#include "validator_network_client.h"
#include "validator_network_service_grpc.h"
#include "const.h"
#include <exception>
#include "../../../logging/logging.h"


void ValidatorNetworkClient::SendStreamBlock(const zera_validator::Block *request)
{
    int call_num = 1;
    for (size_t x = 0; x < stubs_.size(); ++x)
    {
        grpc::ClientContext context;
        Empty response;

        std::vector<zera_validator::DataChunk> chunks;
        ValidatorServiceImpl::chunkData(request->SerializeAsString(), &chunks);

        // Set a deadline of 5 seconds for the gRPC call
        std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
        context.set_deadline(deadline);

        auto writer = stubs_[x]->AsyncStreamBroadcast(&context, &response, &cq_, reinterpret_cast<void *>(call_num));

        void *got_tag_writer;
        bool ok_writer = false;
        cq_.Next(&got_tag_writer, &ok_writer);

        // Send each chunk
        for (size_t i = 0; i < chunks.size(); ++i)
        {
            call_num++;
            writer->Write(chunks[i], reinterpret_cast<void *>(call_num));
            // Wait for the previous Write operation to complete.
            void *got_tag;
            bool ok = false;
            cq_.Next(&got_tag, &ok);
        }
        call_num++;
        // Signal the end of Writes and wait for the server to acknowledge.
        writer->WritesDone(reinterpret_cast<void *>(call_num));
        void *got_tag;
        bool ok = false;
        cq_.Next(&got_tag, &ok);

        call_num++;
        // Finish the RPC.
        grpc::Status status;
        writer->Finish(&status, reinterpret_cast<void *>(call_num));
        cq_.Next(&got_tag, &ok);
        if (ok && got_tag == reinterpret_cast<void *>(call_num) && status.ok())
        {
        }
        else
        {
            std::cerr << "RPC failed: " << status.error_message() << std::endl;
        }
    }
}

void ValidatorNetworkClient::StartRegisterSeeds(const ValidatorRegistration *request)
{
    std::vector<std::shared_ptr<grpc::Channel>> channels;
    ValidatorRegistration *registration_request = new ValidatorRegistration();
    registration_request->CopyFrom(*request);

    for (auto seed : ValidatorConfig::get_seed_validators())
    {
        logging::print("seed validator:", seed);
        std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(seed, grpc::InsecureChannelCredentials());
        channels.push_back(channel);
    }
    ValidatorNetworkClient client(channels);
    client.AsyncValidatorSend(request);
    client.delete_calls();
    delete registration_request;
}

// Public function to start gossip protocal
template <typename TXType>
void ValidatorNetworkClient::StartGossip(const TXType *request)
{
    TXType *copy = new TXType();
    copy->CopyFrom(*request);
    std::vector<std::shared_ptr<grpc::Channel>> channels;
    get_channels(channels, false);
    if (channels.size() == 0)
    {
        delete copy;
        return;
    }

    ValidatorNetworkClient client(channels);
    client.AsyncValidatorSend(copy);
    client.delete_calls();
    delete copy;
}
template void ValidatorNetworkClient::StartGossip<zera_txn::MintTXN>(const zera_txn::MintTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::ItemizedMintTXN>(const zera_txn::ItemizedMintTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::ValidatorRegistration>(const zera_txn::ValidatorRegistration *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::NFTTXN>(const zera_txn::NFTTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::QuashTXN>(const zera_txn::QuashTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::CoinTXN>(const zera_txn::CoinTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *request);
template void ValidatorNetworkClient::StartGossip<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *request);

template <>
void ValidatorNetworkClient::StartGossip<zera_validator::Block>(const zera_validator::Block *request)
{
    zera_validator::Block *block = new zera_validator::Block();
    block->CopyFrom(*request);
    signatures::sign_block_broadcast(block, ValidatorConfig::get_gen_key_pair());

    std::vector<std::shared_ptr<grpc::Channel>> channels;
    get_channels(channels);

    ValidatorNetworkClient client(channels);

    if (channels.size() == 0)
    {
        delete block;
        return;
    }

    if (request->ByteSize() > static_cast<int>(CHUNK_SIZE))
    {
        client.SendStreamBlock(block);
    }
    else
    {
        client.AsyncValidatorSend(block);
    }
    client.delete_calls();
    delete block;
}

template <>
void ValidatorNetworkClient::StartGossip<zera_validator::BlockAttestation>(const zera_validator::BlockAttestation *request)
{
    zera_validator::BlockAttestation *copy = new zera_validator::BlockAttestation();
    copy->CopyFrom(*request);
    std::vector<std::shared_ptr<grpc::Channel>> channels;

    get_channels(channels, false);

    ValidatorNetworkClient client(channels);
    client.SendAttestation(copy);
    client.delete_attestation_calls();
    delete copy;
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::MintTXN>(const zera_txn::MintTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorMint(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::NFTTXN>(const zera_txn::NFTTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorNFT(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::ItemizedMintTXN>(const zera_txn::ItemizedMintTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorItemMint(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::InstrumentContract>(const zera_txn::InstrumentContract *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorContract(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::GovernanceProposal>(const zera_txn::GovernanceProposal *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorGovernProposal(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::GovernanceVote>(const zera_txn::GovernanceVote *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorGovernVote(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorSmartContract(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::SmartContractExecuteTXN>(const zera_txn::SmartContractExecuteTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorSmartContractExecute(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorExpenseRatio(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::ValidatorRegistration>(const zera_txn::ValidatorRegistration *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorRegistration(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_validator::Block>(const zera_validator::Block *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncBroadcast(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::ContractUpdateTXN>(const zera_txn::ContractUpdateTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorContractUpdate(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}

template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::ValidatorHeartbeat>(const zera_txn::ValidatorHeartbeat *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorHeartbeat(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::DelegatedTXN>(const zera_txn::DelegatedTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorDelegatedVoting(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::QuashTXN>(const zera_txn::QuashTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorQuash(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorRevoke(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::FastQuorumTXN>(const zera_txn::FastQuorumTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorFastQuorum(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorCompliance(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorBurnSBT(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::CoinTXN>(const zera_txn::CoinTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorCoin(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::SmartContractInstantiateTXN>(const zera_txn::SmartContractInstantiateTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorSmartContractInstantiate(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_validator::TXNGossip>(const zera_validator::TXNGossip *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncGossip(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
template <>
void ValidatorNetworkClient::GRPCSend<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response)
{
    std::unique_ptr<grpc::ClientAsyncResponseReader<Empty>> rpc(
        stubs_[call_num]->AsyncValidatorAllowance(context, *request, &cq_));
    rpc->Finish(response, status, reinterpret_cast<void *>(static_cast<size_t>(call_num)));
}
