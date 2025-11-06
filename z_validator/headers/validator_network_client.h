#ifndef VALIDATOR_NETWORK_CLIENT_H
#define VALIDATOR_NETWORK_CLIENT_H

// Standard Library
#include <memory>
#include <future>
#include <random>
#include <thread>
#include <mutex>
#include <map>
#include <fstream>
#include <string>

// Third-party Libraries
#include <grpcpp/grpcpp.h>
#include <google/protobuf/empty.pb.h>
#include <google/protobuf/timestamp.pb.h>

// Project Headers
#include "txn.pb.h"
#include "validator.pb.h"
#include "validator.grpc.pb.h"
#include "db_base.h"
#include "const.h"
#include "validators.h"
#include "zera_status.h"
#include "wallets.h"
#include "../logging/logging.h"

using google::protobuf::Empty;
using google::protobuf::Timestamp;
using zera_txn::InstrumentContract;
using zera_txn::MintTXN;
using zera_txn::ValidatorRegistration;
using zera_validator::Block;
using zera_validator::BlockBatch;
using zera_validator::BlockSync;
using zera_validator::ValidatorSync;
using zera_validator::ValidatorSyncRequest;

class ValidatorNetworkClient
{
public:
	// Constructor for synchronous network calls
	ValidatorNetworkClient(std::shared_ptr<grpc::Channel> channel)
		: stub_(zera_validator::ValidatorService::NewStub(channel)) {}

	// Constructor for asynchronous network calls
	ValidatorNetworkClient(const std::vector<std::shared_ptr<grpc::Channel>> &channels)
		: stubs_(channels.size())
	{
		for (size_t x = 0; x < channels.size(); ++x)
		{
			stubs_[x] = zera_validator::ValidatorService::NewStub(channels[x]);
		}
	}

	template <typename TXType>
	static void StartGossip(const TXType *request);
	static void GossipThread();

	// Sync funcs
	grpc::Status SyncBlockchain(const BlockSync *request, std::vector<zera_validator::DataChunk> *responses);

	grpc::Status AttestationSend(const zera_validator::BlockAttestation *request);
	static void ProcessBlockAttestationAsync(std::vector<zera_validator::DataChunk> &response_chunks, std::shared_ptr<zera_validator::BlockAttestation> request);

	// Helper functions
	static bool StartSyncBlockchain(const bool seed_sync = false);
	// static void StartBroadcast(const zera_validator::Block *request);
	static void StartRegisterSeeds(const ValidatorRegistration *request);
	static void StartHeartBeat(const zera_txn::ValidatorHeartbeat *request);

	static zera_validator::NonceResponse GetNonce(const std::string &server_address)
	{

		zera_validator::NonceRequest request;
		request.set_wallet_address(wallets::generate_wallet_single(ValidatorConfig::get_public_key()));

		std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
		zera_validator::NonceResponse response;

		grpc::ClientContext context;
		std::unique_ptr<zera_validator::ValidatorService::Stub> stub(zera_validator::ValidatorService::NewStub(channel));

		// Make the RPC call
		grpc::Status status = stub->Nonce(&context, request, &response);

		// Check if the RPC call was successful
		if (status.ok())
		{
			logging::print("Nonce RPC call succeeded");
		}
		else
		{
			logging::print("Nonce RPC call failed:", ":", status.error_message());
		}

		return response;
	};
	static void CheckAttestations(std::shared_ptr<zera_validator::BlockAttestation> request);

private:
	std::map<int, grpc::ClientContext *> contexts_;
	std::map<int, grpc::Status *> statuses_;
	std::map<int, Empty *> responses_;
	std::map<int, std::vector<zera_validator::DataChunk> *> attestation_responses_;
	std::unique_ptr<zera_validator::ValidatorService::Stub> stub_;
	std::vector<std::unique_ptr<zera_validator::ValidatorService::Stub>> stubs_;
	grpc::CompletionQueue cq_;
	static std::mutex attestation_mutex;

	void delete_calls()
	{
		for (auto ctx : contexts_)
		{
			delete ctx.second;
		}
		for (auto status : statuses_)
		{
			delete status.second;
		}
		for (auto response : responses_)
		{
			delete response.second;
		}
		contexts_.clear();
		statuses_.clear();
		responses_.clear();
	}
	void delete_attestation_calls()
	{
		for (auto ctx : contexts_)
		{
			delete ctx.second;
		}
		for (auto status : statuses_)
		{
			delete status.second;
		}
		for (auto response : responses_)
		{
			delete response.second;
		}
		contexts_.clear();
		statuses_.clear();
		attestation_responses_.clear();
	}
	void SendGossip(const zera_validator::TXNGossip *request);
	void SendStreamGossip(const zera_validator::TXNGossip *request);
	void SendStreamBlock(const zera_validator::Block *block);

	void SendAttestation(const zera_validator::BlockAttestation *request);

	template <typename TXType>
	void GRPCSend(const TXType *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, Empty *response);

	void GRPCSend(const zera_validator::BlockAttestation *request, const int call_num, grpc::ClientContext *context, grpc::Status *status, zera_validator::BlockAttestationResponse *response);
	template <typename TXType>
	void ValidatorSend(const TXType *request, const int call_num)
	{
		grpc::ClientContext *context = new grpc::ClientContext();
		grpc::Status *status = new grpc::Status();
		Empty *response = new Empty;
		std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::seconds(2);
		context->set_deadline(deadline);

		try
		{
			GRPCSend(request, call_num, context, status, response);
		}
		catch (const std::exception &e)
		{
			delete context;
			delete status;
			delete response;
			logging::log("Error in GRPCSend: " + std::string(e.what()));
			return;
		}

		statuses_[call_num] = status;
		responses_[call_num] = response;
		contexts_[call_num] = context;
	}

	template <typename TXType>
	void AsyncValidatorSend(const TXType *request)
	{

		for (size_t i = 0; i < stubs_.size(); ++i)
		{
			ValidatorSend(request, i);
		}

		size_t responses_received = 0;

		// Process the CompletionQueue
		while (responses_received < stubs_.size())
		{
			void *got_tag;
			bool ok = false;

			// Add a timeout to prevent indefinite blocking
			auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(2);
			grpc::CompletionQueue::NextStatus status = cq_.AsyncNext(&got_tag, &ok, deadline);

			if (status == grpc::CompletionQueue::NextStatus::GOT_EVENT && ok)
			{
				int server_num = static_cast<int>(reinterpret_cast<size_t>(got_tag));
				auto it = statuses_.find(server_num);
				if (it == statuses_.end())
				{
					logging::print("Error: Received response for unknown server " + std::to_string(server_num));
					continue;
				}

				if (!it->second->ok())
				{
					if (it->second->error_code() == grpc::StatusCode::DEADLINE_EXCEEDED)
					{
						logging::print("Error: Call to server timed out");
					}
					else
					{
						logging::print("Error: Call to server " + std::to_string(server_num) + " failed: " + it->second->error_message());
					}
				}
				else
				{
					logging::print("Received successful response from server " + std::to_string(server_num));
				}
			}
			else if (status == grpc::CompletionQueue::NextStatus::TIMEOUT)
			{
				logging::print("AsyncValidatorSend: CompletionQueue timed out");
			}
			else
			{
				logging::print("AsyncValidatorSend: CompletionQueue failed or returned false");
			}

			++responses_received;
		}
	}

	static void get_channels(std::vector<std::shared_ptr<grpc::Channel>> &channels, bool broadcast = true)
	{
		std::vector<zera_txn::Validator> validators = get_random_validators();
		int x = 0;
		for (const auto validator : validators)
		{
			std::string pub_key = wallets::get_public_key_string(validator.public_key());
			if (pub_key != ValidatorConfig::get_public_key() && validator.online() && x < 10)
			{
				std::string host = validator.host() + ":" + validator.validator_port();
				std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(host, grpc::InsecureChannelCredentials());
				channels.push_back(channel);
				x++;
			}

			if (x >= 9)
			{
				break;
			}
		}

		if (broadcast)
		{
			// send broadcast to explorer servers
			std::ifstream file(EXPLORER_CONFIG); // Open the file
			if (file.is_open())
			{
				std::string line;
				while (std::getline(file, line))
				{
					std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(line, grpc::InsecureChannelCredentials());
					channels.push_back(channel);
				}
				file.close(); // Close the file
			}
		}
	}
};

#endif // VALIDATOR_NETWORK_CLIENT_H