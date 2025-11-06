// Standard library headers
#include <string>
#include <iostream>
#include <iomanip>
#include <random>

// Third-party library headers
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/empty.pb.h>
#include <grpcpp/grpcpp.h>
#include <rocksdb/db.h>

// Project-specific headers
#include "validator_network_service_grpc.h"
#include "txn.pb.h"
#include "validator.pb.h"
#include "validator.grpc.pb.h"
#include "signatures.h"
#include "block.h"
#include "hashing.h"
#include "db_base.h"
#include "validator_network_client.h"
#include "zera_status.h"
#include "verify_process_txn.h"
#include "threadpool.h"
#include "../../../logging/logging.h"

using namespace zera_validator;
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

namespace
{
	ZeraStatus unchunk_block(std::vector<zera_validator::DataChunk> *responses, zera_validator::Block *block)
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
		if (!block->ParseFromString(concatenated_data))
		{
			// Handle the error, if the data cannot be parsed
			return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "Failed to parse BlockBatch from concatenated chunks.");
		}
		return ZeraStatus();
	}

}

grpc::Status ValidatorServiceImpl::Broadcast(grpc::ServerContext *context, const Block *request, google::protobuf::Empty *response)
{
	Block *txn = new Block();
	txn->CopyFrom(*request);

	// Enqueue the task into the thread pool
	ValidatorThreadPool::enqueueTask([txn](){ 
		ValidatorServiceImpl::ProcessBroadcastAsync(txn); 
		delete txn;
		});

	return grpc::Status::OK;
}

grpc::Status ValidatorServiceImpl::StreamBroadcast(grpc::ServerContext *context, grpc::ServerReader<zera_validator::DataChunk> *reader, google::protobuf::Empty *response)
{
	Block *txn = new Block();

	zera_validator::DataChunk chunk;
	std::vector<zera_validator::DataChunk> chunks;
	while (reader->Read(&chunk))
	{
		chunks.push_back(chunk);
	}

	ZeraStatus status = unchunk_block(&chunks, txn);

	if (!status.ok())
	{
		delete txn;
		return grpc::Status::CANCELLED;
	}

	// Enqueue the task into the thread pool
	ValidatorThreadPool::enqueueTask([txn](){ 
		ValidatorServiceImpl::ProcessBroadcastAsync(txn);
		delete txn;
		});

	return grpc::Status::OK;
}

void ValidatorServiceImpl::ProcessBroadcastAsync(const Block *request)
{
	Block *block = new Block();
	block->CopyFrom(*request);
	logging::print("ProcessBroadcastAsync");

	rocksdb::WriteBatch wallet_batch;
	ZeraStatus status = vp_broadcast::verify_broadcast_block(block);
	if (!status.ok())
	{
		status.prepend_message("broadcast_grpc.cpp: ProcessBroadcastAsync");
		delete block;
		return;
	}


	signatures::sign_block_broadcast(block, ValidatorConfig::get_gen_key_pair());

	Block* block_copy = new Block();
	block_copy->CopyFrom(*block);
	
	ValidatorThreadPool::enqueueTask([block_copy](){ 
        ValidatorNetworkClient::StartGossip(block_copy);
        delete block_copy; 
    });
            
	delete block;
}
