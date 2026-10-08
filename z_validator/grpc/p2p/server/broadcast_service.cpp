// Standard library headers
#include <string>
#include <iostream>
#include <iomanip>
#include <random>
#include <chrono>

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

	// These chunks are buffered in full BEFORE the block is parsed/validated, so cap
	// total bytes, chunk count, and wall-clock time INSIDE the loop. Otherwise any peer
	// that can reach the P2P port can stream data indefinitely (or trickle it slowloris
	// style) and force unbounded allocation before validation runs (CWE-400).
	size_t total_bytes = 0;
	const auto stream_deadline = std::chrono::steady_clock::now() +
								 std::chrono::seconds(INBOUND_STREAM_DEADLINE_SECONDS);
	while (reader->Read(&chunk))
	{
		total_bytes += chunk.chunk_data().size();

		if (total_bytes > MAX_BROADCAST_STREAM_BYTES ||
			chunks.size() >= static_cast<size_t>(MAX_INBOUND_STREAM_CHUNKS) ||
			std::chrono::steady_clock::now() > stream_deadline)
		{
			logging::print("StreamBroadcast: peer exceeded stream limits, aborting. bytes: " +
							   std::to_string(total_bytes) + " chunks: " + std::to_string(chunks.size() + 1),
						   false);
			delete txn;
			return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "broadcast stream exceeded size/chunk/time limits");
		}

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
	logging::print("ProcessBroadcastAsync", true);

	rocksdb::WriteBatch wallet_batch;

	if(db_hash_index::exist(block->block_header().hash()))
	{
		delete block;
		return;
	}

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
