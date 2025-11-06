// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"
#include "validator_network_service_grpc.h"

// Project-specific headers (from the current directory)
#include "db_base.h"
#include "block.h"
#include "signatures.h"
#include "test.h"
#include "validators.h"
#include "../../../db/reorg.h"
#include "threadpool.h"
#include "../../../logging/logging.h"

namespace
{

    std::string get_block_key(uint64_t height, std::string hash)
    {
        std::ostringstream oss;
        oss << std::setw(20) << std::setfill('0') << height;
        std::string paddedHeight = oss.str();
        return paddedHeight + ":" + hash;
    }

    ZeraStatus unchunk_attestation(std::vector<zera_validator::DataChunk> *responses, zera_validator::BlockAttestation *attestation)
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
        if (!attestation->ParseFromString(concatenated_data))
        {
            // Handle the error, if the data cannot be parsed
            return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "Failed to parse BlockBatch from concatenated chunks.");
        }

        return ZeraStatus();
    }

    void has_preference_response(zera_validator::BlockAttestation &request, zera_validator::BlockAttestation &current_attestation, zera_validator::BlockAttestationResponse &response)
    {
        std::string current_block_hash = current_attestation.block_hash();
        response.set_no_preference(false);

        if (request.block_hash() == current_block_hash)
        {
            response.set_support(true);
        }
        else
        {
            auto hash_vec = base58_decode(current_block_hash);
            std::string hash_str(hash_vec.begin(), hash_vec.end());
            std::string key;
            db_hash_index::get_single(hash_str, key);
            response.set_support(false);
            zera_validator::BlockHeader header;
            std::string header_data;
            zera_validator::Block block;
            std::string block_data;

            if (db_headers::get_single(key, header_data) && header.ParseFromString(header_data) && db_blocks::get_single(key, block_data) && block.ParseFromString(block_data))
            {
                block.mutable_block_header()->CopyFrom(header);
                response.mutable_supported_block()->CopyFrom(block);
            }
            else
            {
                logging::print("could not find header with key:", key);
                response.set_no_preference(true);
            }
        }

        response.mutable_validator_support()->CopyFrom(current_attestation.validator_support());

        if (current_attestation.confirmed())
        {
            response.set_confirmed(true);
        }
        else
        {
            response.set_confirmed(false);
        }
    }

    void no_preference_response(zera_validator::BlockAttestation &request, zera_validator::BlockAttestation &current_attestation, zera_validator::BlockAttestationResponse &response)
    {
        zera_validator::BlockHeader header;
        std::string header_data;
        zera_validator::Block block;
        std::string block_data;
        std::string block_hash;

        // check what block you have preference for
        // if none, send a no preference response
        // if you have a preference, send the block you support
        if (db_hash_index::get_single(std::to_string(request.block_height()), block_hash))
        {

            response.set_no_preference(false);

            if (block_hash == request.block_hash())
            {
                response.set_support(true);
            }
            else
            {
                response.set_support(false);
                if (db_headers::get_single(block_hash, header_data) && header.ParseFromString(header_data) && db_blocks::get_single(block_hash, block_data) && block.ParseFromString(block_data))
                {
                    db_blocks::get_single(block_hash, block_data);
                    block.ParseFromString(block_data);
                    block.mutable_block_header()->CopyFrom(header);
                    response.mutable_supported_block()->CopyFrom(block);
                }
                else
                {
                    response.set_no_preference(true);
                }
            }
        }
        else
        {
            response.set_no_preference(true);
        }

        if (!response.no_preference())
        {
            zera_txn::PublicKey public_key;
            public_key.set_single(ValidatorConfig::get_gen_public_key());
            std::string signature = signatures::sign_block_hash(block_hash, ValidatorConfig::get_gen_key_pair());

            zera_validator::ValidatorSupport *validator_support = response.add_validator_support();
            validator_support->mutable_public_key()->CopyFrom(public_key);
            validator_support->set_signature(signature);
        }
    }
}

grpc::Status ValidatorServiceImpl::StreamBlockAttestation(grpc::ServerContext *context, grpc::ServerReaderWriter<::zera_validator::DataChunk, ::zera_validator::DataChunk> *stream)
{
    // request data
    zera_validator::BlockAttestation *request = new zera_validator::BlockAttestation();

    zera_validator::DataChunk chunk;
    std::vector<zera_validator::DataChunk> chunks;

    // read attestation data from stream
    while (stream->Read(&chunk))
    {
        chunks.push_back(chunk);
    }

    // unchunk attestation data
    ZeraStatus status = unchunk_attestation(&chunks, request);

    if (!status.ok())
    {
        logging::print("Failed to unchunk attestation");
        delete request;
        return grpc::Status::CANCELLED;
    }

    // verify signature of request
    if (!signatures::verify_request(*request))
    {
        logging::print("Failed to verify request");
        delete request;
        return grpc::Status::CANCELLED;
    }

    // verify that this is the block that is next up to be attested
    std::string confirmed_height;
    db_confirmed_blocks::get_single(CONFIRMED_BLOCK_LATEST, confirmed_height);
    uint64_t confirmed_height_int = std::stoull(confirmed_height);

    // get your current attestation state if you have one and store values in response
    // if client is trying to attest to a block that is already confirmed
    // send them your preference for that block with confirmation
    if (request->block_height() <= confirmed_height_int)
    {
        std::string attestation_data;
        zera_validator::BlockAttestation current_attestation;
        if (db_attestation::get_single(std::to_string(request->block_height()), attestation_data) && current_attestation.ParseFromString(attestation_data))
        {
            // get your current attestation state if you have one and store values in response
            zera_validator::BlockAttestationResponse *response1 = new zera_validator::BlockAttestationResponse();
            response1->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
            has_preference_response(*request, current_attestation, *response1);
            // sign response
            signatures::sign_attestation_response(response1, ValidatorConfig::get_gen_key_pair());
            //  Start asynchronous processing of the request
            std::vector<zera_validator::DataChunk> response_chunks;
            chunkData(response1->SerializeAsString(), &response_chunks);

            for (const auto &chunk : response_chunks)
            {
                stream->Write(chunk);
            }

            delete request;
            delete response1;
            return grpc::Status::OK;
        }

        logging::print("Block already confirmed");
        delete request;
        return grpc::Status::CANCELLED;
    }

    // verify all signatures on attestation
    if (!signatures::verify_attestation(*request))
    {
        logging::print("Failed to verify attestation");
        delete request;
        return grpc::Status::CANCELLED;
    }

    // get your current attestation state if you have one and store values in response
    zera_validator::BlockAttestationResponse *response = new zera_validator::BlockAttestationResponse();
    std::string attestation_data;
    zera_validator::BlockAttestation current_attestation;
    if (db_attestation::get_single(std::to_string(request->block_height()), attestation_data) && current_attestation.ParseFromString(attestation_data))
    {
        has_preference_response(*request, current_attestation, *response);
    }
    else
    {
        no_preference_response(*request, current_attestation, *response);
    }

    // 1.
    // check latest block height and hash, must match attestation
    // if height is one less, you have no preference
    // if height is the same and hash is different, you disagree

    // set public key in response
    zera_txn::PublicKey public_key;
    public_key.set_single(ValidatorConfig::get_gen_public_key());
    response->mutable_public_key()->CopyFrom(public_key);

    // sign response
    signatures::sign_attestation_response(response, ValidatorConfig::get_gen_key_pair());

    ///////////////////////
    // process attestation
    ///////////////////////
    // 1. check lastest block and confirm block height and hash
    // 3. if you agree with the block, send a response agreeing with attestation
    // 4. check qurom of validators on this block
    // 5. store attestation in db
    // 4. send attestation to other validators

    // response data
    //  Start asynchronous processing of the request
    std::vector<zera_validator::DataChunk> response_chunks;
    chunkData(response->SerializeAsString(), &response_chunks);

    for (const auto &chunk : response_chunks)
    {
        stream->Write(chunk);
    }

    // Enqueue the task into the thread pool
    ValidatorThreadPool::enqueueTask([request, response](){ 
        ValidatorServiceImpl::ProcessBlockAttestationAsync(request, response);
        delete request;
        delete response;
        });

    // Start asynchronous processing of the request
    // std::thread asyncProcessingThread(&ValidatorServiceImpl::ProcessBlockAttestationAsync, request, response);
    // asyncProcessingThread.detach();

    return grpc::Status::OK;
}

void ValidatorServiceImpl::ProcessBlockAttestationAsync(const zera_validator::BlockAttestation *request, const zera_validator::BlockAttestationResponse *response)
{
    std::string validator_archive_data;
    uint32_t block_height = request->block_height();
    block_height -= 1;
    db_validator_archive::get_single(std::to_string(block_height), validator_archive_data);
    zera_validator::ValidatorArchive validator_archive;
    validator_archive.ParseFromString(validator_archive_data);

    // check qurom of validators on this block
    // store attestation in db
    // send attestation to other validators

    if (response->no_preference())
    {
        return;
    }

    uint256_t quorum = 0;
    zera_validator::BlockAttestation attestation;
    std::vector<std::string> validators;
    if (response->support())
    {
        // add all validators from request and response
        for (auto support : request->validator_support())
        {
            zera_validator::ValidatorSupport *validator_support = attestation.add_validator_support();
            validator_support->CopyFrom(support);
            std::string pub_key = wallets::get_public_key_string(support.public_key());
            validators.push_back(pub_key);
        }

        for (auto support : response->validator_support())
        {
            std::string pub_key = wallets::get_public_key_string(support.public_key());
            if (std::find(validators.begin(), validators.end(), pub_key) == validators.end())
            {
                zera_validator::ValidatorSupport *validator_support = attestation.add_validator_support();
                validator_support->CopyFrom(support);
                // newValidator not in validators, so add it
                validators.push_back(pub_key);
            }
        }

        attestation.set_block_hash(request->block_hash());
        attestation.set_block_height(request->block_height());

        uint256_t total_support = 0;
        uint256_t total_staked(validator_archive.total_balance());

        // check quorum of validators on the support of this block
        for (auto support : attestation.validator_support())
        {
            std::string pub_key = wallets::get_public_key_string(support.public_key());
            std::string base58_pub = base58_encode_public_key(pub_key);

            auto it = validator_archive.validators().find(base58_pub);
            if (it != validator_archive.validators().end())
            {
                uint256_t amount(it->second.total_balance());
                total_support += amount;
                // Proceed with using amount
            }
            else
            {
                std::cerr << "Validator not found in the archive." << std::endl;
                // Handle the case where the validator is not found
            }
        }

        total_support = total_support * 100;

        quorum = total_support / total_staked;
    }
    else
    {
        attestation.mutable_validator_support()->CopyFrom(response->validator_support());
        attestation.set_block_hash(response->supported_block().block_header().hash());
        attestation.set_block_height(response->supported_block().block_header().block_height());
    }

    attestation.mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
    signatures::sign_request(&attestation, ValidatorConfig::get_gen_key_pair());

    if (quorum >= ATTESTATION_QUORUM)
    {
        db_confirmed_blocks::store_single(CONFIRMED_BLOCK_LATEST, std::to_string(attestation.block_height()));
        db_confirmed_blocks::store_single(std::to_string(attestation.block_height()), attestation.block_hash());
        attestation.set_confirmed(true);
        Reorg::remove_old_backups(std::to_string(attestation.block_height()));
    }
    else
    {
        std::string ledger_data;
        zera_validator::AttestationLedger attestation_ledger;
        db_attestation_ledger::get_single(std::to_string(attestation.block_height()), ledger_data);
        attestation_ledger.ParseFromString(ledger_data);
        std::string base58_hash = base58_encode(attestation.block_hash());
        attestation_ledger.mutable_block_attestation_responses()->at(base58_hash).mutable_validator_support()->CopyFrom(attestation.validator_support());
        db_attestation_ledger::store_single(std::to_string(attestation.block_height()), attestation_ledger.SerializeAsString());
    }


    db_attestation::store_single(std::to_string(attestation.block_height()), attestation.SerializeAsString());
    // send attestation to other validators
}
