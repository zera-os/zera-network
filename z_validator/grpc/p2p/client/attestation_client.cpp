// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"

// Project-specific headers
#include "validator_network_client.h"
#include "db_base.h"
// #include "db_blocks.h"
// #include "db_headers.h"
// #include "db_wallets.h"
// #include "db_hash_index.h"
// #include "db_contracts.h"
#include "block.h"
#include "signatures.h"
#include "test.h"
#include "const.h"
#include "validators.h"
#include "base58.h"
#include "../block_process/block_process.h"
#include "../../../db/reorg.h"
#include "threadpool.h"
#include "../../../logging/logging.h"
#include "validator_api_client.h"

namespace
{
    void set_attestation(const zera_validator::AttestationLedger &ledger, std::shared_ptr<zera_validator::BlockAttestation> request, const std::vector<std::pair<std::string, uint256_t>> block_support_vec, bool confirmed)
    {
        // set parameters of attestation
        // store attestation in database
        zera_validator::BlockAttestation attestation;
        attestation.set_block_hash(block_support_vec[0].first);
        attestation.set_block_height(request->block_height());
        attestation.mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());

        for (auto support : ledger.block_attestation_responses().at(block_support_vec[0].first).validator_support())
        {
            attestation.add_validator_support()->CopyFrom(support);
        }

        attestation.set_confirmed(confirmed);

        signatures::sign_request(&attestation, ValidatorConfig::get_gen_key_pair());

        db_attestation::store_single(std::to_string(request->block_height()), attestation.SerializeAsString());
    }

    uint256_t get_quorum(const zera_validator::ValidatorArchive &archive, const uint256_t &block_support_orig)
    {
        uint256_t total_staked(archive.total_balance());
        uint256_t block_support = block_support_orig * 100;
        uint256_t quorum = block_support / total_staked;

        return quorum;
    }

    void get_blocks_total_support(zera_validator::AttestationLedger &ledger, std::map<std::string, uint256_t> &block_support, const zera_validator::ValidatorArchive &archive)
    {
        int x = 0;
        int y = 0;
        std::vector<int> remove_x;
        std::vector<int> remove_y;

        for (auto block_attestation : ledger.block_attestation_responses())
        {
            uint256_t support_amount = 0;
            for (auto support : block_attestation.second.validator_support())
            {
                std::string public_key = wallets::get_public_key_string(support.public_key());

                uint256_t validator_value = 0;

                std::string base58_pub = base58_encode_public_key(public_key);
                auto it = archive.validators().find(base58_pub);

                if (it != archive.validators().end())
                {
                    validator_value = boost::multiprecision::uint256_t(it->second.total_balance());
                    // Use total_balance as needed
                }
                else
                {
                    remove_y.push_back(y);
                    remove_x.push_back(x);
                }

                support_amount += validator_value;
                y++;
            }

            block_support.insert({block_attestation.first, support_amount});
            x++;
        }
    }
    void remove_duplicate_validators(zera_validator::AttestationLedger &ledger)
    {
        std::map<std::string, google::protobuf::Timestamp> duplicate_validators; // current time validator entered attested block (if timestamp is greater than current, replace to new block hash)
        std::map<std::string, std::string> duplicate_validators_hash;            //
        std::map<std::string, int> duplicate_validators_index;

        std::vector<std::pair<std::string, int>> remove_support; // block_hash, index

        for (auto attestation : ledger.block_attestation_responses())
        {

            int y = 0;
            for (auto support : attestation.second.validator_support())
            {
                std::string public_key = wallets::get_public_key_string(support.public_key());
                if (duplicate_validators.find(public_key) == duplicate_validators.end())
                {

                    duplicate_validators.insert({public_key, support.timestamp()});
                    duplicate_validators_hash.insert({public_key, attestation.first});
                    duplicate_validators_index.insert({public_key, y});
                }
                else
                {
                    if (support.timestamp().seconds() > duplicate_validators[public_key].seconds())
                    {
                        remove_support.push_back({duplicate_validators_hash[public_key], duplicate_validators_index[public_key]});
                        duplicate_validators[public_key] = support.timestamp();
                        duplicate_validators_hash[public_key] = attestation.first;
                        duplicate_validators_index[public_key] = y;
                    }
                    else
                    {
                        remove_support.push_back({attestation.first, y});
                    }
                }
                y++;
            }
        }

        // Sort remove_support in reverse order
        std::sort(remove_support.begin(), remove_support.end(), [](const std::pair<std::string, int> &a, const std::pair<std::string, int> &b)
                  { return a.second > b.second; });

        for (auto remove : remove_support)
        {
            std::string base58_hash = base58_encode(remove.first);
            auto response = ledger.mutable_block_attestation_responses()->at(base58_hash);
            response.mutable_validator_support()->erase(response.mutable_validator_support()->begin() + remove.second);
        }
    }
    void chunk_data(const std::string &data, std::vector<zera_validator::DataChunk> *responses)
    {
        size_t dataSize = data.size();
        int x = 0;
        for (size_t i = 0; i < dataSize; i += CHUNK_SIZE)
        {
            zera_validator::DataChunk chunk;
            chunk.set_chunk_data(data.substr(i, std::min(CHUNK_SIZE, dataSize - i)));
            chunk.set_chunk_number(x);
            responses->push_back(chunk);
            x++;
        }
        if (!responses->empty())
        {
            responses->at(0).set_total_chunks(static_cast<int>(responses->size()));
        }
    }

    ZeraStatus unchunk_block_attestation(std::vector<zera_validator::DataChunk> &responses, zera_validator::BlockAttestationResponse *response)
    {
        // Step 1: Sort the chunks based on chunk_number
        std::sort(responses.begin(), responses.end(),
                  [](const zera_validator::DataChunk &a, const zera_validator::DataChunk &b)
                  {
                      return a.chunk_number() < b.chunk_number();
                  });

        // Step 2: Concatenate the chunk_data
        std::string concatenated_data;
        for (const auto &chunk : responses)
        {
            concatenated_data += chunk.chunk_data();
        }

        // Step 3: Deserialize into BlockBatch
        if (!response->ParseFromString(concatenated_data))
        {
            // Handle the error, if the data cannot be parsed
            return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "Failed to parse BlockBatch from concatenated chunks.");
        }
        return ZeraStatus();
    }

    void process_response_chunks(std::shared_ptr<std::vector<std::vector<zera_validator::DataChunk>>> all_data, std::shared_ptr<zera_validator::BlockAttestation> request)
    {
        for (auto &chunks : *all_data)
        {
            ValidatorNetworkClient::ProcessBlockAttestationAsync(chunks, request);
        }

        ValidatorNetworkClient::CheckAttestations(request);
    }
}

std::mutex ValidatorNetworkClient::attestation_mutex;

void ValidatorNetworkClient::CheckAttestations(std::shared_ptr<zera_validator::BlockAttestation> request)
{
    std::lock_guard<std::mutex> lock(attestation_mutex);
    std::string block_height = std::to_string(request->block_height());
    std::string ledger_data;
    zera_validator::AttestationLedger ledger;

    db_attestation_ledger::get_single(block_height, ledger_data);
    ledger.ParseFromString(ledger_data);

    std::string archive_data;
    zera_validator::ValidatorArchive archive;
    uint32_t previous_block_height = request->block_height() - 1;
    db_validator_archive::get_single(std::to_string(previous_block_height), archive_data);
    archive.ParseFromString(archive_data);

    remove_duplicate_validators(ledger);

    std::map<std::string, uint256_t> block_support; // key = block_hash, value = support_amount

    get_blocks_total_support(ledger, block_support, archive);

    if (block_support.size() <= 0)
    {
        logging::print("No support for block 1");
        return;
    }

    std::vector<std::pair<std::string, uint256_t>> block_support_vec;

    // Copy map to vector of pairs
    for (auto support : block_support)
    {
        block_support_vec.push_back({support.first, support.second});
    }

    if (block_support_vec.size() <= 0)
    {
        logging::print("No support for block");
        return;
    }

    // Sort vector in descending order by value
    std::sort(block_support_vec.begin(), block_support_vec.end(), [](const std::pair<std::string, uint256_t> &a, const std::pair<std::string, uint256_t> &b)
              { return a.second > b.second; });

    // get quorum of supported block
    uint256_t quorum = get_quorum(archive, block_support_vec[0].second);

    // check if this is a confirmed block
    bool confirmed = quorum >= ATTESTATION_QUORUM;
    std::string attesteation_data;
    db_attestation::get_single(std::to_string(request->block_height()), attesteation_data);
    zera_validator::BlockAttestation attestation;
    attestation.ParseFromString(attesteation_data);
    // set and store new preffered attestation
    set_attestation(ledger, request, block_support_vec, confirmed);

    //  if this is a confirmed block and it is different then your current chain, reorg and process
    //    if this block ends up not being valid go to second highest support block (this should not happen)
    //  else store block hash in confirmed blocks database
    std::string hash = base58_encode(request->block_hash());
    logging::print("**********CHECK ATTESTATIONS**********");
    logging::print("my support hash:", base58_encode(attestation.block_hash()));
    logging::print("block height:", std::to_string(request->block_height()));
    logging::print("block hash:", block_support_vec[0].first);
    logging::print("confirmed:", std::to_string(confirmed));
    logging::print("quorum:", quorum.str());
    logging::print("request block hash:", hash);
    logging::print("*************************************");

    if (confirmed)
    {
        std::string my_hash = base58_encode(attestation.block_hash());

        if (my_hash != block_support_vec[0].first)
        {
            logging::print("ATTEMPTING REORG");
            Reorg::reorg_blockchain();
            ValidatorAPIClient::ClearPendingEventsForBlock(request->block_height());
        }
        else
        {
            logging::print("storing confirmed block");
            // Store block hash in confirmed blocks database
            db_confirmed_blocks::store_single(CONFIRMED_BLOCK_LATEST, std::to_string(request->block_height()));
            db_confirmed_blocks::store_single(std::to_string(request->block_height()), request->block_hash());
            Reorg::remove_old_backups(std::to_string(request->block_height()));
            ValidatorAPIClient::SendPendingEventsForBlock(request->block_height());
        }
    }
}

void ValidatorNetworkClient::SendAttestation(const zera_validator::BlockAttestation *request)
{

    auto request_copy = std::make_shared<zera_validator::BlockAttestation>();
    request_copy->CopyFrom(*request);
    auto all_data = std::make_shared<std::vector<std::vector<zera_validator::DataChunk>>>();

    int call_num = 1;
    for (size_t x = 0; x < stubs_.size(); ++x)
    {
        grpc::ClientContext context;
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(2);
        context.set_deadline(deadline);

        std::vector<zera_validator::DataChunk> chunks;
        chunk_data(request->SerializeAsString(), &chunks);

        auto stream = stubs_[x]->AsyncStreamBlockAttestation(&context, &cq_, reinterpret_cast<void *>(call_num));

        void *got_tag_writer;
        bool ok_writer = false;
        cq_.Next(&got_tag_writer, &ok_writer);

        // Send each chunk
        for (size_t i = 0; i < chunks.size(); ++i)
        {
            call_num++;
            stream->Write(chunks[i], reinterpret_cast<void *>(call_num));
            // Wait for the previous Write operation to complete.
            void *got_tag;
            bool ok = false;
            cq_.Next(&got_tag, &ok);
        }

        call_num++;
        // Signal the end of Writes and wait for the server to acknowledge.
        stream->WritesDone(reinterpret_cast<void *>(call_num));
        void *got_tag;
        bool ok = false;
        cq_.Next(&got_tag, &ok);

        call_num++;
        // Read responses from the server
        zera_validator::DataChunk response_chunk;
        std::vector<zera_validator::DataChunk> *response_chunks = new std::vector<zera_validator::DataChunk>();
        stream->Read(&response_chunk, reinterpret_cast<void *>(call_num));

        void *got_tag_reader;
        bool ok_reader = false;
        bool failed = false;
        while (cq_.Next(&got_tag_reader, &ok_reader))
        {
            if (!ok_reader || got_tag_reader != reinterpret_cast<void *>(call_num))
            {
                failed = true;
                break;
            }

            response_chunks->push_back(response_chunk);
            call_num++;
            // Perform the read operation
            stream->Read(&response_chunk, reinterpret_cast<void *>(call_num));
            // You can add additional logic here to handle the read operation if needed
        }

        if (failed && response_chunks->size() <= 0)
        {
            // Ensure the stream is closed properly
            grpc::Status status;
            stream->Finish(&status, reinterpret_cast<void *>(call_num));
            if (!status.ok())
            {
                if (status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED)
                {
                    std::cerr << "Error: Deadline exceeded while reading data." << std::endl;
                }
                else
                {
                    std::cerr << "Error: Stream finish failed with status: " << status.error_message() << std::endl;
                }
            }
            break;
        }
        all_data->push_back(*response_chunks);
        call_num++;

        // Finish the RPC.
        grpc::Status status;
        stream->Finish(&status, reinterpret_cast<void *>(call_num));

        if (!status.ok())
        {
            if (status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED)
            {
                std::cerr << "Error: Deadline exceeded for validator " << x << std::endl;
            }
            else
            {
                std::cerr << "Error: Stream finish failed with status: " << status.error_message() << std::endl;
            }
            break;
        }

        if (!cq_.Next(&got_tag, &ok))
        {
            std::cerr << "Error: Completion queue next operation failed." << std::endl;
        }
        else
        {
            if (ok && got_tag == reinterpret_cast<void *>(call_num) && status.ok())
            {
                logging::print("RPC finished successfully.");
            }
            else
            {
                std::cerr << "Error: RPC failed with status: " << status.error_message() << std::endl;
            }
        }
    }


    // Enqueue the task into the thread pool
    ValidatorThreadPool::enqueueTask([all_data, request_copy]()
                     { process_response_chunks(all_data, request_copy); });

    // Process response_chunk...
    // std::thread asyncProcessingThread(&process_response_chunks, all_data, request_copy);
    // asyncProcessingThread.detach();
}

// Process block attestation data asynchronously
// 1. Verify the attestation data signature
// 2. Store the attestation data in the database
// 3. Check support values of all attestations you currently ahve
// 4. If support is over 1/2 of validators, add block to confirmed blocks
// 5. If a new block has more support than current, validate block and adopt it
void ValidatorNetworkClient::ProcessBlockAttestationAsync(std::vector<zera_validator::DataChunk> &response_chunks, std::shared_ptr<zera_validator::BlockAttestation> request)
{
    // unchunk attestation data
    zera_validator::BlockAttestationResponse response;
    ZeraStatus status = unchunk_block_attestation(response_chunks, &response);

    if (!status.ok())
    {
        logging::print("Failed to unchunk attestation data.");
    }

    // 1. Verify the attestation data signature
    if (!signatures::verify_request(response))
    {
        logging::print("ProcessBlockAttestationAsync: Signature verification failed.");
        return;
    }

    if (response.no_preference())
    {
        logging::print("Sender had no preference for block.");
        return;
    }
    std::string block_height = std::to_string(request->block_height());
    std::string ledger_data;
    zera_validator::AttestationLedger ledger;

    // lock mutex, only one instance of this function can access the database at once
    std::lock_guard<std::mutex> lock(attestation_mutex);

    // 2. Store the attestation data in the database
    db_attestation_ledger::get_single(block_height, ledger_data);
    ledger.ParseFromString(ledger_data);

    std::string base58_hash;
    if (response.support())
    {
        base58_hash = base58_encode(request->block_hash());
    }
    else
    {
        base58_hash = base58_encode(response.supported_block().block_header().hash());
    }
    auto it = ledger.mutable_block_attestation_responses()->find(base58_hash);

    for (auto support : ledger.block_attestation_responses())
    {

        if (it != ledger.block_attestation_responses().end())
        {
            // The key exists in the map
            auto &block_ledger = it->second;
            std::set<std::string> validators;
            for (auto support : block_ledger.validator_support())
            {
                std::string validator_key = wallets::get_public_key_string(support.public_key());

                if (validators.find(validator_key) == validators.end())
                {
                    validators.insert(validator_key);
                }
            }

            for (auto support : response.validator_support())
            {
                std::string validator_key = wallets::get_public_key_string(support.public_key());

                if (validators.find(validator_key) == validators.end())
                {
                    validators.insert(validator_key);
                    block_ledger.add_validator_support()->CopyFrom(support);
                }
            }

            // Use value...
        }
        else
        {
            logging::print("did not find hash:", base58_hash);
            zera_validator::AttestationSupport support;
            support.mutable_validator_support()->CopyFrom(response.validator_support());
            support.mutable_supported_block()->CopyFrom(response.supported_block());
            // The key does not exist in the map
            // Handle the case...
            (*ledger.mutable_block_attestation_responses())[base58_hash] = support;
        }

        db_attestation_ledger::store_single(block_height, ledger.SerializeAsString());
    }
}