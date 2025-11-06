// Standard library headers
#include <string>
#include <iostream>

// Third-party library headers
#include "validator.pb.h"
#include "txn.pb.h"

// Project-specific headers
#include "validator_network_client.h"
#include "validator_network_service_grpc.h"
#include "db_base.h"

void ValidatorNetworkClient::SendStreamGossip(const zera_validator::TXNGossip *request)
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

        auto writer = stubs_[x]->AsyncStreamGossip(&context, &response, &cq_, reinterpret_cast<void *>(call_num));

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

void ValidatorNetworkClient::GossipThread()
{
    zera_txn::PublicKey pub_key;
    KeyPair kp = ValidatorConfig::get_key_pair();
    std::string pub_key_str(kp.public_key.begin(), kp.public_key.end());
    pub_key.set_single(pub_key_str);

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        zera_validator::TXNGossip gossip;
        std::vector<std::string> keys;
        std::vector<std::string> values;
        db_gossip::get_all_data(keys, values);

        if(keys.size() == 0)
        {
            continue;
        }

        rocksdb::WriteBatch batch;
        int x = 0;
        for(auto key : keys)
        {
            zera_validator::TXN* txn = gossip.add_txns();
            txn->ParseFromString(values[x]);
            batch.Delete(key);
            x++;
        }
        db_gossip::store_batch(batch);

        std::vector<std::shared_ptr<grpc::Channel>> channels;
        get_channels(channels, false);

        if (channels.size() == 0)
        {
            continue;
        }

        gossip.mutable_public_key()->CopyFrom(pub_key);
        signatures::sign_txn_gossip(&gossip, kp);

        ValidatorNetworkClient client(channels);

        if(gossip.ByteSize() >= CHUNK_SIZE)
        {
            client.SendStreamGossip(&gossip);
        }
        else
        {
            client.AsyncValidatorSend(&gossip);
        }
        client.delete_calls();
    }
}