#include "attestation_process.h"
#include "db_base.h"
#include "validators.h"
#include "validator_network_client.h"
#include "signatures.h"
#include "threadpool.h"

namespace
{
    void archive_attestation(const zera_validator::BlockAttestation *request)
    {
        std::string block_height = std::to_string(request->block_height());
        std::string ledger_data;
        db_attestation_ledger::get_single(block_height, ledger_data);

        zera_validator::AttestationLedger ledger;
        ledger.ParseFromString(ledger_data);

        zera_validator::AttestationSupport att_support;

        att_support.mutable_validator_support()->CopyFrom(request->validator_support());
        std::string base58_hash = base58_encode(request->block_hash());
        (*ledger.mutable_block_attestation_responses())[base58_hash] = att_support;

        db_attestation_ledger::store_single(block_height, ledger.SerializeAsString());
        db_attestation::store_single(block_height, request->SerializeAsString());
    }
}
void AttestationProcess::CreateAttestation(zera_validator::Block *block)
{

    logging::print("Creating Attestation");
    zera_validator::BlockAttestation *attestation = new zera_validator::BlockAttestation();
    std::string public_key = ValidatorConfig::get_gen_public_key();
    attestation->set_block_hash(block->block_header().hash());
    attestation->set_block_height(block->block_header().block_height());
    attestation->mutable_public_key()->set_single(public_key);
    attestation->set_previous_block_hash(block->block_header().previous_block_hash());

    zera_validator::ValidatorSupport *support = attestation->add_validator_support();

    support->mutable_public_key()->set_single(public_key);

    std::string block_signature = signatures::sign_block_hash(attestation->block_hash(), ValidatorConfig::get_gen_key_pair());
    support->set_signature(block_signature);
    support->mutable_timestamp()->set_seconds(std::time(nullptr));

    signatures::sign_request(attestation, ValidatorConfig::get_gen_key_pair());

    archive_attestation(attestation);
    
    ValidatorThreadPool::enqueueTask([attestation](){ 
        ValidatorNetworkClient::StartGossip(attestation);
        delete attestation;
        });
}