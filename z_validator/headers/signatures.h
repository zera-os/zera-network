#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <sodium.h>
#include <string>
#include <vector>
#include <iostream>
#include "validator.pb.h"
#include <rocksdb/db.h>
#include "const.h"
#include "zera_status.h"
#include "zera_api.pb.h"


struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};
enum class KeyType {
    ED25519,
    ED448,
    ERROR_TYPE
};

namespace signatures {
    template <typename TXType>
    bool verify_txns(TXType& tx);

    template <typename TXType>
    bool verify_request(TXType& txn);

    template <typename TXType>
    void sign_txns(TXType* txn, KeyPair key_pair);

    template <typename TXType>
    void sign_request(TXType* txn, KeyPair key_pair);
    bool verify_transfers(zera_txn::CoinTXN txn);
    bool verify_activity_request(zera_api::ActivityRequest request);
    bool verify_multi(const std::string& public_key, const std::string& signature, const std::string& message); 
    void sign_block_broadcast(zera_validator::Block* block, KeyPair key_pair);
    void sign_block_proposer(zera_validator::Block *block, KeyPair key_pair);
    void sign_instrument_contract(zera_txn::InstrumentContract* ctxn, KeyPair key_pair);
    void sign_attestation_response(zera_validator::BlockAttestationResponse* response, KeyPair key_pair);
    std::string sign_block_hash(const std::string& block_hash, KeyPair key_pair);
    ZeraStatus verify_block_batch(zera_validator::BlockBatch& block_batch);
    ZeraStatus verify_block(zera_validator::Block& block);
    ZeraStatus verify_block_validator(zera_validator::Block& block);
    KeyType get_key_type(const std::string &public_key, bool restricted = false);
    int get_key_size(const KeyType& key_type);
    bool verify_attestation(const zera_validator::BlockAttestation& attestation);
    void sign_new_coin_txn(zera_txn::CoinTXN* txn, std::vector<KeyPair> key_pairs);
    void sign_txn_gossip(zera_validator::TXNGossip *txn, KeyPair key_pair);
    bool verify_txn_gossip(zera_validator::TXNGossip *txn);
    void sign_smart_contract_event(zera_api::SmartContractEventsResponse *event, KeyPair key_pair);
    bool verify_message(const std::string& message, const std::string& signature, const std::string& public_key);
    void sign_response(zera_api::ContractResponse *response, KeyPair key_pair);
    void sign_response(zera_api::SmartContractEventsSearchResponse *response, KeyPair key_pair);
    // std::string sign_message(const std::vector<unsigned char>& message, KeyPair key_pair);
    // bool verify_signature(const std::vector<unsigned char>& message, std::vector<unsigned char>& signature, std::vector<unsigned char>& public_key);
};
#endif 
