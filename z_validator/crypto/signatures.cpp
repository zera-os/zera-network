// Standard library headers
#include <vector>
#include <stdexcept>
#include <iostream>
#include <regex>
#include <sstream>

// Third-party library headers
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>

// Project-specific headers
#include "signatures.h"
#include "validator.pb.h"
// #include "db_wallets.h"
#include "db_base.h"
#include "test.h"
#include "wallets.h"
#include "wallet.pb.h"
#include "base58.h"
#include "hex_conversion.h"
#include "validators.h"
#include "../logging/logging.h"
#include "zera_api.pb.h"

namespace
{

    KeyType extract_public_key(std::vector<uint8_t> &public_key, std::vector<uint8_t> &public_key_extract)
    {

        std::string pub_key_str(public_key.begin(), public_key.end());

        KeyType key_type = signatures::get_key_type(pub_key_str);

        if (pub_key_str.length() < 4 || key_type == KeyType::ERROR_TYPE)
        {
            return KeyType::ERROR_TYPE;
        }

        int key_size = 0;

        if (key_type == KeyType::ED25519)
        {
            key_size = 32;
        }
        else if (key_type == KeyType::ED448)
        {
            key_size = 57;
        }
        else
        {
            return KeyType::ERROR_TYPE;
        }

        std::string pub_key_extract_str = pub_key_str.substr(pub_key_str.size() - key_size);

        public_key_extract.assign(pub_key_extract_str.begin(), pub_key_extract_str.end());

        return key_type;
    }

    // ##################################################
    //                 BASE FUNCTIONS
    // ##################################################
    //  Function to sign a message using either Ed25519 with Sodium or Ed448 with OpenSSL
    std::string sign_message(const std::vector<unsigned char> &message, KeyPair key_pair)
    {

        std::vector<uint8_t> pub_key_extract;
        KeyType key_type = extract_public_key(key_pair.public_key, pub_key_extract);
        std::vector<uint8_t> private_key = key_pair.private_key;
        std::vector<uint8_t> signature; // Create a vector to hold the signature

        if (key_type == KeyType::ED25519) // If the key type is Ed25519
        {
            // Use the sodium crypto_sign_detached function to sign the message
            signature = std::vector<uint8_t>(crypto_sign_BYTES); // Allocate space for the signature
            if (crypto_sign_detached(signature.data(), nullptr, message.data(), message.size(), private_key.data()) != 0)
            {
                // If the signature generation fails, throw an error
                std::string sig_str(signature.begin(), signature.end());
                return sig_str;
            }
            std::string sig_str(signature.begin(), signature.end());
            // Return the signature
            return sig_str;
        }
        else if (key_type == KeyType::ERROR_TYPE) // If the key type is not recognized or is not Ed448
        {
            std::string sig_str(signature.begin(), signature.end());
            // Return an empty signature vector
            return sig_str;
        }

        // If the key type is Ed448
        unsigned char *sig = NULL;
        size_t sig_len;
        EVP_PKEY *evp_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL, private_key.data(), private_key.size());

        if (evp_key == NULL)
        {
            std::string sig_str(signature.begin(), signature.end());
            // Return an empty signature vector
            return sig_str;
        }

        // Create a new signing context and initialize it with the private key
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

        if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, evp_key) != 1)
        {
            // If the initialization of the signing context fails, free resources and throw an error
            EVP_PKEY_free(evp_key);
            EVP_MD_CTX_free(mdctx);
            std::string sig_str(signature.begin(), signature.end());
            // Return an empty signature vector
            return sig_str;
        }

        // Get the size of the signature buffer needed
        EVP_DigestSign(mdctx, NULL, &sig_len, message.data(), message.size());

        // Resize the signature buffer to the correct size
        signature = std::vector<unsigned char>(sig_len);

        // Sign the message
        EVP_DigestSign(mdctx, signature.data(), &sig_len, message.data(), message.size());

        // Free the resources used by the signing context and the EVP_PKEY object
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(evp_key);

        std::string sig_str(signature.begin(), signature.end());
        // Return the signature
        return sig_str;
    }

    // Verify the signature of a message using the specified public key and key type
    bool verify_signature(const std::vector<unsigned char> &message, std::vector<unsigned char> &signature, std::vector<unsigned char> &public_key)
    {

        if (signature.size() == 0 || public_key.size() == 0 || message.size() == 0)
        {
            logging::print("Signature, public key, or message is empty");
            return false;
        }

        std::vector<uint8_t> pub_key_extract;
        KeyType key_type = extract_public_key(public_key, pub_key_extract);
        std::string pub_key_extract_str(pub_key_extract.begin(), pub_key_extract.end());
        std::string signature_str(signature.begin(), signature.end());

        if (key_type == KeyType::ED25519)
        {
            return crypto_sign_verify_detached(signature.data(), message.data(), message.size(), pub_key_extract.data()) == 0;
        }
        else if (key_type == KeyType::ERROR_TYPE)
        {
            // If the key type is not recognized, return false
            return false;
        }

        // For Ed448 keys, create an EVP_PKEY object from the public key
        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, pub_key_extract.data(), pub_key_extract.size());

        if (pkey == NULL)
        {
            logging::print("Failed to create EVP_PKEY object");
            return false;
        }

        // Create a new message digest context and initialize it with the public key
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1)
        {
            // If the context fails to initialize, free the resources and throw an error
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(md_ctx);
            logging::print("Failed to initialize verification context");
            return false;
        }

        // Verify the message digest signature
        if (EVP_DigestVerify(md_ctx, signature.data(), signature.size(), message.data(), message.size()) != 1)
        {
            logging::print("Failed to initialize verification context v2");
            // If the signature is not valid, free the resources and return false
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(md_ctx);
            return false;
        }
        else
        {
            // If the signature is valid, free the resources and return true
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(md_ctx);
            return true;
        }
    }
    // ##################################################
    //                   VERIFYING
    // ##################################################
    template <typename TXType>
    bool multi_signature(TXType &tx)
    {
        TXType tx_copy;
        tx_copy.CopyFrom(tx);
        zera_txn::BaseTXN *base = tx_copy.mutable_base();

        zera_txn::MultiKey *multi_key = base->mutable_public_key()->mutable_multi();

        if (multi_key->multi_patterns_size() <= 0)
        {
            return false;
        }

        base->release_hash();

        int x = multi_key->signatures_size() - 1;
        std::map<std::string, std::vector<std::string>> class_keys;

        while (x >= 0)
        {
            std::string *signature = multi_key->mutable_signatures()->ReleaseLast();

            if (signature == nullptr || signature->empty())
            {
                return false;
            }

            std::smatch match;
            std::string public_key;
            std::string prefix;
            std::string pub_str = multi_key->public_keys(x);

            size_t prefix_end = pub_str.find_first_of('_');

            if (prefix_end != std::string::npos && prefix_end > 1 && pub_str[0] == 'c' && isdigit(pub_str[1]))
            {
                // Extract the prefix
                prefix = pub_str.substr(0, prefix_end);

                // Extract the rest of the string
                public_key = pub_str.substr(prefix_end + 1);
            }
            else
            {
                continue;
            }

            if (public_key == "")
            {
                return false;
            }
            else if (*signature != "")
            {
                std::string message_str = tx_copy.SerializeAsString();

                if (signatures::verify_multi(public_key, *signature, message_str))
                {

                    class_keys[prefix].push_back(public_key);
                }
            }
            x--;
        }

        bool valid = false;
        for (auto pattern : multi_key->multi_patterns())
        {
            std::map<std::string, int> class_reqs;

            if (pattern.class__size() != pattern.required_size())
            {
                continue;
            }

            int y = 0;
            while (y < pattern.class__size())
            {
                std::string class_name = "c" + std::to_string(pattern.class_(y));
                class_reqs[class_name] = pattern.required(y);
                y++;
            }

            for (auto req : class_reqs)
            {
                if (class_keys[req.first].size() < req.second)
                {
                    valid = false;
                    break;
                }
                else
                {
                    valid = true;
                }
            }

            if (valid)
            {
                break;
            }
        }
        return valid;
    }
}

int signatures::get_key_size(const KeyType &key_type)
{
    switch (key_type)
    {
    case KeyType::ED25519:
        return 32;
    case KeyType::ED448:
        return 57;
    default:
        return 0;
    }
}
KeyType signatures::get_key_type(const std::string &public_key, bool restricted)
{
    std::string key_type_str = public_key.substr(0, 2);

    KeyType key_type;

    if (key_type_str == "A_")
    {
        key_type = KeyType::ED25519;
    }
    else if (key_type_str == "B_")
    {
        key_type = KeyType::ED448;
    }
    else if (key_type_str == "r_")
    {
        if (restricted)
        {
            key_type = KeyType::ERROR_TYPE;
        }
        else
        {
            std::string extract_string = public_key.substr(2, public_key.size() - 1);
            key_type = get_key_type(extract_string, true);
        }
    }
    else
    {
        key_type = KeyType::ERROR_TYPE;
    }

    return key_type;
}
// ##################################################
//                   SIGNING
// ##################################################

void signatures::sign_block_proposer(zera_validator::Block *block, KeyPair key_pair)
{
    zera_validator::BlockHeader *block_header = block->mutable_block_header();
    block_header->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
    std::string message_str = block->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    block_header->set_signature(signature);
}
void signatures::sign_block_broadcast(zera_validator::Block *block, KeyPair key_pair)
{
    block->release_public_key();
    block->release_signature();
    block->mutable_public_key()->set_single(ValidatorConfig::get_gen_public_key());
    std::string message_str = block->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    block->set_signature(signature);
}

void signatures::sign_instrument_contract(zera_txn::InstrumentContract *ctxn, KeyPair key_pair)
{
    std::string message_str = ctxn->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    zera_txn::BaseTXN *base = ctxn->mutable_base();
    base->set_signature(signature);
}

template <typename TXType>
void signatures::sign_request(TXType *txn, KeyPair key_pair)
{
    std::string message_str = txn->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    txn->set_signature(signature);
}
template void signatures::sign_request<zera_validator::BlockBatch>(zera_validator::BlockBatch *, KeyPair);
template void signatures::sign_request<zera_validator::Block>(zera_validator::Block *, KeyPair);
template void signatures::sign_request<zera_validator::ValidatorSync>(zera_validator::ValidatorSync *, KeyPair);
template void signatures::sign_request<zera_validator::ValidatorSyncRequest>(zera_validator::ValidatorSyncRequest *, KeyPair);
template void signatures::sign_request<zera_validator::BlockSync>(zera_validator::BlockSync *, KeyPair);
template void signatures::sign_request<zera_validator::BlockAttestation>(zera_validator::BlockAttestation *, KeyPair);

void signatures::sign_new_coin_txn(zera_txn::CoinTXN *txn, std::vector<KeyPair> key_pairs)
{
    // get txn string with no signatures added
    std::string message_str = txn->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    // sign for each key with the same txn string and add all signatures to auth
    for (auto kp : key_pairs)
    {
        std::string signature = sign_message(message, kp);
        txn->mutable_auth()->add_signature(signature);
    }
}

template <typename TXType>
void signatures::sign_txns(TXType *txn, KeyPair key_pair)
{
    std::string message_str = txn->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    txn->mutable_base()->set_signature(signature);
}
template void signatures::sign_txns<zera_txn::ValidatorRegistration>(zera_txn::ValidatorRegistration *, KeyPair);
template void signatures::sign_txns<zera_txn::ValidatorHeartbeat>(zera_txn::ValidatorHeartbeat *, KeyPair);
template void signatures::sign_txns<zera_txn::ProposalResult>(zera_txn::ProposalResult *, KeyPair);
template void signatures::sign_txns<zera_txn::SmartContractTXN>(zera_txn::SmartContractTXN *, KeyPair);

// ##################################################
//                   VERIFYING
// ##################################################
bool signatures::verify_multi(const std::string &public_key, const std::string &signature, const std::string &message)
{
    try
    {
        std::vector<uint8_t> public_key_vec(public_key.begin(), public_key.end());
        std::vector<uint8_t> signature_vec(signature.begin(), signature.end());
        std::vector<uint8_t> message_vec(message.begin(), message.end());
        return verify_signature(message_vec, signature_vec, public_key_vec);
    }
    catch (...)
    {
        return false;
    }
}

template <typename TXType>
bool signatures::verify_txns(TXType &tx)
{
    try
    {
        TXType tx_copy;
        tx_copy.CopyFrom(tx);
        zera_txn::BaseTXN *base = tx_copy.mutable_base();
        base->release_hash();

        if (tx.base().public_key().multi().signatures_size() > 0)
        {
            if (tx.base().public_key().multi().signatures_size() != tx.base().public_key().multi().public_keys_size())
            {
                logging::print("verify_txns 1");
                return false;
            }
            return multi_signature(tx);
        }

        if (!base->has_signature())
        {
            logging::print("verify_txns 2");
            return false;
        }

        std::string public_key_str = wallets::get_public_key_string(base->public_key());
        std::string encoded_pub = base58_encode_public_key(public_key_str);

        std::vector<uint8_t> public_key(public_key_str.begin(), public_key_str.end());
        std::string *signature_str = base->release_signature();

        std::string message_str = tx_copy.SerializeAsString();

        std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
        std::vector<uint8_t> message(message_str.begin(), message_str.end());

        return verify_signature(message, signature, public_key);
    }
    catch (...)
    {
        logging::print("verify_txns 3");
        return false;
    }
}
template bool signatures::verify_txns<zera_txn::GovernanceProposal>(zera_txn::GovernanceProposal &);
template bool signatures::verify_txns<zera_txn::GovernanceVote>(zera_txn::GovernanceVote &);
template bool signatures::verify_txns<zera_txn::NFTTXN>(zera_txn::NFTTXN &);
template bool signatures::verify_txns<zera_txn::MintTXN>(zera_txn::MintTXN &);
template bool signatures::verify_txns<zera_txn::ItemizedMintTXN>(zera_txn::ItemizedMintTXN &);
template bool signatures::verify_txns<zera_txn::InstrumentContract>(zera_txn::InstrumentContract &);
template bool signatures::verify_txns<zera_txn::SmartContractTXN>(zera_txn::SmartContractTXN &);
template bool signatures::verify_txns<zera_txn::SmartContractExecuteTXN>(zera_txn::SmartContractExecuteTXN &);
template bool signatures::verify_txns<zera_txn::ExpenseRatioTXN>(zera_txn::ExpenseRatioTXN &);
template bool signatures::verify_txns<zera_txn::ContractUpdateTXN>(zera_txn::ContractUpdateTXN &);
template bool signatures::verify_txns<zera_txn::ValidatorHeartbeat>(zera_txn::ValidatorHeartbeat &);
template bool signatures::verify_txns<zera_txn::DelegatedTXN>(zera_txn::DelegatedTXN &);
template bool signatures::verify_txns<zera_txn::QuashTXN>(zera_txn::QuashTXN &);
template bool signatures::verify_txns<zera_txn::FastQuorumTXN>(zera_txn::FastQuorumTXN &);
template bool signatures::verify_txns<zera_txn::RevokeTXN>(zera_txn::RevokeTXN &);
template bool signatures::verify_txns<zera_txn::ComplianceTXN>(zera_txn::ComplianceTXN &);
template bool signatures::verify_txns<zera_txn::BurnSBTTXN>(zera_txn::BurnSBTTXN &);
template bool signatures::verify_txns<zera_txn::SmartContractInstantiateTXN>(zera_txn::SmartContractInstantiateTXN &);
template bool signatures::verify_txns<zera_txn::RequiredVersion>(zera_txn::RequiredVersion &);
template bool signatures::verify_txns<zera_txn::AllowanceTXN>(zera_txn::AllowanceTXN &);

template <>
bool signatures::verify_txns<zera_txn::ValidatorRegistration>(zera_txn::ValidatorRegistration &tx)
{
    try
    {
        zera_txn::ValidatorRegistration tx_copy;
        tx_copy.CopyFrom(tx);
        zera_txn::BaseTXN *base = tx_copy.mutable_base();
        std::string *hash = base->release_hash();

        if (tx.base().public_key().multi().signatures_size() > 0 || !base->has_signature())
        {
            logging::print("Validator Registration 1");
            return false;
        }
        std::string *gen_sig = tx_copy.release_generated_signature();

        std::string public_key_str = wallets::get_public_key_string(base->public_key());

        std::vector<uint8_t> public_key(public_key_str.begin(), public_key_str.end());

        std::string *signature_str = base->release_signature();

        std::string message_str = tx_copy.SerializeAsString();

        std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
        std::vector<uint8_t> message(message_str.begin(), message_str.end());

        if (verify_signature(message, signature, public_key))
        {
            if (tx.register_())
            {

                if (!tx_copy.has_generated_public_key())
                {
                    logging::print("Validator Registration 2");
                    return false;
                }

                std::string pub_key_gen_str = wallets::get_public_key_string(tx_copy.generated_public_key());
                std::vector<uint8_t> gen_public_key(pub_key_gen_str.begin(), pub_key_gen_str.end());
                std::vector<uint8_t> gen_signature(gen_sig->begin(), gen_sig->end());
                std::vector<uint8_t> gen_message(hash->begin(), hash->end());

                bool passed = verify_signature(gen_message, gen_signature, gen_public_key);
                if (passed)
                {
                    return true;
                }
                else
                {
                    logging::print("Validator Registration 3");
                    return false;
                }
            }
            else
            {
                logging::print("Validator Registration 4");
                return true;
            }
        }
        logging::print("Validator Registration 5");
        return false;
    }
    catch (...)
    {
        logging::print("Validator Registration 6");
        return false;
    }
}

template <>
bool signatures::verify_txns<zera_txn::CoinTXN>(zera_txn::CoinTXN &tx)
{
    try
    {

        zera_txn::CoinTXN tx_copy;
        tx_copy.CopyFrom(tx);
        zera_txn::BaseTXN *base = tx_copy.mutable_base();
        base->release_hash();

        if (tx_copy.auth().public_key_size() != tx_copy.auth().signature_size() || tx_copy.auth().public_key_size() != tx_copy.auth().nonce_size())
        {
            logging::print("public key size (" + std::to_string(tx_copy.auth().public_key_size()) + ") does not match signature size (" + std::to_string(tx_copy.auth().signature_size()) + ") or nonce size (" + std::to_string(tx_copy.auth().nonce_size()) + ")");
            return false;
        }

        std::vector<std::string> signatures;
        for (auto signature : tx_copy.auth().signature())
        {
            if (signature == "")
            {
                return false;
            }

            signatures.push_back(signature);
        }

        tx_copy.mutable_auth()->mutable_signature()->Clear();
        std::string message_str = tx_copy.SerializeAsString();
        int x = 0;
        for (auto public_key : tx_copy.auth().public_key())
        {
            if (public_key.multi().signatures_size() > 0)
            {
                if (public_key.multi().signatures_size() != public_key.multi().public_keys_size())
                {
                    return false;
                }
                if (multi_signature(tx))
                {

                    x++;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                std::string public_key_str = wallets::get_public_key_string(public_key);
                std::vector<uint8_t> public_key_vec(public_key_str.begin(), public_key_str.end());
                std::vector<uint8_t> signature_vec(signatures[x].begin(), signatures[x].end());
                std::vector<uint8_t> message_vec(message_str.begin(), message_str.end());

                if (verify_signature(message_vec, signature_vec, public_key_vec))
                {
                    x++;
                }
                else
                {
                    return false;
                }
            }
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}

template <typename TXType>
bool signatures::verify_request(TXType &txn)
{
    try
    {
        std::string pub_key_str = wallets::get_public_key_string(txn.public_key());
        std::vector<uint8_t> public_key(pub_key_str.begin(), pub_key_str.end());
        TXType copy;
        copy.CopyFrom(txn);

        std::string *signature_str = copy.release_signature();
        std::string message_str = copy.SerializeAsString();
        std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
        std::vector<uint8_t> message(message_str.begin(), message_str.end());

        return verify_signature(message, signature, public_key);
    }
    catch (...)
    {
        return false;
    }
}
template bool signatures::verify_request<zera_validator::BlockSync>(zera_validator::BlockSync &);
template bool signatures::verify_request<zera_validator::ValidatorSyncRequest>(zera_validator::ValidatorSyncRequest &);
template bool signatures::verify_request<zera_validator::ValidatorSync>(zera_validator::ValidatorSync &);
template bool signatures::verify_request<zera_validator::BlockAttestation>(zera_validator::BlockAttestation &);
template bool signatures::verify_request<zera_validator::BlockAttestationResponse>(zera_validator::BlockAttestationResponse &);

ZeraStatus signatures::verify_block_batch(zera_validator::BlockBatch &block_batch)
{
    std::string pub_key_str = wallets::get_public_key_string(block_batch.public_key());
    std::vector<uint8_t> public_key(pub_key_str.begin(), pub_key_str.end());
    zera_validator::BlockBatch batch_copy;
    batch_copy.CopyFrom(block_batch);
    std::string *signature_str = batch_copy.release_signature();
    std::string message_str = batch_copy.SerializeAsString();
    std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    if (!verify_signature(message, signature, public_key))
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "signatures.cpp: verify_block_batch: Failed to verify Block Batch signature");

    for (auto tmp_block : block_batch.blocks())
    {
        ZeraStatus status = verify_block(tmp_block);
        if (!status.ok())
        {
            status.prepend_message("verify_block_batch");
            return status;
        }
    }

    return ZeraStatus(ZeraStatus::Code::OK);
}
ZeraStatus signatures::verify_block_validator(zera_validator::Block &block)
{
    std::string block_pub = wallets::get_public_key_string(block.public_key());

    if (block_pub.empty() || block.signature().empty())
    {
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "signatures: verify_block_validator: block does not have validator signature or public key");
    }

    zera_validator::Block block_copy;
    block_copy.CopyFrom(block);

    std::string *signature_str = block_copy.release_signature();
    std::string message_str = block_copy.SerializeAsString();

    std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string pub_key_str = wallets::get_public_key_string(block.public_key());
    std::vector<uint8_t> public_key(pub_key_str.begin(), pub_key_str.end());

    if (!verify_signature(message, signature, public_key))
    {
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "signatures: verify_block_validator: block validator signature failed");
    }

    return ZeraStatus(ZeraStatus::Code::OK);
}
ZeraStatus signatures::verify_block(zera_validator::Block &block)
{
    if (!block.block_header().has_signature())
    {
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "signatures: verify_block: block_header does not have a signature");
    }
    std::string public_key_string = wallets::get_public_key_string(block.block_header().public_key());

    std::vector<uint8_t> public_key(public_key_string.begin(), public_key_string.end());
    zera_validator::Block block_copy;
    block_copy.CopyFrom(block);
    block_copy.mutable_block_header()->release_hash();

    std::string *signature_str = block_copy.mutable_block_header()->release_signature();
    std::string message_str = block_copy.SerializeAsString();

    std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    if (!verify_signature(message, signature, public_key))
    {
        logging::print(block.block_header().DebugString());
        return ZeraStatus(ZeraStatus::Code::SIGNATURE_ERROR, "signatures: verify_block: block_header signature failed");
    }

    return ZeraStatus(ZeraStatus::Code::OK);
}
bool signatures::verify_activity_request(zera_api::ActivityRequest request)
{
    std::string pub_key_str = wallets::get_public_key_string(request.public_key());
    std::vector<uint8_t> public_key(pub_key_str.begin(), pub_key_str.end());
    std::string *signature_str = request.release_signature();
    std::string message_str = request.SerializeAsString();
    std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    return verify_signature(message, signature, public_key);
}
bool signatures::verify_attestation(const zera_validator::BlockAttestation &attestation)
{
    std::vector<uint8_t> block_hash(attestation.block_hash().begin(), attestation.block_hash().end());
    for (auto support : attestation.validator_support())
    {
        std::string support_pub_key = wallets::get_public_key_string(support.public_key());
        std::vector<uint8_t> public_key(support_pub_key.begin(), support_pub_key.end());
        std::vector<uint8_t> signature(support.signature().begin(), support.signature().end());

        if (!verify_signature(block_hash, signature, public_key))
        {
            return false;
        }
    }

    return true;
}
void signatures::sign_attestation_response(zera_validator::BlockAttestationResponse *response, KeyPair key_pair)
{
    std::string message_str = response->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);

    response->set_signature(signature);
}

std::string signatures::sign_block_hash(const std::string &block_hash, KeyPair key_pair)
{
    std::vector<uint8_t> message(block_hash.begin(), block_hash.end());
    std::string signature = sign_message(message, key_pair);
    return signature;
}

void signatures::sign_txn_gossip(zera_validator::TXNGossip *txn, KeyPair key_pair)
{
    std::string message_str = txn->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    txn->set_signature(signature);
}
bool signatures::verify_txn_gossip(zera_validator::TXNGossip *txn)
{
    std::string public_key_str = wallets::get_public_key_string(txn->public_key());
    std::vector<uint8_t> public_key(public_key_str.begin(), public_key_str.end());
    std::string *signature_str = txn->release_signature();
    std::string message_str = txn->SerializeAsString();
    std::vector<uint8_t> signature(signature_str->begin(), signature_str->end());
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    if (!verify_signature(message, signature, public_key))
    {
        return false;
    }

    return true;
}

void signatures::sign_smart_contract_event(zera_api::SmartContractEventsResponse *event, KeyPair key_pair)
{
    std::string message_str = event->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    event->set_signature(signature);
}

bool signatures::verify_message(const std::string& message, const std::string& signature, const std::string& public_key)
{
    auto public_key_vec = base58_decode_public_key(public_key);
    auto signature_vec = base58_decode(signature);
    auto message_vec = hex_conversion::hex_to_bytes(message);

    return verify_signature(message_vec, signature_vec, public_key_vec);
}
void signatures::sign_response(zera_api::ContractResponse *response, KeyPair key_pair)
{
    std::string message_str = response->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    response->set_signature(signature);
}

void signatures::sign_response(zera_api::SmartContractEventsSearchResponse *response, KeyPair key_pair)
{
    std::string message_str = response->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    response->set_signature(signature);
}