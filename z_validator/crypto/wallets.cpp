#include "wallets.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <sstream>
#include <regex>

#include "base58.h"
#include "txn.pb.h"

namespace
{
    int get_key_size(const KeyType &key_type)
    {

        switch (key_type)
        {
        case KeyType::ED25519:
        {
            return 32;
        }
        case KeyType::ED448:
        {
            return 57;
        }
        case KeyType::ERROR_TYPE:
        {
            return 0;
        }
        }
    }

    std::vector<uint8_t> hash_a(const std::vector<uint8_t> &data)
    {
        return Hashing::sha256_hash(data);
    }
    std::vector<uint8_t> hash_b(const std::vector<uint8_t> &data)
    {
        return Hashing::sha512_hash(data);
    }
    std::vector<uint8_t> hash_c(const std::vector<uint8_t> &data)
    {
        return Hashing::blake3_hash(data);
    }
    std::vector<uint8_t> hash_d(const std::vector<uint8_t> &data)
    {
        return Hashing::blake3_hash(data, Blake3HashLength::Bits_512);
    }
    std::vector<uint8_t> hash_e(const std::vector<uint8_t> &data)
    {
        return Hashing::blake3_hash(data, Blake3HashLength::Bits_1024);
    }
    std::vector<uint8_t> hash_f(const std::vector<uint8_t> &data)
    {
        return Hashing::blake3_hash(data, Blake3HashLength::Bits_2048);
    }
    std::vector<uint8_t> hash_g(const std::vector<uint8_t> &data)
    {
        return Hashing::blake3_hash(data, Blake3HashLength::Bits_4096);
    }
    std::vector<uint8_t> hash_dbz(const std::vector<uint8_t> &data)
    {
        return Hashing::blake3_hash(data, Blake3HashLength::Bits_9001);
    }
    std::vector<uint8_t> hash_h(const std::vector<uint8_t> &data)
    {
        return Hashing::shake_hash(data, SHAKEHashLength::Bits_1024);
    }
    std::vector<uint8_t> hash_i(const std::vector<uint8_t> &data)
    {
        return Hashing::shake_hash(data, SHAKEHashLength::Bits_2048);
    }
    std::vector<uint8_t> hash_j(const std::vector<uint8_t> &data)
    {
        return Hashing::shake_hash(data, SHAKEHashLength::Bits_4096);
    }

    std::vector<uint8_t> hash_pk(const HashType &hash_type, std::vector<uint8_t> &data)
    {
        std::vector<uint8_t> wallet_address;

        switch (hash_type)
        {
        case HashType::hash_a:
        {
            wallet_address = hash_a(data);
            break;
        }
        case HashType::hash_b:
        {
            wallet_address = hash_b(data);
            break;
        }
        case HashType::hash_c:
        {
            wallet_address = hash_c(data);
            break;
        }
        case HashType::hash_d:
        {
            wallet_address = hash_d(data);
            break;
        }
        case HashType::hash_e:
        {
            wallet_address = hash_e(data);
            break;
        }
        case HashType::hash_f:
        {
            wallet_address = hash_f(data);
            break;
        }
        case HashType::hash_g:
        {
            wallet_address = hash_g(data);
            break;
        }
        case HashType::hash_h:
        {
            wallet_address = hash_h(data);
            break;
        }
        case HashType::hash_i:
        {
            wallet_address = hash_i(data);
            break;
        }
        case HashType::hash_j:
        {
            wallet_address = hash_j(data);
            break;
        }
        case HashType::hash_dbz:
        {
            wallet_address = hash_dbz(data);
            break;
        }
        case HashType::wallet_r:
        {
            return wallet_address;
            break;
        }
        case HashType::wallet_error:
        {
            return wallet_address;
            break;
        }
        default:
        {
            return wallet_address;
            break;
        }
        }
        return wallet_address;
    }

    std::string multi_hash(std::vector<std::string> &hash_tokens, std::string &public_key)
    {
        int x = hash_tokens.size() - 1;
        HashType hash_type;

        std::vector<uint8_t> public_key_vec(public_key.begin(), public_key.end());
        std::string return_string;
        while (x >= 0)
        {

            hash_type = wallets::get_wallet_type(hash_tokens[x]);

            if (hash_type == HashType::wallet_r || hash_type == HashType::wallet_error)
            {
                return return_string;
            }

            public_key_vec = hash_pk(hash_type, public_key_vec);
            if (public_key_vec.size() == 0)
            {
                return "";
            }
            x--;
        }

        return_string.assign(public_key_vec.begin(), public_key_vec.end());
        return return_string;
    }

    std::string generate_wallet_r(const std::string &data)
    {
        KeyType key_type = signatures::get_key_type(data);

        if (key_type == KeyType::ERROR_TYPE)
        {
            return "";
        }

        int key_size = get_key_size(key_type);

        std::string prefix = data.substr(2, data.size() - key_size - 2);
        std::string extract_pub_key = data.substr(data.size() - key_size);

        std::stringstream ss(prefix);
        std::string item;
        std::vector<std::string> hash_tokens;

        while (std::getline(ss, item, '_'))
        {
            hash_tokens.push_back(item);
        }
        if (hash_tokens.size() < 0)
        {
            return "";
        }

        extract_pub_key = multi_hash(hash_tokens, extract_pub_key);

        if (extract_pub_key.empty())
        {
            return extract_pub_key;
        }

        extract_pub_key = multi_hash(hash_tokens, extract_pub_key);

        return extract_pub_key;
    }

    std::string get_multi_pub_string(const zera_txn::MultiKey &multi_key)
    {
        std::string multi_public_key = "";

        int x = 0;

        while (x < multi_key.public_keys_size())
        {
            std::string public_key = multi_key.public_keys(x);

            std::regex pattern("^c\\d+_");
            std::string result = std::regex_replace(public_key, pattern, "");

            if (result == "")
            {
                return "";
            }
            KeyType key_type = signatures::get_key_type(result);
            if (key_type == KeyType::ERROR_TYPE)
            {
                return "";
            }
            int key_size = signatures::get_key_size(key_type);
            std::string extract_pub_key = result.substr(result.size() - key_size);
            multi_public_key += extract_pub_key;

            x++;
        }

        // multiple accepted patterns
        for (auto pattern : multi_key.multi_patterns())
        {

            std::string pattern_string = "";
            x = 0;

            if (pattern.class__size() != pattern.required_size())
            {
                return "";
            }

            // parse together the single pattern
            while (x < pattern.class__size())
            {
                pattern_string += "c" + std::to_string(pattern.class_(x)) + "r" + std::to_string(pattern.required(x));
                x++;
            }
            multi_public_key += "_" + pattern_string;
        }

        return multi_public_key;
    }

    std::string generate_gov_sc_wallet(const std::string &auth, const std::string &transfer_symbol)
    {
        HashType type = wallets::get_wallet_type(auth);

        std::string wallet_address = auth;
        if (type == HashType::wallet_g)
        {
            if (wallet_address.length() > 4)
            {
                wallet_address = wallet_address.substr(4);
            }
        }
        else if (type == HashType::wallet_sc)
        {
            if (wallet_address.length() > 3)
            {
                wallet_address = wallet_address.substr(3);
            }
        }
        else
        {
            return "";
        }
        auto vec = Hashing::sha256_hash(wallet_address);
        std::string hash = std::string(vec.begin(), vec.end());

        return hash + transfer_symbol;
    }
}

std::string wallets::get_public_key_string(const zera_txn::PublicKey &public_key)
{
    std::string pk_string = "";

    if (public_key.has_governance_auth())
    {
        pk_string = public_key.governance_auth();
    }
    else if (public_key.has_multi())
    {
        pk_string = get_multi_pub_string(public_key.multi());

        for(auto token : public_key.multi().hash_tokens())
        {
            pk_string += token + "_" + pk_string ;
        }
    }
    else if (public_key.has_smart_contract_auth())
    {
        pk_string = public_key.smart_contract_auth();
    }
    else
    {
        pk_string = public_key.single();
    }

    return pk_string;
}
HashType wallets::get_wallet_type(const zera_txn::PublicKey &public_key)
{
    std::string pk_string = get_public_key_string(public_key);

    return get_wallet_type(pk_string);
}

HashType wallets::get_wallet_type(std::string pub_key)
{
    HashType wallet_type = HashType::wallet_error;

    if (pub_key.length() < 1)
    {
        return wallet_type;
    }

    std::regex pattern(R"(^[A-Za-z]+)");
    std::smatch match;
    std::string wallet_pref;

    if (std::regex_search(pub_key, match, pattern))
    {
        wallet_pref = match.str();
    }
    else
    {
        return wallet_type;
    }

    if (wallet_pref == "a")
    {
        wallet_type = HashType::hash_a;
    }
    else if (wallet_pref == "b")
    {
        wallet_type = HashType::hash_b;
    }
    else if (wallet_pref == "c")
    {
        wallet_type = HashType::hash_c;
    }
    else if (wallet_pref == "d")
    {
        wallet_type = HashType::hash_d;
    }
    else if (wallet_pref == "e")
    {
        wallet_type = HashType::hash_e;
    }
    else if (wallet_pref == "f")
    {
        wallet_type = HashType::hash_f;
    }
    else if (wallet_pref == "g")
    {
        wallet_type = HashType::hash_g;
    }
    else if (wallet_pref == "h")
    {
        wallet_type = HashType::hash_h;
    }
    else if (wallet_pref == "i")
    {
        wallet_type = HashType::hash_i;
    }
    else if (wallet_pref == "j")
    {
        wallet_type = HashType::hash_j;
    }
    else if (wallet_pref == "dbz")
    {
        wallet_type = HashType::hash_dbz;
    }
    else if (wallet_pref == "r")
    {
        wallet_type = HashType::wallet_r;
    }
    else if (wallet_pref == "gov")
    {
        wallet_type = HashType::wallet_g;
    }
    else if (wallet_pref == "sc")
    {
        wallet_type = HashType::wallet_sc;
    }

    return wallet_type;
}


std::string wallets::generate_wallet_multi(const zera_txn::PublicKey &public_key, const std::string transfer_symbol)
{

    zera_txn::MultiKey multi_key = public_key.multi();

    std::string multi_public_key = get_multi_pub_string(multi_key);

    std::vector<std::string> hash_tokens;
    bool restricted = false;
    int x = 0;
    if (multi_key.hash_tokens(0) == "r")
    {
        x = 1;
        restricted = true;
    }

    while (x < multi_key.hash_tokens_size())
    {
        hash_tokens.push_back(multi_key.hash_tokens(x));
        x++;
    }

    std::string wallet_address = multi_hash(hash_tokens, multi_public_key);

    if (restricted)
    {
        wallet_address = multi_hash(hash_tokens, wallet_address);
    }

    return wallet_address + transfer_symbol;
}

std::string wallets::generate_wallet(const zera_txn::PublicKey &public_key, const std::string transfer_symbol)
{
    if (public_key.multi().public_keys_size() > 0)
    {
        return generate_wallet_multi(public_key, transfer_symbol);
    }

    if (public_key.has_governance_auth())
    {
        return generate_gov_sc_wallet(public_key.governance_auth(), transfer_symbol);
    }
    else if (public_key.has_smart_contract_auth())
    {
        return generate_gov_sc_wallet(public_key.smart_contract_auth(), transfer_symbol);
    }

    return generate_wallet_single(public_key.single(), transfer_symbol);
}

std::string wallets::generate_wallet_single(const std::string &public_key, const std::string transfer_symbol)
{
    HashType wallet_type = get_wallet_type(public_key);

    std::string wallet_address;

    if (wallet_type == HashType::wallet_r)
    {
        wallet_address = generate_wallet_r(public_key.substr(2, public_key.size() - 1));

        if (wallet_address.empty())
        {
            return wallet_address;
        }
        return wallet_address + transfer_symbol;
    }

    KeyType key_type = signatures::get_key_type(public_key);

    if (key_type == KeyType::ERROR_TYPE)
    {
        return "";
    }

    int key_size = get_key_size(key_type);

    std::vector<uint8_t> pub_vec(public_key.begin(), public_key.end());

    std::string prefix(pub_vec.begin() + 2, pub_vec.end() - key_size); //= public_key.substr(0, public_key.size() - key_size);
    std::string extract_pub_key = public_key.substr(public_key.size() - key_size);

    std::stringstream ss(prefix);
    std::string item;
    std::vector<std::string> hash_tokens;

    while (std::getline(ss, item, '_'))
    {
        hash_tokens.push_back(item);
    }
    if (hash_tokens.size() <= 0)
    {
        return "";
    }

    std::string wallet_adr = multi_hash(hash_tokens, extract_pub_key);

    if (wallet_adr.empty())
    {
        return "";
    }

    return wallet_adr + transfer_symbol;
}

// Generate a new key pair of the specified type
KeyPair wallets::generate_key_pair(KeyType key_type)
{

    KeyPair key_pair;

    if (key_type == KeyType::ED25519)
    {
        // Generate a new Ed25519 key pair using the sodium crypto_sign_keypair function
        key_pair.public_key = std::vector<uint8_t>(crypto_sign_PUBLICKEYBYTES);
        key_pair.private_key = std::vector<uint8_t>(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(key_pair.public_key.data(), key_pair.private_key.data());
        return key_pair;
    }
    else if (key_type != KeyType::ED448)
    {
        // If the key type is not recognized, return an empty key pair
        return key_pair;
    }

    // Generate a new Ed448 key pair using the OpenSSL EVP_PKEY_keygen function
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_keygen(ctx, &pkey);

    // Extract the raw private key bytes
    size_t private_key_len = 0;
    EVP_PKEY_get_raw_private_key(pkey, NULL, &private_key_len);
    std::vector<unsigned char> private_key_data(private_key_len);
    EVP_PKEY_get_raw_private_key(pkey, private_key_data.data(), &private_key_len);

    // Extract the raw public key bytes
    size_t public_key_len = 0;
    EVP_PKEY_get_raw_public_key(pkey, NULL, &public_key_len);
    std::vector<unsigned char> public_key_data(public_key_len);
    EVP_PKEY_get_raw_public_key(pkey, public_key_data.data(), &public_key_len);

    // Convert the binary encoding of the public and private keys to vectors of uint8_t and return them
    key_pair.public_key = std::vector<uint8_t>(public_key_data.begin(), public_key_data.end());
    key_pair.private_key = std::vector<uint8_t>(private_key_data.begin(), private_key_data.end());

    // Create a new signing context and initialize it with the private key
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    // Free the resources used by the EVP_PKEY and EVP_PKEY_CTX objects
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return key_pair;
}

template <typename TXType>
void wallets::get_wallet_txn(TXType *txn, std::vector<std::string> &wallets, std::vector<uint64_t> &nonces)
{
    std::string wallet = wallets::generate_wallet(txn->base().public_key());
    uint64_t nonce = txn->base().nonce();

    wallets.push_back(wallet);
    nonces.push_back(nonce);
}

template <>
void wallets::get_wallet_txn<zera_txn::CoinTXN>(zera_txn::CoinTXN *txn, std::vector<std::string> &wallets, std::vector<uint64_t> &nonces)
{
    int x = 0;

    for (auto public_key : txn->auth().public_key())
    {

        std::string wallet = wallets::generate_wallet(public_key);
        uint64_t nonce = txn->auth().nonce(x);

        wallets.push_back(wallet);
        nonces.push_back(nonce);
        x++;
    }
}