// Standard library headers
#include <chrono>
#include <fstream>
#include <random>

// Third-party library headers
// (none provided)

// Project-specific headers
#include "test.h"
#include "hashing.h"
#include "base58.h"
#include "db_base.h"
// #include "db_wallets.h"
// #include "db_contracts.h"
#include "wallets.h"
#include "signatures.h"
#include "wallet.pb.h"
#include "const.h"
#include "../logging/logging.h"

using namespace zera_txn;
using namespace zera_validator;

KeyPair Block_Test::key_pair;
KeyPair Block_Test::own_keypair;
KeyType Block_Test::key_type;
KeyPair Block_Test::contract_keypair;
std::vector<KeyPair> Block_Test::auth_contract_keys;
std::vector<KeyPair> Block_Test::premint_restricted_keypairs;
std::vector<KeyPair> Block_Test::premint_keypairs;


namespace
{
    std::string get_restricted_test_keys(std::string key_pair_str)
    {

        KeyPair key_pair;
        // Find the position of the space character
        size_t spacePosition = key_pair_str.find(' ');
        std::string firstKey;

        if (spacePosition != std::string::npos)
        {
            HashType type = wallets::get_wallet_type(key_pair_str);
            std::string prefix;

            firstKey = key_pair_str.substr(0, spacePosition);
        }
        return firstKey;
    }
}
KeyPair split_keys_decode(std::string key_pair_str)
{

     KeyPair key_pair;
    // Find the position of the space character
    size_t spacePosition = key_pair_str.find(' ');

    if (spacePosition != std::string::npos)
    {
        std::string prefix;
        std::string firstKey = key_pair_str.substr(0, spacePosition);

        size_t pos = key_pair_str.find_last_of('_');

        if (pos != std::string::npos)
        {
            prefix = firstKey.substr(0, pos + 1); // +1 to include the last underscore
            firstKey = firstKey.substr(pos + 1);
            // Use letters and publicKey
        }

        std::string public_key_str = prefix + firstKey;
        key_pair.public_key = base58_decode_public_key(public_key_str);



        std::string private_key_str = key_pair_str.substr(spacePosition + 1);
        key_pair.private_key = base58_decode(private_key_str);
    }
    return key_pair;
}


void generate_key_pairs()
{
    std::vector<std::string> pubs;
    std::vector<std::string> privs;

    for (int x = 0; x < 10; x++)
    {
        KeyType key_type = KeyType::ED25519;
        KeyPair keypair = wallets::generate_key_pair(key_type);
        std::string public_key(keypair.public_key.begin(), keypair.public_key.end());
        std::string private_key(keypair.private_key.begin(), keypair.private_key.end());

        pubs.push_back(base58_encode(keypair.public_key));
        privs.push_back(base58_encode(keypair.private_key));
    }
    for (int x = 0; x < 10; x++)
    {
        logging::print("a_", pubs.at(x), privs.at(x));
    }

    return;
}
