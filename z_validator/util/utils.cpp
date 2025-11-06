
#include <string>
#include <vector>
#include <mutex>
#include <fstream>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

#include "utils.h"
#include "const.h"
#include "signatures.h"
#include "txn.pb.h"
#include "wallets.h"
#include "../temp_data/temp_data.h"
#include "../logging/logging.h"
#include "db_base.h"
#include "base58.h"

namespace
{
    std::vector<std::string> get_hash_tokens(const zera_txn::PublicKey &pk, const KeyType &key_type)
    {

        std::vector<std::string> hash_tokens;

        if (pk.has_multi())
        {
            for (auto hash : pk.multi().hash_tokens())
            {
                hash_tokens.push_back(hash);
            }
        }
        else if (!pk.has_governance_auth() && !pk.has_smart_contract_auth())
        {

            std::string public_key = wallets::get_public_key_string(pk);

            HashType wallet_type = wallets::get_wallet_type(public_key);

            if (wallet_type == HashType::wallet_r)
            {
                public_key = public_key.substr(2);
            }

            int key_size = signatures::get_key_size(key_type);

            std::vector<uint8_t> pub_vec(public_key.begin(), public_key.end());

            std::string prefix(pub_vec.begin() + 2, pub_vec.end() - key_size); //= public_key.substr(0, public_key.size() - key_size);
            std::string extract_pub_key = public_key.substr(public_key.size() - key_size);

            std::stringstream ss(prefix);
            std::string item;

            while (std::getline(ss, item, '_'))
            {
                hash_tokens.push_back(item);
            }

            if (wallet_type == HashType::wallet_r)
            {
                hash_tokens.push_back("r");
            }
        }
        return hash_tokens;
    }

    uint256_t get_hash_fee(const zera_txn::PublicKey &pk, const KeyType &key_type)
    {
        std::vector<std::string> hash_tokens = get_hash_tokens(pk, key_type);

        if (hash_tokens.empty())
        {
            return 0;
        }

        uint256_t hash_fee = 0;

        for (auto hash : hash_tokens)
        {
            switch (hash[0])
            {
            case 'a':
                hash_fee += get_fee("a_HASH_FEE");
                break;
            case 'b':
                hash_fee += get_fee("b_HASH_FEE");
                break;
            case 'c':
                hash_fee += get_fee("c_HASH_FEE");
                break;
            case 'r':
                hash_fee *= get_fee("RESTRICTED_KEY_FEE");
                break;
            default:
                break;
            }
        }

        return hash_fee;
    }
}

uint256_t get_key_fee(const zera_txn::PublicKey &pk)
{
    std::vector<KeyType> key_types;
    KeyType key_type;

    if (pk.has_multi())
    {
        for (auto pub : pk.multi().public_keys())
        {
            key_types.push_back(signatures::get_key_type(pub));
        }
    }
    else if (!pk.has_governance_auth() || !pk.has_smart_contract_auth())
    {
        std::string public_key = wallets::get_public_key_string(pk);
        key_type = signatures::get_key_type(public_key);
        key_types.push_back(key_type);
    }

    uint256_t key_fee = 0;
    for (auto key : key_types)
    {
        switch (key_type)
        {
        case KeyType::ED25519:
            key_fee += get_fee("A_KEY_FEE");
            break;
        case KeyType::ED448:
            key_fee += get_fee("B_KEY_FEE");
            break;
        case KeyType::ERROR_TYPE:
            key_fee += 0;
            break;
        default:
            key_fee += 0;
            break;
        }
    }
    key_fee += get_hash_fee(pk, key_type);

    return key_fee;
}

bool is_restricted_symbol(const std::string &symbol)
{
    std::string restricted_symbols_sc;
    if(!db_smart_contracts::get_single(RESTRICTED_PROXY, restricted_symbols_sc) || restricted_symbols_sc == "")
    {
        return false;
    }

    restricted_symbols_sc += "_" + symbol;
    std::string restricted_symbols_data;

    if(db_smart_contracts::get_single(restricted_symbols_sc, restricted_symbols_data) && restricted_symbols_data == "true")
    {
        return true;
    }
    else
    {   
        return false;
    }
}

uint256_t get_fee(const std::string &fee_type)
{
    std::string fee_key;

    if(!db_smart_contracts::get_single(NETWORK_FEE_PROXY, fee_key) || fee_key == "")
    {
        if(fee_type == "VALIDATOR_FEE_PERCENTAGE")
        {
            return VALIDATOR_FEE_PERCENTAGE;
        }
        else if(fee_type == "BURN_FEE_PERCENTAGE" )
        {
            return BURN_FEE_PERCENTAGE;
        }
        else if(fee_type == "TREASURY_FEE_PERCENTAGE")
        {
            return TREASURY_FEE_PERCENTAGE;
        }

        return 1;
    }


    fee_key += "_" + fee_type;

    std::string fee_data;
    if(!db_smart_contracts::get_single(fee_key, fee_data) || fee_data == "")
    {
        if(fee_type == "VALIDATOR_FEE_PERCENTAGE")
        {
            return VALIDATOR_FEE_PERCENTAGE;
        }
        else if(fee_type == "BURN_FEE_PERCENTAGE" )
        {
            return BURN_FEE_PERCENTAGE;
        }
        else if(fee_type == "TREASURY_FEE_PERCENTAGE")
        {
            return TREASURY_FEE_PERCENTAGE;
        }

        return 1;
    }

    uint256_t fee(fee_data);

    return fee;
}
uint256_t get_txn_fee(const zera_txn::TRANSACTION_TYPE &txn_type)
{

    std::string txn_type_name = zera_txn::TRANSACTION_TYPE_Name(txn_type);

    std::string fee_key;
    if(!db_smart_contracts::get_single(NETWORK_FEE_PROXY, fee_key) || fee_key == "")
    {
        return 1;
    }

    fee_key += "_" + txn_type_name;

    std::string fee_data;
    if(!db_smart_contracts::get_single(fee_key, fee_data) || fee_data == "")
    {
        return 1;
    }

    uint256_t fee(fee_data);

    return fee;
}

uint256_t get_txn_fee_contract(const zera_txn::TRANSACTION_TYPE &txn_type, const zera_txn::InstrumentContract *txn)
{
    switch (txn_type)
    {
    case zera_txn::TRANSACTION_TYPE::CONTRACT_TXN_TYPE:
    {
        if (txn->base().public_key().has_smart_contract_auth() && txn->base().public_key().smart_contract_auth() == "sc_bridge_proxy_1")
        {
            return get_fee("CONTRACT_TXN_FEE");
        }

        uint256_t price;
        contract_price_tracker::get_price(txn->contract_id(), price);
        return price;
    }
    default:
        return 0;
    }
}

bool is_valid_uint256(const std::string &s)
{
    if (s.empty())
    {
        return false;
    }

    if (s.length() == 1 && s[0] == '0')
        return true; // empty string or "0" is valid

    // Check if every character is a digit
    for (char c : s)
    {
        if (c < '0' || c > '9')
            return false;
    }

    // Parse into a boost uint256_t
    boost::multiprecision::uint256_t num(s);

    // If the parsed number is less than the maximum value of uint256_t, it's valid
    boost::multiprecision::uint256_t max_uint256 = (boost::multiprecision::uint256_t(1) << 256) - 1;

    return num <= max_uint256;
}

void set_explorer_config()
{
    std::ifstream explore_config(EXPLORER_CONFIG);
    std::ifstream file("/z_validator/config/explorer_servers.conf");

    if (!explore_config.is_open())
    {
        if (file.is_open())
        {
            std::ofstream destFile(EXPLORER_CONFIG);
            if (!destFile.is_open())
            {
                std::cerr << "Failed to open the destination config file." << std::endl;
            }
            else
            {
                std::string line;
                while (std::getline(file, line))
                {
                    if (!(destFile << line << '\n'))
                    {
                        std::cerr << "Failed to write to destination config file." << std::endl;
                    }
                }
                file.close();
                destFile.close(); // Close the destination file
            }
        }
    }
    else
    {
        explore_config.close();
    }
}

std::string get_seconds_key(const std::time_t &t)
{
    std::ostringstream oss;
    oss << std::setw(12) << std::setfill('0') << t;
    return oss.str();
}

std::string get_txn_key(uint64_t nonce, std::string hash)
{
    std::ostringstream oss;
    oss << std::setw(20) << std::setfill('0') << nonce;
    std::string paddedHeight = oss.str();
    return paddedHeight + ":" + hash;
}

uint256_t get_circulating_supply(const std::string &contract_id)
{
    std::string max_data;
    zera_wallets::MaxSupply max_supply;
    if (!db_contract_supply::get_single(contract_id, max_data) || !max_supply.ParseFromString(max_data))
    {
        return 0;
    }

    uint256_t circ_supply(max_supply.circulation());

    std::string circulating_supply_contract;
    std::string whitelist_wallets;

    if(!db_smart_contracts::get_single(CIRCULATING_SUPPLY_CONTRACT, circulating_supply_contract) || circulating_supply_contract == "")
    {
        return circ_supply;
    }
    
    circulating_supply_contract += "_WHITE_LIST_NETWORK";


    if(!db_smart_contracts::get_single(circulating_supply_contract, whitelist_wallets) || whitelist_wallets == "")
    {
        return circ_supply;
    }

    //split into string vec by comma
    std::stringstream ss(whitelist_wallets);
    std::string wallet;
    uint256_t whitelist_amount = 0;
    while (std::getline(ss, wallet, ','))
    {
        auto address_vec = base58_decode(wallet);
        std::string address(address_vec.begin(), address_vec.end());
        std::string wallet_contract = address + contract_id;
        std::string wallet_data;
        if(!db_processed_wallets::get_single(wallet_contract, wallet_data) && !db_wallets::get_single(wallet_contract, wallet_data))
        {
            continue;
        }

        uint256_t wallet_amount(wallet_data);
        whitelist_amount += wallet_amount;
    }

    return circ_supply - whitelist_amount;
}
