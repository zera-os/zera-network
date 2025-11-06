#pragma once

#include <string>
#include <vector>
#include <iostream>
#include "hashing.h"
#include "signatures.h"

enum class HashType {
	hash_a = 1,
	hash_b = 2,
	hash_c = 3,
	hash_d = 4,
	hash_e = 5,
	hash_f = 6,
	hash_g = 7,
	hash_h = 8,
	hash_i = 9,
	hash_j = 10,
	hash_dbz = 11,
	wallet_r = 12,
	wallet_g = 13,
	wallet_sc = 14,
	wallet_error = 15
};

namespace wallets {
	std::string get_public_key_string(const zera_txn::PublicKey& public_key);
	std::string generate_wallet_single(const std::string& public_key, const std::string transfer_symbol = "");
	std::string generate_wallet(const zera_txn::PublicKey& public_key, const std::string transfer_symbol = "");
	std::string generate_wallet_multi(const zera_txn::PublicKey& public_key, const std::string transfer_symbol = "");
	HashType get_wallet_type(std::string pub_key);
	HashType get_wallet_type(const zera_txn::PublicKey &public_key);
	KeyPair generate_key_pair(KeyType key_type);
	
	template <typename TXType>
	void get_wallet_txn(TXType* txn, std::vector<std::string>& wallets, std::vector<uint64_t>& nonces);
};

