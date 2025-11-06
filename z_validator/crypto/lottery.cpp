// Standard library headers
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>

// Third-party library headers

// Project-specific headers
#include "lottery.h"
//#include "db_headers.h"
#include "db_base.h"
#include "validator.pb.h"
#include "hashing.h"
#include "base58.h"

////////////////////////////////////////
namespace {

	uint64_t convertHashToSeed(const std::vector<uint8_t>& hash) {
		if (hash.size() < 8) {
			throw std::runtime_error("Insufficient bytes to convert to uint64_t");
		}

		std::stringstream ss;
		for (int i = 0; i < 8; ++i) {
			ss << std::hex << static_cast<int>(hash[i]);
		}
		uint64_t seed;
		ss >> seed;

		return seed;
	}

	void get_hashes(std::vector<uint64_t>& heights, std::vector<std::string>& hashes, int amount) {

		std::vector<zera_validator::BlockHeader> headers;
		std::vector<std::string> keys;
		db_headers_tag::get_last_amount(headers, keys, amount);

		for (size_t x = 0; x < headers.size(); x++) {
			hashes.push_back(keys.at(x).substr(21));
			heights.push_back(headers.at(x).block_height());
		}
	}
	void get_hash_order(uint64_t seed, std::vector<uint64_t>& heights, std::vector<std::string>& hashes) {
		// Initialize random number generator
		std::mt19937_64 rng(seed);

		// Perform Fisher-Yates shuffle
		for (int i = static_cast<int>(heights.size()) - 1; i > 0; --i) {
			std::uniform_int_distribution<int> distribution(0, i);
			int j = distribution(rng);
			std::swap(heights[i], heights[j]);
			std::swap(hashes[i], hashes[j]);
		}

		return;
	}
	void get_entropy_seed(uint64_t& entropy_seed, std::vector<uint64_t>& heights, std::vector<std::string>& hashes) {
		entropy_seed = 0;
		std::vector<uint8_t> entropy_hash;

		std::string hash_3_5_str = hashes.at(2) + std::to_string(heights.at(2) + heights.at(4)) + hashes.at(4);
		std::string hash_4_1_str = hashes.at(3) + std::to_string(heights.at(3) + heights.at(0)) + hashes.at(0);
		std::string hash_2_6_str = hashes.at(1) + std::to_string(heights.at(1) + heights.at(5)) + hashes.at(5);

		std::vector<uint8_t> hash_3_5_vec(hash_3_5_str.begin(), hash_3_5_str.end());
		std::vector<uint8_t> hash_4_1_vec(hash_4_1_str.begin(), hash_4_1_str.end());
		std::vector<uint8_t> hash_2_6_vec(hash_2_6_str.begin(), hash_2_6_str.end());

		std::vector<uint8_t> hash_35 = Hashing::sha256_hash(hash_3_5_vec);
		std::vector<uint8_t> hash_41 = Hashing::sha256_hash(hash_4_1_vec);
		std::vector<uint8_t> hash_26 = Hashing::sha256_hash(hash_2_6_vec);

		std::vector<uint8_t> hash_35_41_vec = hash_35;
		std::vector<uint8_t> hash_26_26_vec = hash_26;

		hash_35_41_vec.insert(hash_35_41_vec.end(), hash_41.begin(), hash_41.end());
		hash_26_26_vec.insert(hash_26_26_vec.end(), hash_26.begin(), hash_26.end());

		std::vector<uint8_t> hash_3541 = Hashing::sha256_hash(hash_35_41_vec);
		std::vector<uint8_t> hash_2626 = Hashing::sha256_hash(hash_26_26_vec);

		std::vector<uint8_t> hash_order_entropy_vec = hash_3541;
		hash_order_entropy_vec.insert(hash_order_entropy_vec.end(), hash_2626.begin(), hash_2626.end());

		std::vector<uint8_t> order_entropy = Hashing::sha256_hash(hash_order_entropy_vec);

		entropy_seed = convertHashToSeed(order_entropy);
	}

	void read_entropy_data(uint64_t& entropy_seed, std::vector<uint64_t>& heights, std::vector<std::string>& hashes) {

		for (int x = 0; x < hashes.size(); x++) {
			std::vector<uint8_t> hash_vec(hashes.at(x).begin(), hashes.at(x).end());
		}
	}
}

uint64_t get_validator_seed() {
	std::vector<uint64_t> heights;
	std::vector<std::string> hashes;
	uint64_t entropy_seed;
	get_hashes(heights, hashes, 6);

	if (heights.size() >= 6)
	{
		get_entropy_seed(entropy_seed, heights, hashes);
		get_hash_order(entropy_seed, heights, hashes);
		get_entropy_seed(entropy_seed, heights, hashes);
	}
	return entropy_seed;
}