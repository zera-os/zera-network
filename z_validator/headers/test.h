#ifndef _TEST_H_
#define _TEST_H_

#include <vector>
#include <string>
#include "validator.pb.h"
#include "txn.pb.h"
#include "signatures.h"

class Block_Test {
public:
	//static void read_block(zera_validator::Block& block, zera_validator::BlockHeader& block_header);
	static void read_block_batch(zera_validator::BlockBatch& batch);
	static KeyType key_type;
	static KeyPair key_pair;
	static KeyPair own_keypair;
	static KeyPair contract_keypair;
	static std::vector<KeyPair> auth_contract_keys;
	static std::vector<KeyPair> premint_restricted_keypairs;
	static std::vector<KeyPair> premint_keypairs;

};

void generate_key_pairs();


#endif