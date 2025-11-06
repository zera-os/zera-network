#ifndef _BLOCK_H_
#define _BLOCK_H_

#include <vector>
#include <string>
#include "validator.pb.h"
#include <rocksdb/write_batch.h>
#include "signatures.h"
#include <tuple>
#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;

namespace block_utils
{
	void set_block(zera_validator::Block *block);
	void set_block_sync(zera_validator::Block *block, const zera_validator::BlockHeader &original_header);
	void hash_block(zera_validator::Block *block);
	std::string block_batch_to_write_batch(zera_validator::BlockBatch *block_batch, rocksdb::WriteBatch &write_block_batch, rocksdb::WriteBatch &write_header_batch, rocksdb::WriteBatch &hash_index_batch);
	bool check_block(zera_validator::Block &block);
	std::string block_to_write(zera_validator::Block *block, std::string &write_block, std::string &write_header);
	ZeraStatus process_txns_and_create_write_batches(zera_validator::Block *block, rocksdb::WriteBatch *wallet_batch);
	ZeraStatus verify_coin_tx_and_create_write_batch(zera_validator::Block *block);
	ZeraStatus verify_mint_tx_and_create_write_batch(zera_validator::Block *block);
	ZeraStatus verify_contract_tx_and_create_write_batch(zera_validator::Block *block);
}

#endif
