#ifndef DB_H
#define DB_H
#include <rocksdb/db.h>
#include <rocksdb/write_batch.h> 
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include "const.h"
#include "zera_status.h"

using namespace boost::multiprecision;

class database {
public:
	static int open_db(rocksdb::DB*& db, rocksdb::Options& options, const std::string& db_type);
	static void close_db(rocksdb::DB*& db);
	static int store_single(rocksdb::DB* db, const std::string& key, const std::string& data);
	static int get_data(rocksdb::DB* db, const std::string& key, std::string& data);
	static int store_batch(rocksdb::DB* db, rocksdb::WriteBatch& batch);
	static int get_all_data(rocksdb::DB* db, std::vector<std::string>& keys, std::vector<std::string>& values);
	static int get_multi_data(rocksdb::DB* db, std::string& start_key, int amount, std::vector<std::string>& keys, std::vector<std::string>& values);
	static int get_last_data(rocksdb::DB* db, std::string& last_key, std::string& last_value);
	static int get_last_amount(rocksdb::DB* db, std::vector<std::string>& keys, std::vector<std::string>& values, int amount);
	static int remove_single(rocksdb::DB* db, const std::string& key);
	static void commit(rocksdb::DB* db);
	static int get_all_keys(rocksdb::DB* db, std::vector<std::string>& keys);
	static int compact_all(rocksdb::DB* db);
};
#endif