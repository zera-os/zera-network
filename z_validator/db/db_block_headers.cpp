#include "db_base.h"
#include "validator.pb.h"
#include <locale>
#include <iostream>
#include <string>
#include "hashing.h"
#include "base58.h"
#include "reorg.h"
#include "../logging/logging.h"

int db_headers_tag::get_multi_data(std::string& start_key, int amount, std::vector<zera_validator::BlockHeader>& block_headers)
{
    if (Reorg::is_in_progress.load()) {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    std::lock_guard<std::mutex> lock(db_headers::db_mutex);
    std::vector<std::string> keys;
    std::vector<std::string> values;

    if (!database::get_multi_data(db_headers::db, start_key, amount, keys, values)){
        logging::print("Error retrieving multi header data.");
        return 0;
    }
    for (int x = 0; x < values.size(); x++) {
        zera_validator::BlockHeader block_header;
        if (!block_header.ParseFromString(values.at(x))) {
            logging::print("Error parsing multi header data.");
            return 0;
        }
        block_headers.push_back(block_header);
    }

    return 1;
}
int db_headers_tag::get_multi_data_keys(std::string& start_key, int amount, std::vector<zera_validator::BlockHeader>& block_headers, std::vector<std::string>& keys)
{
    if (Reorg::is_in_progress.load()) {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    std::vector<std::string> values;

    if (!database::get_multi_data(db_headers::db, start_key, amount, keys, values)){
        logging::print("Error retrieving multi header data.");
        return 0;
    }
    for (int x = 0; x < values.size(); x++) {
        zera_validator::BlockHeader block_header;
        if (!block_header.ParseFromString(values.at(x))) {
            logging::print("Error parsing multi header data.");
            return 0;
        }
        block_headers.push_back(block_header);
    }

    return 1;
}

int db_headers_tag::get_last_amount(std::vector<zera_validator::BlockHeader>& headers, std::vector<std::string>& keys, int amount) {
    if (Reorg::is_in_progress.load()) {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    std::vector<std::string> values;
    if (!database::get_last_amount(db_headers::db, keys, values, amount)) {
        return false;
    }
    for (int x = 0; x < values.size(); x++) {
        zera_validator::BlockHeader header;
        if (!header.ParseFromString(values.at(x)))
            return 0;
        headers.push_back(header);
    }

    return 1;
}
int db_headers_tag::get_last_data(zera_validator::BlockHeader& block_header, std::string& last_key) {
    if (Reorg::is_in_progress.load()) {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    std::string last_value;
    if (!database::get_last_data(db_headers::db, last_key, last_value))
    {
        return 0;
    }
    block_header.ParseFromString(last_value);
    return 1;
}