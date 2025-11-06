#include "db_base.h"
#include <locale>
#include <iostream>
#include <string>
#include "hashing.h"
#include "validator.pb.h"
#include "reorg.h"
#include "base58.h"
#include "../logging/logging.h"

int db_blocks_tag::get_all_blocks(std::vector<zera_validator::Block> &blocks)
{
    if (Reorg::is_in_progress.load())
    {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    std::vector<std::string> keys;
    std::vector<std::string> values;

    if (!database::get_all_data(db_blocks::db, keys, values))
    {
        logging::print("Error retrieving all block data.");
        return 0;
    }

    for (int x = 0; x < values.size(); x++)
    {
        zera_validator::Block block;
        if (!block.ParseFromString(values.at(x)))
        {
            logging::print("Error parsing all block data.");
            return 0;
        }
        blocks.push_back(block);
    }
    return 1;
}
int db_blocks_tag::get_multi_data(std::string &start_key, int amount, std::vector<zera_validator::Block> &blocks)
{
    if (Reorg::is_in_progress.load())
    {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    std::vector<std::string> keys;
    std::vector<std::string> values;
    if (!database::get_multi_data(db_blocks::db, start_key, amount, keys, values))
    {
        logging::print("Error retrieving multi block data.");
        return 0;
    }

    for (int x = 0; x < values.size(); x++)
    {
        zera_validator::Block block;
        if (!block.ParseFromString(values.at(x)))
        {
            logging::print("Error parsing multi block data.");
            return 0;
        }
        blocks.push_back(block);
    }
    return 1;
}


int db_blocks_tag::get_last_data(zera_validator::Block &block, std::string &last_key)
{
    if (Reorg::is_in_progress.load())
    {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed.");
        return 0;
    }
    std::string last_value;

    if (!database::get_last_data(db_blocks::db, last_key, last_value))
    {
        return 0;
    }
    block.ParseFromString(last_value);

    return 1;
}

