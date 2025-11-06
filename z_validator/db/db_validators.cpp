#include "db_base.h"
#include "validator.pb.h"
#include "database.h"
#include "reorg.h"
#include "../logging/logging.h"

int db_validators_tag::get_all_validators(std::vector<zera_txn::Validator> &validators)
{
    if (Reorg::is_in_progress.load())
    {
        // Handle the fact that a reorg is in progress, e.g., by postponing or skipping the function
        logging::print("Reorg in progress. Database operation delayed. Get all validators.");
        return 0;
    }
    std::vector<std::string> keys;
    std::vector<std::string> values;

    if (!database::get_all_data(db_validators::db, keys, values))
    {
        logging::print("Error retrieving all validators.");
        return 0;
    }

    for (auto value : values)
    {
        zera_txn::Validator validator;
        if (!validator.ParseFromString(value))
        {
            logging::print("Error parsing all validator data.");
        }
        if (validator.online())
        {
            validators.push_back(validator);
        }
    }

    return 1;
}

int db_validators_tag::get_all_keys(std::vector<std::string> &keys)
{
    return database::get_all_keys(db_validators::db, keys);
}