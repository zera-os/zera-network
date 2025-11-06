#include "temp_data.h"
#include "db_base.h"
#include "../logging/logging.h"

// Definitions for the static member variables
std::map<std::string, zera_wallets::MaxSupply> supply_tracker::max_supply;
std::mutex supply_tracker::mtx;

ZeraStatus supply_tracker::store_supply(const zera_txn::InstrumentContract &contract, const uint256_t &amount)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string contract_id = contract.contract_id();
    uint256_t circulation;
    bool exist = false;

    zera_wallets::MaxSupply backup_max_supply;

    try
    {
        if (max_supply.find(contract_id) != max_supply.end())
        {
            exist = true;

            backup_max_supply = max_supply[contract_id]; // backup for potential rollback

            circulation = boost::lexical_cast<uint256_t>(max_supply[contract_id].circulation());
            circulation += amount; 
            max_supply[contract_id].set_circulation(boost::lexical_cast<std::string>(circulation));
        }
        else
        {
            zera_wallets::MaxSupply temp_supply;
            std::string max_data;
            if (!db_contract_supply::get_single(contract_id, max_data) || !temp_supply.ParseFromString(max_data))
            {
                return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, "temp_data: store_supply: contract does not exist? " + contract_id);
            }

            circulation = boost::lexical_cast<uint256_t>(temp_supply.circulation());
            circulation += amount;
            temp_supply.set_circulation(boost::lexical_cast<std::string>(circulation));
            max_supply[contract_id] = temp_supply;
        }
    }
    catch (const std::exception &e)
    {
        if(exist){
            // Rollback to the previous state
            max_supply[contract_id] = backup_max_supply;
        }

        // Log the error
        std::cerr << "Exception in store_supply: " << e.what() << std::endl;

        // Notify the caller
        return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, "Error in store_supply: " + std::string(e.what()));
    }

    uint256_t max = boost::lexical_cast<uint256_t>(max_supply[contract_id].max_supply());
    
    if (circulation > max)
    {
        return ZeraStatus(ZeraStatus::BLOCK_FAULTY_TXN, "temp_data: store_supply: This mint sets circulation over max supply: " + contract_id);
    }

    return ZeraStatus();
}

ZeraStatus supply_tracker::supply_to_database()
{
    std::lock_guard<std::mutex> lock(mtx);
    rocksdb::WriteBatch supply_batch;
    
    for (const auto &supply : max_supply)
    {
        std::string serialized_data = supply.second.SerializeAsString();
        
        if(serialized_data.empty())
        {
            // Cleanup if necessary
            max_supply.clear();
            return ZeraStatus(ZeraStatus::Code::PROTO_ERROR, "temp_data.cpp: supply_to_database: Serialization failed");
        }
        
        supply_batch.Put(supply.first, serialized_data);
    }

    max_supply.clear();

    bool db_status = db_contract_supply::store_batch(supply_batch);
    
    if(!db_status)
    {
        return ZeraStatus(ZeraStatus::Code::DATABASE_ERROR, "temp_data.cpp: supply_to_database: Batch Store failed.");
    }
    
    return ZeraStatus(); // No error message needed on success
}
