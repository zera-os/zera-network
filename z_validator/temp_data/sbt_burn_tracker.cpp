#include "temp_data.h"
#include "db_base.h"

std::vector<std::string> sbt_burn_tracker::sbt_list;
std::mutex sbt_burn_tracker::mtx;

void sbt_burn_tracker::add_burn(const std::string& sbt_id)
{
    std::lock_guard<std::mutex> lock(mtx);
    if(std::find(sbt_list.begin(), sbt_list.end(), sbt_id)!= sbt_list.end()) {
        return;
    }
    sbt_list.push_back(sbt_id);
}

void sbt_burn_tracker::clear_burns(){
    if(sbt_list.empty()){
        return;
    }   

    std::lock_guard<std::mutex> lock(mtx);
    rocksdb::WriteBatch burn_batch;
    for(auto burn : sbt_list)
    {
        burn_batch.Delete(burn);
    }
    
    db_contract_items::store_batch(burn_batch);
    sbt_list.clear();
}