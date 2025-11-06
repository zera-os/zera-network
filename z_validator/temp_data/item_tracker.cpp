#include "temp_data.h"
#include "db_base.h"

std::vector<std::string> item_tracker::item_list;
std::mutex item_tracker::mtx;

ZeraStatus item_tracker::add_item(const std::string& item_id)
{
    std::lock_guard<std::mutex> lock(mtx);
    if(std::find(item_list.begin(), item_list.end(), item_id)!= item_list.end()) {
        return ZeraStatus(ZeraStatus::TXN_FAILED, "temp_data: add_item: cannot mint item, already exists. " + item_id, zera_txn::TXN_STATUS::INVALID_ITEM);
    }
    item_list.push_back(item_id);
    return ZeraStatus();
}

void item_tracker::clear_items(){
    if(item_list.empty()){
        return;
    }   

    std::lock_guard<std::mutex> lock(mtx);

    item_list.clear();
}