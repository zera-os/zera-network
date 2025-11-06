#include "temp_data.h"
#include "db_base.h"

std::vector<std::string> fast_quorum_tracker::proposal_list;
std::mutex fast_quorum_tracker::mtx;

void fast_quorum_tracker::add_proposal(const std::string& proposal_id)
{
    std::lock_guard<std::mutex> lock(mtx);
    if(std::find(proposal_list.begin(), proposal_list.end(), proposal_id) != proposal_list.end()) {
        return;
    }
    proposal_list.push_back(proposal_id);
}

void fast_quorum_tracker::clear_proposals(){
    std::lock_guard<std::mutex> lock(mtx);
    proposal_list.clear();
}
