#include "temp_data.h"
#include "proposer.h"
#include "../logging/logging.h"

std::vector<zera_txn::Validator> proposer_tracker::proposers;
std::mutex proposer_tracker::mtx;

void proposer_tracker::add_proposer(const zera_txn::Validator& proposer_data){
    std::lock_guard<std::mutex> lock(mtx);
    zera_txn::Validator new_proposer;
    new_proposer.CopyFrom(proposer_data);
    proposers.push_back(new_proposer);
}
bool proposer_tracker::check_proposer(const zera_txn::PublicKey& proposer_key)
{
    std::lock_guard<std::mutex> lock(mtx);

    std::string val_key = wallets::get_public_key_string(proposer_key);
    std::string val_value;
    db_validators::get_single(val_key, val_value);
    zera_txn::Validator val;
    val.ParseFromString(val_value);

    for(auto& proposer : proposers)
    {
        if(proposer.public_key().single() == val.public_key().single())
        {
            return true;
        }
    }

    return false;
}
void proposer_tracker::get_current_proposers(std::vector<zera_txn::Validator>& proposer_data){
    std::lock_guard<std::mutex> lock(mtx);

    if(proposers.size() == 0)
    {
        zera_validator::BlockHeader last_header; //get last block header
        std::string last_key;
        db_headers_tag::get_last_data(last_header, last_key);
        std::vector<zera_txn::Validator> new_proposers = SelectValidatorsByWeight(last_header.hash(), last_header.block_height()); //select validators for the lottery
        int x = 0;
        while(x < proposers.size())
        {
            proposers.push_back(new_proposers.at(x));
            x++;
        }
    }
    logging::print("proposers size:", std::to_string(proposers.size()));
    proposer_data.assign(proposers.begin(), proposers.end());
}

void proposer_tracker::clear_proposers(){
    std::lock_guard<std::mutex> lock(mtx);
    proposers.clear();
}