#include "zera_status.h"

class compliance{
    public:
    static bool check_compliance(const std::string &wallet_address, const zera_txn::InstrumentContract &contract);
    static void get_levels(const std::string &wallet_address, const std::string &contract_id, std::vector<uint32_t> &levels);
};