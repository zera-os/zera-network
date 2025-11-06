#include <string>
#include "proposer.h"

struct BlockProccessManager
{
    transactions txns;
    std::string proposer_pub;
    int64_t last_block_time;
    zera_validator::Block *block;

};