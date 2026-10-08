#include "startup_config.h"
#include "logging.h"
#include "block_process.h"
#include "db_base.h"
#include <rocksdb/write_batch.h>
#include "reorg.h"
#include "validators.h"

#include "sc_base64.h"
#include "base58.h"
#include "zera_api.pb.h"
#include "validator.pb.h"

#include <unordered_map>

void checkpoint_blockchain()
{
    logging::print("Checkpoint blockchain", true);
    zera_validator::BlockHeader block_header;
    std::string last_key;
    db_headers_tag::get_last_data(block_header, last_key);
    Reorg::checkpoint_blockchain("100006", block_header);
    logging::print("Checkpoint blockchain done", true);
}

int main()
{

    if (!startup_config::configure_startup())
    {
        logging::print("Startup configuration failed, exiting.");
        return -1;
    }
    //test_function();
    checkpoint_blockchain();
    block_process::start_block_process();

    // A scheduled restore/failure must also restart under an on-failure policy.
    return ValidatorConfig::get_shutdown() ? 1 : 0;
}
