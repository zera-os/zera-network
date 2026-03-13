#include "startup_config.h"
#include "logging.h"
#include "block_process.h"
#include "db_base.h"
#include <rocksdb/write_batch.h>
#include "reorg.h"

#include "sc_base64.h"
#include "base58.h"

int main()
{

    if (!startup_config::configure_startup())
    {
        logging::print("Startup configuration failed, exiting.");
        return -1;
    }
    block_process::start_block_process();

    return 0;
}