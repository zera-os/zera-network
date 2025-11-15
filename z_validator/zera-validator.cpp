#include "startup_config.h"
#include "logging.h"
#include "block_process.h"

int main()
{
    if(!startup_config::configure_startup())
    {
        logging::print("Startup configuration failed, exiting.");
        return -1;
    }

    logging::print("Startup configuration successful, starting block process.");
    block_process::start_block_process();

    return 0;
}