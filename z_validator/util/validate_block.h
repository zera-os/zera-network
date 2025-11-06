#pragma once

// Standard library headers
#include <string>
#include <iostream>
#include <iostream>
#include <thread>
#include <mutex>
#include <memory>

// Third-party library headers
#include "validator.pb.h"

// Project-specific headers
#include "db_base.h"
#include "block.h"
#include "signatures.h"
#include "test.h"
#include "const.h"
#include "validators.h"
#include "base58.h"
#include "proposer.h"
#include "../crypto/merkle.h"
#include "zera_status.h"

//This function is used to validate a block one at a time. It is used to validate a block from sync and broadcast
struct ValidateBlock
{
public:
    
    static ZeraStatus process_block_from_sync(const zera_validator::Block &block)
    {
        std::lock_guard<std::mutex> lock(processing_mutex);
        return block_process(block);
        // Other processing logic if needed
    }

    static ZeraStatus process_block_from_broadcast(const zera_validator::Block &block)
    {
        std::lock_guard<std::mutex> lock(processing_mutex);
        return block_process(block, true);
        // Other processing logic if needed
    }

private:
    static ZeraStatus block_process(const zera_validator::Block &block, bool broadcast = false);

    static std::mutex processing_mutex;
};