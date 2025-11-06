#pragma once

#include "txn.pb.h"
#include "validator.pb.h"
#include "hashing.h"

class merkle_tree{
public:
    static void build_merkle_tree(zera_validator::Block* block);
};