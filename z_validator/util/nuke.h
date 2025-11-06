#include <string>
#include "txn.pb.h"
#include "validator.pb.h"
#include "const.h"
#include "logging.h"
#include "base58.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <fstream>
#include "validators.h"
#include "wallets.h"
#include "temp_data.h"
#include "signatures.h"
#include "hashing.h"
#include <google/protobuf/util/time_util.h>
#include <google/protobuf/timestamp.pb.h>
#include "block_process.h"
#include "block.h"
#include <vector>
#include "merkle.h"
#include "proposer.h"


class nuke{
    public:
    static void create_genesis_block();
    static std::string get_legal_string();
    static void set_all_zra_premints(zera_txn::InstrumentContract *txn);
    static void set_iit_governance(zera_txn::Governance *governance);
    static void set_standard_governance(zera_txn::Governance *governance);
    static void add_gov_restricted_key(zera_txn::RestrictedKey *restricted_key, const std::string &gov_key, uint32_t key_weight);
    static void make_vali(zera_txn::Validator *validator);
    static void set_ace_governance(zera_txn::Governance *governance);
};