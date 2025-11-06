// Project-specific headers
#include <cstddef>
#include "const.h"
#include "../block_process.h"
#include "wallets.h"
#include "validators.h"
#include "db_base.h"
#include "proposer.h"
#include "base58.h"
#include "utils.h"
#include "../../logging/logging.h"

template <>
ZeraStatus block_process::process_txn<zera_txn::RequiredVersion>(const zera_txn::RequiredVersion *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{

    if(!txn->base().public_key().has_governance_auth())
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_required_version.cpp: check_restricted: Governance auth is required.", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
    }
    std::string key = wallets::get_public_key_string(txn->base().public_key());

    //change log
    if(key != "gov_$ZRA+0000" && key != "gov_$ZIP+0000")
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_required_version.cpp: check_restricted: Governance auth from ZRA is required.", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
    }

    // check nonce, if its bad return failed txn
    ZeraStatus status = block_process::check_nonce(txn->base().public_key(), 0, txn->base().hash(), sc_txn);

    if(!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, status.message(), zera_txn::TXN_STATUS::INVALID_TXN_DATA);
    }

    if(txn->version_size() <= 0)
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, "process_required_version.cpp: check_parameters: Version is required.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }
    else
    {
        logging::print("process_required_version.cpp: process_txn: RequiredVersion", std::to_string(txn->version(0)), true);
    }

    status_fees.set_status(zera_txn::TXN_STATUS::OK);

    return ZeraStatus();
}