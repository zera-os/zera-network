#include "../block_process.h"

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

#include "db_base.h"
#include "../../temp_data/temp_data.h"

template <>
ZeraStatus block_process::check_parameters<zera_txn::ComplianceTXN>(const zera_txn::ComplianceTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

    if(!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_compliance.cpp: check_parameters: Contract does not exist.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }

    if(txn->compliance_size() <= 0)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_compliance.cpp: check_parameters: Compliance size is 0.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
    }

    return ZeraStatus();
}