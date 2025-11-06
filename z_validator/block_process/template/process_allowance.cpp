#include "../block_process.h"

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

#include "db_base.h"
#include "../../temp_data/temp_data.h"
#include "utils.h"
#include "fees.h"

template <>
ZeraStatus block_process::check_parameters<zera_txn::AllowanceTXN>(const zera_txn::AllowanceTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

    if (!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Contract not found: " + txn->contract_id(), zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }

    if(txn->authorize())
    {
        if(txn->has_allowed_currency_equivalent() && txn->has_allowed_amount())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Both allowed_currency_equivalent and allowed_amount are set. Only one should be set.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        if(txn->has_allowed_currency_equivalent())
        {
            if(!is_valid_uint256(txn->allowed_currency_equivalent()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "allowed_currency_equivelent is not a valid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
            }

            if(!zera_fees::check_qualified(txn->contract_id()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Contract requires qualified token fees", zera_txn::TXN_STATUS::INVALID_CONTRACT_FEE_ID);
            }
        }
        else if(txn->has_allowed_amount())
        {
            if(!is_valid_uint256(txn->allowed_amount()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "allowed_amount is not a valid uint256", zera_txn::TXN_STATUS::INVALID_UINT256);
            }
        }
        if(txn->has_period_months() && txn->has_period_seconds())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Both period_months and period_seconds are set. Only one should be set.", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }

        if(txn->has_period_months() && txn->period_months() <= 0)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "period_months must be greater than 0", zera_txn::TXN_STATUS::INVALID_PARAMETERS);
        }
    }
    
    return ZeraStatus();
}