#include "../block_process.h"


template <>
ZeraStatus block_process::check_parameters<zera_txn::RevokeTXN>(const zera_txn::RevokeTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

    if (!status.ok())
    {
        return status;
    }

    if (!db_contract_items::exist(txn->item_id() + txn->contract_id()))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_revoke.cpp: check_parameters: Item does not exist.", zera_txn::TXN_STATUS::INVALID_ITEM);
    }

    return ZeraStatus();
}
