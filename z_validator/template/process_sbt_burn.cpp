#include <regex>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

#include "../block_process.h"
#include "wallets.h"
#include "../temp_data/temp_data.h"
#include "../compliance/compliance.h"

template <>
ZeraStatus block_process::check_parameters<zera_txn::BurnSBTTXN>(const zera_txn::BurnSBTTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    zera_txn::InstrumentContract contract;
    ZeraStatus status = block_process::get_contract(txn->contract_id(), contract);

    if(!status.ok()){
        return status;
    }

    auto wallet_address = wallets::generate_wallet(txn->base().public_key());
    
    if (!compliance::check_compliance(wallet_address, contract))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
    }

    if(contract.type() != zera_txn::SBT){
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_sbt_burn.cpp: check_parameters: contract is not SBT", zera_txn::TXN_STATUS::INVALID_ITEM);
    }


    zera_validator::NFT sbt;
    std::string sbt_data;
    std::string sbt_id = txn->item_id() + txn->contract_id();
    if(db_contract_items::get_single(sbt_id, sbt_data)){
        sbt.ParseFromString(sbt_data);
    }
    else{
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_sbt_burn.cpp: check_parameters: sbt not found", zera_txn::TXN_STATUS::INVALID_ITEM);
    }

    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());

    if(wallet_adr != sbt.holder_address()){
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_sbt_burn.cpp: check_parameters: wallet address does not match sbt holder address", zera_txn::TXN_STATUS::INVALID_WALLET_ADDRESS);
    }

    if(txn->item_id() != sbt.item_id()){
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_sbt_burn.cpp: check_parameters: item_id does not match sbt item_id", zera_txn::TXN_STATUS::INVALID_ITEM);
    }

    if(txn->contract_id() != sbt.contract_id()){
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_sbt_burn.cpp: check_parameters: contract_id does not match sbt contract_id", zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }

    sbt_burn_tracker::add_burn(sbt_id);

    return ZeraStatus();
}