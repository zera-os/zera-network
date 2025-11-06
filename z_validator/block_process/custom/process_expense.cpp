#include "../block_process.h"
#include <regex>
#include <google/protobuf/util/time_util.h>

#include "../../governance/time_calc.h"
#include "../../temp_data/temp_data.h"
#include "wallets.h"
#include "../../logging/logging.h"
#include "fees.h"

namespace
{
    ZeraStatus process_wallets(const zera_txn::ExpenseRatio &expense_ratio, const zera_txn::ExpenseRatioTXN *txn, zera_txn::ExpenseRatioResult *result)
    {
        std::string contract_id = txn->contract_id();
        result->set_contract_id(contract_id);
        std::string rec_wallet = txn->output_address();
        std::string sender_key = rec_wallet + contract_id;
        result->set_recipient_address(rec_wallet);
        result->set_hash(txn->base().hash());
        uint256_t percent = expense_ratio.percent();
        uint256_t diviser = 100000;

        for (auto wallet : txn->addresses())
        {
            std::string wallet_balance;
            db_wallets::get_single(wallet + contract_id, wallet_balance);
            uint256_t balance(wallet_balance);
            uint256_t expense_amount = (balance * percent) / diviser;
            balance_tracker::add_txn_balance(rec_wallet, contract_id, expense_amount, txn->base().hash());
            balance_tracker::subtract_txn_balance(wallet, contract_id, expense_amount, txn->base().hash());

            zera_txn::Wallets *wallet1 = result->add_wallets();
            wallet1->set_address(wallet);
            wallet1->set_amount(boost::lexical_cast<std::string>(expense_amount));
        }

        return ZeraStatus();
    }

    ZeraStatus check_parameters_expense(const zera_txn::ExpenseRatioTXN *txn, zera_txn::ExpenseRatio &today_expense_ratio, zera_txn::TXNStatusFees &status_fees)
    {
        ZeraStatus status = zera_fees::process_interface_fees(txn->base(), status_fees);

        if (!status.ok())
        {
            return status;
        }

        zera_validator::BlockHeader new_header;
        std::string new_key;
        db_headers_tag::get_last_data(new_header, new_key);
        google::protobuf::Timestamp now_ts = new_header.timestamp();
        std::tm now = time_calc::get_start_date(now_ts);
        zera_validator::ExpenseTracker expense_tracker;
        std::string expense_data;
        db_expense_ratio::get_single(txn->contract_id(), expense_data);
        expense_tracker.ParseFromString(expense_data);

        int month = now.tm_mon + 1;
        if (expense_tracker.day() == now.tm_mday && expense_tracker.month() == month)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_expense.cpp: check_parameters: Expense ratio already processed today.", zera_txn::TXN_STATUS::EXPENSE_RATIO_DUPLICATE);
        }

        zera_txn::InstrumentContract contract;
        status = block_process::get_contract(txn->contract_id(), contract);
        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_expense.cpp: check_parameters_expense: Contract does not exist.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        std::string pub_key = wallets::get_public_key_string(txn->base().public_key());
        status = restricted_keys_check::check_restricted_keys(txn, contract, zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE);

        if (!status.ok())
        {
            return status;
        }

        for (auto expense_ratio : contract.expense_ratio())
        {
            if (expense_ratio.day() == now.tm_mday && expense_ratio.month() == month)
            {
                today_expense_ratio.CopyFrom(expense_ratio);
                return ZeraStatus();
            }
        }

        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_expense.cpp: check_parameters: Expense ratio not allowed on this day.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }
}
template <>
ZeraStatus block_process::process_txn<zera_txn::ExpenseRatioTXN>(const zera_txn::ExpenseRatioTXN *txn, zera_txn::TXNStatusFees &status_fees, zera_txn::ExpenseRatioResult *result, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address, bool sc_txn)
{
    uint64_t nonce = txn->base().nonce();

    ZeraStatus status = block_process::check_nonce(txn->base().public_key(), nonce, txn->base().hash(), sc_txn);

    if (!status.ok())
    {
        return status;
    }
    zera_txn::InstrumentContract fee_contract;
    status = block_process::get_contract(txn->base().fee_id(), fee_contract);
    if (!status.ok())
    {
        return status;
    }

    status = zera_fees::process_simple_fees(txn, status_fees, zera_txn::TRANSACTION_TYPE::EXPENSE_RATIO_TYPE, fee_address);
    
    if (!status.ok())
    {
        return status;
    }

    zera_txn::ExpenseRatio expense_ratio;
    status = check_parameters_expense(txn, expense_ratio, status_fees);

    if (status.ok())
    {
        status = process_wallets(expense_ratio, txn, result);
    }

    status_fees.set_status(status.txn_status());

    if (status.code() != ZeraStatus::Code::OK)
    {
        logging::print(status.read_status());
    }

    if (status.ok())
    {
        zera_validator::ExpenseTracker expense_tracker;
        expense_tracker.set_day(expense_ratio.day());
        expense_tracker.set_month(expense_ratio.month());
        db_expense_ratio::store_single(txn->contract_id(), expense_tracker.SerializeAsString());
    }
    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());
    status_fees.set_status(status.txn_status());
    if(!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }

    return ZeraStatus();
}