#pragma once

// Standard library headers
#include <string>

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>

// Project-specific headers
#include "txn.pb.h"
#include "wallet.pb.h"
#include "zera_status.h"

using uint256_t = boost::multiprecision::uint256_t;

class zera_fees
{
    public:
    enum ALLOWED_CONTRACT_FEE
    {
        ANY = 0,
        QUALIFIED = 1,
        ALLOWED = 2,
        NOT_ALLOWED = 3
    };

    static ZeraStatus process_interface_fees(const zera_txn::BaseTXN &base, zera_txn::TXNStatusFees &status_fees);
    static ZeraStatus process_interface_fees(const zera_txn::CoinTXN *txn, zera_txn::TXNStatusFees &status_fees);

    static ZeraStatus process_fees(const zera_txn::InstrumentContract &contract, uint256_t fee_amount,
                                   const std::string &wallet_adr, const std::string &fee_symbol,
                                   bool base, zera_txn::TXNStatusFees &status_fees, const std::string &txn_hash, const std::string &current_validator_address = "", const bool storage_fees = false);

    static ZeraStatus calculate_fees(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                     const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const zera_txn::PublicKey &public_key, const std::string &contract_id, const bool safe_send = false);

    static ZeraStatus calculate_fees(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                     const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const std::string &contract_id, const bool safe_send = false);

    static ZeraStatus calculate_fees_heartbeat(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                               const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const zera_txn::PublicKey &public_key,const std::string &contract_id);

    static bool check_qualified(const std::string &contract_id);

    static ZeraStatus check_allowed_contract_fee(const google::protobuf::RepeatedPtrField<std::string> &allowed_fees, const std::string contract_id, zera_fees::ALLOWED_CONTRACT_FEE &allowed_fee);

    static bool get_cur_equiv(const std::string &contract_id, uint256_t &cur_equiv);
    static bool get_cur_equiv_validator(const std::string &contract_id, uint256_t &cur_equiv);

    template <typename TXType>
    static ZeraStatus process_simple_fees(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address = "", const bool &sc_txn = false, const std::string &sc_fee_address = "");

    template <typename TXType>
    static ZeraStatus process_simple_fees_gas(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address = "", const bool &sc_txn = false, const std::string &sc_fee_address = "");

};

// Charge an internal smart contract txn's network fee as gas drawn from the live
// contract's approved gas budget (the global execution sender). usd_fee is the fee
// in USD fee-units BEFORE any denomination/equiv/multiplier conversion (i.e.
// fee_per_byte * bytes + key fees + first-time wallet fees). Accumulates into
// sender.txn_fee_gas (settled only on success). Returns false if the budget cannot
// afford it, in which case the internal txn should fail with OUT_OF_GAS.
// Implemented in smart_contract/helpers/nf_fee_helper.cpp; declared here (and not
// in nf_helpers.h) so block_process callers don't have to pull in wasmedge.h.
bool consume_sc_txn_fee_gas(const uint256_t &usd_fee);