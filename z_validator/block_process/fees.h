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
                                     const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const zera_txn::PublicKey &public_key, const bool safe_send = false);

    static ZeraStatus calculate_fees(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                     const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const bool safe_send = false);

    static ZeraStatus calculate_fees_heartbeat(const uint256_t &TOKEN_USD_EQIV, const uint256_t &FEE_PER_BYTE, const int &bytes,
                                               const std::string &authorized_fees, uint256_t &txn_fee_amount, std::string denomination_str, const zera_txn::PublicKey &public_key);

    static bool check_qualified(const std::string &contract_id);

    static ZeraStatus check_allowed_contract_fee(const google::protobuf::RepeatedPtrField<std::string> &allowed_fees, const std::string contract_id, zera_fees::ALLOWED_CONTRACT_FEE &allowed_fee);

    static bool get_cur_equiv(const std::string &contract_id, uint256_t &cur_equiv);

    template <typename TXType>
    static ZeraStatus process_simple_fees(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, const std::string &fee_address = "");

    template <typename TXType>
    static ZeraStatus process_simple_fees_gas(const TXType *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, uint256_t &fee_amount, const std::string &fee_address = "");

};