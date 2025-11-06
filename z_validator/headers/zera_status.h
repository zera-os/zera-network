#ifndef ERROR_CODES_H
#define ERROR_CODES_H
#include <string>
#include "txn.pb.h"

class ZeraStatus
{
public:
    enum Code
    {
        OK = 0,
        UNKNOWN_ERROR = -1,
        SIGNATURE_ERROR = -2,
        HASH_ERROR = -3,
        PROTO_ERROR = -4,
        DATABASE_ERROR = -5,
        BLOCK_HEIGHT_MISMATCH = -6,
        WALLET_ERROR = -7,
        WALLET_VALIDATOR_ERROR = -8,
        WALLET_INSUFFICIENT_FUNDS = -9,
        CONTRACT_AUTH_ERROR = -10,
        CONTRACT_ERROR = -11,
        BLOCK_FAULTY_TXN = -12,
        BLOCKCHAIN_DUPLICATE_ERROR = -13,
        COIN_TXN_ERROR = -14,
        DUPLICATE_TXN_ERROR = -15,
        MINT_ERROR = -16,
        PROPOSAL_ERROR = -17,
        VOTING_ERROR = -18,
        PARAMETER_ERROR = -19,
        TXN_FAILED = -20,
        TIME_DELAY = -21,
        NON_RESTRICTED_KEY = -22,
        NONCE_ERROR = -23,

        // Add more error codes as needed
    };

    ZeraStatus(Code code)
        : code_(code), message_(""), txn_status_(zera_txn::TXN_STATUS::OK) {}

    ZeraStatus(Code code, const std::string &message, zera_txn::TXN_STATUS txn_status)
        : code_(code), message_(message), txn_status_(txn_status) {}

    ZeraStatus(Code code, zera_txn::TXN_STATUS txn_status)
        : code_(code), message_("TXN Failed."), txn_status_(txn_status) {}

    ZeraStatus(Code code, const std::string &message)
        : code_(code), message_(message), txn_status_(zera_txn::TXN_STATUS::OK) {}

    ZeraStatus() : code_(Code::OK), message_(""), txn_status_(zera_txn::TXN_STATUS::OK) {}

    bool ok() const
    {
        return code_ == Code::OK;
    }
    zera_txn::TXN_STATUS txn_status()
    {
        return txn_status_;
    }
    Code code() const
    {
        return code_;
    }
    void prepend_message(const std::string prepend)
    {
        message_ = prepend + ": " + message_;
    }
    void append_message(const std::string append)
    {
        message_ += ": " + append;
    }
    const std::string &message() const
    {
        return message_;
    }
    
    void set_status(zera_txn::TXN_STATUS status)
    {
        txn_status_ = status;
    }

    const std::string read_status(bool only_code = false) const
    {
        std::string status;
        switch (code_)
        {
        case Code::OK:
            if (only_code)
            {
                status = "OK";
            }
            else
            {
                status = "OK: " + message_;
            }
            break;
        case Code::UNKNOWN_ERROR:
            if (only_code)
            {
                status = "UNKNOWN_ERROR";
            }
            else
            {
                status = "UNKNOWN_ERROR: " + message_;
            }
            break;
        case Code::SIGNATURE_ERROR:
            if (only_code)
            {
                status = "SIGNATURE_ERROR";
            }
            else
            {
                status = "SIGNATURE_ERROR: " + message_;
            }
            break;
        case Code::HASH_ERROR:
            if (only_code)
            {
                status = "HASH_ERROR";
            }
            else
            {
                status = "HASH_ERROR: " + message_;
            }
            break;
        case Code::PROTO_ERROR:
            if (only_code)
            {
                status = "PROTO_ERROR";
            }
            else
            {
                status = "PROTO_ERROR: " + message_;
            }
            break;
        case Code::DATABASE_ERROR:
            if (only_code)
            {
                status = "DATABASE_ERROR";
            }
            else
            {
                status = "DATABASE_ERROR: " + message_;
            }
            break;
        case Code::BLOCK_HEIGHT_MISMATCH:
            if (only_code)
            {
                status = "BLOCK_HEIGHT_MISMATCH";
            }
            else
            {
                status = "BLOCK_HEIGHT_MISMATCH: " + message_;
            }
            break;
        case Code::WALLET_ERROR:
            if (only_code)
            {
                status = "WALLET_ERROR";
            }
            else
            {
                status = "WALLET_ERROR: " + message_;
            }
            break;
        case Code::WALLET_VALIDATOR_ERROR:
            if (only_code)
            {
                status = "WALLET_VALIDATOR_ERROR";
            }
            else
            {
                status = "WALLET_VALIDATOR_ERROR: " + message_;
            }
            break;
        case Code::WALLET_INSUFFICIENT_FUNDS:
            if (only_code)
            {
                status = "WALLET_INSUFFICIENT_FUNDS";
            }
            else
            {
                status = "WALLET_INSUFFICIENT_FUNDS: " + message_;
            }
            break;
        case Code::CONTRACT_AUTH_ERROR:
            if (only_code)
            {
                status = "CONTRACT_AUTH_ERROR";
            }
            else
            {
                status = "CONTRACT_AUTH_ERROR: " + message_;
            }
            break;
        case Code::CONTRACT_ERROR:
            if (only_code)
            {
                status = "CONTRACT_ERROR";
            }
            else
            {
                status = "CONTRACT_ERROR: " + message_;
            }
            break;
        case Code::BLOCK_FAULTY_TXN:
            if (only_code)
            {
                status = "BLOCK_FAULTY_TXN";
            }
            else
            {
                status = "BLOCK_FAULTY_TXN: " + message_;
            }
            break;
        case Code::BLOCKCHAIN_DUPLICATE_ERROR:
            if (only_code)
            {
                status = "BLOCKCHAIN_DUPLICATE_ERROR";
            }
            else
            {
                status = "BLOCKCHAIN_DUPLICATE_ERROR: " + message_;
            }
            break;
        case Code::COIN_TXN_ERROR:
            if (only_code)
            {
                status = "COIN_TXN_ERROR";
            }
            else
            {
                status = "COIN_TXN_ERROR: " + message_;
            }
            break;
        case Code::DUPLICATE_TXN_ERROR:
            if (only_code)
            {
                status = "DUPLICATE_TXN_ERROR";
            }
            else
            {
                status = "DUPLICATE_TXN_ERROR: " + message_;
            }
            break;
        case Code::MINT_ERROR:
            if (only_code)
            {
                status = "MINT_ERROR";
            }
            else
            {
                status = "MINT_ERROR: " + message_;
            }
            break;
        case Code::PROPOSAL_ERROR:
            if (only_code)
            {
                status = "PROPOSAL_ERROR";
            }
            else
            {
                status = "PROPOSAL_ERROR: " + message_;
            }
            break;
        case Code::VOTING_ERROR:
            if (only_code)
            {
                status = "VOTING_ERROR";
            }
            else
            {
                status = "VOTING_ERROR: " + message_;
            }
            break;
        case Code::PARAMETER_ERROR:
            if (only_code)
            {
                status = "PARAMETER_ERROR";
            }
            else
            {
                status = "PARAMETER_ERROR: " + message_;
            }
            break;
        case Code::TXN_FAILED:
            if (only_code)
            {
                status = "TXN_FAILED";
            }
            else
            {
                status = "TXN_FAILED: " + message_;
            }
            break;
        case Code::TIME_DELAY:
            if (only_code)
            {
                status = "TIME_DELAY";
            }
            else
            {
                status = "TIME_DELAY: " + message_;
            }
            break;
        case Code::NON_RESTRICTED_KEY:
            if (only_code)
            {
                status = "NON_RESTRICTED_KEY";
            }
            else
            {
                status = "NON_RESTRICTED_KEY: " + message_;
            }
            break;
        case Code::NONCE_ERROR:
            if (only_code)
            {
                status = "NONCE_ERROR";
            }
            else
            {
                status = "NONCE_ERROR: " + message_;
            }
            break;
        default:
            if (only_code)
            {
                status = "UNKNOWN_ERROR";
            }
            else
            {
                status = "UNKNOWN_ERROR: " + message_;
            }
            break;
        }

        return status;
    }

private:
    Code code_;
    std::string message_;
    zera_txn::TXN_STATUS txn_status_;
};

#endif // ERROR_CODES_H
