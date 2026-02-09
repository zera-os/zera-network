#include <fstream>
#include <ctime>
#include <vector>
#include "../block_process.h"
#include "../../temp_data/temp_data.h"
#include "const.h"
#include "../logging/logging.h"
#include "fees.h"
#include "base58.h"

const std::string WASM2WAT_LOCATION = "Downloads/wabt/build/wasm2wat";

const std::vector<std::string> FORBIDDEN_WASM_OPS{
    "f32.mul",
    "f64.mul",
    "f32.div",
    "f64.div",
};

namespace
{
    // RAII wrapper for temporary files
    class TempFile
    {
        std::string path_;
        bool should_delete_;

    public:
        TempFile(const std::string &path) : path_(path), should_delete_(true) {}

        ~TempFile()
        {
            if (should_delete_ && !path_.empty())
            {
                std::remove(path_.c_str()); // C++ way, more portable than system()
            }
        }

        const std::string &path() const { return path_; }
        void keep() { should_delete_ = false; }

        // Prevent copying
        TempFile(const TempFile &) = delete;
        TempFile &operator=(const TempFile &) = delete;
    };

    bool is_valid_smart_contract_name(const std::string &name)
    {
        if (name.empty())
        {
            return false;
        }

        for (char c : name)
        {
            if (!std::isalnum(c) && c != '-' && c != '_')
            {
                return false;
            }
        }

        return true;
    }
}

namespace
{
    bool smart_contract_valid(const zera_txn::SmartContractTXN *txn)
    {

        if (db_smart_contracts::exist(txn->smart_contract_name()))
        {
            logging::print("smart_contract already exists");
            return false;
        }

        if (!is_valid_smart_contract_name(txn->smart_contract_name()))
        {
            logging::print("smart_contract name is not valid");
            return false;
        }

        auto storage_file_name = base58_encode(txn->base().hash());

        // RAII objects will clean up automatically on ANY return path
        TempFile wasm_file("/tmp/" + storage_file_name + ".wasm");
        TempFile wat_file("/tmp/" + storage_file_name + ".wat");

        // 1. Write WASM file
        {
            std::ofstream out(wasm_file.path(), std::ios::binary);
            if (!out)
            {
                logging::print("Error: unable to open file for writing: " + wasm_file.path());
                return false; // ✅ TempFile destructor cleans up
            }
            out << txn->binary_code();
            // out.close() happens automatically via RAII
        }

        // 2. wasm2wat
        std::string command = WASM2WAT_LOCATION + " " + wasm_file.path() + " -o " + wat_file.path();
        int result = system(command.c_str());

        if (result != 0)
        {
            logging::print("Error: wasm2wat command failed with exit code " + std::to_string(result));
            return false; // ✅ Both TempFiles clean up automatically
        }

        // 3. Validate
        std::string wat_file_content;
        std::getline(std::ifstream(wat_file.path()), wat_file_content, '\0');

        bool is_valid = true;
        for (const auto &forbidden_op : FORBIDDEN_WASM_OPS)
        {
            if (wat_file_content.find(forbidden_op) != std::string::npos)
            {
                is_valid = false;
                logging::print("NOT VALID:", forbidden_op);
                break;
            }
        }

        // Cleanup happens automatically when TempFile objects go out of scope
        return is_valid;
    }
}

template <>
ZeraStatus block_process::process_txn<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn)
{

    logging::print("[ProcessSmartContractDeploy] deploying smart contract...", txn->smart_contract_name());

    uint64_t nonce = txn->base().nonce();
    ZeraStatus status;

    // timed txns do need to check nonce, they have already been checked on the original txn
    if (!timed)
    {
        // check nonce, if its bad return failed txn
        status = block_process::check_nonce(txn->base().public_key(), nonce, txn->base().hash(), sc_txn);

        if (!status.ok())
        {
            return status;
        }
    }

    // this checks to see if the key is valid to send this type of txn, also checks to see if key is from a validator, which is not allowed
    std::string pub_key = wallets::get_public_key_string(txn->base().public_key());
    status = block_process::check_validator(pub_key, txn_type);

    if (!status.ok())
    {
        return ZeraStatus(ZeraStatus::Code::BLOCK_FAULTY_TXN, status.message(), zera_txn::TXN_STATUS::INVALID_TXN_DATA);
    }

    // process base fees. If wallet cannot pay fees or anything else is wrong with the fees return failed txn
    status = zera_fees::process_simple_fees(txn, status_fees, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE, fee_address, sc_txn);

    if (!status.ok())
    {
        return status;
    }

    status = zera_fees::process_interface_fees(txn->base(), status_fees);

    if (status.ok())
    {
        if (!smart_contract_valid(txn))
        {
            status = ZeraStatus(ZeraStatus::Code::TXN_FAILED, "Forbidden smart contract instructions", zera_txn::TXN_STATUS::INVALID_TXN_DATA);
        }
    }

    //*****************************************************
    // STORING CONTRACT
    //*****************************************************
    // this needs to happen when block is made this will be stored on block completion
    // this only happens when the block is made becuase if the block fails after this txn, it would be tough to back track and remove this contract
    // You can see where I store this in txn_batch/batch_smart_contract.cpp which is called in store_txns.cpp which is called to store all txn data of the block
    // db_smart_contracts::store_single(txn->smart_contract_name(), txn->SerializeAsString());

    logging::print("[ProcessSmartContractDeploy] DONE");

    // nothing went wrong, status is good!
    // add nonce to nonce tracker, if block passed nonce will be stored for wallet
    std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());
    status_fees.set_status(status.txn_status());
    if (!sc_txn)
    {
        nonce_tracker::add_nonce(wallet_adr, nonce, txn->base().hash());
    }

    // if txn failed,
    if (!status.ok())
    {
        logging::print(status.read_status());
    }

    // always return a passed status if the txn is valid, this includes failed txns, only return failed if the txn is invalid which would be things like fee/public key issues
    // the status used before is to set status_fees, which stores its status state in the block
    // this one is to return is just to say if the txn will be in the block or not failed or passed
    return ZeraStatus();
}