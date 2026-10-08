#include <fstream>
#include <ctime>
#include <vector>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include "../block_process.h"
#include "../../temp_data/temp_data.h"
#include "const.h"
#include "../logging/logging.h"
#include "fees.h"
#include "base58.h"

// WASM2WAT_LOCATION and its release-pinned hash live in const.h; the binary is
// verified against the pinned hash at startup (see startup_config.cpp).

// wasm2wat runs deterministically on every validator while processing a block,
// so an input that hangs or blows up the tool would stall the whole network at
// the same block. The child is therefore sandboxed: a wall-clock timeout plus
// CPU/address-space/file-size rlimits bound the work regardless of input.
constexpr unsigned int WASM2WAT_TIMEOUT_SECONDS = 10;              // wall-clock ceiling
constexpr rlim_t WASM2WAT_CPU_SECONDS = 10;                        // RLIMIT_CPU
constexpr rlim_t WASM2WAT_MEM_BYTES = 1024ull * 1024 * 1024;       // RLIMIT_AS (1 GB)
constexpr rlim_t WASM2WAT_FSIZE_BYTES = 256ull * 1024 * 1024;      // RLIMIT_FSIZE (.wat output cap)
constexpr std::streamsize MAX_WAT_READ_BYTES = 256ll * 1024 * 1024; // ceiling when reading .wat back

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

    // Run wasm2wat as a direct child process (argv, no shell) with resource
    // limits and a wall-clock timeout. Returns true only if the tool exited
    // cleanly (status 0) within the bounds. Any timeout, signal death (e.g. the
    // kernel killing it on RLIMIT_CPU) or non-zero exit returns false.
    //
    // This replaces system(), which spawned a shell, applied no limits and no
    // timeout, and would block forever on a hanging tool -- deterministically
    // stalling every validator at the same block.
    bool run_wasm2wat(const std::string &wasm_path, const std::string &wat_path)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            logging::print("Error: fork failed for wasm2wat: " + std::string(std::strerror(errno)));
            return false;
        }

        if (pid == 0)
        {
            // Child: clamp resources, then exec the tool directly (no shell, so
            // nothing in argv is interpreted -- also removes any injection surface).
            struct rlimit rl;

            rl.rlim_cur = WASM2WAT_CPU_SECONDS;
            rl.rlim_max = WASM2WAT_CPU_SECONDS;
            setrlimit(RLIMIT_CPU, &rl);

            rl.rlim_cur = WASM2WAT_MEM_BYTES;
            rl.rlim_max = WASM2WAT_MEM_BYTES;
            setrlimit(RLIMIT_AS, &rl);

            rl.rlim_cur = WASM2WAT_FSIZE_BYTES;
            rl.rlim_max = WASM2WAT_FSIZE_BYTES;
            setrlimit(RLIMIT_FSIZE, &rl);

            const char *argv[] = {
                WASM2WAT_LOCATION.c_str(),
                wasm_path.c_str(),
                "-o",
                wat_path.c_str(),
                nullptr};

            execv(WASM2WAT_LOCATION.c_str(), const_cast<char *const *>(argv));
            // execv only returns on failure.
            _exit(127);
        }

        // Parent: poll for completion, enforcing a wall-clock timeout.
        const unsigned int poll_interval_us = 50000; // 50ms
        const unsigned int max_polls = (WASM2WAT_TIMEOUT_SECONDS * 1000000u) / poll_interval_us;

        for (unsigned int i = 0; i < max_polls; ++i)
        {
            int wstatus = 0;
            pid_t r = waitpid(pid, &wstatus, WNOHANG);

            if (r == pid)
            {
                if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0)
                {
                    return true;
                }

                if (WIFSIGNALED(wstatus))
                {
                    logging::print("Error: wasm2wat killed by signal " + std::to_string(WTERMSIG(wstatus)));
                }
                else
                {
                    logging::print("Error: wasm2wat exited with code " + std::to_string(WEXITSTATUS(wstatus)));
                }
                return false;
            }

            if (r < 0)
            {
                logging::print("Error: waitpid failed for wasm2wat: " + std::string(std::strerror(errno)));
                return false;
            }

            usleep(poll_interval_us);
        }

        // Timed out: kill the child and reap it so it doesn't linger as a zombie.
        logging::print("Error: wasm2wat timed out after " + std::to_string(WASM2WAT_TIMEOUT_SECONDS) + "s; killing child");
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        return false;
    }

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

        // 2. wasm2wat (sandboxed: no shell, resource limits, wall-clock timeout)
        if (!run_wasm2wat(wasm_file.path(), wat_file.path()))
        {
            return false; // ✅ Both TempFiles clean up automatically
        }

        // 3. Validate
        // Read the .wat back with an explicit ceiling. A dense ~4 MB wasm can
        // expand into a hundreds-of-MB .wat, so an unbounded read (previously
        // getline(..., '\0') over the whole file) could balloon memory well
        // beyond the input size. RLIMIT_FSIZE bounds what the child can write;
        // this bounds what we pull back into memory.
        std::string wat_file_content;
        {
            std::ifstream wat_in(wat_file.path(), std::ios::binary);
            if (!wat_in)
            {
                logging::print("Error: unable to open wat file for reading: " + wat_file.path());
                return false;
            }

            wat_file_content.resize(static_cast<size_t>(MAX_WAT_READ_BYTES));
            wat_in.read(&wat_file_content[0], MAX_WAT_READ_BYTES);
            wat_file_content.resize(static_cast<size_t>(wat_in.gcount()));

            if (wat_in.gcount() == MAX_WAT_READ_BYTES && wat_in.peek() != std::char_traits<char>::eof())
            {
                logging::print("Error: wat output exceeds read ceiling of " + std::to_string(MAX_WAT_READ_BYTES) + " bytes");
                return false;
            }
        }

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
ZeraStatus block_process::process_txn<zera_txn::SmartContractTXN>(const zera_txn::SmartContractTXN *txn, zera_txn::TXNStatusFees &status_fees, const zera_txn::TRANSACTION_TYPE &txn_type, bool timed, const std::string &fee_address, bool sc_txn, const std::string &sc_fee_address)
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
    status = zera_fees::process_simple_fees(txn, status_fees, zera_txn::TRANSACTION_TYPE::SMART_CONTRACT_TYPE, fee_address, sc_txn, sc_fee_address);

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