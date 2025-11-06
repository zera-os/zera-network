#include <regex>

#include "../block_process.h"
#include "../../temp_data/temp_data.h"
#include "utils.h"
#include "../restricted/restricted_keys.h"
#include "../logging/logging.h"
#include "fees.h"

namespace
{
    ZeraStatus check_contract(const std::string &contract_id)
    {
        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(contract_id, contract);
        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_cur_equiv.cpp: check_contract: Contract does not exist. - " + contract_id, zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        if (contract.type() != zera_txn::CONTRACT_TYPE::TOKEN)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_cur_equiv.cpp: check_contract: Contract is not a token.", zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        return ZeraStatus();
    }

    ZeraStatus check_restricted(const std::string &contract_id, std::string public_key)
    {
        zera_txn::InstrumentContract contract;
        ZeraStatus status = block_process::get_contract(contract_id, contract);
        if (!status.ok())
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_cur_equiv.cpp: check_restricted: Contract does not exist. - " + contract_id, zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        std::regex pattern("^\\:.*");

        for (auto r_keys : contract.restricted_keys())
        {
            std::string r_public_key = *(r_keys.mutable_public_key()->mutable_single());
            if (std::regex_match(r_public_key, pattern))
            {
                std::string inherited = r_keys.mutable_public_key()->mutable_single()->substr(1);
                zera_txn::InstrumentContract inherited_contract;
                ZeraStatus status = block_process::get_contract(inherited, inherited_contract);

                if (!status.ok())
                {
                    break;
                }

                for (auto inherited_key : inherited_contract.restricted_keys())
                {
                    std::string pub_key = wallets::get_public_key_string(inherited_key.public_key());
                    if (pub_key == public_key)
                    {
                        return ZeraStatus();
                    }
                }
            }

            std::string pub_key = wallets::get_public_key_string(r_keys.public_key());
            if (pub_key == public_key)
            {
                return ZeraStatus();
            }
        }

        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_cur_equiv.cpp: check_restricted: Public key is not authorized to use this contract.", zera_txn::TXN_STATUS::INVALID_AUTH_KEY);
    }
}