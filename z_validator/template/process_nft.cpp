#include "proposer.h"
#include "utils.h"
#include "../../temp_data/temp_data.h"
#include "zera_status.h"
#include "wallets.h"
#include "validators.h"
#include "../block_process.h"
#include "../compliance/compliance.h"
#include "fees.h"

namespace
{

    ZeraStatus calculate_contract_fee(const zera_txn::InstrumentContract &contract, const zera_validator::NFT &nft, const zera_txn::NFTTXN *txn, uint256_t &contract_fee_amount)
    {

        zera_fees::ALLOWED_CONTRACT_FEE allowed_fee;
        ZeraStatus status = zera_fees::check_allowed_contract_fee(nft.contract_fees().allowed_fee_instrument(), txn->contract_fee_id(), allowed_fee);

        if (!status.ok())
        {
            return status;
        }
        if (allowed_fee == zera_fees::ALLOWED_CONTRACT_FEE::QUALIFIED)
        {
            if (!zera_fees::check_qualified(txn->contract_fee_id()))
            {
                return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: calculate_contract_fee: Contract requires qualified token fees", zera_txn::TXN_STATUS::INVALID_CONTRACT_FEE_ID);
            }
        }

        // get the currency equivalent multiplier
        uint256_t fee_equiv;
        if(zera_fees::get_cur_equiv(txn->contract_fee_id(), fee_equiv))
        {
            fee_equiv = ONE_DOLLAR;
        }

        uint256_t denomination(contract.coin_denomination().amount());
        uint256_t contract_fee(nft.contract_fees().fee());
        uint256_t item_fee = (denomination * contract_fee);
        contract_fee_amount = (item_fee / fee_equiv);

        uint256_t authorized(txn->contract_fee_amount());
        if (authorized < contract_fee_amount)
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: calculate_contract_fee: sender did not authorize enough contract fees", zera_txn::TXN_STATUS::AUTHORIZED_INSUFFICIENT_CONTRACT_FEES);
        }

        return ZeraStatus();
    }

    ZeraStatus process_contract_fees(const zera_validator::NFT &nft, uint256_t fee_amount,
                                     const std::string &wallet_adr, const std::string &fee_symbol, zera_txn::TXNStatusFees &status_fees, const std::string &txn_hash)
    {

        const uint256_t zero_256 = 0;
        uint256_t sender_balance;
        std::string sender_key = wallet_adr + fee_symbol;

        ZeraStatus status = balance_tracker::subtract_txn_balance(wallet_adr, fee_symbol, fee_amount, txn_hash);

        if (!status.ok())
        {
            return status;
        }

        auto tres_wallet_vec = base58_decode(ValidatorConfig::get_treasury_wallet());
        std::string treasury_wallet(tres_wallet_vec.begin(), tres_wallet_vec.end());

        uint256_t burn_percent = 0;
        uint256_t validator_percent = 0;
        uint256_t treasury_percent = 0;
        uint256_t contract_percent = 0;

        uint256_t validator_fee = 0;
        uint256_t contract_fee = 0;
        uint256_t treasury_fee = 0;
        uint256_t burn_fee = 0;

        burn_percent = boost::lexical_cast<uint256_t>(nft.contract_fees().burn());
        validator_percent = boost::lexical_cast<uint256_t>(nft.contract_fees().validator());
        treasury_percent = boost::lexical_cast<uint256_t>(nft.contract_fees().burn());
        contract_percent = 100 - burn_percent - treasury_percent;

        if (validator_percent > zero_256)
        {
            validator_fee = (validator_percent * fee_amount) / 100;
            std::string validator_adr = ValidatorConfig::get_fee_address_string();
            balance_tracker::add_txn_balance(validator_adr, fee_symbol, validator_fee, txn_hash);
            proposing::set_txn_token_fees(txn_hash, fee_symbol, validator_adr, validator_fee);
        }
        if (treasury_percent > zero_256)
        {
            treasury_fee = (treasury_percent * fee_amount) / 100;
            balance_tracker::add_txn_balance(treasury_wallet, fee_symbol, treasury_fee, txn_hash);
            proposing::set_txn_token_fees(txn_hash, fee_symbol, treasury_wallet, treasury_fee);
        }

        if (contract_percent > zero_256)
        {
            contract_fee = fee_amount - validator_fee - burn_fee;
            balance_tracker::add_txn_balance(nft.contract_fees().fee_address(), fee_symbol, contract_fee, txn_hash);
            proposing::set_txn_token_fees(txn_hash, fee_symbol, nft.contract_fees().fee_address(), contract_fee);
        }

        status_fees.set_base_contract_id(fee_symbol);
        status_fees.set_base_fees(boost::lexical_cast<std::string>(fee_amount));
        // verification of balance was verified, add new balance to sender balances

        return ZeraStatus(ZeraStatus::Code::OK);
    }

}

template <>
ZeraStatus block_process::check_parameters<zera_txn::NFTTXN>(const zera_txn::NFTTXN *txn, zera_txn::TXNStatusFees &status_fees, const std::string &fee_address)
{
    if (!check_safe_send(txn->base(), txn->recipient_address()))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: process_txn: NFT transactions cannot be safe send.", zera_txn::TXN_STATUS::INVALID_SAFE_SEND);
    }
    zera_txn::InstrumentContract contract;
    ZeraStatus status = get_contract(txn->contract_id(), contract);
    if(!status.ok())
    {
        return status;
    }

    auto wallet_address = wallets::generate_wallet(txn->base().public_key());
    
    if (!compliance::check_compliance(wallet_address, contract))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
    }

    if (!compliance::check_compliance(txn->recipient_address(), contract))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_coin.cpp: process_transfer: Compliance check failed. output wallet.", zera_txn::TXN_STATUS::COMPLIANCE_CHECK_FAILED);
    }

    if(contract.type() != zera_txn::NFT)
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: check_parameters: contract is not NFT", zera_txn::TXN_STATUS::INVALID_CONTRACT);
    }
    std::string nft_data;
    zera_validator::NFT nft;
    if (!db_contract_items::get_single(txn->item_id() + txn->contract_id(), nft_data) || !nft.ParseFromString(nft_data))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: check_nft: nft does not exist.", zera_txn::TXN_STATUS::INVALID_NFT);
    }

    if (nft.holder_address() != wallets::generate_wallet(txn->base().public_key()))
    {
        return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: check_nft: Client does not own nft.", zera_txn::TXN_STATUS::NFT_OWNERSHIP);
    }

    if (nft.has_contract_fees())
    {
        std::string contract_data;
        zera_txn::InstrumentContract contract;
        if (!db_contracts::get_single(txn->contract_fee_id(), contract_data) || !contract.ParseFromString(contract_data))
        {
            return ZeraStatus(ZeraStatus::Code::TXN_FAILED, "process_nft.cpp: check_nft: Contract fee token does not exist. " + txn->contract_fee_id(), zera_txn::TXN_STATUS::INVALID_CONTRACT);
        }

        uint256_t contract_fee_amount;
        ZeraStatus status = calculate_contract_fee(contract, nft, txn, contract_fee_amount);
        if (!status.ok())
        {
            return status;
        }

        std::string wallet_adr = wallets::generate_wallet(txn->base().public_key());
        status = process_contract_fees(nft, contract_fee_amount, wallet_adr, txn->contract_fee_id(), status_fees, txn->base().hash());

        if (!status.ok())
        {
            return status;
        }
    }
    return ZeraStatus();
}
