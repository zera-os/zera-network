#include "txn_batch.h"
#include "db_base.h"
#include "base58.h"
#include "validators.h"
#include "../logging/logging.h"
#include <ctime>
#include <chrono>
#include "wallets.h"

void txn_batch::batch_allowance_txns(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed, const uint64_t &block_time)
{
    rocksdb::WriteBatch allowance_batch;

    for (auto allowance : txns.allowance_txns())
    {
        if (txn_passed.at(allowance.base().hash()))
        {
            std::string contract_id = allowance.contract_id();
            zera_validator::AllowanceState state;

            auto wallet = wallets::generate_wallet(allowance.base().public_key());
            std::string key = wallet + allowance.wallet_address() + contract_id;

            if (!allowance.authorize())
            {
                allowance_batch.Delete(key);
                allowance_batch.Delete("PRE_" + key);
                continue;
            }

            state.mutable_public_key()->CopyFrom(allowance.base().public_key());

            if (allowance.has_allowed_currency_equivalent())
            {
                state.set_allowed_currency_equivalent(allowance.allowed_currency_equivalent());
            }
            else if (allowance.has_allowed_amount())
            {
                state.set_allowed_amount(allowance.allowed_amount());
            }

            if (allowance.has_period_months())
            {
                state.set_period_months(allowance.period_months());
            }
            else if (allowance.has_period_seconds())
            {
                state.set_period_seconds(allowance.period_seconds());
            }

            state.mutable_start_time()->CopyFrom(allowance.start_time());
            state.set_used_amount("0");

            if (state.start_time().seconds() == 0)
            {
                state.mutable_start_time()->set_seconds(block_time);
            }

            uint64_t period_end = state.start_time().seconds();
            if (state.has_period_seconds() && state.period_seconds() > 0)
            {
                if (period_end < block_time)
                {
                    // Calculate the number of periods needed to reach or exceed block_time
                    uint64_t periods = (block_time - period_end + state.period_seconds() - 1) / state.period_seconds();
                    period_end += periods * state.period_seconds();
                }
            }
            else if (state.has_period_seconds() && state.period_seconds() == 0)
            {
                period_end = 0;
            }
            else if (state.has_period_months())
            {
                // Convert period_end (seconds since epoch) to a tm structure
                std::time_t period_end_time_t = static_cast<std::time_t>(period_end);
                std::tm period_end_tm = *std::gmtime(&period_end_time_t);

                // Calculate the number of months to add
                uint32_t months_to_add = state.period_months();

                // Break months_to_add into years and remaining months
                uint32_t years_to_add = months_to_add / 12; // Calculate full years
                uint32_t remaining_months_to_add = months_to_add % 12;

                while (std::mktime(&period_end_tm) < static_cast<std::time_t>(block_time))
                {
                    period_end_tm.tm_year += years_to_add; // Add full years
                    period_end_tm.tm_mon += remaining_months_to_add;

                    // Normalize the time structure
                    period_end = static_cast<uint64_t>(std::mktime(&period_end_tm));
                }
            }

            state.mutable_period_end()->set_seconds(period_end);
            allowance_batch.Delete("PRE_" + key);
            allowance_batch.Put(key, state.SerializeAsString());
        }
    }
    db_allowance::store_batch(allowance_batch);
}

void txn_batch::batch_required_version(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    if (txns.has_required_version_txn())
    {

        zera_txn::RequiredVersion required_version = txns.required_version_txn();
        required_version.CopyFrom(txns.required_version_txn());

        if (txn_passed.at(required_version.base().hash()))
        {
            ValidatorConfig::set_required_version(required_version.version(0));
            db_system::remove_single(REQUIRED_VERSION);
            db_system::store_single(REQUIRED_VERSION, required_version.SerializeAsString());
        }
    }
}

void txn_batch::batch_revoke(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{

    rocksdb::WriteBatch revoke_batch;

    for (auto revoke : txns.revoke_txns())
    {
        if (txn_passed.at(revoke.base().hash()))
        {
            revoke_batch.Delete(revoke.item_id() + revoke.contract_id());
        }
    }

    db_contract_items::store_batch(revoke_batch);
}
void txn_batch::batch_compliance(const zera_txn::TXNS &txns, const std::map<std::string, bool> &txn_passed)
{
    rocksdb::WriteBatch compliance_batch;
    for (auto compliance : txns.compliance_txns())
    {
        if (txn_passed.at(compliance.base().hash()))
        {
            for (auto compliance_assign : compliance.compliance())
            {
                std::string compliance_data;
                zera_validator::WalletLookup wallet_lookup;

                if (db_wallet_lookup::get_single(compliance_assign.recipient_address(), compliance_data))
                {
                    wallet_lookup.ParseFromString(compliance_data);
                }

                auto compliance_map = wallet_lookup.mutable_compliance();
                bool continue_while = true;
                while (continue_while)
                {
                    auto it = compliance_map->find(compliance.contract_id());
                    if (it != compliance_map->end())
                    {
                        // Key exists, remove the item from the repeated field
                        auto &compliance_levels = it->second;
                        auto levels = compliance_levels.mutable_levels();
                        bool found = false;
                        for (int i = 0; i < levels->size(); ++i)
                        {
                            if (levels->Get(i).level() == compliance_assign.compliance_level())
                            {
                                levels->SwapElements(i, levels->size() - 1);
                                levels->RemoveLast();
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            continue_while = false;
                        }
                    }
                    else
                    {
                        continue_while = false;
                    }
                }
                if (compliance_assign.assign_revoke())
                {
                    zera_validator::ComplianceData data;

                    data.set_level(compliance_assign.compliance_level());
                    data.mutable_expiry()->CopyFrom(compliance_assign.expiry());

                    (*wallet_lookup.mutable_compliance())[compliance.contract_id()].add_levels()->CopyFrom(data);
                    for (auto levels : (*wallet_lookup.mutable_compliance())[compliance.contract_id()].levels())
                    {
                    }
                }

                compliance_batch.Put(compliance_assign.recipient_address(), wallet_lookup.SerializeAsString());

                db_wallet_lookup::store_batch(compliance_batch);
            }
        }
    }
}