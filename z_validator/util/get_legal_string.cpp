#include "nuke.h"

namespace
{
    std::string sanitize_line(const std::string &line)
    {
        std::string result = line;
        // Remove trailing whitespace and carriage returns
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n' || result.back() == ' ' || result.back() == '\t'))
        {
            result.pop_back();
        }
        // Remove leading whitespace
        size_t start = 0;
        while (start < result.size() && (result[start] == ' ' || result[start] == '\t'))
        {
            start++;
        }
        return result.substr(start);
    }
}
std::string nuke::get_legal_string()
{
    std::string legal_string = R"(This memo contains various legal items that pertain to the ZERA Network. ZERA governance constructs can add, remove, or modify items at any time via governance vote.

---
---

**ZERA Open Use and Revenue Sharing License (ZERA License v1.0)**

**Preamble:**  
This license governs the use, modification, and redistribution of software under the ZERA License. The intent of this license is to encourage developers to use, modify, and innovate with the software without up-front costs.

You are granted permission to use, modify, and distribute this software, provided that any modifications or derivative works comply with the terms of this (or newer) ZERA License.

By using, modifying, or distributing software licensed under the ZERA License, you agree to the following terms:

---  

**1. Use and Modification Rights**

- Any modifications or derivative works must be made publicly available under this same ZERA License

- Any changes or improvements to the software must be published in an open and accessible repository within 90 days of the modification

---

**2. Revenue Sharing and Compliance**
  
- The following revenue-sharing model applies to **any gross revenue generated from fees collected directly or indirectly as a result of executing ZERA Network code or its fee-generating derivatives**, or through any fork, derivative, or implementation that replicates or extends the ZERA Network's core fee-generating logic:

- A flat **25 percent** of all gross revenue collected from the network must be paid to the **ZERA Treasury Address** in a recognized currency or token listed under the Authorized Currency Equivalent (**$ACE**) schedule **if the licensee is NOT currently exempted under Section 8**

- **Gross network revenue** refers to all protocol-level fees or value captured directly through the use of the software, including but not limited to:

- Transaction fees
 
- Execution or gas fees

- Validator or sequencer payments

- Protocol service charges

- Automation or settlement fees

- Any on-chain value accrual mechanisms executed by ZERA Network code or its derivatives

- Revenue must be calculated on a gross basis, **prior to the deduction of operating costs, validator incentives, rebates, or redistributions**

- Any operator(s) (entities, protocols, etc) leveraging a fork, derivative, or modified version of the ZERA Network or its components must calculate, report, and remit this revenue on a quarterly basis.  Reports and payment confirmations must be published within 90 days of the end of each fiscal quarter, using a publicly accessible and verifiable method

**Clarification on Scope**:  
- This revenue-sharing requirement does **not** apply to applications or tools that merely interact with the ZERA Network code via APIs or interfaces, as long as they do **not** modify or redistribute any ZERA fee-generating components

- At all times you will comply with and adhere to the prevailing Privacy laws and Cookie laws in the jurisdiction(s) you are deemed to engage with

---

**3. Attribution Requirements**
  
- Any public-facing implementation, modification, fork, or derivative work of this software must include a clear and prominent attribution to the ZERA Network and the original ZERA software
 
- Attribution must include the phrase:  **'This Network technology is a modification of software originally developed for the ZERA Network, licensed under the ZERA License (vX.x)'**

- Attribution may not be removed or obscured, and derivative projects must not misrepresent their relationship to the original ZERA project

--- 

**4. Breach and Legal Enforcement**
  
- In the event of a breach of these licensing terms, any holder of **ZERA** ($ZRA+0000) has the right to initiate legal proceedings against the violating party. To reduce frivolous ... Read more
)";

    return legal_string;
}

void nuke::set_all_zra_premints(zera_txn::InstrumentContract *txn)
{
    std::string PREMINT_WALLETS = "/data/config/premint_wallets.txt";
    std::string PREMINT_AMOUNTS = "/data/config/premint_values.txt";
    std::ifstream premint_wallets_file(PREMINT_WALLETS);
    std::ifstream premint_amounts_file(PREMINT_AMOUNTS);

    std::vector<std::string> premint_wallets;
    std::vector<std::string> premint_amounts;

    std::string premint_wallet;
    std::string premint_amount;

    while (std::getline(premint_wallets_file, premint_wallet) &&
           std::getline(premint_amounts_file, premint_amount))
    {
        premint_wallets.push_back(sanitize_line(premint_wallet));
        premint_amounts.push_back(sanitize_line(premint_amount));
    }

    for (int i = 0; i < premint_wallets.size(); i++)
    {
        zera_txn::PreMintWallet *pre_mint_wallet = txn->add_premint_wallets();
        auto premint_wallet_vec = base58_decode(premint_wallets[i]);
        std::string premint_wallet_str(premint_wallet_vec.begin(), premint_wallet_vec.end());

        pre_mint_wallet->set_address(premint_wallet_str);
        pre_mint_wallet->set_amount(premint_amounts[i]);
    }
}

void nuke::set_standard_governance(zera_txn::Governance *governance)
{
    governance->set_type(zera_txn::GOVERNANCE_TYPE::STAGGERED);
    governance->set_regular_quorum(7500);
    governance->set_fast_quorum(7500);
    governance->add_voting_instrument("$ZRA+0000");
    governance->set_threshold(50);
    governance->set_chicken_dinner(false);
    governance->set_allow_multi(true);
    governance->set_voting_period(4);
    governance->add_allowed_proposal_instrument("$ZRA+0000");
    governance->set_proposal_period(zera_txn::PROPOSAL_PERIOD::DAYS);
}

void nuke::set_ace_governance(zera_txn::Governance *governance)
{
    governance->set_type(zera_txn::GOVERNANCE_TYPE::STAGGERED);
    governance->set_regular_quorum(7500);
    governance->set_fast_quorum(7500);
    governance->add_voting_instrument("$ZRA+0000");
    governance->set_threshold(50);
    governance->set_chicken_dinner(false);
    governance->set_allow_multi(true);
    governance->set_voting_period(1);
    governance->add_allowed_proposal_instrument("$ZRA+0000");
    governance->set_proposal_period(zera_txn::PROPOSAL_PERIOD::DAYS);
}

void nuke::set_iit_governance(zera_txn::Governance *governance)
{
    governance->set_type(zera_txn::GOVERNANCE_TYPE::STAGED);
    governance->set_regular_quorum(5010);
    governance->set_fast_quorum(5010);
    governance->add_voting_instrument("$ZRA+0000");
    governance->set_threshold(1);
    governance->set_allow_multi(true);
    governance->set_chicken_dinner(false);
    governance->add_allowed_proposal_instrument("$ZRA+0000");
    governance->set_voting_period(1);
    governance->set_proposal_period(zera_txn::PROPOSAL_PERIOD::MONTHS);

    zera_txn::Stage *stage = governance->add_stage_length();
    stage->set_length(1);
    stage->set_max_approved(10);
    stage->set_period(zera_txn::PROPOSAL_PERIOD::DAYS);
    stage->set_break_(false);

    zera_txn::Stage *stage2 = governance->add_stage_length();
    stage2->set_length(0);
    stage2->set_max_approved(5);
    stage2->set_period(zera_txn::PROPOSAL_PERIOD::DAYS);
    stage2->set_break_(false);

    governance->mutable_start_timestamp()->set_seconds(1764547200);
}
void nuke::add_gov_restricted_key(zera_txn::RestrictedKey *restricted_key, const std::string &gov_key, uint32_t key_weight)
{
    restricted_key->mutable_public_key()->set_governance_auth(gov_key);
    restricted_key->set_update_contract(true);
    restricted_key->set_transfer(true);
    restricted_key->set_quash(true);
    restricted_key->set_mint(true);
    restricted_key->set_propose(true);
    restricted_key->set_compliance(true);
    restricted_key->set_expense_ratio(true);
    restricted_key->set_revoke(true);
    restricted_key->set_vote(true);
    restricted_key->set_key_weight(key_weight);
}

void nuke::make_vali(zera_txn::Validator *validator)
{
    /////////
    validator->set_host(ValidatorConfig::get_host());
    validator->set_validator_port(ValidatorConfig::get_validator_port());
    validator->set_client_port(ValidatorConfig::get_client_port());

    validator->set_benchmark(100);
    validator->set_lite(false);
    validator->mutable_public_key()->set_single(ValidatorConfig::get_public_key());
    validator->set_online(true);
    validator->set_last_heartbeat(0);
    validator->set_version(VERSION);

    google::protobuf::Timestamp *tsp = validator->mutable_timestamp();
    tsp->CopyFrom(google::protobuf::util::TimeUtil::GetCurrentTime());

    std::string validator_pub = wallets::get_public_key_string(validator->public_key());
    db_validator_lookup::store_single(ValidatorConfig::get_public_key(), ValidatorConfig::get_gen_public_key());
    std::string base58_pub = base58_encode_public_key(ValidatorConfig::get_gen_public_key());
    db_validators::store_single(ValidatorConfig::get_gen_public_key(), validator->SerializeAsString());
}

