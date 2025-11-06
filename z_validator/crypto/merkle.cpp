#include <string>
#include <vector>

#include "merkle.h"
#include "base58.h"

namespace
{
    void store_all_hashes(std::vector<std::vector<uint8_t>> &hash_list, const zera_txn::TXNS &txns)
    {
        std::vector<uint8_t> hash_vec;

        for (auto txn : txns.coin_txns()) //1
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.mint_txns())//2
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.item_mint_txns())//3
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.contract_txns())//4
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.governance_votes())//5
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.governance_proposals())//6
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.smart_contracts())//7
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.smart_contract_executes())//8
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.expense_ratios())//11
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.nft_txns())//12
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.contract_update_txns())//13
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.validator_registration_txns())//14
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.validator_heartbeat_txns())//15
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.proposal_result_txns())//16
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.expense_ratio_result_txns())//17
        {
            hash_vec.assign(txn.hash().begin(), txn.hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.delegated_voting_txns())//19
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.quash_txns())//20
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.fast_quorum_txns())//21
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.revoke_txns())//22
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.compliance_txns())//23
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.burn_sbt_txns())//24
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
        for (auto txn : txns.smart_contract_instantiate_txns())//24
        {
            hash_vec.assign(txn.base().hash().begin(), txn.base().hash().end());
            hash_list.push_back(hash_vec);
        }
    }
    void merkle_root(std::vector<std::vector<uint8_t>> &hash_list, std::string &merkle_root)
    {
        if (hash_list.size() == 0)
        {
            merkle_root = "No transactions in block";
            return;
        }
        bool first = true;
        while (hash_list.size() > 1 || first)
        {

            first = false;
            std::vector<std::vector<uint8_t>> new_hash_list;
            for (int i = 0; i < hash_list.size(); i += 2)
            {

                std::vector<uint8_t> hash1;
                std::vector<uint8_t> hash2;
                std::vector<uint8_t> new_hash;
                if (i == hash_list.size() - 1)
                {
                    hash1 = hash_list[i];
                    hash2 = hash_list[i];
                }
                else
                {
                    hash1 = hash_list[i];
                    hash2 = hash_list[i + 1];
                }
                new_hash.insert(new_hash.end(), hash1.begin(), hash1.end());
                new_hash.insert(new_hash.end(), hash2.begin(), hash2.end());
                new_hash_list.push_back(new_hash);
            }
            hash_list.swap(new_hash_list);
            new_hash_list.clear();
            for (auto appended : hash_list)
            {
                new_hash_list.push_back(Hashing::sha256_hash(appended));
            }

            hash_list.swap(new_hash_list);
        }

        merkle_root.assign(hash_list[0].begin(), hash_list[0].end());
    }
}

void merkle_tree::build_merkle_tree(zera_validator::Block *block)
{
    zera_txn::TXNS txns = block->transactions();
    std::vector<std::vector<uint8_t>> hash_list;
    std::string merkle_root_str;
    store_all_hashes(hash_list, txns);


    merkle_root(hash_list, merkle_root_str);
    block->mutable_block_header()->set_merkle_root(merkle_root_str);
}
