#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>

// ===== Existing types =====

struct SmartContractState
{
    std::string smart_contract;
    std::string instance;
};

struct AllStakers
{
    std::map<std::string, uint8_t> staker_states;
};

struct WalletStake
{
    uint64_t principle;
    uint64_t total_reward;
    uint64_t daily_release;
    uint64_t total_released;
    uint64_t last_reward_day;
    std::string term;
};

struct LiquidStake
{
    uint64_t bump_id;
    uint64_t principle;
    uint64_t last_reward_day;
    uint64_t daily_release;
    uint64_t unstake_day;
};

struct AllWalletStakes
{
    std::map<std::string, WalletStake> staker_states;
    LiquidStake liquid_stake;
};

struct LiquidityPool
{
    std::string token1;
    std::string token2;
    std::string lp_token_id;
    std::string token1_volume;
    std::string token2_volume;
    std::string circulating_lp_tokens;
    bool active;
    std::string derived_wallet;
    std::string redeemed_lp_tokens;
    uint64_t fee_percent;
};

struct NetworkValues
{
    std::vector<std::string> values;
};

struct InstantStake
{
    uint64_t principle;
    uint64_t total_reward;
    uint64_t release_day;
    std::string term;
};

struct AllInstantStakers
{
    std::map<std::string, uint8_t> staker_states;
    uint64_t earliest_release_day;
};

struct AllWalletInstantStakes
{
    std::map<std::string, InstantStake> staker_states;
};

// ===== Enums =====

enum class SenderType : uint32_t
{
    Delegate = 0,
    Current = 1,
    ContractBefore = 2,
    OriginalContract = 3,
    User = 4
};

enum class TransactionType : uint32_t
{
    UnknownType = 0,
    CoinType = 1,
    MintType = 2,
    ItemMintType = 3,
    ContractTxnType = 4,
    VoteType = 5,
    ProposalType = 6,
    SmartContractType = 7,
    SmartContractExecuteType = 8,
    ExpenseRatioType = 9,
    NftType = 10,
    UpdateContractType = 11,
    ValidatorRegistrationType = 12,
    ValidatorHeartbeatType = 13,
    ProposalResultType = 14,
    DelegatedVotingType = 15,
    RevokeType = 16,
    QuashType = 17,
    FastQuorumType = 18,
    ComplianceType = 19,
    SbtBurnType = 20,
    RequiredVersion = 21,
    SmartContractInstantiateType = 22,
    AllowanceType = 23,
    ProposalCancelType = 24,
};

enum class ContractFeeType : uint32_t
{
    None = 0,
    Fixed = 1,
    CurEquivalent = 2,
    Percentage = 3,
};

enum class GovernanceType : uint32_t
{
    Adaptive = 0,
    Staged = 1,
    Cycle = 2,
    Staggered = 3,
    Remove = 4,
};

enum class ProposalPeriod : uint32_t
{
    Days = 0,
    Months = 1,
};

enum class ContractType : uint32_t
{
    Token = 0,
    Nft = 1,
    Sbt = 2,
};

// ===== Structs =====

struct Sender
{
    SenderType type;
    std::string sc_name;
    std::string sc_instance;
};

struct NetworkTXN
{
    TransactionType txn_type;
    std::string payload;
    Sender sender;
};

struct ProtoTimestamp
{
    int64_t seconds;
    int32_t nanos;
};

struct MultiPatterns
{
    std::vector<uint32_t> pattern_class;
    std::vector<uint32_t> required;
};

struct MultiKey
{
    std::vector<std::string> public_keys;
    std::vector<std::vector<uint8_t>> signatures;
    std::vector<MultiPatterns> multi_patterns;
    std::vector<std::string> hash_tokens;
};

struct PublicKey
{
    std::string single;
    std::optional<MultiKey> multi;
    std::optional<std::string> smart_contract_auth;
    std::optional<std::string> governance_auth;
};

struct RestrictedKey
{
    PublicKey public_key;
    int64_t time_delay;
    bool global;
    bool update_contract;
    bool transfer;
    bool quash;
    bool mint;
    bool vote;
    bool propose;
    bool compliance;
    bool expense_ratio;
    bool revoke;
    uint32_t key_weight;
};

struct ContractFees
{
    std::string fee;
    std::optional<std::string> fee_address;
    std::string burn;
    std::string validator;
    std::vector<std::string> allowed_fee_instrument;
    ContractFeeType contract_fee_type;
};

struct KeyValuePair
{
    std::string key;
    std::string value;
};

struct ExpenseRatio
{
    uint32_t day;
    uint32_t month;
    uint32_t percent;
};

struct ComplianceEntry
{
    std::string contract_id;
    uint32_t compliance_level;
};

struct TokenCompliance
{
    std::vector<ComplianceEntry> compliance;
};

struct Stage
{
    uint32_t length;
    ProposalPeriod period;
    bool break_stage;
    uint32_t max_approved;
};

struct Governance
{
    GovernanceType governance_type;
    uint32_t regular_quorum;
    std::optional<uint32_t> fast_quorum;
    std::vector<std::string> voting_instrument;
    uint32_t threshold;
    std::optional<bool> chicken_dinner;
    bool allow_multi;
    std::optional<uint32_t> voting_period;
    std::vector<std::string> allowed_proposal_instrument;
    std::optional<ProposalPeriod> proposal_period;
    std::vector<Stage> stage_length;
    std::optional<ProtoTimestamp> start_timestamp;
    std::optional<uint32_t> max_approved;
};

struct ContractUpdateTXN
{
    std::string contract_id;
    uint64_t contract_version;
    std::optional<std::string> name;
    std::optional<Governance> governance;
    std::vector<RestrictedKey> restricted_keys;
    std::optional<ContractFees> contract_fees;
    std::vector<KeyValuePair> custom_parameters;
    std::vector<ExpenseRatio> expense_ratio;
    std::vector<TokenCompliance> token_compliance;
    std::optional<bool> kyc_status;
    std::optional<bool> immutable_kyc_status;
    std::optional<uint32_t> quash_threshold;
};

struct PreMintWallet
{
    std::string address;
    std::string amount;
};

struct CoinDenomination
{
    std::string denomination_name;
    std::string amount;
};

struct MaxSupplyRelease
{
    ProtoTimestamp release_date;
    std::string amount;
};

struct TransferAuthentication
{
    std::vector<PublicKey> public_key;
    std::vector<std::vector<uint8_t>> signature;
    std::vector<uint64_t> nonce;
    std::vector<std::string> allowance_address;
    std::vector<uint64_t> allowance_nonce;
};

struct InputTransfers
{
    uint64_t index;
    std::string amount;
    uint32_t fee_percent;
    std::optional<uint32_t> contract_fee_percent;
};

struct OutputTransfers
{
    std::string wallet_address;
    std::string amount;
    std::optional<std::string> memo;
};

struct CoinTXN
{
    std::string contract_id;
    TransferAuthentication auth;
    std::vector<InputTransfers> input_transfers;
    std::vector<OutputTransfers> output_transfers;
    std::optional<std::string> contract_fee_id;
    std::optional<std::string> contract_fee_amount;
};

struct MintTXN
{
    std::string contract_id;
    std::string amount;
    std::string recipient_address;
};

struct InstrumentContractTXN
{
    uint64_t contract_version;
    std::string symbol;
    std::string name;
    std::optional<Governance> governance;
    std::vector<RestrictedKey> restricted_keys;
    std::optional<std::string> max_supply;
    std::optional<ContractFees> contract_fees;
    std::vector<PreMintWallet> premint_wallets;
    std::optional<CoinDenomination> coin_denomination;
    std::vector<KeyValuePair> custom_parameters;
    std::string contract_id;
    std::vector<ExpenseRatio> expense_ratio;
    ContractType contract_type;
    bool update_contract_fees;
    bool update_expense_ratio;
    std::optional<uint32_t> quash_threshold;
    std::vector<TokenCompliance> token_compliance;
    bool kyc_status;
    bool immutable_kyc_status;
    std::vector<MaxSupplyRelease> max_supply_release;
};
