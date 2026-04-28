#include "sc_base64.h"
#include "base64.h"

namespace
{
    // ===== Primitive readers =====

    size_t read_varint(const std::string &data, size_t &pos)
    {
        size_t result = 0;
        size_t shift = 0;

        while (pos < data.size())
        {
            uint8_t byte = static_cast<uint8_t>(data[pos++]);
            result |= static_cast<size_t>(byte & 0x7F) << shift;

            if ((byte & 0x80) == 0)
                break;

            shift += 7;
        }

        return result;
    }

    std::string read_postcard_string(const std::string &data, size_t &pos)
    {
        size_t len = read_varint(data, pos);

        if (pos + len > data.size())
            return "";

        std::string result = data.substr(pos, len);
        pos += len;
        return result;
    }

    uint64_t read_u64(const std::string &data, size_t &pos)
    {
        uint64_t result = 0;
        size_t shift = 0;

        while (pos < data.size())
        {
            uint8_t byte = static_cast<uint8_t>(data[pos++]);
            result |= static_cast<uint64_t>(byte & 0x7F) << shift;

            if ((byte & 0x80) == 0)
                break;

            shift += 7;
        }

        return result;
    }

    uint32_t read_u32(const std::string &data, size_t &pos)
    {
        return static_cast<uint32_t>(read_varint(data, pos));
    }

    int64_t read_i64(const std::string &data, size_t &pos)
    {
        uint64_t raw = read_u64(data, pos);
        return static_cast<int64_t>((raw >> 1) ^ (-(raw & 1)));
    }

    int32_t read_i32(const std::string &data, size_t &pos)
    {
        uint32_t raw = read_u32(data, pos);
        return static_cast<int32_t>((raw >> 1) ^ (-(raw & 1)));
    }

    bool read_bool(const std::string &data, size_t &pos)
    {
        if (pos >= data.size())
            return false;

        uint8_t byte = static_cast<uint8_t>(data[pos++]);
        return byte != 0;
    }

    std::vector<uint8_t> read_bytes(const std::string &data, size_t &pos)
    {
        size_t len = read_varint(data, pos);
        std::vector<uint8_t> result;
        if (pos + len > data.size())
            return result;
        result.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return result;
    }

    std::vector<uint32_t> read_u32_vec(const std::string &data, size_t &pos)
    {
        size_t count = read_varint(data, pos);
        std::vector<uint32_t> result;
        result.reserve(count);
        for (size_t i = 0; i < count && pos < data.size(); ++i)
            result.push_back(read_u32(data, pos));
        return result;
    }

    std::vector<std::string> read_string_vec(const std::string &data, size_t &pos)
    {
        size_t count = read_varint(data, pos);
        std::vector<std::string> result;
        result.reserve(count);
        for (size_t i = 0; i < count && pos < data.size(); ++i)
            result.push_back(read_postcard_string(data, pos));
        return result;
    }

    std::vector<std::vector<uint8_t>> read_bytes_vec(const std::string &data, size_t &pos)
    {
        size_t count = read_varint(data, pos);
        std::vector<std::vector<uint8_t>> result;
        result.reserve(count);
        for (size_t i = 0; i < count && pos < data.size(); ++i)
            result.push_back(read_bytes(data, pos));
        return result;
    }

    // ===== Option readers =====

    std::optional<bool> read_option_bool(const std::string &data, size_t &pos)
    {
        if (pos >= data.size())
            return std::nullopt;
        uint8_t tag = static_cast<uint8_t>(data[pos++]);
        if (tag == 0)
            return std::nullopt;
        return read_bool(data, pos);
    }

    std::optional<uint32_t> read_option_u32(const std::string &data, size_t &pos)
    {
        if (pos >= data.size())
            return std::nullopt;
        uint8_t tag = static_cast<uint8_t>(data[pos++]);
        if (tag == 0)
            return std::nullopt;
        return read_u32(data, pos);
    }

    std::optional<std::string> read_option_string(const std::string &data, size_t &pos)
    {
        if (pos >= data.size())
            return std::nullopt;
        uint8_t tag = static_cast<uint8_t>(data[pos++]);
        if (tag == 0)
            return std::nullopt;
        return read_postcard_string(data, pos);
    }

    std::optional<std::vector<uint8_t>> read_option_bytes(const std::string &data, size_t &pos)
    {
        if (pos >= data.size())
            return std::nullopt;
        uint8_t tag = static_cast<uint8_t>(data[pos++]);
        if (tag == 0)
            return std::nullopt;
        return read_bytes(data, pos);
    }

    // ===== Existing struct readers =====

    WalletStake read_wallet_stake(const std::string &data, size_t &pos)
    {
        WalletStake stake;
        stake.principle = read_u64(data, pos);
        stake.total_reward = read_u64(data, pos);
        stake.daily_release = read_u64(data, pos);
        stake.total_released = read_u64(data, pos);
        stake.last_reward_day = read_u64(data, pos);
        stake.term = read_postcard_string(data, pos);
        return stake;
    }

    LiquidStake read_liquid_stake(const std::string &data, size_t &pos)
    {
        LiquidStake liquid;
        liquid.bump_id = read_u64(data, pos);
        liquid.principle = read_u64(data, pos);
        liquid.last_reward_day = read_u64(data, pos);
        liquid.daily_release = read_u64(data, pos);
        liquid.unstake_day = read_u64(data, pos);
        return liquid;
    }

    InstantStake read_instant_stake(const std::string &data, size_t &pos)
    {
        InstantStake stake;
        stake.principle = read_u64(data, pos);
        stake.total_reward = read_u64(data, pos);
        stake.release_day = read_u64(data, pos);
        stake.term = read_postcard_string(data, pos);
        return stake;
    }

    // ===== New struct readers =====

    MultiPatterns read_multi_patterns(const std::string &data, size_t &pos)
    {
        MultiPatterns mp;
        mp.pattern_class = read_u32_vec(data, pos);
        mp.required = read_u32_vec(data, pos);
        return mp;
    }

    MultiKey read_multi_key(const std::string &data, size_t &pos)
    {
        MultiKey mk;
        mk.public_keys = read_bytes_vec(data, pos);
        mk.signatures = read_bytes_vec(data, pos);

        size_t mp_count = read_varint(data, pos);
        mk.multi_patterns.reserve(mp_count);
        for (size_t i = 0; i < mp_count && pos < data.size(); ++i)
            mk.multi_patterns.push_back(read_multi_patterns(data, pos));

        mk.hash_tokens = read_string_vec(data, pos);
        return mk;
    }

    PublicKey read_public_key(const std::string &data, size_t &pos)
    {
        PublicKey pk;
        pk.single = read_bytes(data, pos);

        // Option<MultiKey>
        if (pos < data.size() && static_cast<uint8_t>(data[pos++]) != 0)
            pk.multi = read_multi_key(data, pos);

        pk.smart_contract_auth = read_option_bytes(data, pos);
        pk.governance_auth = read_option_bytes(data, pos);
        return pk;
    }

    RestrictedKey read_restricted_key(const std::string &data, size_t &pos)
    {
        RestrictedKey rk;
        rk.public_key = read_public_key(data, pos);
        rk.time_delay = read_i64(data, pos);
        rk.global = read_bool(data, pos);
        rk.update_contract = read_bool(data, pos);
        rk.transfer = read_bool(data, pos);
        rk.quash = read_bool(data, pos);
        rk.mint = read_bool(data, pos);
        rk.vote = read_bool(data, pos);
        rk.propose = read_bool(data, pos);
        rk.compliance = read_bool(data, pos);
        rk.expense_ratio = read_bool(data, pos);
        rk.revoke = read_bool(data, pos);
        rk.key_weight = read_u32(data, pos);
        return rk;
    }

    ContractFees read_contract_fees(const std::string &data, size_t &pos)
    {
        ContractFees cf;
        cf.fee = read_postcard_string(data, pos);
        cf.fee_address = read_option_bytes(data, pos);
        cf.burn = read_postcard_string(data, pos);
        cf.validator = read_postcard_string(data, pos);
        cf.allowed_fee_instrument = read_string_vec(data, pos);
        cf.contract_fee_type = static_cast<ContractFeeType>(read_u32(data, pos));
        return cf;
    }

    KeyValuePair read_key_value_pair(const std::string &data, size_t &pos)
    {
        KeyValuePair kv;
        kv.key = read_postcard_string(data, pos);
        kv.value = read_postcard_string(data, pos);
        return kv;
    }

    ExpenseRatio read_expense_ratio(const std::string &data, size_t &pos)
    {
        ExpenseRatio er;
        er.day = read_u32(data, pos);
        er.month = read_u32(data, pos);
        er.percent = read_u32(data, pos);
        return er;
    }

    ComplianceEntry read_compliance_entry(const std::string &data, size_t &pos)
    {
        ComplianceEntry ce;
        ce.contract_id = read_postcard_string(data, pos);
        ce.compliance_level = read_u32(data, pos);
        return ce;
    }

    TokenCompliance read_token_compliance(const std::string &data, size_t &pos)
    {
        TokenCompliance tc;
        size_t count = read_varint(data, pos);
        tc.compliance.reserve(count);
        for (size_t i = 0; i < count && pos < data.size(); ++i)
            tc.compliance.push_back(read_compliance_entry(data, pos));
        return tc;
    }

    ProtoTimestamp read_proto_timestamp(const std::string &data, size_t &pos)
    {
        ProtoTimestamp ts;
        ts.seconds = read_i64(data, pos);
        ts.nanos = read_i32(data, pos);
        return ts;
    }

    Stage read_stage(const std::string &data, size_t &pos)
    {
        Stage s;
        s.length = read_u32(data, pos);
        s.period = static_cast<ProposalPeriod>(read_u32(data, pos));
        s.break_stage = read_bool(data, pos);
        s.max_approved = read_u32(data, pos);
        return s;
    }

    Governance read_governance(const std::string &data, size_t &pos)
    {
        Governance g;
        g.governance_type = static_cast<GovernanceType>(read_u32(data, pos));
        g.regular_quorum = read_u32(data, pos);
        g.fast_quorum = read_option_u32(data, pos);
        g.voting_instrument = read_string_vec(data, pos);
        g.threshold = read_u32(data, pos);
        g.chicken_dinner = read_option_bool(data, pos);
        g.allow_multi = read_bool(data, pos);
        g.voting_period = read_option_u32(data, pos);
        g.allowed_proposal_instrument = read_string_vec(data, pos);

        // Option<ProposalPeriod>
        if (pos < data.size() && static_cast<uint8_t>(data[pos++]) != 0)
            g.proposal_period = static_cast<ProposalPeriod>(read_u32(data, pos));

        // Vec<Stage>
        size_t stage_count = read_varint(data, pos);
        g.stage_length.reserve(stage_count);
        for (size_t i = 0; i < stage_count && pos < data.size(); ++i)
            g.stage_length.push_back(read_stage(data, pos));

        // Option<ProtoTimestamp>
        if (pos < data.size() && static_cast<uint8_t>(data[pos++]) != 0)
            g.start_timestamp = read_proto_timestamp(data, pos);

        g.max_approved = read_option_u32(data, pos);
        return g;
    }

    Sender read_sender(const std::string &data, size_t &pos)
    {
        Sender s;
        s.type = static_cast<SenderType>(read_u32(data, pos));
        if (s.type == SenderType::Delegate)
        {
            s.sc_name = read_postcard_string(data, pos);
            s.sc_instance = read_postcard_string(data, pos);
        }
        return s;
    }

    // ===== Write helpers =====

    void write_varint(std::string &output, size_t value)
    {
        while (value >= 0x80)
        {
            output.push_back(static_cast<char>((value & 0x7F) | 0x80));
            value >>= 7;
        }
        output.push_back(static_cast<char>(value & 0x7F));
    }

    void write_postcard_string(std::string &output, const std::string &str)
    {
        write_varint(output, str.size());
        output.append(str);
    }

}

// ===== Existing top-level decode/encode =====

SmartContractState decode_smart_contract_state(const std::string &b64_encoded)
{
    SmartContractState state;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return state;

    size_t pos = 0;
    state.smart_contract = read_postcard_string(postcard_bytes, pos);
    state.instance = read_postcard_string(postcard_bytes, pos);

    return state;
}

AllStakers decode_all_stakers(const std::string &b64_encoded)
{
    AllStakers stakers;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return stakers;

    size_t pos = 0;

    size_t num_entries = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        std::string key = read_postcard_string(postcard_bytes, pos);

        if (pos >= postcard_bytes.size())
            break;

        uint8_t value = static_cast<uint8_t>(postcard_bytes[pos++]);

        stakers.staker_states[key] = value;
    }

    return stakers;
}

AllWalletStakes decode_all_wallet_stakes(const std::string &b64_encoded)
{
    AllWalletStakes all_stakes;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return all_stakes;

    size_t pos = 0;

    size_t num_entries = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        std::string key = read_postcard_string(postcard_bytes, pos);

        WalletStake stake = read_wallet_stake(postcard_bytes, pos);

        all_stakes.staker_states[key] = stake;
    }

    all_stakes.liquid_stake = read_liquid_stake(postcard_bytes, pos);

    return all_stakes;
}

LiquidityPool decode_liquidity_pool(const std::string &b64_encoded)
{
    LiquidityPool pool;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return pool;

    size_t pos = 0;

    pool.token1 = read_postcard_string(postcard_bytes, pos);
    pool.token2 = read_postcard_string(postcard_bytes, pos);
    pool.lp_token_id = read_postcard_string(postcard_bytes, pos);
    pool.token1_volume = read_postcard_string(postcard_bytes, pos);
    pool.token2_volume = read_postcard_string(postcard_bytes, pos);
    pool.circulating_lp_tokens = read_postcard_string(postcard_bytes, pos);
    pool.active = read_bool(postcard_bytes, pos);
    pool.derived_wallet = read_postcard_string(postcard_bytes, pos);
    pool.redeemed_lp_tokens = read_postcard_string(postcard_bytes, pos);
    pool.fee_percent = read_u64(postcard_bytes, pos);

    return pool;
}

NetworkValues decode_network_values(const std::string &b64_encoded)
{
    NetworkValues network_values;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return network_values;

    size_t pos = 0;

    size_t num_values = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_values && pos < postcard_bytes.size(); ++i)
    {
        std::string value = read_postcard_string(postcard_bytes, pos);
        network_values.values.push_back(value);
    }

    return network_values;
}

AllInstantStakers decode_all_instant_stakers(const std::string &b64_encoded)
{
    AllInstantStakers stakers;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return stakers;

    size_t pos = 0;

    size_t num_entries = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        std::string key = read_postcard_string(postcard_bytes, pos);

        if (pos >= postcard_bytes.size())
            break;

        uint8_t value = static_cast<uint8_t>(postcard_bytes[pos++]);

        stakers.staker_states[key] = value;
    }

    stakers.earliest_release_day = read_u64(postcard_bytes, pos);

    return stakers;
}

AllWalletInstantStakes decode_all_wallet_instant_stakes(const std::string &b64_encoded)
{
    AllWalletInstantStakes all_stakes;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return all_stakes;

    size_t pos = 0;

    size_t num_entries = read_varint(postcard_bytes, pos);

    for (size_t i = 0; i < num_entries && pos < postcard_bytes.size(); ++i)
    {
        std::string key = read_postcard_string(postcard_bytes, pos);

        InstantStake stake = read_instant_stake(postcard_bytes, pos);

        all_stakes.staker_states[key] = stake;
    }

    return all_stakes;
}

std::string encode_smart_contract_state(const SmartContractState &state)
{
    std::string postcard_bytes;

    write_postcard_string(postcard_bytes, state.smart_contract);
    write_postcard_string(postcard_bytes, state.instance);

    return base64_encode(postcard_bytes);
}

// ===== New top-level decode =====

NetworkTXN decode_network_txn(const std::string &b64_encoded)
{
    NetworkTXN txn;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return txn;

    size_t pos = 0;

    txn.txn_type = static_cast<TransactionType>(read_u32(postcard_bytes, pos));
    txn.payload = read_postcard_string(postcard_bytes, pos);
    txn.sender = read_sender(postcard_bytes, pos);

    return txn;
}

ContractUpdateTXN decode_contract_update_txn(const std::string &b64_encoded)
{
    ContractUpdateTXN txn;

    std::string postcard_bytes = base64_decode(b64_encoded);
    if (postcard_bytes.empty())
        return txn;

    size_t pos = 0;

    txn.contract_id = read_postcard_string(postcard_bytes, pos);
    txn.contract_version = read_u64(postcard_bytes, pos);
    txn.name = read_option_string(postcard_bytes, pos);

    // Option<Governance>
    if (pos < postcard_bytes.size() && static_cast<uint8_t>(postcard_bytes[pos++]) != 0)
        txn.governance = read_governance(postcard_bytes, pos);

    // Vec<RestrictedKey>
    size_t rk_count = read_varint(postcard_bytes, pos);
    txn.restricted_keys.reserve(rk_count);
    for (size_t i = 0; i < rk_count && pos < postcard_bytes.size(); ++i)
        txn.restricted_keys.push_back(read_restricted_key(postcard_bytes, pos));

    // Option<ContractFees>
    if (pos < postcard_bytes.size() && static_cast<uint8_t>(postcard_bytes[pos++]) != 0)
        txn.contract_fees = read_contract_fees(postcard_bytes, pos);

    // Vec<KeyValuePair>
    size_t kv_count = read_varint(postcard_bytes, pos);
    txn.custom_parameters.reserve(kv_count);
    for (size_t i = 0; i < kv_count && pos < postcard_bytes.size(); ++i)
        txn.custom_parameters.push_back(read_key_value_pair(postcard_bytes, pos));

    // Vec<ExpenseRatio>
    size_t er_count = read_varint(postcard_bytes, pos);
    txn.expense_ratio.reserve(er_count);
    for (size_t i = 0; i < er_count && pos < postcard_bytes.size(); ++i)
        txn.expense_ratio.push_back(read_expense_ratio(postcard_bytes, pos));

    // Vec<TokenCompliance>
    size_t tc_count = read_varint(postcard_bytes, pos);
    txn.token_compliance.reserve(tc_count);
    for (size_t i = 0; i < tc_count && pos < postcard_bytes.size(); ++i)
        txn.token_compliance.push_back(read_token_compliance(postcard_bytes, pos));

    txn.kyc_status = read_option_bool(postcard_bytes, pos);
    txn.immutable_kyc_status = read_option_bool(postcard_bytes, pos);
    txn.quash_threshold = read_option_u32(postcard_bytes, pos);

    return txn;
}
