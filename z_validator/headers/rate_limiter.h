#pragma once

#include <iostream>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <cmath>
#include <thread>
#include <string>
#include <memory>
#include <unordered_set>

using namespace std::chrono;

namespace
{
    // --- Configurable Constants ---
    constexpr auto WINDOW_DURATION = minutes(5);
}

// Turn a gRPC peer string into the bare client address.
// grpc's context->peer() looks like "ipv4:1.2.3.4:52034" or "ipv6:[::1]:52034".
// Callers used to take everything before the FIRST colon, which collapsed every
// client into the single bucket "ipv4"/"ipv6", breaking per-IP limits and the
// whitelist. This strips the transport prefix and the trailing port instead.
inline std::string extract_ip_from_peer(const std::string &peer)
{
    std::string ip = peer;

    if (ip.rfind("ipv4:", 0) == 0 || ip.rfind("ipv6:", 0) == 0)
    {
        ip = ip.substr(5);
    }
    else if (ip.rfind("unix:", 0) == 0)
    {
        return ip; // unix sockets have no ip:port structure
    }

    // Strip the trailing ":port". For bracketed IPv6 ("[::1]:52034") the port
    // separator is the colon after ']'; the colons inside the brackets stay.
    size_t bracket = ip.find(']');
    size_t last_colon = ip.rfind(':');
    if (last_colon != std::string::npos && (bracket == std::string::npos || last_colon > bracket))
    {
        ip = ip.substr(0, last_colon);
    }

    return ip;
}

// --- Rate Limiter Config ---
struct RateLimiterConfig
{
    double baseRefillRate = 1.0; // Default refill rate (tokens per second)
    double baseCapacity = 3.0;   // Default maximum capacity of the bucket
    double refillScale = 0.2;    // Scaling factor for good behavior
    double capacityScale = 0.5;  // Scaling factor for bucket size increase

    bool staticMode = false;       // If true, use static config
    double staticRefillRate = 2.0; // Static refill rate
    double staticCapacity = 100.0; // Static max tokens
};

// --- Efficient TimeSeries with Pruning ---
struct TimeSeries
{
    std::vector<steady_clock::time_point> times;
    size_t start = 0;

    void record()
    {
        times.push_back(steady_clock::now());
    }

    void prune()
    {
        auto cutoff = steady_clock::now() - WINDOW_DURATION;
        while (start < times.size() && times[start] < cutoff)
            ++start;
        if (start > 100)
        {
            times.erase(times.begin(), times.begin() + start);
            start = 0;
        }
    }

    size_t size()
    {
        prune();
        return times.size() - start;
    }
};

// --- Token Bucket Implementation ---
class TokenBucket
{
public:
    TokenBucket(double rate, double cap)
        : refillRate(rate), capacity(cap), tokens(cap),
          lastRefillTime(steady_clock::now()) {}

    void updateParams(double rate, double cap)
    {
        std::lock_guard<std::mutex> lock(mtx);
        refill();
        refillRate = rate;
        capacity = cap;
        tokens = std::min(tokens, capacity);
    }

    // --- Pre-check: checks if there are enough tokens (with refill considered)
    bool canProceed()
    {
        std::lock_guard<std::mutex> lock(mtx);
        refill();             // Make sure the bucket is up-to-date
        return tokens >= 1.0; // Only bad transactions consume tokens
    }

    // --- Finalize: actually consume a token if it's a bad transaction
    void finalize()
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (tokens >= 1.0)
        {
            tokens -= 1.0;
        }
    }

    // --- Atomically consume a token for a request. Unlike canProceed/finalize,
    // every call costs a token, so refill rate/capacity directly bound the
    // request rate (used by public API endpoints where every request has a cost).
    bool tryConsume()
    {
        std::lock_guard<std::mutex> lock(mtx);
        refill();
        if (tokens >= 1.0)
        {
            tokens -= 1.0;
            return true;
        }
        return false;
    }

private:
    double refillRate;
    double capacity;
    double tokens;
    steady_clock::time_point lastRefillTime;
    std::mutex mtx;

    void refill()
    {
        auto now = steady_clock::now();
        double seconds = duration<double>(now - lastRefillTime).count();
        tokens = std::min(capacity, tokens + seconds * refillRate);
        lastRefillTime = now;
    }
};

// --- IP Profile with Activity Tracking ---
struct IPProfile
{
    TimeSeries goodTxns;
    TimeSeries badTxns;
    std::shared_ptr<TokenBucket> bucket;
    RateLimiterConfig config;
    steady_clock::time_point lastSeen;

    IPProfile(const RateLimiterConfig &cfg) : config(cfg)
    {
        if (cfg.staticMode)
        {
            bucket = std::make_shared<TokenBucket>(cfg.staticRefillRate, cfg.staticCapacity);
        }
        else
        {
            bucket = std::make_shared<TokenBucket>(cfg.baseRefillRate, cfg.baseCapacity);
        }

        lastSeen = steady_clock::now();
    }

    void record(bool isBad)
    {
        lastSeen = steady_clock::now();
        if (isBad)
            badTxns.record();
        else
            goodTxns.record();
    }

    void updateBucket()
    {
        if (config.staticMode)
            return;

        size_t good = goodTxns.size();
        size_t bad = badTxns.size();

        double trust = good / (1.0 + bad);
        double usage = std::log(1.0 + good);
        double score = trust * usage;

        double refill = config.baseRefillRate + config.refillScale * score;
        double cap = config.baseCapacity + config.capacityScale * score;

        bucket->updateParams(refill, cap);
    }
};

// --- Rate Limiter Engine ---
class RateLimiter
{
    std::unordered_map<std::string, std::shared_ptr<IPProfile>> ipMap;
    std::unordered_set<std::string> whitelist;
    std::shared_mutex mapMutex;
    RateLimiterConfig config;
    size_t requestCount = 0;
    size_t cleanupInterval = 100;

public:
    RateLimiter(const RateLimiterConfig &cfg = {}) : config(cfg) {}

    void addToWhitelist(const std::string &ip)
    {
        whitelist.insert(ip);
    }

    // --- Configure the RateLimiter with a new configuration ---
    void configure(const RateLimiterConfig &newConfig)
    {
        config = newConfig; // Update the global configuration
    }

    // --- Step 1: Pre-check without consuming a token
    bool canProceed(const std::string &ip)
    {
        if (isWhitelisted(ip)) return true;

        auto profile = getOrCreate(ip);
        return profile->bucket->canProceed(); // No isBad needed
    }
    // --- Per-request limiting: every (non-whitelisted) request consumes a token.
    // Returns false when the caller has exhausted their budget and should be
    // rejected. Use this for public API endpoints; the canProceed/processUpdate
    // pair only charges for BAD requests and is meant for the txn ingress paths.
    bool consumeToken(const std::string &ip)
    {
        if (isWhitelisted(ip)) return true;

        auto profile = getOrCreate(ip);
        profile->lastSeen = steady_clock::now();

        if (++requestCount % cleanupInterval == 0)
        {
            cleanupInactiveIPs();
        }

        return profile->bucket->tryConsume();
    }

    // --- Step 2: Finalize and Update State
    void processUpdate(const std::string &ip, bool isBad)
    {
        auto profile = getOrCreate(ip);
        profile->record(isBad);
        profile->updateBucket();

        // Only finalize if the transaction is bad
        if (isBad)
        {
            profile->bucket->finalize();
        }

        if (++requestCount % cleanupInterval == 0)
        {
            cleanupInactiveIPs();
        }
    }

private:
    bool isWhitelisted(const std::string &ip)
    {
        return whitelist.count(ip);
    }
    std::shared_ptr<IPProfile> getOrCreate(const std::string &ip)
    {
        {
            std::shared_lock rlock(mapMutex);
            auto it = ipMap.find(ip);
            if (it != ipMap.end())
                return it->second;
        }

        std::unique_lock wlock(mapMutex);
        auto &profile = ipMap[ip];
        if (!profile)
            profile = std::make_shared<IPProfile>(config);
        return profile;
    }

    void cleanupInactiveIPs()
    {
        auto cutoff = steady_clock::now() - WINDOW_DURATION;
        std::unique_lock wlock(mapMutex);

        for (auto it = ipMap.begin(); it != ipMap.end();)
        {
            if (it->second->lastSeen < cutoff)
            {
                it = ipMap.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

};