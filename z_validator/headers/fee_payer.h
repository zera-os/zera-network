#ifndef FEE_PAYER_H
#define FEE_PAYER_H

// Helpers for the third-party fee payer ("sponsored txn") feature.
//
// A sponsor pays the fees for a txn the user already signed. The sponsor
// counter-signs the entire user-signed txn and supplies their own nonce.
//
// v1 scope: a fee_payer is ONLY accepted on GovernanceVote txns. Every other
// txn type that carries a fee_payer must be rejected at signature verification.
// This file is header-only on purpose so no new CMake source entry is required.

#include <string>

#include "txn.pb.h"
#include "wallets.h"

namespace fee_payer
{
    // True if this txn carries a third-party fee payer.
    inline bool has(const zera_txn::BaseTXN &base)
    {
        return base.has_fee_payer();
    }

    // Wallet address that funds the fees: the sponsor when present, otherwise the sender.
    inline std::string source_wallet(const zera_txn::BaseTXN &base)
    {
        if (base.has_fee_payer())
        {
            return wallets::generate_wallet(base.fee_payer().public_key());
        }
        return wallets::generate_wallet(base.public_key());
    }

    // Sponsor wallet address (assumes a fee payer is present).
    inline std::string payer_wallet(const zera_txn::BaseTXN &base)
    {
        return wallets::generate_wallet(base.fee_payer().public_key());
    }

    // v1 allowlist of txn types permitted to carry a fee_payer. Default deny;
    // specialized to allow only GovernanceVote.
    template <typename TXType>
    struct type_allowed_t
    {
        static constexpr bool value = false;
    };

    template <>
    struct type_allowed_t<zera_txn::GovernanceVote>
    {
        static constexpr bool value = true;
    };

    template <typename TXType>
    constexpr bool type_allowed()
    {
        return type_allowed_t<TXType>::value;
    }
}

#endif
