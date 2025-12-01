# Zera Network v1.0.1

A high-performance, governance-driven blockchain network featuring smart contracts, compliance integration, and advanced consensus mechanisms.

The ZERA Network is not a fork of an existing protocol. It is built from the ground up to satisfy ZERA's specific goals.

## Overview

Zera Network is a next-generation layer-1 blockchain infrastructure designed for general purpose utility with an emphasize on autonomous governance. Built in C++17, the network provides a robust validator implementation with native support for smart contracts, on-chain governance, and more.

## Key Features

### 🔗 Core Blockchain Capabilities
- **High-Performance Validator**: Optimized C++ implementation with multi-threaded block processing
- **Transaction Types**: Many different native transaction types
- **Governance Core**: Built with a deeply interweaved governance system capable of complex workflows and integrations

### 🤖 Smart Contract Platform
- **WebAssembly Support**: Execute smart contracts via WasmEdge runtime
- **Native Functions**: Pre-built functions for transfers, voting, allowances, and more
- **Contract Bridging**: Inter-contract communication capabilities
- **Stateful Execution**: Persistent storage and state management for contracts

### 🗳️ On-Chain Governance
- **Proposal System**: Community-driven network upgrades and parameter changes
- **Delegated Voting**: Token holders can delegate voting power
- **Time-Based Calculations**: Epoch and period management for governance cycles
- **Customizability**: Staggared, Cycle, Staged, and Adaptive governance types natively supported to adapt to various needs with customizable parameters (quorums, thresholds, proposal-flow)

### 🔐 Security & Compliance
- **Cryptographic Signatures**: Ed25519 & Ed448 transaction signing
- **Attestation Process**: Validator attestation for consensus integrity
- **Compliance Module**: Regulatory compliance framework available for tokens
- **Restricted Keys**: Extensive special-purpose key management system

### 🌐 Network Architecture
- **gRPC P2P Protocol**: High-performance peer-to-peer communication
- **Gossip Protocol**: Efficient block and transaction propagation
- **Block Synchronization**: Fast sync for new validators joining the network
- **RESTful API**: Public API for blockchain queries and transaction submission

### 💎 Advanced Features
- **NFT Support**: Native non-fungible token creation and management
- **Item Minting**: Custom digital asset issuance
- **SBT (Soulbound Tokens)**: Non-transferable token support
- **Much More**: Explore everything from expense ratio's to complex multi-tiered multi-wallet support

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Zera Validator Node                  │
├─────────────────────────────────────────────────────────┤
│  gRPC API Layer          │  P2P Network Layer           │
├──────────────────────────┴──────────────────────────────┤
│  Smart Contract Engine (WebAssembly)                    │
├─────────────────────────────────────────────────────────┤
│  Block Processing  │  Governance  │  Attestation        │
├─────────────────────────────────────────────────────────┤
│  Transaction Verification & Batch Processing            │
├─────────────────────────────────────────────────────────┤
│  Storage Layer (RocksDB)                                │
└─────────────────────────────────────────────────────────┘
```

## Technology Stack

- **Language**: C++17
- **Networking**: gRPC, Protocol Buffers
- **Storage**: RocksDB
- **Cryptography**: libsodium, OpenSSL
- **Smart Contracts**: WasmEdge
- **Build System**: CMake

## Getting Started

### Prerequisites
- CMake 3.8+
- C++17 compatible compiler
- gRPC and Protocol Buffers
- RocksDB / LevelDB
- libsodium
- WasmEdge runtime

## Transaction Types

Zera Network supports a diverse set of transaction types including but not limited to:

- **Standard**: Transfers, allowances, approvals, revocations
- **Governance**: Proposals, voting, fast quorum, quashing
- **Validator**: Registration, heartbeats, validator management
- **Smart Contracts**: Deploy, instantiate, execute
- **Assets**: NFT minting, item creation, SBT operations
- **Treasury**: Expense management, coin issuance

## Community & Governance

All major network changes go through the on-chain governance process, ensuring community-driven evolution of the protocol.

## License

See [LICENSE.md](LICENSE.md) for details.

## Rules of Engagement

See [rules-of-engagement.md](rules-of-engagement.md) for details.

## Contributing

Contributions are welcome! Please submit proposals through the governance system for protocol changes, or submit pull requests for bug fixes and improvements.

---

**Built with ❤️ by the Zera Community**
