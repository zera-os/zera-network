# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1]

### Added
- Checkpoint block re-execution functionality
- Syncing state to checkpoint (latest version)
- Confirmed blocks efficiency upgrade for reorg block creation/storage
- `DATA_DIR` environment variable support in `.env` file for configurable validator data storage location

#### Native Functions
- `TransferMulti` - Multi-recipient transfer functionality
- `DerivedSend` - Send from derived wallet addresses
- `InstrumentContractDEX` - DEX instrumentation for smart contracts
- `DerivedSendMulti` - Multi-send from derived wallets
- `DerivedDelegateSend` - Send from delegated derived wallets
- `DerivedCurrentSend` - Send from current derived wallet context
- `DerivedSendAll` - Send all tokens from derived wallet
- `DerivedDelegateSendAll` - Send all tokens from delegated derived wallet
- `DerivedCurrentSendAll` - Send all tokens from current derived wallet context
- `DeriveWallet` - Derive wallet addresses from base wallet
- `DeriveWalletCurrent` - Derive wallet in current context
- `DeriveWalletDelegate` - Derive delegated wallet addresses
- `SmartContractExists` - Check if smart contract exists on chain
- `WalletExists` - Check if wallet exists on chain

#### Transaction Types
- `ProposalCancelTXN` - Allows users to cancel their own proposals

#### Staking & Governance
- Validators can now use authorized tokens to stake (in addition to native tokens)
- Staked coins can now be used for voting power with proposed multipliers
- Enhanced voting power calculation system

### Changed
- Upgraded logging to spdlog with automatic log rotation
  - Max file size: 100MB
  - Max files: 10
  - Total disk usage: 1GB max
  - Old logs automatically deleted
- Temporary smart contract files now use RAII (Resource Acquisition Is Initialization) pattern to guarantee cleanup
- Smart contract deployment temporary storage now uses deterministic txn hash instead of random number generation
- Redesigned base fee system for authorized tokens with more robust validation
- New ACE (Authorized Coin Exchange) system that uses native DEX for pricing and authorization determination
- Public keys no longer require hash tokens for operation

### Fixed
- Memory leak in key generation (`wallets.cpp` L575) - `EVP_MD_CTX` context was created but never used/released
- Added shutdown trigger on critical database failure during reorg - manual intervention required in this rare case

### Security
- Removed insecure `Randomish` native function and all helper functions from `smart_contract_service.cpp` - this was a development/testing function not intended for production
- Removed insecure random number usage in `process_smart_contract_deploy.cpp` - replaced with deterministic txn hash for temporary file storage

### Removed
- `Randomish` native function (`WasmEdge_Result Randomish()` L929)
- `generate_random_string()` helper function (L433)
- "Hack" flag used for testing proposal functions quickly - development/testing code not intended for production
