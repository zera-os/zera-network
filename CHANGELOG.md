# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1]

### Added
- Checkpoint block re-execution functionality
- Syncing state to checkpoint (latest version)
- Confirmed blocks efficiency upgrade for reorg block creation/storage
- `DATA_DIR` environment variable support in `.env` file for configurable validator data storage location

### Changed
- Upgraded logging to spdlog with automatic log rotation
  - Max file size: 100MB
  - Max files: 10
  - Total disk usage: 1GB max
  - Old logs automatically deleted
- Temporary smart contract files now use RAII (Resource Acquisition Is Initialization) pattern to guarantee cleanup
- Smart contract deployment temporary storage now uses deterministic txn hash instead of random number generation

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
