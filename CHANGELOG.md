# Changelog

All notable changes to this project are documented in this file.

## 1.3.0

### Added

- Batch and multicall decoding. The analyzer now unwraps Multicall3 (aggregate, aggregate3, aggregate3Value, tryAggregate), OpenZeppelin multicall, and Gnosis Safe multiSend calls, recursively running the rule set on each inner call so a dangerous action hidden inside a batch is caught instead of reported as an unknown selector. Inner findings are labeled with their position and target, and a critical inner finding raises the overall severity.

## 1.2.1

### Fixed

- Calldata selector matching is now case insensitive. Uppercase or mixed-case calldata was previously mislabeled transaction.unknown-selector, so an unlimited approval encoded in uppercase hex was not flagged.
- Maximum uint160 detection now requires a full 32-byte word, removing a latent false positive.
- TOML configuration rejects unknown keys, so a misspelled section or rule name is reported instead of silently ignored.
- SARIF rule severity now reflects the highest severity seen per rule id.
- The preflight, trace, and proxy usage strings list --config, and the --rpc-url rejection message names the correct command.

## 1.2.0

### Added

- Detection of ERC-20 allowance increases, with an unlimited-allowance finding for maximum values.
- Detection of ERC-20 permit signed approvals (EIP-2612), with an unlimited-allowance finding for maximum values.
- Detection of ERC-20 transfer and transferFrom calls for transaction context.
- Detection of contract creation (CREATE and CREATE2) in execution traces.
- Detection of Uniswap Permit2 operations: allowance approval with an unlimited uint160 finding, signed permit and permitTransferFrom calls, and transferFrom.

### Changed

- JSON and SARIF reports are now produced by a serializer, which sorts object keys and guarantees well-formed output.

### Fixed

- JSON and SARIF rendering now escapes all control characters in the U+0000 to U+001F range, preventing invalid output.

## 1.1.0

### Added

- Anvil-backed integration testing for RPC preflight behavior.
- LCOV coverage reports as CI workflow artifacts.
- Release binaries for Linux, Windows, and macOS.
- Transaction findings for NFT operator approvals, privileged contract actions, and zero-address recipients.
- Configurable high-risk contract recipients through TOML rule configuration.
- Feature request and pull request templates for contributors.

## 1.0.0

### Added

- Transaction inspection for ERC-20 approvals, including unlimited approval findings.
- Text, JSON, and SARIF 2.1.0 reporting formats.
- JSON-RPC preflight with chain validation and gas estimation.
- Call trace analysis for delegate calls, internal transfers, and execution errors.
- EIP-1967 and UUPS proxy inspection.
- TOML rule configuration with reusable rule pack discovery.
- Compiled rule pack interfaces for custom transaction, trace, and proxy checks.
- Continuous integration and a manual SARIF upload workflow.

### Documentation

- Architecture, rules, provider requirements, contribution, and security guidance.
