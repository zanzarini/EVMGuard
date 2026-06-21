# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- Detection of ERC-20 allowance increases, with an unlimited-allowance finding for maximum values.
- Detection of ERC-20 permit signed approvals (EIP-2612), with an unlimited-allowance finding for maximum values.
- Detection of ERC-20 transfer and transferFrom calls for transaction context.
- Detection of contract creation (CREATE and CREATE2) in execution traces.
- Detection of Uniswap Permit2 operations: allowance approval with an unlimited uint160 finding, signed permit and permitTransferFrom calls, and transferFrom.

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
