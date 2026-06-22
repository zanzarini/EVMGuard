# EVMGuard

[![CI](https://github.com/zanzarini/EVMGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/zanzarini/EVMGuard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/zanzarini/EVMGuard)](https://github.com/zanzarini/EVMGuard/releases)
[![License](https://img.shields.io/github/license/zanzarini/EVMGuard)](LICENSE)

EVMGuard is an open-source command-line tool that inspects EVM transactions for dangerous effects before you sign them. It decodes calldata, simulates against a JSON-RPC endpoint, walks call traces, and classifies proxy contracts, flagging risks such as unlimited token approvals, Permit2 grants, and blanket NFT approvals. It runs locally, sends no telemetry, and emits text, JSON, or SARIF for CI.

## Status

Version 1.2.1 is a correctness patch over 1.2.0. It makes calldata selector matching case insensitive, hardens configuration parsing and report severity, and keeps the 1.2.0 risk analysis for ERC-20 allowances, EIP-2612, Uniswap Permit2, transfers, and contract-creation traces.

## Scope

EVMGuard will inspect transaction requests and execution traces to identify effects such as token approvals, asset transfers, delegate calls, and proxy usage. It does not sign transactions, broadcast transactions, manage private keys, or provide financial advice.

## Why EVMGuard

- Open source and auditable, under the Apache License 2.0.
- Runs locally and sends no telemetry. Transaction data never leaves your machine.
- Offline calldata analysis with `inspect`, no RPC endpoint required.
- Machine-readable JSON and SARIF output that drops straight into CI and GitHub Code Scanning.
- A single static binary for Linux, Windows, and macOS, with no runtime dependencies.

## Current capabilities

- Command-line transaction inspection.
- Text, JSON, and SARIF reports.
- Detection of ERC-20 `approve` calls.
- Critical finding for unlimited ERC-20 approvals.
- Critical findings for NFT operator approvals, privileged contract actions, and zero-address recipients.
- Detection of ERC-20 allowance increases and EIP-2612 permit approvals, including unlimited-allowance findings.
- Detection of ERC-20 transfer and transferFrom calls for transaction context.
- Detection of Uniswap Permit2 approvals, signed permits and transfers, including unlimited uint160 allowances.
- Configurable high-risk recipient detection.
- RPC preflight with endpoint chain ID validation and gas estimation.
- Call trace analysis for delegate calls, internal native transfers, and execution errors.
- EIP-1967 proxy inspection for implementation, administrator, beacon, and UUPS metadata.
- TOML rule configuration and reusable rule pack discovery.
- Compiled rule pack interface for custom transaction, trace, and proxy checks.
- Unit, Anvil integration, and coverage reporting workflows.

## Binary releases

Linux, Windows, and macOS binaries are attached to each [GitHub release](https://github.com/zanzarini/EVMGuard/releases).

## Quick start

The complete command, flag, output, and rule reference is in the [user manual](docs/usage.md).

Install the stable Rust toolchain, then run:

```bash
cargo run -p evmguard-cli -- inspect \
  --chain-id 8453 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x095ea7b30000000000000000000000003333333333333333333333333333333333333333ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --format text
```

Use `--format json` for automation-friendly output.

Use `--format sarif` to generate a SARIF 2.1.0 report for security tooling.

## Rule configuration

Use `--config evmguard.toml` with any command to disable rules or override their severity:

```toml
[rules]
disabled = ["transaction.unknown-selector"]

[rules.severity]
"erc20.unlimited-approval" = "warning"

[targets]
suspicious = ["0x1111111111111111111111111111111111111111"]
```

Supported severities are `info`, `warning`, and `critical`.

Addresses listed under `targets.suspicious` produce a critical finding when used as a transaction recipient. Use this list for contracts that require explicit review in your environment.

Use `include = ["path/to/rules.toml"]` at the top level to load reusable rule packs. Local configuration overrides included severities.

## RPC preflight

Run a preflight request against a standard EVM JSON-RPC endpoint before submitting a transaction:

```bash
evmguard preflight \
  --rpc-url https://your-rpc-endpoint.example \
  --chain-id 8453 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x095ea7b3 \
  --value 0
```

The preflight verifies the endpoint chain ID and calls `eth_estimateGas`. It does not broadcast or sign transactions.

## Call trace analysis

Use a trace-capable EVM JSON-RPC endpoint to simulate a call with `debug_traceCall` and analyze its call tree:

```bash
evmguard trace \
  --rpc-url https://your-trace-rpc-endpoint.example \
  --chain-id 8453 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x \
  --format json
```

The endpoint must support the `debug_traceCall` method and the `callTracer` tracer.

## Proxy inspection

Inspect a contract address for EIP-1967 proxy slots:

```bash
evmguard proxy \
  --rpc-url https://your-rpc-endpoint.example \
  --chain-id 8453 \
  --address 0x1111111111111111111111111111111111111111 \
  --format json
```

The inspection reads implementation, administrator, and beacon storage slots. It identifies UUPS implementations through `proxiableUUID` when the contract exposes that method.

## GitHub Code Scanning

The `EVMGuard SARIF` workflow can be started manually from the Actions tab. It runs a transaction preflight with the supplied RPC endpoint and uploads the resulting SARIF report to GitHub Code Scanning.

## Network support

Supported JSON-RPC methods and endpoint requirements are documented in [docs/providers.md](docs/providers.md).

## Roadmap

The initial roadmap is available in [docs/roadmap.md](docs/roadmap.md). The architecture and rule model are documented in [docs/architecture.md](docs/architecture.md) and [docs/rules.md](docs/rules.md).

## Safety notice

EVMGuard provides analysis, not a safety guarantee. Results must be independently reviewed before acting on a transaction.

## Contributing

Contribution guidelines are available in [CONTRIBUTING.md](CONTRIBUTING.md). Security issues must follow [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

## Release history

Release notes are maintained in [CHANGELOG.md](CHANGELOG.md).
