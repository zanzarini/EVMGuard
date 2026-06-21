# EVMGuard

EVMGuard is an open-source EVM transaction inspection tool for identifying security-relevant effects before a transaction is submitted.

## Status

Pre-alpha. The initial release establishes the Rust workspace, command-line interface, reporting formats, and the first static inspection rule for ERC-20 unlimited approvals.

## Scope

EVMGuard will inspect transaction requests and execution traces to identify effects such as token approvals, asset transfers, delegate calls, and proxy usage. It does not sign transactions, broadcast transactions, manage private keys, or provide financial advice.

## Current capabilities

- Command-line transaction inspection.
- Text and JSON reports.
- Detection of ERC-20 `approve` calls.
- Critical finding for unlimited ERC-20 approvals.
- RPC preflight with endpoint chain ID validation and gas estimation.
- Call trace analysis for delegate calls, internal native transfers, and execution errors.
- EIP-1967 proxy inspection for implementation, administrator, beacon, and UUPS metadata.
- Unit tests for inspection rules.

## Quick start

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

## Roadmap

The initial roadmap is available in [docs/roadmap.md](docs/roadmap.md). The architecture and rule model are documented in [docs/architecture.md](docs/architecture.md) and [docs/rules.md](docs/rules.md).

## Safety notice

EVMGuard provides analysis, not a safety guarantee. Results must be independently reviewed before acting on a transaction.

## Contributing

Contribution guidelines are available in [CONTRIBUTING.md](CONTRIBUTING.md). Security issues must follow [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
