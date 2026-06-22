# Roadmap

## v0.1.0

- Rust workspace and command-line interface.
- Static ERC-20 approval inspection.
- Text and JSON reports.
- Unit tests and continuous integration.

## v0.2.0

- HTTP JSON-RPC preflight with chain validation and gas estimation.
- `debug_traceCall` integration with the `callTracer` tracer.
- Delegate call, internal transfer, and execution error findings.
- EIP-1967 and UUPS proxy inspection.

## v0.3.0

- SARIF 2.1.0 output.
- Manual GitHub Code Scanning workflow.
- TOML rule configuration.
- Rule configuration file.

## v1.0.0

- Stable rule interfaces and compiled rule pack registry.
- Supported network and provider documentation.

## v1.1.0

- Anvil integration testing and LCOV coverage artifacts.
- Release binaries for Linux, Windows, and macOS.
- Expanded transaction risk rules and configurable high-risk recipients.
- Contribution templates for feature requests and pull requests.

## v1.2.0

- ERC-20 allowance increase, EIP-2612 permit, transfer, and transferFrom detection.
- Uniswap Permit2 approval, permit, and transfer detection.
- Contract creation findings in execution traces.
- Serializer-backed JSON and SARIF rendering.
- Proxy classification and configuration error test coverage.

## v1.2.1

- Case-insensitive calldata selector matching.
- Configuration parsing and report severity hardening.
