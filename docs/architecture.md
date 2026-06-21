# Architecture

## Design principles

- Deterministic analysis for identical inputs.
- Separation between transaction acquisition, trace normalization, rule evaluation, and reporting.
- No private-key handling.
- Machine-readable output for CI and downstream integrations.

## Current workspace

| Crate | Responsibility |
| --- | --- |
| `evmguard-core` | Transaction, finding, severity, and report domain types. |
| `evmguard-analyzer` | Static inspection rules. |
| `evmguard-report` | Text and JSON output rendering. |
| `evmguard-rpc` | HTTP JSON-RPC transport, chain validation, and gas estimation. |
| `evmguard-cli` | Command-line argument parsing and orchestration. |

## Planned execution pipeline

```text
Transaction request
  -> RPC preflight or local fork executor
  -> trace normalizer
  -> analyzer rules
  -> text, JSON, and SARIF reports
```

## Planned extension points

- RPC adapters for trace-capable EVM providers.
- Local fork execution through Anvil.
- Trace rules for token transfers, delegate calls, and proxy behavior.
- SARIF reporting for CI integrations.
- Rule configuration and external rule packs.
