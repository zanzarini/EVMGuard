# Architecture

## Design principles

- Deterministic analysis for identical inputs.
- Separation between transaction acquisition, trace normalization, rule evaluation, and reporting.
- No private-key handling.
- Machine-readable output for CI and downstream integrations.

## Current workspace

| Crate | Responsibility |
| --- | --- |
| `evmguard-core` | Transaction, proxy, call trace, finding, severity, and report domain types. |
| `evmguard-analyzer` | Static inspection rules. |
| `evmguard-report` | Text and JSON output rendering. |
| `evmguard-rpc` | HTTP JSON-RPC transport, preflight, call trace normalization, and proxy storage inspection. |
| `evmguard-cli` | Command-line argument parsing and orchestration. |

## Planned execution pipeline

```text
Transaction request
  -> RPC preflight or trace executor
  -> trace normalizer
  -> analyzer rules
  -> text, JSON, and SARIF reports
```

## Planned extension points

- Local fork execution through Anvil.
- Trace rules for token transfers.
