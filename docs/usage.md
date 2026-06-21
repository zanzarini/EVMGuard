# EVMGuard User Manual

## 1. Overview

EVMGuard is an open-source, Rust command-line tool that inspects EVM transactions for security-relevant effects **before they are signed**. It decodes calldata, simulates transactions against a JSON-RPC endpoint, walks call traces, and classifies proxy contracts, producing findings in human-readable text, machine-readable JSON, or SARIF 2.1.0 for CI pipelines.

EVMGuard is an analysis tool only. It does **not** sign transactions, **does not** broadcast transactions, **does not** handle, store, or manage private keys, and **does not** guarantee that an analyzed transaction or contract is safe. Every result requires human review. EVMGuard is licensed under the Apache License 2.0.

---

## 2. Table of Contents

1. [Overview](#1-overview)
2. [Table of Contents](#2-table-of-contents)
3. [Installation](#3-installation)
4. [Command Structure and Global Behavior](#4-command-structure-and-global-behavior)
5. [Command Reference](#5-command-reference)
   - [inspect](#51-inspect)
   - [preflight](#52-preflight)
   - [trace](#53-trace)
   - [proxy](#54-proxy)
6. [Arguments and Input Validation Reference](#6-arguments-and-input-validation-reference)
7. [Output Formats](#7-output-formats)
8. [Complete Rules Catalog](#8-complete-rules-catalog)
9. [Configuration File (evmguard.toml)](#9-configuration-file-evmguardtoml)
10. [Networks and RPC Providers](#10-networks-and-rpc-providers)
11. [CI and Integrations](#11-ci-and-integrations)
12. [Practical Recipes](#12-practical-recipes)
13. [Exit Codes and Error Handling](#13-exit-codes-and-error-handling)
14. [Limitations and Safety Notice](#14-limitations-and-safety-notice)
15. [Troubleshooting and FAQ](#15-troubleshooting-and-faq)
16. [Contributing, Security Reporting, and License](#16-contributing-security-reporting-and-license)

---

## 3. Installation

### 3.1 Prebuilt Binaries (Recommended for Non-Programmers)

Linux, Windows, and macOS binaries are attached to each GitHub release at:

```
https://github.com/zanzarini/EVMGuard/releases
```

Each release ships three assets:

| Platform | Asset name |
| --- | --- |
| Linux | `evmguard-linux` |
| Windows | `evmguard-windows.exe` |
| macOS | `evmguard-macos` |

#### Linux

```bash
# Download the binary from the release page, then:
chmod +x evmguard-linux
./evmguard-linux --help
```

#### macOS

```bash
chmod +x evmguard-macos
./evmguard-macos --help
```

#### Windows

Download `evmguard-windows.exe` and run it from PowerShell or Command Prompt:

```powershell
.\evmguard-windows.exe --help
```

Throughout this manual the command is written as `evmguard`. Substitute the actual binary name for your platform (for example `./evmguard-linux`, `./evmguard-macos`, or `.\evmguard-windows.exe`).

### 3.2 Building from Source

EVMGuard is a Rust workspace. You need the stable Rust toolchain.

- **Edition:** 2021
- **Minimum supported Rust version (MSRV):** 1.82
- **Toolchain channel:** `stable`, with components `clippy` and `rustfmt` (defined in `rust-toolchain.toml`, profile `minimal`)
- **Workspace version:** 1.2.0

Clone the repository and run the CLI through cargo:

```bash
git clone https://github.com/zanzarini/EVMGuard.git
cd EVMGuard
cargo run -p evmguard-cli -- --help
```

Any command shown in this manual can be run from source by replacing `evmguard` with `cargo run -p evmguard-cli --`. For example:

```bash
cargo run -p evmguard-cli -- inspect --chain-id 1 --from 0x... --to 0x... --data 0x...
```

To produce an optimized binary:

```bash
cargo build --release -p evmguard-cli
```

The resulting binary is placed at `target/release/evmguard` (with a `.exe` extension on Windows).

#### Workspace crates

| Crate | Responsibility |
| --- | --- |
| `evmguard-core` | Transaction, proxy, call trace, finding, severity, and report domain types |
| `evmguard-analyzer` | Static inspection rules |
| `evmguard-report` | Text and JSON output rendering |
| `evmguard-rpc` | HTTP JSON-RPC transport, preflight, call trace normalization, and proxy storage inspection |
| `evmguard-cli` | Command-line argument parsing and orchestration |

#### Extensibility and design principles

The analyzer exposes `Rule`, `RulePack`, and `RuleRegistry` for compiled extensions. Rule packs receive a transaction, trace, or proxy context and return standard findings. Dynamic loading is intentionally outside the initial interface.

The analysis pipeline is: transaction request -> RPC preflight or trace executor -> trace normalizer -> analyzer rules -> text, JSON, and SARIF reports. Core design principles include deterministic analysis for identical inputs, no private-key handling, and machine-readable output for CI.

---

## 4. Command Structure and Global Behavior

### 4.1 Invocation form

```
evmguard <command> [flags...]
```

The command is the first argument. The four subcommands are:

| Command | Network access | Purpose |
| --- | --- | --- |
| `inspect` | Offline | Static calldata and recipient analysis, no RPC |
| `preflight` | Online | Chain-ID check plus gas estimation |
| `trace` | Online | Chain-ID check plus call-trace analysis |
| `proxy` | Online | Proxy classification from storage slots |

In addition, `help`, `--help`, or `-h` at the top level prints help.

### 4.2 Help

Running any of:

```bash
evmguard help
evmguard --help
evmguard -h
```

prints the four per-command usage strings separated by blank lines and exits successfully:

```
Usage:
  evmguard inspect --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--config <path>] [--format text|json|sarif]

Usage:
  evmguard preflight --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json|sarif]

Usage:
  evmguard trace --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json|sarif]

Usage:
  evmguard proxy --rpc-url <url> --chain-id <id> --address <address> [--format text|json|sarif]
```

If no command is given, or an unknown command is given, the same four usage strings are printed as an **error** (see Section 13). Within a subcommand, supplying `--help` or `-h` prints just that command's usage string, returned through the error path with the `Error: ` prefix.

### 4.3 Exit codes and the `Error:` prefix

- On success the process exits with code **0**.
- On any error the process prints `Error: ` followed by the error message to **stderr** and exits with code **1**.

---

## 5. Command Reference

All commands accept `--format text|json|sarif` (default `text`) and `--config <path>` (default: none, which uses the default rule set). Note that although all four commands accept `--config`, it appears in the printed usage string only for `inspect`.

### 5.1 inspect

**Purpose:** Fully offline static analysis. `inspect` never constructs an RPC client and never performs network access. It loads configuration, runs the static rule set against the calldata and recipient, applies configuration, and renders the report.

**Syntax:**

```
evmguard inspect --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--config <path>] [--format text|json|sarif]
```

**Exact usage string:**

```
Usage:
  evmguard inspect --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--config <path>] [--format text|json|sarif]
```

**Flags:**

| Flag | Required | Type | Default |
| --- | --- | --- | --- |
| `--chain-id` | Yes | unsigned integer (u64), non-zero | none |
| `--from` | Yes | string (address) | none |
| `--to` | Yes | string (address) | none |
| `--data` | Yes | hex string | none |
| `--value` | No | string | `"0"` |
| `--config` | No | path string | none (default rule set) |
| `--format` | No | `text` \| `json` \| `sarif` | `text` |

**RPC methods required:** None. `inspect` is fully offline and does **not** accept `--rpc-url`. Supplying `--rpc-url` to `inspect` triggers the error in Section 6.

**Example:**

```bash
evmguard inspect \
  --chain-id 1 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x095ea7b3000000000000000000000000333333333333333333333333333333333333333effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

This calldata is an ERC-20 `approve` granting the maximum uint256 allowance. Expected text output (illustrative):

```
EVMGuard inspection
Chain ID: 1
From: 0x1111111111111111111111111111111111111111
To: 0x2222222222222222222222222222222222222222
Highest severity: critical
Findings:
  [info] erc20.approval: ERC-20 approval call detected.
  [critical] erc20.unlimited-approval: Unlimited ERC-20 approval detected.
```

### 5.2 preflight

**Purpose:** Verifies the endpoint chain ID against the requested chain ID, then estimates gas. It does not broadcast or sign. The result attaches a preflight block containing the RPC chain ID and gas estimate.

**Syntax:**

```
evmguard preflight --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json|sarif]
```

**Exact usage string:**

```
Usage:
  evmguard preflight --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json|sarif]
```

**Flags:**

| Flag | Required | Type | Default |
| --- | --- | --- | --- |
| `--rpc-url` | Yes | string (URL) | none |
| `--chain-id` | Yes | unsigned integer (u64), non-zero | none |
| `--from` | Yes | string (address) | none |
| `--to` | Yes | string (address) | none |
| `--data` | Yes | hex string | none |
| `--value` | No | string | `"0"` |
| `--config` | No | path string (accepted but not shown in usage) | none |
| `--format` | No | `text` \| `json` \| `sarif` | `text` |

**RPC methods required:** `eth_chainId` and `eth_estimateGas`.

**Example:**

```bash
evmguard preflight \
  --rpc-url https://your-endpoint.example/rpc \
  --chain-id 8453 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x \
  --format text
```

Expected text output (illustrative, matching the rendering rules):

```
EVMGuard inspection
Chain ID: 8453
From: 0x1111111111111111111111111111111111111111
To: 0x2222222222222222222222222222222222222222
Highest severity: info
Findings:
  [info] transaction.empty-calldata: Transaction contains no calldata.
Preflight:
  RPC chain ID: 8453
  Gas estimate: 21000
```

### 5.3 trace

**Purpose:** Verifies the endpoint chain ID, then runs `debug_traceCall` with the `callTracer`, and analyzes the resulting call-frame tree, extending the report with `trace.*` findings.

**Syntax:**

```
evmguard trace --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json|sarif]
```

**Exact usage string:**

```
Usage:
  evmguard trace --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json|sarif]
```

**Flags:** Identical to `preflight` (`--rpc-url` required, `--chain-id`, `--from`, `--to`, `--data` required; `--value` default `"0"`; `--config` accepted but not in usage; `--format` default `text`).

**RPC methods required:** `eth_chainId`, `debug_traceCall`, and the `callTracer` tracer. Trace functionality is commonly restricted to dedicated trace endpoints and may not be available on public RPC services.

**Example:**

```bash
evmguard trace \
  --rpc-url https://your-trace-endpoint.example/rpc \
  --chain-id 1 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0xa9059cbb0000000000000000000000004444444444444444444444444444444444444444000000000000000000000000000000000000000000000000000000000000000a \
  --format json
```

The output is a JSON report whose `findings` array additionally includes any `trace.*` findings produced from the call-frame tree (delegatecalls, contract creation, internal native transfers, execution errors).

### 5.4 proxy

**Purpose:** Reads the EIP-1967 implementation, administrator, and beacon storage slots of a contract, classifies the proxy kind (EIP-1967, UUPS, or Beacon), and reports an upgrade administrator if present. UUPS implementations are identified through `proxiableUUID`.

**Syntax:**

```
evmguard proxy --rpc-url <url> --chain-id <id> --address <address> [--format text|json|sarif]
```

**Exact usage string:**

```
Usage:
  evmguard proxy --rpc-url <url> --chain-id <id> --address <address> [--format text|json|sarif]
```

**Flags:**

| Flag | Required | Type | Default |
| --- | --- | --- | --- |
| `--rpc-url` | Yes | string (URL) | none |
| `--chain-id` | Yes | unsigned integer (u64), non-zero | none |
| `--address` | Yes | string (address) | none |
| `--config` | No | path string (accepted but not shown in usage) | none |
| `--format` | No | `text` \| `json` \| `sarif` | `text` |

`proxy` has **no** `--from`, `--to`, `--data`, or `--value` flags; it uses `--address` instead.

**RPC methods required:** `eth_chainId`, `eth_getStorageAt`, and `eth_call`.

**Example:**

```bash
evmguard proxy \
  --rpc-url https://your-endpoint.example/rpc \
  --chain-id 1 \
  --address 0x5555555555555555555555555555555555555555 \
  --format text
```

Expected text output for an EIP-1967 proxy with an implementation set and no findings (illustrative):

```
EVMGuard proxy inspection
Address: 0x5555555555555555555555555555555555555555
Kind: EIP-1967
Implementation: 0ximpl...
Admin: None
Beacon: None
Findings:
  [info] proxy.eip1967: EIP-1967 proxy detected at 0x5555555555555555555555555555555555555555.
```

---

## 6. Arguments and Input Validation Reference

### 6.1 Address format

Addresses are validated by `is_evm_address`: the value must be exactly **42 characters**, start with `0x`, and have every character after `0x` be an ASCII hex digit (the `0x` prefix plus exactly 40 hex characters).

For configuration addresses, normalization strips a leading `0x` or `0X` (case-insensitive), requires exactly 40 ASCII-hex characters, and stores the result lowercased with a `0x` prefix.

### 6.2 Calldata hex format

Calldata is validated by `is_hex_data`: it must start with `0x`, the number of characters after `0x` must be **even**, and every character after `0x` must be an ASCII hex digit.

For static analysis, the analyzer strips a leading `0x` before matching selectors. Selector matching uses 8-hex-character selectors (4 bytes); each ABI word is 64 hex characters (32 bytes).

### 6.3 Value format and normalization

`--value` defaults to the string `"0"`. The RPC layer normalizes it as follows:

- The literal `"0"` becomes `"0x0"`.
- Otherwise the value must start with `0x`; if it does not, it is rejected.
- The hex quantity after `0x` must be non-empty and all ASCII hex digits.
- Leading zeros are stripped to produce a minimal RPC hex quantity. If all characters are zero, the result is `"0x0"`; otherwise it is `0x<stripped quantity>`.

### 6.4 Chain-ID rules

`--chain-id` is parsed as an unsigned 64-bit integer (`u64`) and must be **non-zero**. Because the internal chain-id defaults to 0, omitting `--chain-id` triggers the non-zero requirement error.

### 6.5 Complete error message reference

#### CLI parsing errors

| Trigger | Exact message |
| --- | --- |
| No command given, or unknown top-level command | The four usage strings joined by blank lines |
| Recognized flag is the last token with no value (parse_arguments) | `Missing value for <flag>.\n<command usage>` |
| Recognized flag is the last token with no value (proxy) | `Missing value for <flag>.\n<PROXY_USAGE>` |
| Unrecognized token (parse_arguments) | `Unknown argument: <token>.\n<command usage>` |
| Unrecognized token (proxy) | `Unknown argument: <token>.\n<PROXY_USAGE>` |
| `--help` / `-h` inside a subcommand (parse_arguments) | The relevant per-command usage string (returned as an error) |
| `--help` / `-h` inside `proxy` | `PROXY_USAGE` (returned as an error) |
| `--chain-id` not a u64 | `Chain ID must be an unsigned integer.` |
| `--format` not text/json/sarif | `Format must be text, json, or sarif.` |
| `--rpc-url` used with `inspect` | `--rpc-url is only valid with the preflight command.\n<command usage>` |
| `--chain-id` zero or missing | `A non-zero --chain-id is required.` |
| `--from`, `--to`, or `--data` missing/empty (inspect, preflight, trace) | `--from, --to, and --data are required.\n<command usage>` |
| `--rpc-url` missing (preflight, trace) | `--rpc-url is required.\n<command usage>` |
| `--rpc-url` missing (proxy) | `--rpc-url is required.\n<PROXY_USAGE>` |
| `--address` missing (proxy) | `--address is required.\n<PROXY_USAGE>` |

> Note: the `--rpc-url is only valid with the preflight command` message names only `preflight`, even though `trace` and `proxy` also accept `--rpc-url`. Only `inspect` rejects `--rpc-url`.

#### Network / chain-id mismatch errors

| Trigger | Exact message |
| --- | --- |
| Endpoint chain ID does not match requested | `RPC endpoint chain ID <remote> does not match requested chain ID <requested>.` |

#### RPC transport and validation errors (from `evmguard-rpc`)

| Variant | Display format |
| --- | --- |
| InvalidEndpoint | `Invalid RPC endpoint: <message>` |
| InvalidTransaction | `Invalid transaction: <message>` |
| Transport | `RPC transport error: <error>` |
| Http | `RPC endpoint returned HTTP status <status>` |
| Remote | `RPC endpoint returned error <code>: <message>` |
| InvalidResponse | `Invalid RPC response: <message>` |

Specific RPC validation messages:

| Trigger | Message |
| --- | --- |
| Endpoint scheme not http/https | `endpoint must use HTTP or HTTPS` |
| `from` not a valid address | `from must be a 20-byte EVM address` |
| `to` not a valid address | `to must be a 20-byte EVM address` |
| `data` not even-length hex with 0x | `data must be even-length hexadecimal data prefixed with 0x` |
| `value` not 0 or hex quantity | `value must be 0 or an RPC hex quantity` |
| proxy `--address` invalid | `address must be a 20-byte EVM address` |
| quantity result not hex / missing 0x | `<field> result must be a hexadecimal quantity` |
| quantity result empty | `<field> result must not be empty` |
| quantity exceeds u64 | `<field> result exceeds the supported range` |
| storage result not hex word | `storage result must be a hexadecimal word` |
| storage result wrong length | `storage result must be a 32-byte hexadecimal word` |
| eth_call result not a string | `eth_call result must be a string` |
| contract returned empty address | `contract returned an empty address` |
| JSON-RPC response missing result | `missing result field` |
| trace `calls` not an array | `calls field must be an array` |
| trace missing required field | `call trace is missing required <field> field` |
| trace field wrong type | `call trace field <field> must be a string` |

For a remote JSON-RPC error, EVMGuard extracts the error `code` and `message` from the response. When the error object has no `message`, EVMGuard substitutes `Unknown JSON-RPC error`; when it has no `code`, the code defaults to `0`.

The HTTP JSON-RPC client uses a 15-second request timeout. Requests are sent as POST with the envelope `{"jsonrpc":"2.0","id":1,"method":<method>,"params":<params>}`.

---

## 7. Output Formats

Select the format with `--format text|json|sarif`. Parsing is case-sensitive and exact; any other value yields `Format must be text, json, or sarif.`

Severity values are lowercase strings: `info`, `warning`, `critical`.

### 7.1 Text

Transaction analysis (inspect / preflight / trace) text layout:

```
EVMGuard inspection
Chain ID: <chain_id>
From: <from>
To: <to>
Highest severity: <highest_severity>
Findings:
  [<severity>] <rule_id>: <message>
  ...
```

Each finding line has two leading spaces, the severity in square brackets, then `rule_id: message`. If a preflight result is present, the following block is appended (omitted entirely when absent):

```
Preflight:
  RPC chain ID: <rpc_chain_id>
  Gas estimate: <gas_estimate>
```

Complete text example (chain 8453, one info finding, preflight present):

```
EVMGuard inspection
Chain ID: 8453
From: 0xfrom
To: 0xto
Highest severity: info
Findings:
  [info] test.rule: Test finding.
Preflight:
  RPC chain ID: 8453
  Gas estimate: 21000
```

Proxy text layout (no Preflight block):

```
EVMGuard proxy inspection
Address: <address>
Kind: <kind>
Implementation: <implementation>
Admin: <admin>
Beacon: <beacon>
Findings:
  [<severity>] <rule_id>: <message>
```

Absent optional proxy fields render as the literal string `None`. `kind` renders as `EIP-1967`, `UUPS`, `Beacon`, or `None`. Complete proxy text example:

```
EVMGuard proxy inspection
Address: 0xproxy
Kind: EIP-1967
Implementation: 0ximpl
Admin: None
Beacon: None
Findings:
```

### 7.2 JSON

JSON is produced with `serde_json` pretty printing, which emits object keys in **sorted (lexicographic)** order and appends a trailing newline. Output is always valid JSON.

Transaction JSON structure:

- `transaction`: object with `chainId` (number), `from`, `to`, `data`, `value` (strings)
- `highestSeverity`: string (`info` / `warning` / `critical`)
- `preflight`: object with `rpcChainId` and `gasEstimate`, or JSON `null` when absent
- `findings`: array of objects, each with `ruleId`, `severity`, `message`

Complete JSON example (keys shown in serde's sorted order):

```json
{
  "findings": [
    {
      "message": "Test finding.",
      "ruleId": "test.rule",
      "severity": "info"
    }
  ],
  "highestSeverity": "info",
  "preflight": {
    "gasEstimate": 21000,
    "rpcChainId": 8453
  },
  "transaction": {
    "chainId": 8453,
    "data": "0x",
    "from": "0xfrom",
    "to": "0xto",
    "value": "0"
  }
}
```

Proxy JSON structure:

- `proxy`: object with `address`, `kind`, `implementation`, `admin`, `beacon`
- `findings`: array of finding objects

In proxy JSON, `kind` is a string (`EIP-1967` / `UUPS` / `Beacon`) or JSON `null` when absent, and the optional `implementation`, `admin`, and `beacon` fields serialize to JSON `null` when absent (not the literal string `None` used in text output).

### 7.3 SARIF

SARIF output conforms to SARIF 2.1.0 and is shared by both transaction and proxy commands (proxy SARIF renders the same finding structure). Top-level structure:

- `$schema`: `https://json.schemastore.org/sarif-2.1.0.json`
- `version`: `2.1.0`
- `runs`: exactly one run, with `tool.driver.name` = `EVMGuard`, `tool.driver.rules`, and `results`

`rules[]` is deduplicated per `rule_id` (first severity seen per rule id wins; rule ids are sorted). Each rule object: `{ "id": <rule_id>, "defaultConfiguration": { "level": <level> } }`. `results[]` has one entry per finding (not deduplicated): `{ "ruleId": ..., "level": ..., "message": { "text": ... } }`.

#### Severity-to-SARIF level mapping

| Severity | SARIF level |
| --- | --- |
| `info` | `note` |
| `warning` | `warning` |
| `critical` | `error` |

Complete SARIF example (one critical finding):

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "results": [
        {
          "level": "error",
          "message": {
            "text": "Critical test finding."
          },
          "ruleId": "test.critical"
        }
      ],
      "tool": {
        "driver": {
          "name": "EVMGuard",
          "rules": [
            {
              "defaultConfiguration": {
                "level": "error"
              },
              "id": "test.critical"
            }
          ]
        }
      }
    }
  ],
  "version": "2.1.0"
}
```

---

## 8. Complete Rules Catalog

Rule identifiers use lowercase dot notation. The severity model is: **info** = observed behavior needing context; **warning** = malformed or potentially unsafe input; **critical** = high-impact effect requiring explicit review.

### 8.1 Transaction rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `transaction.empty-calldata` | info | The calldata payload (after stripping `0x`) is empty: `Transaction contains no calldata.` |
| `transaction.invalid-calldata` | warning | Calldata is odd-length or contains non-hex characters: `Transaction calldata is not valid hexadecimal data.` |
| `transaction.unknown-selector` | info | Non-empty valid-hex calldata whose selector matches no known rule: `Transaction selector is not covered by the active static rule set.` |
| `transaction.zero-address-recipient` | critical | Recipient is the zero address: `Transaction targets the zero address.` (Returns early; does not also emit suspicious-recipient.) |
| `transaction.suspicious-recipient` | critical | Recipient is in the configured high-risk list: `Transaction targets a configured high-risk contract: <address>.` |

### 8.2 ERC-20 rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `erc20.approval` | info | `approve()` detected: `ERC-20 approval call detected.` |
| `erc20.approval-malformed` | warning | approve calldata shorter than 136 hex chars: `ERC-20 approval calldata is shorter than the expected ABI encoding.` |
| `erc20.allowance-increase` | warning | `increaseAllowance()` detected: `ERC-20 allowance increase call detected.` |
| `erc20.allowance-increase-malformed` | warning | increaseAllowance calldata shorter than 136 hex chars: `ERC-20 allowance increase calldata is shorter than the expected ABI encoding.` |
| `erc20.permit` | warning | EIP-2612 `permit()` detected: `ERC-20 permit signed approval call detected.` |
| `erc20.permit-malformed` | warning | permit calldata shorter than 456 hex chars: `ERC-20 permit calldata is shorter than the expected ABI encoding.` |
| `erc20.transfer` | info | `transfer()` detected: `ERC-20 transfer call detected.` (no unlimited check) |
| `erc20.transfer-malformed` | warning | transfer calldata shorter than 136 hex chars: `ERC-20 transfer calldata is shorter than the expected ABI encoding.` |
| `erc20.transfer-from` | info | `transferFrom()` detected: `ERC-20 transferFrom call detected.` |
| `erc20.transfer-from-malformed` | warning | transferFrom calldata shorter than 200 hex chars: `ERC-20 transferFrom calldata is shorter than the expected ABI encoding.` |
| `erc20.unlimited-approval` | critical | Maximum uint256 allowance granted via approve, increaseAllowance, or permit. Messages: `Unlimited ERC-20 approval detected.` / `Unlimited ERC-20 allowance increase detected.` / `Unlimited ERC-20 permit approval detected.` |

### 8.3 Permit2 rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `permit2.approval` | warning | Permit2 `approve()` detected: `Permit2 approval call detected.` |
| `permit2.approval-malformed` | warning | Permit2 approval calldata shorter than 264 hex chars: `Permit2 approval calldata is shorter than the expected ABI encoding.` |
| `permit2.unlimited-approval` | critical | Permit2 approval grants the maximum uint160 allowance: `Unlimited Permit2 approval detected.` |
| `permit2.transfer-from` | info | Permit2 `transferFrom()` detected: `Permit2 transferFrom call detected.` (no unlimited check) |
| `permit2.transfer-from-malformed` | warning | Permit2 transferFrom calldata shorter than 264 hex chars: `Permit2 transferFrom calldata is shorter than the expected ABI encoding.` |
| `permit2.permit` | warning | Permit2 off-chain signed approval (single or batch): `Permit2 signed approval call detected.` |
| `permit2.signature-transfer` | warning | Permit2 signed transfer (single or batch): `Permit2 signed transfer call detected.` |

### 8.4 NFT rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `nft.operator-approval` | critical | `setApprovalForAll(operator, true)` grants control over all tokens: `NFT operator approval grants control over all tokens.` |
| `nft.operator-approval-revoked` | info | `setApprovalForAll(operator, false)` revokes a prior approval: `NFT operator approval is being revoked.` |
| `nft.operator-approval-malformed` | warning | setApprovalForAll calldata shorter than 136 hex chars: `NFT operator approval calldata is shorter than the expected ABI encoding.` |

### 8.5 Contract (privileged-action) rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `contract.privileged-action` | critical | A contract upgrade, admin change, or ownership change. Message: `Privileged contract action detected: <action>.` where `<action>` is one of `upgradeTo`, `upgradeToAndCall`, `changeAdmin`, `transferOwnership`, `renounceOwnership`. |

### 8.6 Trace rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `trace.delegatecall` | warning | A delegatecall executing external code in the caller's storage context: `Delegate call detected at depth <depth> targeting <target>.` |
| `trace.contract-creation` | info | A CREATE or CREATE2 deployment: `Contract creation detected at depth <depth> for <target>.` |
| `trace.internal-native-transfer` | info | A nested frame (depth > 0) with non-zero value: `Internal native asset transfer detected at depth <depth> to <target>.` |
| `trace.execution-reverted` | critical | A frame reported an error: `Execution error detected at depth <depth>: <error>.` |

### 8.7 Proxy rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `proxy.eip1967` | info | Target is an EIP-1967 standard proxy: `EIP-1967 proxy detected at <address>.` |
| `proxy.uups` | info | Target is a UUPS (EIP-1822-style) proxy: `UUPS proxy detected at <address>.` |
| `proxy.beacon` | info | Target is a beacon proxy: `Beacon proxy detected at <address>.` |
| `proxy.admin-present` | warning | The proxy has an upgrade administrator: `Proxy upgrade administrator detected at <admin>.` (Only emitted alongside a detected proxy kind.) |

### 8.8 How unlimited approval is detected

- **ERC-20 (uint256):** `grants_max_allowance(word)` returns true when **every** character of the 64-hex-character amount word is `f` or `F` (that is, `2^256-1`). Used by `erc20.approval` (amount word at hex offset `72..136`), `erc20.allowance-increase` (added value at `72..136`), and `erc20.permit` (value at `136..200`). All three flag `erc20.unlimited-approval`.
- **Permit2 (uint160):** `is_max_uint160(word)` splits the 64-character amount word at length minus 40: the top 24 hex characters must all be `0`, and the bottom 40 hex characters (160 bits) must be non-empty and all `f`/`F` (that is, `type(uint160).max = 2^160-1`). Used only by `permit2.approval` (amount word at `136..200`) to flag `permit2.unlimited-approval`.

### 8.9 Function selectors detected (without 0x prefix)

**ERC-20:**

| Function | Selector |
| --- | --- |
| `approve` | `095ea7b3` |
| `increaseAllowance` | `39509351` |
| `permit` (EIP-2612) | `d505accf` |
| `transfer` | `a9059cbb` |
| `transferFrom` | `23b872dd` |

**Permit2:**

| Function | Selector(s) |
| --- | --- |
| approval | `87517c45` |
| transferFrom | `36c78516` |
| permit (single / batch) | `2b67b570`, `2a2d80d1` |
| signature transfer (single / batch) | `30f28b7a`, `edd9444b` |

**NFT:**

| Function | Selector |
| --- | --- |
| `setApprovalForAll` | `a22cb465` |

**Privileged actions (all map to `contract.privileged-action`, critical):**

| Function | Selector |
| --- | --- |
| `upgradeTo` | `3659cfe6` |
| `upgradeToAndCall` | `4f1ef286` |
| `changeAdmin` | `8f283970` |
| `transferOwnership` | `f2fde38b` |
| `renounceOwnership` | `715018a6` |

### 8.10 Calldata dispatch order

The first matching branch wins. Order of checks in `inspect_calldata`:

1. empty -> `transaction.empty-calldata`
2. invalid hex -> `transaction.invalid-calldata`
3. `095ea7b3` -> ERC-20 approval
4. `a22cb465` -> NFT operator approval
5. `39509351` -> ERC-20 increaseAllowance
6. `d505accf` -> ERC-20 permit
7. `a9059cbb` -> ERC-20 transfer
8. `23b872dd` -> ERC-20 transferFrom
9. `87517c45` -> Permit2 approval
10. `36c78516` -> Permit2 transferFrom
11. `2b67b570` / `2a2d80d1` -> Permit2 permit
12. `30f28b7a` / `edd9444b` -> Permit2 signature transfer
13. the five privileged-action selectors -> `contract.privileged-action`
14. fallback -> `transaction.unknown-selector`

Recipient rules (`transaction.zero-address-recipient`, `transaction.suspicious-recipient`) are always evaluated against `--to`, independently of calldata. The trace tree (`inspect_trace`) and proxy info (`inspect_proxy`) produce the `trace.*` and `proxy.*` findings respectively.

---

## 9. Configuration File (evmguard.toml)

Use `--config evmguard.toml` with any command to disable rules or override their severity. Configuration is applied to findings before rendering.

### 9.1 Full schema and example

```toml
# Load reusable rule packs. Paths are resolved relative to this file's directory.
include = ["path/to/rules.toml"]

[rules]
# Rule IDs whose findings are filtered out entirely.
disabled = ["transaction.unknown-selector"]

[rules.severity]
# Override the severity of specific rules. Values: info, warning, critical.
"erc20.unlimited-approval" = "warning"

[targets]
# Addresses that produce a critical finding when used as a transaction recipient.
suspicious = ["0x1111111111111111111111111111111111111111"]
```

### 9.2 Disabling rules

`[rules].disabled` is a list of rule IDs. Findings whose `rule_id` is in this list are removed before rendering.

### 9.3 Overriding severity

`[rules.severity]` maps `"rule.id" = "info|warning|critical"`. For each remaining finding, if the map contains its rule ID, the finding's severity is set to that value. Supported severity values are exactly `info`, `warning`, and `critical`.

### 9.4 Suspicious target addresses

Addresses listed under `targets.suspicious` produce a `transaction.suspicious-recipient` critical finding when used as a transaction recipient. Use this list for contracts that require explicit review in your environment. Addresses are normalized to lowercase with a `0x` prefix; both `0x1111...` and `0X1111...` match.

### 9.5 Includes, rule packs, and override precedence

Each include path is resolved relative to the directory of the current config file. Includes are processed **first** (each included configuration is merged in), and **then** the local document's severity, disabled, and suspicious entries are applied. Because the severity map is merged with `extend`, local severity entries overwrite included ones. In short: **local configuration overrides included severities.**

### 9.6 Configuration errors

| Trigger | Message |
| --- | --- |
| Include cycle (a path is revisited) | `Configuration include cycle detected: <path>` (contains `include cycle`) |
| Invalid suspicious address | `Invalid contract address in configuration: <address>` (contains `Invalid contract address`) |
| Unrecognized severity string | `Unsupported severity for <rule_id>: <level>` |
| Cannot resolve config path | `Unable to resolve configuration file: <error>` |
| Cannot read config file | `Unable to read configuration file: <error>` |
| TOML parse failure | `Unable to parse configuration file: <error>` |

---

## 10. Networks and RPC Providers

Any provider that supports the required methods for a command can be used. Standard HTTP and HTTPS JSON-RPC endpoints are supported (the endpoint scheme must be `http` or `https`).

### 10.1 Required RPC methods per command

| Command | Required methods |
| --- | --- |
| `inspect` | None (offline) |
| `preflight` | `eth_chainId`, `eth_estimateGas` |
| `trace` | `eth_chainId`, `debug_traceCall` (with `callTracer`) |
| `proxy` | `eth_chainId`, `eth_getStorageAt`, `eth_call` |

Trace functionality is commonly restricted to dedicated trace endpoints and may not be available on public RPC services. If `debug_traceCall` or the `callTracer` is unavailable, the `trace` command cannot run.

### 10.2 Proxy storage slots and selectors (reference)

The `proxy` command reads three EIP-1967 storage slots in order: implementation, admin, beacon.

| Constant | Value |
| --- | --- |
| Implementation slot | `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` |
| Admin slot | `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103` |
| Beacon slot | `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50` |
| `proxiableUUID` selector (UUPS) | `0x52d1902d` |
| Beacon `implementation()` selector | `0x5c60da1b` |

Classification: if the beacon slot is set, the proxy is a Beacon proxy (and the implementation is fetched from the beacon via `0x5c60da1b`). Otherwise, if the implementation slot is set, the proxy is UUPS when `proxiableUUID` (`0x52d1902d`) returns a word equal to the implementation slot (case-insensitive); otherwise it is EIP-1967. If neither beacon nor implementation is present, no proxy kind is detected and no proxy findings are emitted.

### 10.3 Endpoint security guidance

Use environment variables or GitHub Actions secrets for endpoints containing credentials. **Do not commit endpoint URLs that contain keys or access tokens.**

---

## 11. CI and Integrations

### 11.1 SARIF GitHub Actions workflow

The repository includes `.github/workflows/sarif.yml`, named **EVMGuard SARIF**, triggered manually via `workflow_dispatch` from the Actions tab. The job `inspect` ("Generate SARIF report") runs on `ubuntu-latest`.

**Inputs:**

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `rpc_url` | EVM JSON-RPC endpoint | true | |
| `chain_id` | Expected EVM chain ID | true | |
| `from` | Transaction sender address | true | |
| `to` | Transaction target address | true | |
| `data` | Transaction calldata | true | |
| `value` | Transaction value as 0 or an RPC hex quantity | false | `"0"` |

**Command run by the workflow:**

```bash
cargo run -p evmguard-cli -- preflight \
  --rpc-url "${{ inputs.rpc_url }}" \
  --chain-id "${{ inputs.chain_id }}" \
  --from "${{ inputs.from }}" \
  --to "${{ inputs.to }}" \
  --data "${{ inputs.data }}" \
  --value "${{ inputs.value }}" \
  --format sarif > evmguard.sarif
```

Note that the workflow runs a transaction **preflight** (an online command that also verifies the endpoint chain ID and estimates gas), not the offline `inspect` command. The resulting `evmguard.sarif` is uploaded to GitHub Code Scanning via `github/codeql-action/upload-sarif@v3` (`sarif_file: evmguard.sarif`). Permissions: `contents: read`, `security-events: write`. Checkout uses `actions/checkout@v4`; Rust is installed via `dtolnay/rust-toolchain@stable`.

### 11.2 Consuming JSON and SARIF in automation

- **SARIF:** Upload to GitHub Code Scanning (or any SARIF-compatible viewer). The severity-to-level mapping is `info -> note`, `warning -> warning`, `critical -> error`.
- **JSON:** Parse the `findings` array (`ruleId`, `severity`, `message`) and the top-level `highestSeverity`. For transaction reports, inspect `preflight` (`rpcChainId`, `gasEstimate`) when present. Use `highestSeverity` to gate a pipeline (for example, fail when it equals `critical`).

### 11.3 Other workflows (reference)

- **CI** (`.github/workflows/ci.yml`, name `CI`): triggered on push to `main` and `feature/**`, and pull requests to `main` (permissions `contents: read`). Checkout uses `actions/checkout@v7`; Rust is installed via `dtolnay/rust-toolchain@stable`. Jobs:
  - `test` ("Test Rust workspace"): installs the `clippy` and `rustfmt` components, then runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
  - `anvil` ("Test against Anvil"): installs Foundry via `foundry-rs/foundry-toolchain@v1` (version `stable`), then runs `cargo test -p evmguard-cli --test anvil -- --ignored`.
  - `coverage` ("Measure test coverage", `timeout-minutes: 15`): installs the `llvm-tools-preview` component and `cargo install cargo-llvm-cov --locked`, runs `cargo llvm-cov --workspace --lcov --output-path lcov.info`, and uploads the artifact via `actions/upload-artifact@v4` with name `coverage-lcov`, path `lcov.info`, and `if-no-files-found: error`.
- **Release** (`.github/workflows/release.yml`, name `Release binaries`): triggered on release `published` or `workflow_dispatch` with a `tag` input (permissions `contents: write`). Checkout uses `actions/checkout@v7`; Rust is installed via `dtolnay/rust-toolchain@stable`. A matrix (fail-fast disabled) builds three assets (`evmguard-linux`, `evmguard-windows.exe`, `evmguard-macos`) via `cargo build --release -p evmguard-cli` and uploads them to the release with `gh release upload "$RELEASE_TAG" ... --clobber`.

---

## 12. Practical Recipes

### 12.1 Detect an unlimited ERC-20 approval (offline)

```bash
evmguard inspect \
  --chain-id 1 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x095ea7b3000000000000000000000000333333333333333333333333333333333333333effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

Look for `erc20.approval` (info) followed by `erc20.unlimited-approval` (critical).

### 12.2 Check a Permit2 approval

```bash
evmguard inspect \
  --chain-id 1 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x000000000022D473030F116dDEE9F6B43aC78BA3 \
  --data 0x87517c45...
```

A `permit2.approval` (warning) is emitted; if the amount word is the maximum uint160, `permit2.unlimited-approval` (critical) is also emitted.

### 12.3 Spot a setApprovalForAll grant

```bash
evmguard inspect \
  --chain-id 1 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x4444444444444444444444444444444444444444 \
  --data 0xa22cb46500000000000000000000000055555555555555555555555555555555555555550000000000000000000000000000000000000000000000000000000000000001
```

A `true` approved flag yields `nft.operator-approval` (critical); a `false` flag yields `nft.operator-approval-revoked` (info).

### 12.4 Inspect a proxy

```bash
evmguard proxy \
  --rpc-url https://your-endpoint.example/rpc \
  --chain-id 1 \
  --address 0x5555555555555555555555555555555555555555
```

The report shows `Kind` (EIP-1967, UUPS, Beacon, or None), the implementation/admin/beacon addresses, and findings such as `proxy.eip1967`/`proxy.uups`/`proxy.beacon` plus `proxy.admin-present` (warning) if an upgrade admin exists.

### 12.5 Run a preflight

```bash
evmguard preflight \
  --rpc-url https://your-endpoint.example/rpc \
  --chain-id 1 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x
```

The output includes a `Preflight:` block with the RPC chain ID and gas estimate. The endpoint chain ID is verified against `--chain-id`.

### 12.6 Generate SARIF offline with inspect

This recipe produces a SARIF report fully offline using the `inspect` command:

```bash
evmguard inspect \
  --chain-id 1 \
  --from 0x1111111111111111111111111111111111111111 \
  --to 0x2222222222222222222222222222222222222222 \
  --data 0x095ea7b3... \
  --format sarif > evmguard.sarif
```

Upload `evmguard.sarif` to GitHub Code Scanning or any SARIF viewer.

This is a standalone offline example and does **not** mirror the SARIF GitHub Actions workflow described in Section 11.1, which runs the online `preflight` command (`cargo run -p evmguard-cli -- preflight ... --format sarif`). If you want output that matches the CI workflow, use `preflight` with `--format sarif` instead.

---

## 13. Exit Codes and Error Handling

| Exit code | Meaning |
| --- | --- |
| `0` | Success. The report (or help) was printed. |
| `1` | An error occurred. The message is printed to **stderr** prefixed with `Error: `. |

All errors, whether from argument parsing, configuration loading, input validation, chain-id mismatch, or RPC transport, propagate up and are printed as:

```
Error: <message>
```

Reports and help text on the success path are printed to **stdout**.

---

## 14. Limitations and Safety Notice

- EVMGuard performs **static, selector-based** calldata analysis. It recognizes a fixed set of function selectors (listed in Section 8.9). Calldata whose selector is not in that set is reported as `transaction.unknown-selector` and is **not decoded**.
- The static analyzer does not execute transactions. The `preflight`, `trace`, and `proxy` commands query an RPC endpoint but never sign or broadcast anything.
- A finding is a signal, not a verdict. Critical findings (unlimited approvals, operator approvals, privileged actions, zero-address recipients, execution reverts) flag high-impact effects that require explicit human review.
- EVMGuard is an analysis tool and **does not guarantee that an analyzed transaction or contract is safe.**
- EVMGuard performs **no private-key handling** and produces deterministic analysis for identical inputs.

---

## 15. Troubleshooting and FAQ

**Q: I get `--rpc-url is only valid with the preflight command.` when running inspect.**
A: `inspect` is offline and rejects `--rpc-url`. Remove the flag, or use `preflight`/`trace`/`proxy` if you need network access. The message only names `preflight`, but `trace` and `proxy` also accept `--rpc-url`.

**Q: I get `A non-zero --chain-id is required.`**
A: You omitted `--chain-id` or passed `0`. Provide a non-zero unsigned integer.

**Q: I get `RPC endpoint chain ID <a> does not match requested chain ID <b>.`**
A: The endpoint reports a different chain ID than the one you passed via `--chain-id`. Point at the correct endpoint or correct the `--chain-id`.

**Q: The `trace` command fails to get a trace.**
A: Your endpoint likely does not support `debug_traceCall` with the `callTracer`. Trace is commonly restricted to dedicated trace endpoints. Use a trace-capable provider.

**Q: I get `Invalid RPC endpoint: endpoint must use HTTP or HTTPS`.**
A: The `--rpc-url` scheme must be `http` or `https`.

**Q: I get `Invalid transaction: value must be 0 or an RPC hex quantity`.**
A: `--value` must be the literal `0` or a `0x`-prefixed hex quantity with only hex digits.

**Q: I get `Invalid transaction: from must be a 20-byte EVM address` (or `to`).**
A: Addresses must be exactly `0x` plus 40 hex characters (42 characters total).

**Q: My config include fails with an `include cycle` error.**
A: Two config files include each other (directly or transitively). Break the cycle.

**Q: My config fails with `Invalid contract address in configuration`.**
A: A `targets.suspicious` entry is not a valid 40-hex-character address with a `0x`/`0X` prefix.

**Q: Why are my JSON keys in a different order than the manual shows?**
A: They are not; serde emits keys in sorted lexicographic order, which is what the examples show. The output is always valid JSON.

**Q: A request times out.**
A: The HTTP JSON-RPC client uses a 15-second timeout. Check endpoint availability and latency.

---

## 16. Contributing, Security Reporting, and License

### 16.1 Contributing

- Use the **stable** Rust toolchain. `cargo fmt`, `cargo clippy`, and `cargo test` must pass before opening a PR.
- Open an issue before substantial changes. Keep PRs focused on one behavior or rule.
- Include tests for every new or modified rule. Preserve stable rule identifiers once released. Update docs when public behavior changes.
- New rules must define a stable identifier, a severity, expected evidence, test fixtures, and documentation in `docs/rules.md`.
- Use concise imperative commit messages (for example, `Add ERC-20 approval inspection`).

### 16.2 Security reporting

- **Do not disclose security vulnerabilities through public issues.** Use a private security advisory in the repository, including reproduction steps, affected versions, impact, and suggested mitigations where possible.
- Scope: vulnerabilities in EVMGuard source code, release artifacts, CI workflows, or documented deployment instructions.
- Remember: EVMGuard is an analysis tool and does not guarantee that an analyzed transaction or contract is safe.

### 16.3 License

EVMGuard is licensed under the **Apache License 2.0** (SPDX `Apache-2.0`). See the `LICENSE` file in the repository.
