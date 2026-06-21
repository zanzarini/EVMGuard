# Rules

## Rule format

Every finding has a stable identifier, severity, and message. Rule identifiers use lowercase dot notation.

| Rule ID | Severity | Description |
| --- | --- | --- |
| `transaction.empty-calldata` | info | The transaction contains no calldata. |
| `transaction.invalid-calldata` | warning | The calldata is not valid hexadecimal data. |
| `transaction.unknown-selector` | info | The selector is not covered by the active static rules. |
| `erc20.approval-malformed` | warning | The ERC-20 approval calldata is shorter than its expected ABI encoding. |
| `erc20.approval` | info | An ERC-20 approval call was detected. |
| `erc20.unlimited-approval` | critical | An ERC-20 approval grants the maximum uint256 allowance. |

## Severity model

- `info` records an observed behavior that requires context.
- `warning` identifies malformed or potentially unsafe input.
- `critical` identifies a high-impact effect that must be explicitly reviewed.
