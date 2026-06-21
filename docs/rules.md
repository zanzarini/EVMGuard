# Rules

## Rule format

Every finding has a stable identifier, severity, and message. Rule identifiers use lowercase dot notation.

| Rule ID | Severity | Description |
| --- | --- | --- |
| `transaction.empty-calldata` | info | The transaction contains no calldata. |
| `transaction.invalid-calldata` | warning | The calldata is not valid hexadecimal data. |
| `transaction.unknown-selector` | info | The selector is not covered by the active static rules. |
| `transaction.zero-address-recipient` | critical | The transaction targets the zero address. |
| `transaction.suspicious-recipient` | critical | The transaction targets a configured high-risk contract. |
| `erc20.approval-malformed` | warning | The ERC-20 approval calldata is shorter than its expected ABI encoding. |
| `erc20.approval` | info | An ERC-20 approval call was detected. |
| `erc20.unlimited-approval` | critical | An ERC-20 approval, allowance increase, or permit grants the maximum uint256 allowance. |
| `erc20.allowance-increase-malformed` | warning | ERC-20 allowance increase calldata is shorter than its expected ABI encoding. |
| `erc20.allowance-increase` | warning | An ERC-20 allowance increase call was detected. |
| `erc20.permit-malformed` | warning | ERC-20 permit calldata is shorter than its expected ABI encoding. |
| `erc20.permit` | warning | An ERC-20 permit signed approval (EIP-2612) call was detected. |
| `erc20.transfer-malformed` | warning | ERC-20 transfer calldata is shorter than its expected ABI encoding. |
| `erc20.transfer` | info | An ERC-20 transfer call was detected. |
| `erc20.transfer-from-malformed` | warning | ERC-20 transferFrom calldata is shorter than its expected ABI encoding. |
| `erc20.transfer-from` | info | An ERC-20 transferFrom call was detected. |
| `nft.operator-approval-malformed` | warning | NFT operator approval calldata is shorter than its expected ABI encoding. |
| `nft.operator-approval` | critical | An NFT operator approval grants control over all tokens. |
| `nft.operator-approval-revoked` | info | An NFT operator approval is being revoked. |
| `contract.privileged-action` | critical | A contract upgrade, administrator, or ownership action was detected. |
| `trace.delegatecall` | warning | A delegate call was detected in the execution trace. |
| `trace.contract-creation` | info | A contract creation (CREATE or CREATE2) was detected in the execution trace. |
| `trace.internal-native-transfer` | info | An internal native asset transfer was detected. |
| `trace.execution-reverted` | critical | An execution error was detected in the trace. |
| `proxy.eip1967` | info | An EIP-1967 proxy was detected. |
| `proxy.uups` | info | A UUPS proxy was detected. |
| `proxy.beacon` | info | A beacon proxy was detected. |
| `proxy.admin-present` | warning | A proxy upgrade administrator was detected. |

## Severity model

- `info` records an observed behavior that requires context.
- `warning` identifies malformed or potentially unsafe input.
- `critical` identifies a high-impact effect that must be explicitly reviewed.
