# Networks and RPC providers

EVMGuard supports EVM-compatible networks through standard JSON-RPC endpoints.

## Required methods

The `preflight` command requires:

- `eth_chainId`
- `eth_estimateGas`

The `proxy` command requires:

- `eth_chainId`
- `eth_getStorageAt`
- `eth_call`

The `trace` command requires:

- `eth_chainId`
- `debug_traceCall`
- The `callTracer` tracer

## Compatibility

Any provider that supports the required methods for a command can be used. Standard HTTP and HTTPS JSON-RPC endpoints are supported. Trace functionality is commonly restricted to dedicated trace endpoints and may not be available on public RPC services.

## Endpoint handling

Use environment variables or GitHub Actions secrets for endpoints containing credentials. Do not commit endpoint URLs that contain keys or access tokens.
