use std::{error::Error, fmt, time::Duration};

use evmguard_core::{CallFrame, CallType, ProxyInfo, ProxyKind, TransactionRequest};
use reqwest::{blocking::Client, StatusCode, Url};
use serde_json::{json, Value};

const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT: &str = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const BEACON_SLOT: &str = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const UUPS_UUID_SELECTOR: &str = "0x52d1902d";
const BEACON_IMPLEMENTATION_SELECTOR: &str = "0x5c60da1b";

#[derive(Debug)]
pub enum RpcError {
    InvalidEndpoint(String),
    InvalidTransaction(String),
    Transport(reqwest::Error),
    Http(StatusCode),
    Remote { code: i64, message: String },
    InvalidResponse(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(message) => write!(formatter, "Invalid RPC endpoint: {message}"),
            Self::InvalidTransaction(message) => {
                write!(formatter, "Invalid transaction: {message}")
            }
            Self::Transport(error) => write!(formatter, "RPC transport error: {error}"),
            Self::Http(status) => write!(formatter, "RPC endpoint returned HTTP status {status}"),
            Self::Remote { code, message } => {
                write!(formatter, "RPC endpoint returned error {code}: {message}")
            }
            Self::InvalidResponse(message) => write!(formatter, "Invalid RPC response: {message}"),
        }
    }
}

impl Error for RpcError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

pub struct RpcClient {
    client: Client,
    endpoint: Url,
}

impl RpcClient {
    pub fn new(endpoint: &str) -> Result<Self, RpcError> {
        let endpoint =
            Url::parse(endpoint).map_err(|error| RpcError::InvalidEndpoint(error.to_string()))?;

        if endpoint.scheme() != "http" && endpoint.scheme() != "https" {
            return Err(RpcError::InvalidEndpoint(
                "endpoint must use HTTP or HTTPS".to_owned(),
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(RpcError::Transport)?;

        Ok(Self { client, endpoint })
    }

    pub fn chain_id(&self) -> Result<u64, RpcError> {
        let result = self.call("eth_chainId", json!([]))?;
        parse_quantity(result.as_str(), "eth_chainId")
    }

    pub fn estimate_gas(&self, transaction: &TransactionRequest) -> Result<u64, RpcError> {
        let result = self.call("eth_estimateGas", json!([transaction_object(transaction)?]))?;

        parse_quantity(result.as_str(), "eth_estimateGas")
    }

    pub fn trace_call(&self, transaction: &TransactionRequest) -> Result<CallFrame, RpcError> {
        let result = self.call(
            "debug_traceCall",
            json!([
                transaction_object(transaction)?,
                "latest",
                { "tracer": "callTracer" }
            ]),
        )?;

        parse_call_frame(&result)
    }

    pub fn inspect_proxy(&self, address: &str) -> Result<ProxyInfo, RpcError> {
        if !is_evm_address(address) {
            return Err(RpcError::InvalidTransaction(
                "address must be a 20-byte EVM address".to_owned(),
            ));
        }

        let implementation = self.storage_address(address, IMPLEMENTATION_SLOT)?;
        let admin = self.storage_address(address, ADMIN_SLOT)?;
        let beacon = self.storage_address(address, BEACON_SLOT)?;
        let (kind, implementation) = if let Some(beacon) = &beacon {
            (
                Some(ProxyKind::Beacon),
                self.contract_address(beacon, BEACON_IMPLEMENTATION_SELECTOR)
                    .ok(),
            )
        } else if let Some(implementation) = implementation {
            let kind = if self
                .contract_word(&implementation, UUPS_UUID_SELECTOR)
                .map(|value| value.eq_ignore_ascii_case(IMPLEMENTATION_SLOT))
                .unwrap_or(false)
            {
                ProxyKind::Uups
            } else {
                ProxyKind::Eip1967
            };

            (Some(kind), Some(implementation))
        } else {
            (None, None)
        };

        Ok(ProxyInfo {
            address: address.to_owned(),
            kind,
            implementation,
            admin,
            beacon,
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&request)
            .send()
            .map_err(RpcError::Transport)?;
        let status = response.status();

        if !status.is_success() {
            return Err(RpcError::Http(status));
        }

        let response: Value = response.json().map_err(RpcError::Transport)?;

        if let Some(error) = response.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Unknown JSON-RPC error")
                .to_owned();

            return Err(RpcError::Remote { code, message });
        }

        response
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::InvalidResponse("missing result field".to_owned()))
    }

    fn storage_address(&self, address: &str, slot: &str) -> Result<Option<String>, RpcError> {
        let result = self.call("eth_getStorageAt", json!([address, slot, "latest"]))?;
        address_from_word(result.as_str())
    }

    fn contract_word(&self, address: &str, data: &str) -> Result<String, RpcError> {
        let result = self.call(
            "eth_call",
            json!([{ "to": address, "data": data }, "latest"]),
        )?;
        result
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| RpcError::InvalidResponse("eth_call result must be a string".to_owned()))
    }

    fn contract_address(&self, address: &str, data: &str) -> Result<String, RpcError> {
        let result = self.contract_word(address, data)?;
        address_from_word(Some(&result))?.ok_or_else(|| {
            RpcError::InvalidResponse("contract returned an empty address".to_owned())
        })
    }
}

fn address_from_word(value: Option<&str>) -> Result<Option<String>, RpcError> {
    let value = value.ok_or_else(|| {
        RpcError::InvalidResponse("storage result must be a hexadecimal word".to_owned())
    })?;
    let word = value.strip_prefix("0x").ok_or_else(|| {
        RpcError::InvalidResponse("storage result must be a hexadecimal word".to_owned())
    })?;

    if word.len() != 64 || !word.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(RpcError::InvalidResponse(
            "storage result must be a 32-byte hexadecimal word".to_owned(),
        ));
    }

    let address = &word[24..];
    if address.chars().all(|character| character == '0') {
        Ok(None)
    } else {
        Ok(Some(format!("0x{address}")))
    }
}

fn parse_call_frame(value: &Value) -> Result<CallFrame, RpcError> {
    let call_type = value
        .get("type")
        .and_then(Value::as_str)
        .map(CallType::from_trace_value)
        .unwrap_or(CallType::Call);
    let from = required_string(value, "from")?;
    let to = optional_string(value, "to")?;
    let input = optional_string(value, "input")?.unwrap_or_else(|| "0x".to_owned());
    let value_transferred = optional_string(value, "value")?.unwrap_or_else(|| "0x0".to_owned());
    let gas_used = optional_string(value, "gasUsed")?.unwrap_or_else(|| "0x0".to_owned());
    let error = optional_string(value, "error")?;
    let calls = value
        .get("calls")
        .map(|calls| {
            calls
                .as_array()
                .ok_or_else(|| {
                    RpcError::InvalidResponse("calls field must be an array".to_owned())
                })?
                .iter()
                .map(parse_call_frame)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(CallFrame {
        call_type,
        from,
        to,
        input,
        value: value_transferred,
        gas_used,
        error,
        calls,
    })
}

fn required_string(value: &Value, field: &str) -> Result<String, RpcError> {
    optional_string(value, field)?.ok_or_else(|| {
        RpcError::InvalidResponse(format!("call trace is missing required {field} field"))
    })
}

fn optional_string(value: &Value, field: &str) -> Result<Option<String>, RpcError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.to_owned())),
        Some(_) => Err(RpcError::InvalidResponse(format!(
            "call trace field {field} must be a string"
        ))),
    }
}

fn transaction_object(transaction: &TransactionRequest) -> Result<Value, RpcError> {
    if !is_evm_address(&transaction.from) {
        return Err(RpcError::InvalidTransaction(
            "from must be a 20-byte EVM address".to_owned(),
        ));
    }

    if !is_evm_address(&transaction.to) {
        return Err(RpcError::InvalidTransaction(
            "to must be a 20-byte EVM address".to_owned(),
        ));
    }

    if !is_hex_data(&transaction.data) {
        return Err(RpcError::InvalidTransaction(
            "data must be even-length hexadecimal data prefixed with 0x".to_owned(),
        ));
    }

    Ok(json!({
        "from": transaction.from,
        "to": transaction.to,
        "data": transaction.data,
        "value": normalize_value(&transaction.value)?,
    }))
}

fn is_evm_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn is_hex_data(value: &str) -> bool {
    value.starts_with("0x")
        && (value.len() - 2) % 2 == 0
        && value[2..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn normalize_value(value: &str) -> Result<String, RpcError> {
    if value == "0" {
        return Ok("0x0".to_owned());
    }

    let quantity = value.strip_prefix("0x").ok_or_else(|| {
        RpcError::InvalidTransaction("value must be 0 or an RPC hex quantity".to_owned())
    })?;

    if quantity.is_empty()
        || !quantity
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(RpcError::InvalidTransaction(
            "value must be 0 or an RPC hex quantity".to_owned(),
        ));
    }

    let normalized = quantity.trim_start_matches('0');
    if normalized.is_empty() {
        Ok("0x0".to_owned())
    } else {
        Ok(format!("0x{normalized}"))
    }
}

fn parse_quantity(value: Option<&str>, field: &str) -> Result<u64, RpcError> {
    let value = value.ok_or_else(|| {
        RpcError::InvalidResponse(format!("{field} result must be a hexadecimal quantity"))
    })?;
    let quantity = value.strip_prefix("0x").ok_or_else(|| {
        RpcError::InvalidResponse(format!("{field} result must be a hexadecimal quantity"))
    })?;

    if quantity.is_empty() {
        return Err(RpcError::InvalidResponse(format!(
            "{field} result must not be empty"
        )));
    }

    u64::from_str_radix(quantity, 16).map_err(|_| {
        RpcError::InvalidResponse(format!("{field} result exceeds the supported range"))
    })
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::{address_from_word, RpcClient, RpcError};
    use evmguard_core::{CallType, TransactionRequest};
    use serde_json::Value;

    fn transaction() -> TransactionRequest {
        TransactionRequest {
            chain_id: 8453,
            from: "0x1111111111111111111111111111111111111111".to_owned(),
            to: "0x2222222222222222222222222222222222222222".to_owned(),
            data: "0x095ea7b3".to_owned(),
            value: "0".to_owned(),
        }
    }

    fn test_server(response: &str) -> (String, thread::JoinHandle<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("read local address");
        let response = response.to_owned();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];

            let header_end = loop {
                let bytes_read = stream.read(&mut buffer).expect("read request");
                request.extend_from_slice(&buffer[..bytes_read]);

                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };

            let headers =
                String::from_utf8(request[..header_end].to_vec()).expect("decode headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .expect("read content length");

            while request.len() < header_end + content_length {
                let bytes_read = stream.read(&mut buffer).expect("read request body");
                request.extend_from_slice(&buffer[..bytes_read]);
            }

            let body: Value =
                serde_json::from_slice(&request[header_end..header_end + content_length])
                    .expect("parse request body");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response,
            );

            stream
                .write_all(response.as_bytes())
                .expect("write response");

            body
        });

        (format!("http://{address}"), handle)
    }

    #[test]
    fn reads_chain_id_from_json_rpc() {
        let (endpoint, handle) = test_server(r#"{"jsonrpc":"2.0","id":1,"result":"0x2105"}"#);
        let client = RpcClient::new(&endpoint).expect("create client");

        let chain_id = client.chain_id().expect("read chain ID");
        let request = handle.join().expect("join test server");

        assert_eq!(chain_id, 8453);
        assert_eq!(request["method"], "eth_chainId");
    }

    #[test]
    fn estimates_gas_with_normalized_value() {
        let (endpoint, handle) = test_server(r#"{"jsonrpc":"2.0","id":1,"result":"0x5208"}"#);
        let client = RpcClient::new(&endpoint).expect("create client");

        let estimate = client.estimate_gas(&transaction()).expect("estimate gas");
        let request = handle.join().expect("join test server");

        assert_eq!(estimate, 21_000);
        assert_eq!(request["method"], "eth_estimateGas");
        assert_eq!(request["params"][0]["value"], "0x0");
    }

    #[test]
    fn surfaces_json_rpc_errors() {
        let (endpoint, handle) = test_server(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}"#,
        );
        let client = RpcClient::new(&endpoint).expect("create client");

        let error = client.chain_id().expect_err("expect RPC error");
        handle.join().expect("join test server");

        assert!(matches!(
            error,
            RpcError::Remote {
                code: 3,
                message
            } if message == "execution reverted"
        ));
    }

    #[test]
    fn parses_nested_call_traces() {
        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"type":"CALL","from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222","input":"0x","value":"0x0","gasUsed":"0x5208","calls":[{"type":"DELEGATECALL","from":"0x2222222222222222222222222222222222222222","to":"0x3333333333333333333333333333333333333333","input":"0x","value":"0x0","gasUsed":"0x100"}]}}"#;
        let (endpoint, handle) = test_server(response);
        let client = RpcClient::new(&endpoint).expect("create client");

        let trace = client.trace_call(&transaction()).expect("trace call");
        let request = handle.join().expect("join test server");

        assert_eq!(request["method"], "debug_traceCall");
        assert_eq!(request["params"][2]["tracer"], "callTracer");
        assert_eq!(trace.frame_count(), 2);
        assert_eq!(trace.calls[0].call_type, CallType::DelegateCall);
    }

    #[test]
    fn rejects_invalid_transaction_addresses() {
        let client = RpcClient::new("http://127.0.0.1:1").expect("create client");
        let mut transaction = transaction();
        transaction.from = "invalid".to_owned();

        let error = client
            .estimate_gas(&transaction)
            .expect_err("reject invalid address");

        assert!(matches!(error, RpcError::InvalidTransaction(_)));
    }

    #[test]
    fn extracts_an_address_from_a_storage_word() {
        let value = "0x0000000000000000000000002222222222222222222222222222222222222222";

        let address = address_from_word(Some(value)).expect("parse storage word");

        assert_eq!(
            address.as_deref(),
            Some("0x2222222222222222222222222222222222222222")
        );
    }

    #[test]
    fn treats_a_zero_storage_word_as_an_empty_address() {
        let value = "0x0000000000000000000000000000000000000000000000000000000000000000";

        let address = address_from_word(Some(value)).expect("parse storage word");

        assert_eq!(address, None);
    }
}
