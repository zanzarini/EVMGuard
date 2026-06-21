use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
};

use serde_json::Value;

const FROM: &str = "0x1111111111111111111111111111111111111111";
const TO: &str = "0x2222222222222222222222222222222222222222";
const UNLIMITED_APPROVAL: &str = "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[test]
fn inspect_emits_a_critical_json_finding_for_unlimited_approval() {
    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args([
            "inspect",
            "--chain-id",
            "8453",
            "--from",
            FROM,
            "--to",
            TO,
            "--data",
            UNLIMITED_APPROVAL,
            "--format",
            "json",
        ])
        .output()
        .expect("run inspect command");

    let stdout = String::from_utf8(output.stdout).expect("decode command output");

    assert!(output.status.success());
    assert!(stdout.contains("\"highestSeverity\": \"critical\""));
    assert!(stdout.contains("\"ruleId\": \"erc20.unlimited-approval\""));
}

#[test]
fn preflight_requires_an_rpc_endpoint() {
    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args([
            "preflight",
            "--chain-id",
            "8453",
            "--from",
            FROM,
            "--to",
            TO,
            "--data",
            "0x",
        ])
        .output()
        .expect("run preflight command");

    let stderr = String::from_utf8(output.stderr).expect("decode command error");

    assert!(!output.status.success());
    assert!(stderr.contains("--rpc-url is required."));
}

#[test]
fn trace_requires_an_rpc_endpoint() {
    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args([
            "trace",
            "--chain-id",
            "8453",
            "--from",
            FROM,
            "--to",
            TO,
            "--data",
            "0x",
        ])
        .output()
        .expect("run trace command");

    let stderr = String::from_utf8(output.stderr).expect("decode command error");

    assert!(!output.status.success());
    assert!(stderr.contains("--rpc-url is required."));
}

#[test]
fn proxy_requires_an_rpc_endpoint() {
    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args(["proxy", "--chain-id", "8453", "--address", FROM])
        .output()
        .expect("run proxy command");

    let stderr = String::from_utf8(output.stderr).expect("decode command error");

    assert!(!output.status.success());
    assert!(stderr.contains("--rpc-url is required."));
}

#[test]
fn trace_reports_delegate_calls_from_a_remote_call_trace() {
    let (endpoint, handle) = trace_server();
    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args([
            "trace",
            "--rpc-url",
            &endpoint,
            "--chain-id",
            "8453",
            "--from",
            FROM,
            "--to",
            TO,
            "--data",
            "0x",
            "--format",
            "json",
        ])
        .output()
        .expect("run trace command");
    let requests = handle.join().expect("join trace server");
    let stdout = String::from_utf8(output.stdout).expect("decode command output");

    assert!(output.status.success());
    assert_eq!(requests[0]["method"], "eth_chainId");
    assert_eq!(requests[1]["method"], "debug_traceCall");
    assert!(stdout.contains("\"ruleId\": \"trace.delegatecall\""));
}

fn trace_server() -> (String, thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trace server");
    let address = listener.local_addr().expect("read local address");
    let responses = [
        r#"{"jsonrpc":"2.0","id":1,"result":"0x2105"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"type":"CALL","from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222","input":"0x","value":"0x0","gasUsed":"0x5208","calls":[{"type":"DELEGATECALL","from":"0x2222222222222222222222222222222222222222","to":"0x3333333333333333333333333333333333333333","input":"0x","value":"0x0","gasUsed":"0x100"}]}}"#,
    ];
    let handle = thread::spawn(move || {
        responses
            .into_iter()
            .map(|response| {
                let (stream, _) = listener.accept().expect("accept request");
                respond(stream, response)
            })
            .collect()
    });

    (format!("http://{address}"), handle)
}

fn respond(mut stream: std::net::TcpStream, response: &str) -> Value {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).expect("read request");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(request[..header_end].to_vec()).expect("decode headers");
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

    let body = serde_json::from_slice(&request[header_end..header_end + content_length])
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
}
