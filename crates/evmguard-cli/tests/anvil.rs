use std::{
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const FROM: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const TO: &str = "0x1111111111111111111111111111111111111111";

#[test]
#[ignore = "requires an Anvil executable"]
fn preflight_runs_against_anvil() {
    let port = available_port();
    let endpoint = format!("http://127.0.0.1:{port}");
    let _anvil = AnvilProcess::start(port);

    wait_for_endpoint(port);

    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args([
            "preflight",
            "--rpc-url",
            &endpoint,
            "--chain-id",
            "31337",
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
        .expect("run preflight command");
    let stdout = String::from_utf8(output.stdout).expect("decode command output");

    assert!(output.status.success());
    assert!(stdout.contains("\"rpcChainId\": 31337"));
    assert!(stdout.contains("\"gasEstimate\":"));
}

struct AnvilProcess {
    child: Child,
}

impl AnvilProcess {
    fn start(port: u16) -> Self {
        let child = Command::new(anvil_binary())
            .args(["--port", &port.to_string(), "--chain-id", "31337"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Anvil");

        Self { child }
    }
}

impl Drop for AnvilProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn anvil_binary() -> String {
    std::env::var("ANVIL_BINARY").unwrap_or_else(|_| "anvil".to_owned())
}

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve local port")
        .local_addr()
        .expect("read local address")
        .port()
}

fn wait_for_endpoint(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }

    panic!("Anvil did not start within ten seconds.");
}
