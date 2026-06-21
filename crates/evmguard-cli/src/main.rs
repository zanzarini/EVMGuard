use std::{env, process};

use evmguard_analyzer::{inspect, inspect_trace};
use evmguard_core::{PreflightResult, TransactionRequest};
use evmguard_report::{render, OutputFormat};
use evmguard_rpc::RpcClient;

const INSPECT_USAGE: &str = "Usage:\n  evmguard inspect --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json]";
const PREFLIGHT_USAGE: &str = "Usage:\n  evmguard preflight --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json]";
const TRACE_USAGE: &str = "Usage:\n  evmguard trace --rpc-url <url> --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json]";

struct ParsedArguments {
    transaction: TransactionRequest,
    format: OutputFormat,
    rpc_url: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(|| usage().to_owned())?;

    match command.as_str() {
        "inspect" => inspect_command(arguments),
        "preflight" => preflight_command(arguments),
        "trace" => trace_command(arguments),
        "help" | "--help" | "-h" => {
            println!(
                "{}\n\n{}\n\n{}",
                INSPECT_USAGE, PREFLIGHT_USAGE, TRACE_USAGE
            );
            Ok(())
        }
        _ => Err(usage().to_owned()),
    }
}

fn inspect_command(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let parsed = parse_arguments(arguments, false, INSPECT_USAGE)?;
    let report = inspect(parsed.transaction);

    print!("{}", render(&report, parsed.format));
    Ok(())
}

fn preflight_command(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let parsed = parse_arguments(arguments, true, PREFLIGHT_USAGE)?;
    let rpc_url = parsed
        .rpc_url
        .as_deref()
        .ok_or_else(|| "--rpc-url is required.\n".to_owned() + PREFLIGHT_USAGE)?;
    let client = RpcClient::new(rpc_url).map_err(|error| error.to_string())?;
    let remote_chain_id = client.chain_id().map_err(|error| error.to_string())?;

    if remote_chain_id != parsed.transaction.chain_id {
        return Err(format!(
            "RPC endpoint chain ID {remote_chain_id} does not match requested chain ID {}.",
            parsed.transaction.chain_id
        ));
    }

    let gas_estimate = client
        .estimate_gas(&parsed.transaction)
        .map_err(|error| error.to_string())?;
    let mut report = inspect(parsed.transaction);
    report.preflight = Some(PreflightResult {
        rpc_chain_id: remote_chain_id,
        gas_estimate,
    });

    print!("{}", render(&report, parsed.format));
    Ok(())
}

fn trace_command(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let parsed = parse_arguments(arguments, true, TRACE_USAGE)?;
    let rpc_url = parsed
        .rpc_url
        .as_deref()
        .ok_or_else(|| "--rpc-url is required.\n".to_owned() + TRACE_USAGE)?;
    let client = RpcClient::new(rpc_url).map_err(|error| error.to_string())?;
    let remote_chain_id = client.chain_id().map_err(|error| error.to_string())?;

    if remote_chain_id != parsed.transaction.chain_id {
        return Err(format!(
            "RPC endpoint chain ID {remote_chain_id} does not match requested chain ID {}.",
            parsed.transaction.chain_id
        ));
    }

    let trace = client
        .trace_call(&parsed.transaction)
        .map_err(|error| error.to_string())?;
    let mut report = inspect(parsed.transaction);
    report.findings.extend(inspect_trace(&trace));

    print!("{}", render(&report, parsed.format));
    Ok(())
}

fn parse_arguments(
    mut arguments: impl Iterator<Item = String>,
    accepts_rpc_url: bool,
    command_usage: &str,
) -> Result<ParsedArguments, String> {
    let mut transaction = TransactionRequest {
        value: "0".to_owned(),
        ..TransactionRequest::default()
    };
    let mut format = OutputFormat::Text;
    let mut rpc_url = None;
    while let Some(argument) = arguments.next() {
        let value = match argument.as_str() {
            "--chain-id" | "--from" | "--to" | "--data" | "--value" | "--format" | "--rpc-url" => {
                arguments
                    .next()
                    .ok_or_else(|| format!("Missing value for {argument}.\n{command_usage}"))?
            }
            "--help" | "-h" => return Err(command_usage.to_owned()),
            _ => return Err(format!("Unknown argument: {argument}.\n{command_usage}")),
        };

        match argument.as_str() {
            "--chain-id" => {
                transaction.chain_id = value
                    .parse::<u64>()
                    .map_err(|_| "Chain ID must be an unsigned integer.".to_owned())?;
            }
            "--from" => transaction.from = value,
            "--to" => transaction.to = value,
            "--data" => transaction.data = value,
            "--value" => transaction.value = value,
            "--format" => {
                format = OutputFormat::parse(&value)
                    .ok_or_else(|| "Format must be text or json.".to_owned())?;
            }
            "--rpc-url" if accepts_rpc_url => rpc_url = Some(value),
            "--rpc-url" => {
                return Err(format!(
                    "--rpc-url is only valid with the preflight command.\n{command_usage}"
                ));
            }
            _ => return Err(command_usage.to_owned()),
        }
    }

    if transaction.chain_id == 0 {
        return Err("A non-zero --chain-id is required.".to_owned());
    }

    if transaction.from.is_empty() || transaction.to.is_empty() || transaction.data.is_empty() {
        return Err("--from, --to, and --data are required.\n".to_owned() + command_usage);
    }

    if accepts_rpc_url && rpc_url.is_none() {
        return Err("--rpc-url is required.\n".to_owned() + command_usage);
    }

    Ok(ParsedArguments {
        transaction,
        format,
        rpc_url,
    })
}

fn usage() -> String {
    format!("{INSPECT_USAGE}\n\n{PREFLIGHT_USAGE}\n\n{TRACE_USAGE}")
}
