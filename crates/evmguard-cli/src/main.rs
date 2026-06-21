use std::{env, process};

use evmguard_analyzer::inspect;
use evmguard_core::TransactionRequest;
use evmguard_report::{render, OutputFormat};

const USAGE: &str = "Usage:\n  evmguard inspect --chain-id <id> --from <address> --to <address> --data <hex> [--value <value>] [--format text|json]";

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(|| USAGE.to_owned())?;

    match command.as_str() {
        "inspect" => inspect_command(arguments),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn inspect_command(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let (transaction, format) = parse_inspect_arguments(arguments)?;
    let report = inspect(transaction);

    print!("{}", render(&report, format));
    Ok(())
}

fn parse_inspect_arguments(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(TransactionRequest, OutputFormat), String> {
    let mut transaction = TransactionRequest {
        value: "0".to_owned(),
        ..TransactionRequest::default()
    };
    let mut format = OutputFormat::Text;

    while let Some(argument) = arguments.next() {
        let value = match argument.as_str() {
            "--chain-id" | "--from" | "--to" | "--data" | "--value" | "--format" => arguments
                .next()
                .ok_or_else(|| format!("Missing value for {argument}.\n{USAGE}"))?,
            "--help" | "-h" => return Err(USAGE.to_owned()),
            _ => return Err(format!("Unknown argument: {argument}.\n{USAGE}")),
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
            _ => return Err(USAGE.to_owned()),
        }
    }

    if transaction.chain_id == 0 {
        return Err("A non-zero --chain-id is required.".to_owned());
    }

    if transaction.from.is_empty() || transaction.to.is_empty() || transaction.data.is_empty() {
        return Err("--from, --to, and --data are required.\n".to_owned() + USAGE);
    }

    Ok((transaction, format))
}
