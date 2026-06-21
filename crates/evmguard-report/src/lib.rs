use std::collections::BTreeMap;

use evmguard_core::{AnalysisReport, Finding, ProxyReport, Severity};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }
}

pub fn render(report: &AnalysisReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text(report),
        OutputFormat::Json => render_json(report),
        OutputFormat::Sarif => render_sarif(&report.findings),
    }
}

pub fn render_proxy(report: &ProxyReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_proxy_text(report),
        OutputFormat::Json => render_proxy_json(report),
        OutputFormat::Sarif => render_sarif(&report.findings),
    }
}

fn render_text(report: &AnalysisReport) -> String {
    let mut output = format!(
        "EVMGuard inspection\nChain ID: {}\nFrom: {}\nTo: {}\nHighest severity: {}\nFindings:\n",
        report.transaction.chain_id,
        report.transaction.from,
        report.transaction.to,
        report.highest_severity().as_str(),
    );

    for finding in &report.findings {
        output.push_str(&format!(
            "  [{}] {}: {}\n",
            finding.severity.as_str(),
            finding.rule_id,
            finding.message,
        ));
    }

    if let Some(preflight) = &report.preflight {
        output.push_str(&format!(
            "Preflight:\n  RPC chain ID: {}\n  Gas estimate: {}\n",
            preflight.rpc_chain_id, preflight.gas_estimate,
        ));
    }

    output
}

fn render_json(report: &AnalysisReport) -> String {
    let value = json!({
        "transaction": {
            "chainId": report.transaction.chain_id,
            "from": report.transaction.from,
            "to": report.transaction.to,
            "data": report.transaction.data,
            "value": report.transaction.value,
        },
        "highestSeverity": report.highest_severity().as_str(),
        "preflight": report.preflight.as_ref().map(|preflight| {
            json!({
                "rpcChainId": preflight.rpc_chain_id,
                "gasEstimate": preflight.gas_estimate,
            })
        }),
        "findings": report.findings.iter().map(finding_value).collect::<Vec<_>>(),
    });

    to_json_document(&value)
}

fn render_proxy_text(report: &ProxyReport) -> String {
    let kind = report
        .proxy
        .kind
        .as_ref()
        .map(|kind| kind.as_str())
        .unwrap_or("None");
    let mut output = format!(
        "EVMGuard proxy inspection\nAddress: {}\nKind: {}\nImplementation: {}\nAdmin: {}\nBeacon: {}\nFindings:\n",
        report.proxy.address,
        kind,
        report.proxy.implementation.as_deref().unwrap_or("None"),
        report.proxy.admin.as_deref().unwrap_or("None"),
        report.proxy.beacon.as_deref().unwrap_or("None"),
    );

    for finding in &report.findings {
        output.push_str(&format!(
            "  [{}] {}: {}\n",
            finding.severity.as_str(),
            finding.rule_id,
            finding.message,
        ));
    }

    output
}

fn render_proxy_json(report: &ProxyReport) -> String {
    let value = json!({
        "proxy": {
            "address": report.proxy.address,
            "kind": report.proxy.kind.as_ref().map(|kind| kind.as_str()),
            "implementation": report.proxy.implementation,
            "admin": report.proxy.admin,
            "beacon": report.proxy.beacon,
        },
        "findings": report.findings.iter().map(finding_value).collect::<Vec<_>>(),
    });

    to_json_document(&value)
}

fn render_sarif(findings: &[Finding]) -> String {
    let mut severities = BTreeMap::new();
    for finding in findings {
        severities
            .entry(finding.rule_id.as_str())
            .or_insert(finding.severity);
    }

    let rules = severities
        .into_iter()
        .map(|(rule_id, severity)| {
            json!({
                "id": rule_id,
                "defaultConfiguration": { "level": sarif_level(severity) },
            })
        })
        .collect::<Vec<_>>();
    let results = findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.rule_id,
                "level": sarif_level(finding.severity),
                "message": { "text": finding.message },
            })
        })
        .collect::<Vec<_>>();

    let value = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "EVMGuard",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    });

    to_json_document(&value)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "note",
        Severity::Warning => "warning",
        Severity::Critical => "error",
    }
}

fn finding_value(finding: &Finding) -> Value {
    json!({
        "ruleId": finding.rule_id,
        "severity": finding.severity.as_str(),
        "message": finding.message,
    })
}

fn to_json_document(value: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).expect("report values are always serializable")
    )
}

#[cfg(test)]
mod tests {
    use super::{render, OutputFormat};
    use evmguard_core::{AnalysisReport, Finding, PreflightResult, Severity, TransactionRequest};

    #[test]
    fn renders_json_report() {
        let report = AnalysisReport {
            transaction: TransactionRequest {
                chain_id: 8453,
                from: "0xfrom".to_owned(),
                to: "0xto".to_owned(),
                data: "0x".to_owned(),
                value: "0".to_owned(),
            },
            findings: vec![Finding::new("test.rule", Severity::Info, "Test finding.")],
            preflight: Some(PreflightResult {
                rpc_chain_id: 8453,
                gas_estimate: 21_000,
            }),
        };

        let output = render(&report, OutputFormat::Json);
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("report must be valid JSON");

        assert_eq!(value["transaction"]["chainId"], 8453);
        assert_eq!(value["highestSeverity"], "info");
        assert_eq!(value["findings"][0]["ruleId"], "test.rule");
        assert_eq!(value["preflight"]["gasEstimate"], 21_000);
    }

    #[test]
    fn renders_sarif_report() {
        let report = AnalysisReport {
            transaction: TransactionRequest::default(),
            findings: vec![Finding::new(
                "test.critical",
                Severity::Critical,
                "Critical test finding.",
            )],
            preflight: None,
        };

        let output = render(&report, OutputFormat::Sarif);
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("report must be valid SARIF");

        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"][0]["ruleId"], "test.critical");
        assert_eq!(value["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn renders_valid_json_for_empty_and_control_character_inputs() {
        let empty = AnalysisReport {
            transaction: TransactionRequest::default(),
            findings: Vec::new(),
            preflight: None,
        };

        serde_json::from_str::<serde_json::Value>(&render(&empty, OutputFormat::Json))
            .expect("empty report must produce valid JSON");
        serde_json::from_str::<serde_json::Value>(&render(&empty, OutputFormat::Sarif))
            .expect("empty report must produce valid SARIF");

        let control = AnalysisReport {
            transaction: TransactionRequest {
                chain_id: 1,
                from: "0x\u{0008}\u{0000}\u{001f}".to_owned(),
                to: "0xto".to_owned(),
                data: "0x".to_owned(),
                value: "0".to_owned(),
            },
            findings: vec![Finding::new(
                "test.control",
                Severity::Info,
                "Message with a \u{0001} control character.",
            )],
            preflight: None,
        };

        serde_json::from_str::<serde_json::Value>(&render(&control, OutputFormat::Json))
            .expect("control characters must be escaped into valid JSON");
        serde_json::from_str::<serde_json::Value>(&render(&control, OutputFormat::Sarif))
            .expect("control characters must be escaped into valid SARIF");
    }
}
