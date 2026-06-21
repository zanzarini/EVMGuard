use evmguard_core::{AnalysisReport, Finding, ProxyReport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

pub fn render(report: &AnalysisReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text(report),
        OutputFormat::Json => render_json(report),
    }
}

pub fn render_proxy(report: &ProxyReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_proxy_text(report),
        OutputFormat::Json => render_proxy_json(report),
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
    let findings = report
        .findings
        .iter()
        .map(render_finding_json)
        .collect::<Vec<_>>()
        .join(",\n    ");
    let preflight = report
        .preflight
        .as_ref()
        .map(render_preflight_json)
        .unwrap_or_else(|| "null".to_owned());

    format!(
        "{{\n  \"transaction\": {{\n    \"chainId\": {},\n    \"from\": \"{}\",\n    \"to\": \"{}\",\n    \"data\": \"{}\",\n    \"value\": \"{}\"\n  }},\n  \"highestSeverity\": \"{}\",\n  \"preflight\": {},\n  \"findings\": [\n    {}\n  ]\n}}\n",
        report.transaction.chain_id,
        escape_json(&report.transaction.from),
        escape_json(&report.transaction.to),
        escape_json(&report.transaction.data),
        escape_json(&report.transaction.value),
        report.highest_severity().as_str(),
        preflight,
        findings,
    )
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
    let kind = report
        .proxy
        .kind
        .as_ref()
        .map(|kind| format!("\"{}\"", kind.as_str()))
        .unwrap_or_else(|| "null".to_owned());
    let findings = report
        .findings
        .iter()
        .map(render_finding_json)
        .collect::<Vec<_>>()
        .join(",\n    ");

    format!(
        "{{\n  \"proxy\": {{\n    \"address\": \"{}\",\n    \"kind\": {},\n    \"implementation\": {},\n    \"admin\": {},\n    \"beacon\": {}\n  }},\n  \"findings\": [\n    {}\n  ]\n}}\n",
        escape_json(&report.proxy.address),
        kind,
        optional_json_string(report.proxy.implementation.as_deref()),
        optional_json_string(report.proxy.admin.as_deref()),
        optional_json_string(report.proxy.beacon.as_deref()),
        findings,
    )
}

fn optional_json_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_owned())
}

fn render_preflight_json(preflight: &evmguard_core::PreflightResult) -> String {
    format!(
        "{{\n    \"rpcChainId\": {},\n    \"gasEstimate\": {}\n  }}",
        preflight.rpc_chain_id, preflight.gas_estimate,
    )
}

fn render_finding_json(finding: &Finding) -> String {
    format!(
        "{{\n      \"ruleId\": \"{}\",\n      \"severity\": \"{}\",\n      \"message\": \"{}\"\n    }}",
        escape_json(&finding.rule_id),
        finding.severity.as_str(),
        escape_json(&finding.message),
    )
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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

        assert!(output.contains("\"chainId\": 8453"));
        assert!(output.contains("\"ruleId\": \"test.rule\""));
        assert!(output.contains("\"gasEstimate\": 21000"));
    }
}
