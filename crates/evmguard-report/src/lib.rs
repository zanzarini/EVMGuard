use evmguard_core::{AnalysisReport, Finding};

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

    output
}

fn render_json(report: &AnalysisReport) -> String {
    let findings = report
        .findings
        .iter()
        .map(render_finding_json)
        .collect::<Vec<_>>()
        .join(",\n    ");

    format!(
        "{{\n  \"transaction\": {{\n    \"chainId\": {},\n    \"from\": \"{}\",\n    \"to\": \"{}\",\n    \"data\": \"{}\",\n    \"value\": \"{}\"\n  }},\n  \"highestSeverity\": \"{}\",\n  \"findings\": [\n    {}\n  ]\n}}\n",
        report.transaction.chain_id,
        escape_json(&report.transaction.from),
        escape_json(&report.transaction.to),
        escape_json(&report.transaction.data),
        escape_json(&report.transaction.value),
        report.highest_severity().as_str(),
        findings,
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
    use evmguard_core::{AnalysisReport, Finding, Severity, TransactionRequest};

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
        };

        let output = render(&report, OutputFormat::Json);

        assert!(output.contains("\"chainId\": 8453"));
        assert!(output.contains("\"ruleId\": \"test.rule\""));
    }
}
