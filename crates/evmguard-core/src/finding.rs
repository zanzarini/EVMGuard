use crate::TransactionRequest;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    pub fn new(rule_id: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisReport {
    pub transaction: TransactionRequest,
    pub findings: Vec<Finding>,
    pub preflight: Option<PreflightResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightResult {
    pub rpc_chain_id: u64,
    pub gas_estimate: u64,
}

impl AnalysisReport {
    pub fn highest_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info)
    }
}
