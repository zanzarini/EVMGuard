use evmguard_core::{AnalysisReport, Finding, Severity, TransactionRequest};

const ERC20_APPROVE_SELECTOR: &str = "095ea7b3";
const ERC20_APPROVE_LENGTH: usize = 8 + 64 + 64;

pub fn inspect(transaction: TransactionRequest) -> AnalysisReport {
    let findings = inspect_calldata(&transaction.data);

    AnalysisReport {
        transaction,
        findings,
        preflight: None,
    }
}

fn inspect_calldata(data: &str) -> Vec<Finding> {
    let payload = data.strip_prefix("0x").unwrap_or(data);

    if payload.is_empty() {
        return vec![Finding::new(
            "transaction.empty-calldata",
            Severity::Info,
            "Transaction contains no calldata.",
        )];
    }

    if payload.len() % 2 != 0
        || !payload
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return vec![Finding::new(
            "transaction.invalid-calldata",
            Severity::Warning,
            "Transaction calldata is not valid hexadecimal data.",
        )];
    }

    if !payload.starts_with(ERC20_APPROVE_SELECTOR) {
        return vec![Finding::new(
            "transaction.unknown-selector",
            Severity::Info,
            "Transaction selector is not covered by the initial static rule set.",
        )];
    }

    if payload.len() < ERC20_APPROVE_LENGTH {
        return vec![Finding::new(
            "erc20.approval-malformed",
            Severity::Warning,
            "ERC-20 approval calldata is shorter than the expected ABI encoding.",
        )];
    }

    let amount = &payload[72..136];
    let mut findings = vec![Finding::new(
        "erc20.approval",
        Severity::Info,
        "ERC-20 approval call detected.",
    )];

    if amount
        .chars()
        .all(|character| character == 'f' || character == 'F')
    {
        findings.push(Finding::new(
            "erc20.unlimited-approval",
            Severity::Critical,
            "Unlimited ERC-20 approval detected.",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::inspect;
    use evmguard_core::{Severity, TransactionRequest};

    fn transaction_with_data(data: &str) -> TransactionRequest {
        TransactionRequest {
            data: data.to_owned(),
            ..TransactionRequest::default()
        }
    }

    #[test]
    fn reports_unlimited_erc20_approval() {
        let data = "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let report = inspect(transaction_with_data(data));

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.highest_severity(), Severity::Critical);
        assert_eq!(report.findings[1].rule_id, "erc20.unlimited-approval");
    }

    #[test]
    fn reports_regular_erc20_approval() {
        let data = "0x095ea7b300000000000000000000000033333333333333333333333333333333333333330000000000000000000000000000000000000000000000000000000000000001";
        let report = inspect(transaction_with_data(data));

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "erc20.approval");
    }

    #[test]
    fn reports_invalid_calldata() {
        let report = inspect(transaction_with_data("0x123"));

        assert_eq!(report.findings[0].rule_id, "transaction.invalid-calldata");
        assert_eq!(report.highest_severity(), Severity::Warning);
    }
}
