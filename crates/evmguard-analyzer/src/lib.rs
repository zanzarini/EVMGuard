pub mod config;
pub mod plugin;

use evmguard_core::{
    AnalysisReport, CallFrame, CallType, Finding, ProxyInfo, ProxyKind, Severity,
    TransactionRequest,
};

pub use config::RuleConfiguration;
pub use plugin::{Rule, RuleContext, RulePack, RuleRegistry};

const ERC20_APPROVE_SELECTOR: &str = "095ea7b3";
const ERC20_APPROVE_LENGTH: usize = 8 + 64 + 64;
const NFT_SET_APPROVAL_FOR_ALL_SELECTOR: &str = "a22cb465";
const NFT_SET_APPROVAL_FOR_ALL_LENGTH: usize = 8 + 64 + 64;
const PRIVILEGED_ACTION_SELECTORS: [(&str, &str); 5] = [
    ("3659cfe6", "upgradeTo"),
    ("4f1ef286", "upgradeToAndCall"),
    ("8f283970", "changeAdmin"),
    ("f2fde38b", "transferOwnership"),
    ("715018a6", "renounceOwnership"),
];

pub fn inspect(transaction: TransactionRequest) -> AnalysisReport {
    inspect_with_configuration(transaction, &RuleConfiguration::default())
}

pub fn inspect_with_configuration(
    transaction: TransactionRequest,
    configuration: &RuleConfiguration,
) -> AnalysisReport {
    let mut findings = inspect_calldata(&transaction.data);
    findings.extend(inspect_recipient(&transaction.to, configuration));

    AnalysisReport {
        transaction,
        findings,
        preflight: None,
    }
}

pub fn inspect_trace(root: &CallFrame) -> Vec<Finding> {
    let mut findings = Vec::new();
    inspect_frame(root, 0, &mut findings);
    findings
}

pub fn inspect_proxy(proxy: &ProxyInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    match &proxy.kind {
        Some(ProxyKind::Eip1967) => findings.push(Finding::new(
            "proxy.eip1967",
            Severity::Info,
            format!("EIP-1967 proxy detected at {}.", proxy.address),
        )),
        Some(ProxyKind::Uups) => findings.push(Finding::new(
            "proxy.uups",
            Severity::Info,
            format!("UUPS proxy detected at {}.", proxy.address),
        )),
        Some(ProxyKind::Beacon) => findings.push(Finding::new(
            "proxy.beacon",
            Severity::Info,
            format!("Beacon proxy detected at {}.", proxy.address),
        )),
        None => return findings,
    }

    if let Some(admin) = &proxy.admin {
        findings.push(Finding::new(
            "proxy.admin-present",
            Severity::Warning,
            format!("Proxy upgrade administrator detected at {admin}."),
        ));
    }

    findings
}

fn inspect_frame(frame: &CallFrame, depth: usize, findings: &mut Vec<Finding>) {
    if frame.call_type == CallType::DelegateCall {
        let target = frame.to.as_deref().unwrap_or("an unknown target");
        findings.push(Finding::new(
            "trace.delegatecall",
            Severity::Warning,
            format!("Delegate call detected at depth {depth} targeting {target}."),
        ));
    }

    if depth > 0 && is_nonzero_quantity(&frame.value) {
        let target = frame.to.as_deref().unwrap_or("a created contract");
        findings.push(Finding::new(
            "trace.internal-native-transfer",
            Severity::Info,
            format!("Internal native asset transfer detected at depth {depth} to {target}."),
        ));
    }

    if let Some(error) = &frame.error {
        findings.push(Finding::new(
            "trace.execution-reverted",
            Severity::Critical,
            format!("Execution error detected at depth {depth}: {error}."),
        ));
    }

    for child in &frame.calls {
        inspect_frame(child, depth + 1, findings);
    }
}

fn is_nonzero_quantity(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .unwrap_or(value)
        .chars()
        .any(|character| character != '0')
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

    if payload.starts_with(ERC20_APPROVE_SELECTOR) {
        return inspect_erc20_approval(payload);
    }

    if payload.starts_with(NFT_SET_APPROVAL_FOR_ALL_SELECTOR) {
        return inspect_nft_operator_approval(payload);
    }

    for (selector, action) in PRIVILEGED_ACTION_SELECTORS {
        if payload.starts_with(selector) {
            return vec![Finding::new(
                "contract.privileged-action",
                Severity::Critical,
                format!("Privileged contract action detected: {action}."),
            )];
        }
    }

    vec![Finding::new(
        "transaction.unknown-selector",
        Severity::Info,
        "Transaction selector is not covered by the active static rule set.",
    )]
}

fn inspect_erc20_approval(payload: &str) -> Vec<Finding> {
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

fn inspect_nft_operator_approval(payload: &str) -> Vec<Finding> {
    if payload.len() < NFT_SET_APPROVAL_FOR_ALL_LENGTH {
        return vec![Finding::new(
            "nft.operator-approval-malformed",
            Severity::Warning,
            "NFT operator approval calldata is shorter than the expected ABI encoding.",
        )];
    }

    let approved = &payload[72..136];
    if is_nonzero_quantity(approved) {
        return vec![Finding::new(
            "nft.operator-approval",
            Severity::Critical,
            "NFT operator approval grants control over all tokens.",
        )];
    }

    vec![Finding::new(
        "nft.operator-approval-revoked",
        Severity::Info,
        "NFT operator approval is being revoked.",
    )]
}

fn inspect_recipient(address: &str, configuration: &RuleConfiguration) -> Vec<Finding> {
    if is_zero_address(address) {
        return vec![Finding::new(
            "transaction.zero-address-recipient",
            Severity::Critical,
            "Transaction targets the zero address.",
        )];
    }

    if configuration.is_suspicious_contract(address) {
        return vec![Finding::new(
            "transaction.suspicious-recipient",
            Severity::Critical,
            format!("Transaction targets a configured high-risk contract: {address}."),
        )];
    }

    Vec::new()
}

fn is_zero_address(address: &str) -> bool {
    let address = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);

    address.len() == 40 && address.chars().all(|character| character == '0')
}

#[cfg(test)]
mod tests {
    use super::{inspect, inspect_proxy, inspect_trace};
    use evmguard_core::{CallFrame, CallType, ProxyInfo, ProxyKind, Severity, TransactionRequest};

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
    fn reports_nft_operator_approval() {
        let data = "0xa22cb46500000000000000000000000033333333333333333333333333333333333333330000000000000000000000000000000000000000000000000000000000000001";
        let report = inspect(transaction_with_data(data));

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "nft.operator-approval");
        assert_eq!(report.highest_severity(), Severity::Critical);
    }

    #[test]
    fn reports_privileged_contract_actions() {
        let report = inspect(transaction_with_data("0x3659cfe6"));

        assert_eq!(report.findings[0].rule_id, "contract.privileged-action");
        assert_eq!(report.highest_severity(), Severity::Critical);
    }

    #[test]
    fn reports_zero_address_recipient() {
        let mut transaction = transaction_with_data("0x12345678");
        transaction.to = "0x0000000000000000000000000000000000000000".to_owned();
        let report = inspect(transaction);

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "transaction.zero-address-recipient"));
    }

    #[test]
    fn reports_invalid_calldata() {
        let report = inspect(transaction_with_data("0x123"));

        assert_eq!(report.findings[0].rule_id, "transaction.invalid-calldata");
        assert_eq!(report.highest_severity(), Severity::Warning);
    }

    #[test]
    fn reports_nested_trace_effects() {
        let trace = CallFrame {
            call_type: CallType::Call,
            from: "0x1111111111111111111111111111111111111111".to_owned(),
            to: Some("0x2222222222222222222222222222222222222222".to_owned()),
            input: "0x".to_owned(),
            value: "0x0".to_owned(),
            gas_used: "0x5208".to_owned(),
            error: None,
            calls: vec![CallFrame {
                call_type: CallType::DelegateCall,
                from: "0x2222222222222222222222222222222222222222".to_owned(),
                to: Some("0x3333333333333333333333333333333333333333".to_owned()),
                input: "0x".to_owned(),
                value: "0x10".to_owned(),
                gas_used: "0x100".to_owned(),
                error: Some("execution reverted".to_owned()),
                calls: Vec::new(),
            }],
        };

        let findings = inspect_trace(&trace);

        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].rule_id, "trace.delegatecall");
        assert_eq!(findings[1].rule_id, "trace.internal-native-transfer");
        assert_eq!(findings[2].rule_id, "trace.execution-reverted");
        assert_eq!(findings[2].severity, Severity::Critical);
    }

    #[test]
    fn reports_uups_proxy_and_administrator() {
        let proxy = ProxyInfo {
            address: "0x1111111111111111111111111111111111111111".to_owned(),
            kind: Some(ProxyKind::Uups),
            implementation: Some("0x2222222222222222222222222222222222222222".to_owned()),
            admin: Some("0x3333333333333333333333333333333333333333".to_owned()),
            beacon: None,
        };

        let findings = inspect_proxy(&proxy);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "proxy.uups");
        assert_eq!(findings[1].rule_id, "proxy.admin-present");
        assert_eq!(findings[1].severity, Severity::Warning);
    }
}
