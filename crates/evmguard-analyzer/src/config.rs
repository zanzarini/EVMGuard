use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use evmguard_core::{Finding, Severity};
use serde::Deserialize;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuleConfiguration {
    disabled: BTreeSet<String>,
    severity: BTreeMap<String, Severity>,
    suspicious_contracts: BTreeSet<String>,
}

impl RuleConfiguration {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        Self::load(path, &mut BTreeSet::new())
    }

    fn load(path: &Path, visited: &mut BTreeSet<std::path::PathBuf>) -> Result<Self, String> {
        let path = path
            .canonicalize()
            .map_err(|error| format!("Unable to resolve configuration file: {error}"))?;

        if !visited.insert(path.clone()) {
            return Err(format!(
                "Configuration include cycle detected: {}",
                path.display()
            ));
        }

        let content = fs::read_to_string(&path)
            .map_err(|error| format!("Unable to read configuration file: {error}"))?;
        let document: ConfigurationDocument = toml::from_str(&content)
            .map_err(|error| format!("Unable to parse configuration file: {error}"))?;
        let mut configuration = Self::default();
        let directory = path.parent().unwrap_or_else(|| Path::new("."));

        for include in document.include {
            let included = Self::load(&directory.join(include), visited)?;
            configuration.merge(included);
        }

        for (rule_id, level) in document.rules.severity {
            let severity_value = match level.as_str() {
                "info" => Severity::Info,
                "warning" => Severity::Warning,
                "critical" => Severity::Critical,
                _ => return Err(format!("Unsupported severity for {rule_id}: {level}")),
            };
            configuration.severity.insert(rule_id, severity_value);
        }

        configuration.disabled.extend(document.rules.disabled);
        for address in document.targets.suspicious {
            let normalized = normalize_address(&address)?;
            configuration.suspicious_contracts.insert(normalized);
        }

        Ok(configuration)
    }

    pub fn apply(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|finding| !self.disabled.contains(&finding.rule_id))
            .map(|mut finding| {
                if let Some(severity) = self.severity.get(&finding.rule_id) {
                    finding.severity = *severity;
                }
                finding
            })
            .collect()
    }

    pub fn is_suspicious_contract(&self, address: &str) -> bool {
        normalize_address(address)
            .map(|address| self.suspicious_contracts.contains(&address))
            .unwrap_or(false)
    }

    fn merge(&mut self, other: Self) {
        self.disabled.extend(other.disabled);
        self.severity.extend(other.severity);
        self.suspicious_contracts.extend(other.suspicious_contracts);
    }
}

#[derive(Deserialize)]
struct ConfigurationDocument {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    rules: RulesDocument,
    #[serde(default)]
    targets: TargetsDocument,
}

#[derive(Default, Deserialize)]
struct RulesDocument {
    #[serde(default)]
    disabled: Vec<String>,
    #[serde(default)]
    severity: BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
struct TargetsDocument {
    #[serde(default)]
    suspicious: Vec<String>,
}

fn normalize_address(address: &str) -> Result<String, String> {
    let value = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);

    if value.len() != 40 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid contract address in configuration: {address}"
        ));
    }

    Ok(format!("0x{}", value.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::RuleConfiguration;
    use evmguard_core::{Finding, Severity};

    #[test]
    fn disables_rules_and_overrides_severity() {
        let path = env::temp_dir().join(format!("evmguard-rules-{}.toml", std::process::id()));
        fs::write(
            &path,
            "[rules]\ndisabled = [\"rule.disabled\"]\n\n[rules.severity]\n\"rule.adjusted\" = \"critical\"\n",
        )
        .expect("write configuration file");
        let configuration = RuleConfiguration::from_path(&path).expect("load configuration");
        fs::remove_file(&path).expect("remove configuration file");

        let findings = configuration.apply(vec![
            Finding::new("rule.disabled", Severity::Warning, "Disabled finding."),
            Finding::new("rule.adjusted", Severity::Info, "Adjusted finding."),
        ]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn applies_included_rule_packs_before_local_overrides() {
        let directory = env::temp_dir().join(format!("evmguard-pack-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("create rule pack directory");
        let included = directory.join("base.toml");
        let root = directory.join("evmguard.toml");
        fs::write(
            &included,
            "[rules.severity]\n\"rule.adjusted\" = \"warning\"\n",
        )
        .expect("write included rule pack");
        fs::write(
            &root,
            "include = [\"base.toml\"]\n\n[rules.severity]\n\"rule.adjusted\" = \"critical\"\n",
        )
        .expect("write root configuration");
        let configuration = RuleConfiguration::from_path(&root).expect("load configuration");
        fs::remove_dir_all(&directory).expect("remove rule pack directory");

        let findings = configuration.apply(vec![Finding::new(
            "rule.adjusted",
            Severity::Info,
            "Adjusted finding.",
        )]);

        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn recognizes_configured_suspicious_contracts() {
        let path = env::temp_dir().join(format!("evmguard-targets-{}.toml", std::process::id()));
        fs::write(
            &path,
            "[targets]\nsuspicious = [\"0x1111111111111111111111111111111111111111\"]\n",
        )
        .expect("write configuration file");
        let configuration = RuleConfiguration::from_path(&path).expect("load configuration");
        fs::remove_file(&path).expect("remove configuration file");

        assert!(configuration.is_suspicious_contract("0x1111111111111111111111111111111111111111"));
        assert!(configuration.is_suspicious_contract("0X1111111111111111111111111111111111111111"));
        assert!(!configuration.is_suspicious_contract("0x2222222222222222222222222222222222222222"));
    }

    #[test]
    fn rejects_include_cycles() {
        let directory = env::temp_dir().join(format!("evmguard-cycle-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("create configuration directory");
        let first = directory.join("first.toml");
        let second = directory.join("second.toml");
        fs::write(&first, "include = [\"second.toml\"]\n").expect("write first configuration");
        fs::write(&second, "include = [\"first.toml\"]\n").expect("write second configuration");

        let error = RuleConfiguration::from_path(&first).expect_err("expect include cycle error");
        fs::remove_dir_all(&directory).expect("remove configuration directory");

        assert!(error.contains("include cycle"));
    }

    #[test]
    fn rejects_invalid_suspicious_addresses() {
        let path = env::temp_dir().join(format!("evmguard-invalid-{}.toml", std::process::id()));
        fs::write(&path, "[targets]\nsuspicious = [\"0xnothex\"]\n")
            .expect("write configuration file");

        let error = RuleConfiguration::from_path(&path).expect_err("expect invalid address error");
        fs::remove_file(&path).expect("remove configuration file");

        assert!(error.contains("Invalid contract address"));
    }
}
