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
}

impl RuleConfiguration {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|error| format!("Unable to read configuration file: {error}"))?;
        let document: ConfigurationDocument = toml::from_str(&content)
            .map_err(|error| format!("Unable to parse configuration file: {error}"))?;
        let mut severity = BTreeMap::new();

        for (rule_id, level) in document.rules.severity {
            let severity_value = match level.as_str() {
                "info" => Severity::Info,
                "warning" => Severity::Warning,
                "critical" => Severity::Critical,
                _ => return Err(format!("Unsupported severity for {rule_id}: {level}")),
            };
            severity.insert(rule_id, severity_value);
        }

        Ok(Self {
            disabled: document.rules.disabled.into_iter().collect(),
            severity,
        })
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
}

#[derive(Deserialize)]
struct ConfigurationDocument {
    #[serde(default)]
    rules: RulesDocument,
}

#[derive(Default, Deserialize)]
struct RulesDocument {
    #[serde(default)]
    disabled: Vec<String>,
    #[serde(default)]
    severity: BTreeMap<String, String>,
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
}
