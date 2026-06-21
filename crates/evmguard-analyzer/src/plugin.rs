use evmguard_core::{CallFrame, Finding, ProxyInfo, TransactionRequest};

pub enum RuleContext<'a> {
    Transaction(&'a TransactionRequest),
    Trace(&'a CallFrame),
    Proxy(&'a ProxyInfo),
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn evaluate(&self, context: RuleContext<'_>) -> Vec<Finding>;
}

pub struct RulePack {
    name: String,
    rules: Vec<Box<dyn Rule>>,
}

impl RulePack {
    pub fn new(name: impl Into<String>, rules: Vec<Box<dyn Rule>>) -> Self {
        Self {
            name: name.into(),
            rules,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Default)]
pub struct RuleRegistry {
    packs: Vec<RulePack>,
}

impl RuleRegistry {
    pub fn register(&mut self, pack: RulePack) {
        self.packs.push(pack);
    }

    pub fn evaluate(&self, context: RuleContext<'_>) -> Vec<Finding> {
        self.packs
            .iter()
            .flat_map(|pack| pack.rules.iter())
            .flat_map(|rule| {
                rule.evaluate(match &context {
                    RuleContext::Transaction(transaction) => RuleContext::Transaction(transaction),
                    RuleContext::Trace(trace) => RuleContext::Trace(trace),
                    RuleContext::Proxy(proxy) => RuleContext::Proxy(proxy),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Rule, RuleContext, RulePack, RuleRegistry};
    use evmguard_core::{Finding, Severity, TransactionRequest};

    struct ExampleRule;

    impl Rule for ExampleRule {
        fn id(&self) -> &str {
            "example.transaction"
        }

        fn evaluate(&self, context: RuleContext<'_>) -> Vec<Finding> {
            match context {
                RuleContext::Transaction(_) => vec![Finding::new(
                    self.id(),
                    Severity::Info,
                    "Example transaction finding.",
                )],
                _ => Vec::new(),
            }
        }
    }

    #[test]
    fn evaluates_registered_rule_packs() {
        let mut registry = RuleRegistry::default();
        registry.register(RulePack::new("example", vec![Box::new(ExampleRule)]));

        let findings = registry.evaluate(RuleContext::Transaction(&TransactionRequest::default()));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "example.transaction");
    }
}
