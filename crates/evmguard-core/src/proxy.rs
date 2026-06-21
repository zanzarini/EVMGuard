#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyKind {
    Eip1967,
    Uups,
    Beacon,
}

impl ProxyKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Eip1967 => "EIP-1967",
            Self::Uups => "UUPS",
            Self::Beacon => "Beacon",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyInfo {
    pub address: String,
    pub kind: Option<ProxyKind>,
    pub implementation: Option<String>,
    pub admin: Option<String>,
    pub beacon: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyReport {
    pub proxy: ProxyInfo,
    pub findings: Vec<crate::Finding>,
}

impl ProxyInfo {
    pub fn is_proxy(&self) -> bool {
        self.kind.is_some()
    }
}
