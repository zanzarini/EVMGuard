#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallType {
    Call,
    CallCode,
    Create,
    Create2,
    DelegateCall,
    StaticCall,
    Unknown(String),
}

impl CallType {
    pub fn from_trace_value(value: &str) -> Self {
        match value {
            "CALL" => Self::Call,
            "CALLCODE" => Self::CallCode,
            "CREATE" => Self::Create,
            "CREATE2" => Self::Create2,
            "DELEGATECALL" => Self::DelegateCall,
            "STATICCALL" => Self::StaticCall,
            _ => Self::Unknown(value.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Call => "CALL",
            Self::CallCode => "CALLCODE",
            Self::Create => "CREATE",
            Self::Create2 => "CREATE2",
            Self::DelegateCall => "DELEGATECALL",
            Self::StaticCall => "STATICCALL",
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallFrame {
    pub call_type: CallType,
    pub from: String,
    pub to: Option<String>,
    pub input: String,
    pub value: String,
    pub gas_used: String,
    pub error: Option<String>,
    pub calls: Vec<CallFrame>,
}

impl CallFrame {
    pub fn frame_count(&self) -> usize {
        1 + self.calls.iter().map(CallFrame::frame_count).sum::<usize>()
    }
}
