#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransactionRequest {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub data: String,
    pub value: String,
}
