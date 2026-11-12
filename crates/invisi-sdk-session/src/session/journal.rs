use super::*;
pub use crate::sdk::journal::{ManagedPrepared, PreparedSnapshot};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Prepared,
    Authorized,
    Proved,
    Ready,
    Exported,
    Submitted,
    Confirmed,
    Reverted,
    Failed,
    Expired,
    Uncertain,
    Reorged,
}
impl OperationStatus {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Reverted | Self::Failed | Self::Expired
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationRecord {
    pub id: String,
    pub kind: String,
    pub status: OperationStatus,
    pub generation: u64,
    pub inputs: Vec<String>,
    pub deadline: u64,
    pub snapshot: PreparedSnapshot,
    #[serde(default)]
    pub preparation_snapshot: Option<RetainedPreparation>,
    pub transaction_hash: Option<B256>,
    pub call: Option<StoredCall>,
    pub externalized: bool,
    pub broadcaster_id: Option<String>,
    #[serde(default)]
    pub broadcaster_submission_id: Option<String>,
    pub resolved_at: Option<CanonicalBlock>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredCall {
    pub to: Address,
    #[serde(with = "crate::note::bytes_hex")]
    pub data: Vec<u8>,
    pub value: U256,
}
impl From<crate::protocol::TransactionCall> for StoredCall {
    fn from(v: crate::protocol::TransactionCall) -> Self {
        Self {
            to: v.to,
            data: v.data,
            value: v.value,
        }
    }
}
