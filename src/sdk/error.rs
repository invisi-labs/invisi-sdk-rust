//! Stable preparation errors. Codes describe the failing boundary, never inferred from text.
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvisiErrorCode {
    InvalidRecipient,
    EvmAddressNotRegistered,
    RecipientLookupFailed,
    PreparationFailed,
    MissingCapability,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct InvisiError {
    pub code: InvisiErrorCode,
    pub message: String,
    pub details: Value,
}
impl InvisiError {
    pub fn new(code: InvisiErrorCode, message: impl Into<String>, details: Value) -> Self {
        Self {
            code,
            message: message.into(),
            details,
        }
    }
    pub fn with_operation(mut self, operation: &str) -> Self {
        if let Some(details) = self.details.as_object_mut() {
            details
                .entry("operation")
                .or_insert_with(|| Value::String(operation.into()));
        }
        self
    }
    pub(super) fn preparation(operation: &str, cause: String) -> Self {
        Self::new(
            InvisiErrorCode::PreparationFailed,
            cause.clone(),
            serde_json::json!({"operation":operation,"cause":cause}),
        )
    }
}
impl From<InvisiError> for String {
    fn from(value: InvisiError) -> String {
        value.message
    }
}
pub type PreparationResult<T> = std::result::Result<T, InvisiError>;

impl From<String> for InvisiError {
    fn from(cause: String) -> Self {
        Self::new(
            InvisiErrorCode::PreparationFailed,
            cause.clone(),
            serde_json::json!({"cause":cause}),
        )
    }
}
impl From<&str> for InvisiError {
    fn from(cause: &str) -> Self {
        Self::from(cause.to_owned())
    }
}
