//! Stable SDK error codes and preparation errors. Codes describe the failing boundary.
use serde::{Deserialize, Serialize};
use serde_json::Value;
/// Stable prefix for Credit usage-period failures returned by the legacy String result API.
pub const CREDIT_PERIOD_CHANGED: &str = "CREDIT_PERIOD_CHANGED";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvisiErrorCode {
    InvalidRecipient,
    EvmAddressNotRegistered,
    RecipientLookupFailed,
    PreparationFailed,
    MissingCapability,
    CreditPeriodChanged,
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
        let code = if cause
            .strip_prefix(CREDIT_PERIOD_CHANGED)
            .is_some_and(|suffix| suffix.starts_with(':'))
        {
            InvisiErrorCode::CreditPeriodChanged
        } else {
            InvisiErrorCode::PreparationFailed
        };
        Self::new(code, cause.clone(), serde_json::json!({"cause":cause}))
    }
}
impl From<&str> for InvisiError {
    fn from(cause: &str) -> Self {
        Self::from(cause.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credit_period_protocol_code_survives_structured_conversion() {
        let error = InvisiError::from("CREDIT_PERIOD_CHANGED: Credit UTC usage period changed; reauthorize and regenerate proof");
        assert_eq!(error.code, InvisiErrorCode::CreditPeriodChanged);
        let encoded = serde_json::to_value(&error).unwrap();
        assert_eq!(encoded["code"], "CREDIT_PERIOD_CHANGED");
        assert_eq!(
            serde_json::from_value::<InvisiError>(encoded).unwrap(),
            error
        );
        // Similar prose and longer identifiers do not classify as the explicit protocol code.
        for cause in [
            "Credit UTC usage period changed",
            "CREDIT_PERIOD_CHANGED_OTHER: expired",
            "Credit draw deadline expired",
        ] {
            assert_eq!(
                InvisiError::from(cause).code,
                InvisiErrorCode::PreparationFailed
            );
        }
    }
}
