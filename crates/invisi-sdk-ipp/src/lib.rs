//! IPP protocol messages and a session-bound transport, independent of wallet execution.
mod validation;
use serde_json::Value;
pub use validation::{
    api_url, assert_request_matches_session, parse_checkout, parse_checkout_entry,
    parse_checkout_input, parse_credential, parse_json, parse_payment_request,
    parse_payment_session, timestamp, MAX_BODY_BYTES,
};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid IPP message")]
    InvalidMessage,
    #[error("IPP transport failed; recover using the same session")]
    Transport,
    #[error("IPP operation timed out; result remains unknown")]
    Timeout,
    #[error("IPP operation cancelled")]
    Cancelled,
    #[error("IPP service rejected the operation (HTTP {status})")]
    Service {
        code: String,
        status: u16,
        retryable: bool,
        retry_after: Option<std::time::Duration>,
    },
    #[error("IPP request is not eligible for preparation")]
    ExecutionNotAllowed,
    #[error("IPP request does not match the trusted deployment")]
    DeploymentMismatch,
    #[error("IPP preparation failed")]
    Preparation,
}
pub type Result<T> = std::result::Result<T, Error>;
macro_rules! message {
    ($($name:ident),*) => {$(
        #[derive(Clone, PartialEq, Eq, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(pub(crate) Value);
        impl $name { pub fn as_value(&self)->&Value{&self.0} pub fn into_value(self)->Value{self.0} }
        impl std::fmt::Debug for $name { fn fmt(&self,f:&mut std::fmt::Formatter)->std::fmt::Result { f.write_str(stringify!($name)) } }
    )*}
}
message!(
    Checkout,
    CheckoutInput,
    PaymentSession,
    Request,
    Credential,
    CredentialAcknowledgement
);
mod transport;
pub use transport::*;
mod types;
pub use types::*;
#[cfg(feature = "invisi")]
mod adapter;
#[cfg(feature = "invisi")]
pub use adapter::*;
