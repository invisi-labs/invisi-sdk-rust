//! Versioned indexed RPC and independent Ethereum reads. Indexed records are never proof of ownership.
mod broadcaster_discovery;
mod client;
mod finality;
mod note_confirmation;
pub use finality::*;
pub use invisi_sdk_protocol::finality::*;
pub use note_confirmation::*;
mod transport;
mod types;
pub use client::*;
pub use transport::*;
pub use types::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("native finality tag unsupported")]
    FinalityUnsupported,
    #[error("inconsistent native finality")]
    FinalityInconsistent,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("transport: {0}")]
    Transport(String),
    #[error("HTTP {status}")]
    Http {
        status: u16,
        retry_after: Option<String>,
    },
    #[error("RPC {code}: {message}")]
    Remote {
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    },
}
impl From<invisi_sdk_protocol::Error> for Error {
    fn from(value: invisi_sdk_protocol::Error) -> Self {
        match value {
            invisi_sdk_protocol::Error::Invalid(message) => Self::Invalid(message),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
