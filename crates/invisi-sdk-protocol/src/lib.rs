//! Contract ABI, canonical chain/output DTOs and receipt decoding.
pub use invisi_sdk_core::*;
pub mod interfaces;
pub mod protocol;
use serde_json::Value;
#[derive(Debug, thiserror::Error)]
pub enum Error {
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
        data: Option<Value>,
    },
}
pub type Result<T> = std::result::Result<T, Error>;
