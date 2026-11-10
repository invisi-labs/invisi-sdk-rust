//! Contract ABI, canonical chain/output DTOs and receipt decoding.
pub mod gas;
pub mod interfaces;
pub mod protocol;
pub mod statements;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;
pub mod provenance;
pub mod provenance_rotation;
