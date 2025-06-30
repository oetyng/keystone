//! .

use hex::FromHexError;

use crate::{cli::ParseError, import::KeyError};

pub type AppResult<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Invalid signature")]
    InvalidSignature(String),
    #[error("A key already exists for: {0}")]
    Parse(#[from] ParseError),
    #[error("The key was not found: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("Failed to bind to port: {0}")]
    DaemonAlreadyRunning(u16),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type KeyStoreResult<T> = std::result::Result<T, KeyStoreError>;

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("Invalid key name")]
    InvalidName,
    #[error("Invalid component of derivation path")]
    InvalidPathSegment,
    #[error("A key already exists for: {0}")]
    AlreadyExists(String),
    #[error("The key was not found: {0}")]
    NotFound(String),
    #[error("The derivation path was empty: {0}")]
    EmptyPath(String),
    #[error("Invalid evm hex: {0}")]
    InvalidEvmHex(#[from] FromHexError),
    #[error("Invalid evm key: {0}")]
    InvalidEvmKey(String),
    #[error("Failed to convert hex to bls secret key: {0}")]
    BlsKey(#[from] bls::Error),
    #[error("Generation or signing failed: {0}")]
    KeyGen(#[from] KeyError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
