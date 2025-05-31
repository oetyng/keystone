//! .

use hex::FromHexError;

pub type ParseResult<T> = std::result::Result<T, ParseError>;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid source for input: {0}")]
    InvalidInputSource(String),
    #[error("Invalid hex input: {0}")]
    InvalidHexInput(#[from] FromHexError),
    #[error("Invalid base64 input: {0}")]
    InvalidBase64Input(#[from] base64::DecodeError),
    #[error("Failed to read file: {0}")]
    CouldNotReadPath(#[from] std::io::Error),
    #[error("stdin: {0}")]
    StdIn(String),
}
