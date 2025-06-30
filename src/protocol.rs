//! This module defines the protocol for communication between a UI and the service.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

pub const DEFAULT_PORT: u16 = 48522;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    /// Start the daemon
    Start,
    /// Shutdown the daemon
    Shutdown,
    /// List all stored key names
    List,
    /// Store an EVM private key (32 bytes hex-encoded)
    StoreEVM { name: String, evm_sk_hex: String },
    /// Store a BLS private key
    StoreBLS { name: String, bls_sk_hex: String },
    /// Remove a key by name
    Remove(String),
    /// Return public key of stored key
    PublicKey { name: String },
    /// Return public key from derivation path
    PublicKeyOnPath { name: String, path: Vec<String> },
    /// Store a derived key under a new name
    StoreDerived {
        from_name: String,
        path: Vec<String>,
        to_name: String,
    },
    /// Sign using stored key
    Sign { with_name: String, payload: Bytes },
    /// Sign using derived key
    SignOnPath {
        from_name: String,
        path: Vec<String>,
        payload: Bytes,
    },
    /// Verify using stored key
    Verify {
        with_name: String,
        signature: Bytes,
        payload: Bytes,
    },
    /// Verify using derived key
    VerifyOnPath {
        from_name: String,
        path: Vec<String>,
        signature: Bytes,
        payload: Bytes,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    KeyAdded,
    KeyRemoved,
    KeyNames(Vec<String>),
    PublicKey(bls::PublicKey),
    Signature(bls::Signature),
    ValidSignature,
    ShuttingDown,
    Error(String),
}

pub async fn send_msg<T: Serialize, W: AsyncWriteExt + Unpin>(
    mut writer: W,
    msg: &T,
) -> io::Result<()> {
    let data = rmp_serde::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&data).await?;
    Ok(())
}

pub async fn receive_msg<T: for<'de> Deserialize<'de>, R: AsyncReadExt + Unpin>(
    mut reader: R,
) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    let msg = rmp_serde::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(msg)
}
