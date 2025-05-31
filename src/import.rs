//! .

use blst::min_pk::SecretKey as BlstSecretKey;
use sha2::{Digest, Sha256};

pub type KeyResult<T> = std::result::Result<T, KeyError>;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Failed to sign message: {0}")]
    FailedToSignMessage(#[from] evm_crypto::Error),
    #[error("Failed to generate secret key: {0}")]
    FailedToGenerateSecretKey(String),
    #[error("Failed to convert blst secret key to blsttc secret key: {0}")]
    BlsConversionError(#[from] bls::Error),
    #[error("Failed to generate blst secret key")]
    KeyGenerationError,
}

/// Message used to generate the secret key from the EVM secret key
const SECRET_KEY_SEED: &[u8] = b"Massive Array of Internet Disks Secure Access For Everyone";

/// Derives the secret key from the EVM secret key hex string
/// The EVM secret key is used to sign a message and the signature is hashed to derive the secret key
/// Being able to derive the secret key from the EVM secret key allows users to only keep track of one key: the EVM secret key
pub(super) fn derive_key(evm_sk_hex: &str) -> KeyResult<bls::SecretKey> {
    let signature = evm_crypto::sign_message(evm_sk_hex, SECRET_KEY_SEED)
        .map_err(KeyError::FailedToSignMessage)?;
    let blst_key = derive_secret_key_from_seed(&signature)?;
    let secret_key = blst_to_blsttc(&blst_key)?;
    Ok(secret_key)
}

fn derive_secret_key_from_seed(seed: &[u8]) -> KeyResult<BlstSecretKey> {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let hashed_seed = hasher.finalize();
    let sk = BlstSecretKey::key_gen(&hashed_seed, &[]).map_err(|_| KeyError::KeyGenerationError)?;
    Ok(sk)
}

/// Derives a secret key from a signature hex string
#[allow(unused)]
fn key_from_signature_hex(signature_hex: &str) -> KeyResult<bls::SecretKey> {
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| KeyError::FailedToGenerateSecretKey(e.to_string()))?;
    let blst_key = derive_secret_key_from_seed(&signature_bytes)?;
    let secret_key = blst_to_blsttc(&blst_key)?;
    Ok(secret_key)
}

/// Convert a blst secret key to a blsttc secret key and pray that endianness is the same
fn blst_to_blsttc(sk: &BlstSecretKey) -> KeyResult<bls::SecretKey> {
    let sk_bytes = sk.to_bytes();
    let sk = bls::SecretKey::from_bytes(sk_bytes).map_err(KeyError::BlsConversionError)?;
    Ok(sk)
}

mod evm_crypto {
    use ecdsa::Error as KeyError;
    use hex::FromHexError;
    use k256::ecdsa::{RecoveryId, Signature, SigningKey};
    use sha2::digest::generic_array::GenericArray;
    use tiny_keccak::{Hasher, Keccak};
    pub type Result<T> = std::result::Result<T, Error>;

    /// Sign error
    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("Failed to parse EVM secret key as hex: {0}")]
        InvalidEvmHex(#[from] FromHexError),
        #[error("Invalid EVM secret key: {0}")]
        InvalidEvmSecretKey(#[from] KeyError),
    }

    /// Sign a message with an EVM secret key.
    pub fn sign_message(evm_secret_key_str: &str, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = get_signer(evm_secret_key_str)?;
        let message_hash = to_eth_signed_message_hash(message);
        let (signature, _) = sign_message_recoverable(&signing_key, message_hash)?;
        Ok(signature.to_vec())
    }

    fn get_signer(hex: &str) -> Result<SigningKey> {
        let bytes = hex::decode(hex)?;
        let ga = GenericArray::from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(ga)?;
        Ok(signing_key)
    }

    /// Hash a message using Keccak256, then add the Ethereum prefix and hash it again.
    fn to_eth_signed_message_hash<T: AsRef<[u8]>>(message: T) -> [u8; 32] {
        const PREFIX: &str = "\x19Ethereum Signed Message:\n32";
        let hashed_message = hash(message);
        let mut eth_message = Vec::with_capacity(PREFIX.len() + 32);
        eth_message.extend_from_slice(PREFIX.as_bytes());
        eth_message.extend_from_slice(hashed_message.as_slice());
        hash(eth_message)
    }

    /// Sign a message with a recoverable public key.
    fn sign_message_recoverable<T: AsRef<[u8]>>(
        secret_key: &SigningKey,
        message: T,
    ) -> Result<(Signature, RecoveryId)> {
        let hash = to_eth_signed_message_hash(message);
        let (sig, id) = secret_key.sign_prehash_recoverable(&hash)?;
        Ok((sig, id))
    }

    /// Hash data using Keccak256.
    fn hash<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        keccak256(data.as_ref())
    }

    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }
}
