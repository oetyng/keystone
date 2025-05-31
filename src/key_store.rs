//! .

use super::error::{KeyStoreError as Error, KeyStoreResult as Result};

use crate::import;

use bls::{PublicKey, SecretKey, Signature, serde_impl::SerdeSecret};
use bytes::Bytes;
use dashmap::DashMap;
use sha2::digest::generic_array::GenericArray;

#[derive(Clone)]
pub(super) struct KeyStore {
    keys: DashMap<String, SerdeSecret<bls::SecretKey>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
        }
    }

    pub fn names(&self) -> Vec<String> {
        // a bit confusing api, but `.key()`` returns the key
        // of _dashmap_, i.e. the name associated with the secret key
        self.keys.iter().map(|p| p.key().clone()).collect()
    }

    pub fn store_evm(&self, name: String, evm_sk_hex: String) -> Result<()> {
        if name.trim().is_empty() {
            return Err(Error::InvalidName);
        }
        if self.keys.contains_key(&name) {
            return Err(Error::AlreadyExists(name));
        }
        validate_evm_key(&evm_sk_hex)?;

        let bls_sk = import::derive_key(&evm_sk_hex)?;
        self.keys.insert(name, SerdeSecret(bls_sk));

        Ok(())
    }

    pub fn store_bls(&self, name: String, bls_sk_hex: String) -> Result<()> {
        if name.trim().is_empty() {
            return Err(Error::InvalidName);
        }
        if self.keys.contains_key(&name) {
            return Err(Error::AlreadyExists(name));
        }
        let sk = SecretKey::from_hex(&bls_sk_hex)?;
        self.keys.insert(name, SerdeSecret(sk));
        Ok(())
    }

    pub fn remove(&self, name: String) -> Result<()> {
        if !self.keys.contains_key(&name) {
            return Err(Error::NotFound(name));
        }
        self.keys.remove(&name);
        Ok(())
    }

    pub fn public_key(&self, name: String) -> Result<PublicKey> {
        let entry = self.keys.get(&name).ok_or(Error::NotFound(name))?;
        let key = entry.value();
        Ok(key.public_key())
    }

    pub fn public_key_on_path(&self, name: String, path: Vec<String>) -> Result<PublicKey> {
        let secret = self.derive(name, path)?;
        Ok(secret.public_key())
    }

    pub fn store_derived(
        &self,
        from_name: String,
        to_name: String,
        path: Vec<String>,
    ) -> Result<()> {
        if self.keys.contains_key(&to_name) {
            return Err(Error::AlreadyExists(to_name));
        }
        let output_sk = self.derive(from_name, path)?;
        self.keys.insert(to_name, SerdeSecret(output_sk));
        Ok(())
    }

    pub fn sign(&self, with_name: String, payload: Bytes) -> Result<Signature> {
        let sk = self
            .keys
            .get(&with_name)
            .ok_or(Error::NotFound(with_name))?;
        Ok(sk.sign(payload))
    }

    pub fn sign_on_path(
        &self,
        from_name: String,
        path: Vec<String>,
        payload: Bytes,
    ) -> Result<Signature> {
        let sk = self.derive(from_name, path)?;
        Ok(sk.sign(payload))
    }

    pub fn verify(&self, with_name: String, sig: &Signature, msg: Bytes) -> Result<bool> {
        let sk = self.get(with_name)?;
        Ok(sk.public_key().verify(sig, msg))
    }

    pub fn verify_on_path(
        &self,
        from_name: String,
        path: Vec<String>,
        sig: &Signature,
        msg: Bytes,
    ) -> Result<bool> {
        let sk = self.derive(from_name, path)?;
        Ok(sk.public_key().verify(sig, msg))
    }

    fn derive(&self, name: String, mut path: Vec<String>) -> Result<SecretKey> {
        if path.is_empty() {
            return Err(Error::EmptyPath(name));
        }
        if path.iter().any(|seg| seg.is_empty()) {
            return Err(Error::InvalidPathSegment);
        }
        if path.iter().any(|seg| seg.chars().any(|c| c.is_control())) {
            return Err(Error::InvalidPathSegment);
        }
        let key = self.get(name)?;
        let seed = path.remove(0);
        let mut output_sk = key.derive_child(seed.as_bytes());
        for seed in path {
            output_sk = output_sk.derive_child(seed.as_bytes());
        }
        Ok(output_sk)
    }

    fn get(&self, name: String) -> Result<SerdeSecret<SecretKey>> {
        let entry = self.keys.get(&name).ok_or(Error::NotFound(name))?;
        Ok(entry.value().clone())
    }
}

fn validate_evm_key(evm_sk_hex: &str) -> Result<()> {
    let bytes = hex::decode(evm_sk_hex).map_err(Error::InvalidEvmHex)?;
    let ga = GenericArray::from_slice(&bytes);
    let _key =
        k256::ecdsa::SigningKey::from_bytes(ga).map_err(|e| Error::InvalidEvmKey(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeyStoreError;
    use bls::SecretKey;
    use bytes::Bytes;

    fn sk_hex(n: u8) -> String {
        format!("{:064x}", n)
    }

    fn payload() -> Bytes {
        Bytes::from_static(b"test_msg")
    }

    fn path(vec: &[&str]) -> Vec<String> {
        vec.iter().map(|s| s.to_string()).collect()
    }

    // --- STORE ---

    #[test]
    fn store_bls_success() {
        let ks = KeyStore::new();
        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        assert!(ks.public_key("a".into()).is_ok());
    }

    #[test]
    fn store_bls_duplicate_fails() {
        let ks = KeyStore::new();
        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        let err = ks.store_bls("a".into(), sk_hex(2)).unwrap_err();
        assert!(matches!(err, KeyStoreError::AlreadyExists(name) if name == "a"));
    }

    #[test]
    fn store_bls_invalid_hex_fails() {
        let ks = KeyStore::new();
        let err = ks.store_bls("a".into(), "xx".into()).unwrap_err();
        assert!(matches!(err, KeyStoreError::BlsKey(_)));
    }

    #[test]
    fn store_evm_success() {
        let ks = KeyStore::new();
        let evm_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ks.store_evm("evm".into(), evm_hex.into()).unwrap();
        assert!(ks.public_key("evm".into()).is_ok());
    }

    #[test]
    fn store_evm_invalid_hex_fails() {
        let ks = KeyStore::new();
        let err = ks.store_evm("x".into(), "nothex".into()).unwrap_err();
        assert!(matches!(err, KeyStoreError::InvalidEvmHex(_)));
    }

    #[test]
    fn store_derived_success() {
        let ks = KeyStore::new();
        ks.store_bls("base".into(), sk_hex(1)).unwrap();
        ks.store_derived("base".into(), "child".into(), path(&["x", "y"]))
            .unwrap();
        assert!(ks.public_key("child".into()).is_ok());
    }

    #[test]
    fn stores_bls_key_and_returns_correct_public_key() {
        let ks = KeyStore::new();
        let name = "key1".to_string();
        let sk_hex = sk_hex(1);
        ks.store_bls(name.clone(), sk_hex.clone()).unwrap();
        let pk = ks.public_key(name.clone()).unwrap();
        assert_eq!(pk, SecretKey::from_hex(&sk_hex).unwrap().public_key());
    }

    #[test]
    fn store_derived_overwrite_fails() {
        let ks = KeyStore::new();
        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        ks.store_bls("b".into(), sk_hex(2)).unwrap();
        let err = ks
            .store_derived("a".into(), "b".into(), path(&["x"]))
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::AlreadyExists(name) if name == "b"));
    }

    #[test]
    fn store_derived_fails_if_from_key_missing() {
        let ks = KeyStore::new();
        let err = ks
            .store_derived("ghost".into(), "new".into(), path(&["x"]))
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn store_bls_rejects_empty_name() {
        let ks = KeyStore::new();
        let err = ks.store_bls("".into(), sk_hex(1)).unwrap_err();
        assert!(matches!(err, KeyStoreError::InvalidName));
    }

    #[test]
    fn store_evm_rejects_empty_name() {
        let ks = KeyStore::new();
        let evm_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = ks.store_evm("".into(), evm_hex.into()).unwrap_err();
        assert!(matches!(err, KeyStoreError::InvalidName));
    }

    #[test]
    fn store_evm_rejects_existing_key_name() {
        let ks = KeyStore::new();
        let name = "shared".to_string();
        ks.store_bls(name.clone(), sk_hex(1)).unwrap();
        let evm_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = ks.store_evm(name, evm_hex.into()).unwrap_err();
        assert!(matches!(err, KeyStoreError::AlreadyExists(_)));
    }

    // --- REMOVE ---

    #[test]
    fn remove_existing_key_success() {
        let ks = KeyStore::new();
        ks.store_bls("k".into(), sk_hex(1)).unwrap();
        ks.remove("k".into()).unwrap();
        assert!(ks.public_key("k".into()).is_err());
    }

    #[test]
    fn remove_missing_key_fails() {
        let ks = KeyStore::new();
        let err = ks.remove("missing".into()).unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(name) if name == "missing"));
    }

    // --- DERIVATION ---

    #[test]
    fn derive_valid_path_success() {
        let ks = KeyStore::new();
        ks.store_bls("k".into(), sk_hex(1)).unwrap();
        let result = ks.derive("k".into(), path(&["one", "two"]));
        assert!(result.is_ok());
    }

    #[test]
    fn derive_empty_path_fails() {
        let ks = KeyStore::new();
        ks.store_bls("k".into(), sk_hex(1)).unwrap();
        let err = ks.derive("k".into(), vec![]).unwrap_err();
        assert!(matches!(err, KeyStoreError::EmptyPath(name) if name == "k"));
    }

    #[test]
    fn derive_from_missing_key_fails() {
        let ks = KeyStore::new();
        let err = ks.derive("nope".into(), path(&["a"])).unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(name) if name == "nope"));
    }

    #[test]
    fn derive_fails_on_empty_path_segment() {
        let ks = KeyStore::new();
        ks.store_bls("base".into(), sk_hex(1)).unwrap();
        let path = vec!["".into(), "x".into()];
        let err = ks.derive("base".into(), path).unwrap_err();
        assert!(matches!(err, KeyStoreError::InvalidPathSegment));
    }

    #[test]
    fn derive_fails_on_control_character_in_path_segment() {
        let ks = KeyStore::new();
        ks.store_bls("base".into(), sk_hex(1)).unwrap();
        let path = vec!["\u{0000}".into(), "valid".into()];
        let err = ks.derive("base".into(), path).unwrap_err();
        assert!(matches!(err, KeyStoreError::InvalidPathSegment));
    }

    // --- SIGNATURES ---

    #[test]
    fn sign_and_verify_ok() {
        let ks = KeyStore::new();
        ks.store_bls("s".into(), sk_hex(1)).unwrap();
        let sig = ks.sign("s".into(), payload()).unwrap();
        assert!(ks.verify("s".into(), &sig, payload()).unwrap());
    }

    #[test]
    fn sign_fails_if_missing_key() {
        let ks = KeyStore::new();
        let err = ks.sign("ghost".into(), payload()).unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn sign_on_path_and_verify() {
        let ks = KeyStore::new();
        ks.store_bls("root".into(), sk_hex(1)).unwrap();
        let path = path(&["level1"]);
        let sig = ks
            .sign_on_path("root".into(), path.clone(), payload())
            .unwrap();
        let ok = ks
            .verify_on_path("root".into(), path, &sig, payload())
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn sign_on_path_fails_if_key_missing() {
        let ks = KeyStore::new();
        let err = ks
            .sign_on_path("nope".into(), path(&["x"]), payload())
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn sign_on_path_fails_if_path_empty() {
        let ks = KeyStore::new();
        ks.store_bls("root".into(), sk_hex(1)).unwrap();
        let err = ks
            .sign_on_path("root".into(), vec![], payload())
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::EmptyPath(_)));
    }

    #[test]
    fn sign_produces_signature_that_fails_on_wrong_payload() {
        let ks = KeyStore::new();
        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        let sig = ks.sign("a".into(), Bytes::from_static(b"correct")).unwrap();
        let verified = ks
            .verify("a".into(), &sig, Bytes::from_static(b"wrong"))
            .unwrap();
        assert!(!verified);
    }

    // --- SIGNATURE VERIFICATION ---

    #[test]
    fn verify_fails_if_missing_key() {
        let ks = KeyStore::new();
        let sk = SecretKey::random();
        let fake_sig = sk.sign("some message");
        let err = ks.verify("ghost".into(), &fake_sig, payload()).unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn verify_on_path_fails_if_key_missing() {
        let ks = KeyStore::new();
        let sk = SecretKey::random();
        let sig = sk.sign("some message");
        let err = ks
            .verify_on_path("ghost".into(), path(&["a"]), &sig, payload())
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn verify_on_path_fails_if_path_empty() {
        let ks = KeyStore::new();
        ks.store_bls("base".into(), sk_hex(1)).unwrap();
        let sig = ks.sign("base".into(), payload()).unwrap();
        let err = ks
            .verify_on_path("base".into(), vec![], &sig, payload())
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::EmptyPath(_)));
    }

    #[test]
    fn verify_fails_with_signature_from_other_key() {
        let ks = KeyStore::new();
        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        ks.store_bls("b".into(), sk_hex(2)).unwrap();
        let sig = ks.sign("a".into(), payload()).unwrap();
        let verified = ks.verify("b".into(), &sig, payload()).unwrap();
        assert!(!verified);
    }

    // --- PUBLIC KEY RETRIEVAL ---

    #[test]
    fn public_key_on_path_matches_manual_derive() {
        let ks = KeyStore::new();
        ks.store_bls("base".into(), sk_hex(1)).unwrap();
        let path = path(&["a", "b"]);
        let manual = ks.derive("base".into(), path.clone()).unwrap().public_key();
        let via_api = ks.public_key_on_path("base".into(), path).unwrap();
        assert_eq!(manual, via_api);
    }

    #[test]
    fn public_key_fails_if_not_found() {
        let ks = KeyStore::new();
        let err = ks.public_key("none".into()).unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn public_key_on_path_fails_if_key_missing() {
        let ks = KeyStore::new();
        let err = ks
            .public_key_on_path("ghost".into(), path(&["a"]))
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn public_key_on_path_fails_if_path_empty() {
        let ks = KeyStore::new();
        ks.store_bls("k".into(), sk_hex(1)).unwrap();
        let err = ks.public_key_on_path("k".into(), vec![]).unwrap_err();
        assert!(matches!(err, KeyStoreError::EmptyPath(_)));
    }

    // --- INTERNAL GET ---

    #[test]
    fn get_returns_secret_key_if_exists() {
        let ks = KeyStore::new();
        ks.store_bls("k".into(), sk_hex(1)).unwrap();
        let key = ks.get("k".into()).unwrap();
        assert_eq!(
            key.public_key(),
            SecretKey::from_hex(&sk_hex(1)).unwrap().public_key()
        );
    }

    #[test]
    fn get_fails_if_not_found() {
        let ks = KeyStore::new();
        let err = ks.get("ghost".into()).unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    // --- LISTING ---

    #[test]
    fn names_lists_all_inserted_keys() {
        let ks = KeyStore::new();
        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        ks.store_bls("b".into(), sk_hex(2)).unwrap();
        let mut names = ks.names();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    // --- NEXT LVL ---

    #[test]
    fn key_names_are_case_sensitive() {
        let ks = KeyStore::new();
        ks.store_bls("Key".into(), sk_hex(1)).unwrap();
        ks.store_bls("key".into(), sk_hex(2)).unwrap(); // Should not conflict

        let pk_upper = ks.public_key("Key".into()).unwrap();
        let pk_lower = ks.public_key("key".into()).unwrap();
        assert_ne!(pk_upper, pk_lower);

        let mut names = ks.names();
        names.sort();
        assert_eq!(names, vec!["Key", "key"]);
    }

    #[test]
    fn derive_accepts_long_path() {
        let ks = KeyStore::new();
        ks.store_bls("base".into(), sk_hex(1)).unwrap();

        // Generate 100-segment path
        let long_path: Vec<String> = (0..100).map(|i| format!("segment{i}")).collect();

        let result = ks.derive("base".into(), long_path);
        assert!(result.is_ok());
    }

    #[test]
    fn store_bls_rejects_second_insert_with_same_name() {
        let ks = KeyStore::new();
        let name = "dup_key".to_string();

        let first = ks.store_bls(name.clone(), sk_hex(1));
        let second = ks.store_bls(name.clone(), sk_hex(2));

        assert!(first.is_ok());
        assert!(matches!(second.unwrap_err(), KeyStoreError::AlreadyExists(n) if n == name));

        // Confirm that the stored key is still the original one
        let stored_pk = ks.public_key(name).unwrap();
        let expected_pk = SecretKey::from_hex(&sk_hex(1)).unwrap().public_key();
        assert_eq!(stored_pk, expected_pk);
    }

    #[test]
    fn derived_key_is_deterministic() {
        let ks = KeyStore::new();
        ks.store_bls("base".into(), sk_hex(1)).unwrap();

        let path = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let key1 = ks.derive("base".into(), path.clone()).unwrap();
        let key2 = ks.derive("base".into(), path).unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn signing_different_payloads_produces_different_signatures() {
        let ks = KeyStore::new();
        ks.store_bls("s".into(), sk_hex(1)).unwrap();

        let sig1 = ks.sign("s".into(), Bytes::from_static(b"msg1")).unwrap();
        let sig2 = ks.sign("s".into(), Bytes::from_static(b"msg2")).unwrap();

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn signing_same_payload_produces_same_signatures() {
        let ks = KeyStore::new();
        ks.store_bls("s".into(), sk_hex(1)).unwrap();

        let sig1 = ks.sign("s".into(), Bytes::from_static(b"msg1")).unwrap();
        let sig2 = ks.sign("s".into(), Bytes::from_static(b"msg1")).unwrap();

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn keys_are_isolated_from_each_other() {
        let ks = KeyStore::new();
        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        ks.store_bls("b".into(), sk_hex(2)).unwrap();

        let derived_a = ks.derive("a".into(), vec!["x".into()]).unwrap();
        let derived_b = ks.derive("b".into(), vec!["x".into()]).unwrap();

        assert_ne!(derived_a.to_bytes(), derived_b.to_bytes());
    }

    #[test]
    fn names_updates_on_insert_and_remove() {
        let ks = KeyStore::new();

        ks.store_bls("a".into(), sk_hex(1)).unwrap();
        ks.store_bls("b".into(), sk_hex(2)).unwrap();
        let mut names = ks.names();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);

        ks.remove("a".into()).unwrap();
        let names_after = ks.names();
        assert_eq!(names_after, vec!["b"]);
    }

    #[test]
    fn sign_handles_large_payload() {
        let ks = KeyStore::new();
        ks.store_bls("large".into(), sk_hex(1)).unwrap();

        let large_data = vec![42u8; 100_000]; // 100 KB
        let payload = Bytes::from(large_data);

        let sig = ks.sign("large".into(), payload.clone()).unwrap();
        assert!(ks.verify("large".into(), &sig, payload).unwrap());
    }

    #[test]
    fn can_store_and_list_many_keys() {
        let ks = KeyStore::new();
        let total = 10_000;

        for i in 0..total {
            let name = format!("key{i}");
            ks.store_bls(name, sk_hex((i % 255) as u8)).unwrap();
        }

        let mut names = ks.names();
        names.sort();

        assert_eq!(names.len(), total);
        assert_eq!(names.first().unwrap(), "key0");
        assert_eq!(*names.last().unwrap(), format!("key{}", total - 1));
    }

    /// Not necessary really, just tests dashmap..
    #[test]
    fn supports_concurrent_insert_and_read() {
        use std::sync::Arc;
        use std::thread;

        let ks = Arc::new(KeyStore::new());

        // Writer thread
        let ks_writer = ks.clone();
        let writer = thread::spawn(move || {
            for i in 0..1000 {
                let name = format!("k{i}");
                ks_writer.store_bls(name, sk_hex((i % 255) as u8)).unwrap();
            }
        });

        // Reader thread (reads during insertion)
        let ks_reader = ks.clone();
        let reader = thread::spawn(move || {
            let mut total_seen = 0;
            for _ in 0..10 {
                let snapshot = ks_reader.names();
                total_seen += snapshot.len();
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            total_seen
        });

        let _ = writer.join().unwrap();
        let seen = reader.join().unwrap();

        // We don’t assert exact numbers – just that it ran without panic and read data
        assert!(seen > 0);
        assert!(ks.names().len() >= 1000);
    }
}
