//! .

mod cli;
mod daemon;

#[cfg(test)]
pub(super) fn random_32b_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
pub(super) fn random_32b_bls_hex() -> String {
    bls::SecretKey::random().to_hex()
}

#[cfg(test)]
pub(super) fn gen_name() -> String {
    let name = crate::e2e::random_32b_hex();
    name_from(name)
}

#[cfg(test)]
pub(super) fn name_from(mut name: String) -> String {
    name.truncate(6);
    name
}

#[cfg(test)]
pub(super) fn gen_path() -> Vec<String> {
    (0..3)
        .into_iter()
        .map(|_| random_32b_bls_hex())
        .map(name_from)
        .collect()
}
