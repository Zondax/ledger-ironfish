use crate::{rand::LedgerRng, AppSW};
use alloc::vec;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
#[cfg(feature = "ledger")]
use ledger_device_sdk::ecc::{bip32_derive, ChainCode, CurvesId, Secret};
// #[cfg(feature = "ledger")]
// use ledger_device_sdk::random::LedgerRng;

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[inline(never)]
pub fn decrypt(key: &[u8; 32], payload: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AppSW> {
    zlog_stack("start decrypt\0");

    // Generate a random key
    let key = Key::clone_from_slice(key);

    // Create a ChaCha20Poly1305 instance
    let cipher = ChaCha20Poly1305::new(&key);

    let nonce_slice = <&[u8; NONCE_LEN]>::try_from(nonce).map_err(|_| AppSW::InvalidPayload)?;

    // Generate a random nonce
    let nonce = Nonce::clone_from_slice(nonce_slice); // 96-bits; unique per message

    // Encrypt the message with associated data
    let ciphertext = cipher
        .decrypt(&nonce, payload)
        .map_err(|_| AppSW::DecryptionFail)?;

    Ok(ciphertext)
}
