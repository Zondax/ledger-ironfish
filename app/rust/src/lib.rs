/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#![no_std]
#![no_builtins]
#![allow(dead_code, unused_imports)]

use core::panic::PanicInfo;

use chacha20poly1305::{aead::generic_array::GenericArray, ChaCha20Poly1305, Key, KeyInit, Nonce};
use constants::{
    DIFFIE_HELLMAN_PERSONALIZATION, ENCRYPTED_NOTE_OFFSET, ENCRYPTED_NOTE_SIZE,
    ENCRYPTED_NOTE_SIZE_WITH_MAC, ENCRYPTED_SHARED_KEY_SIZE, EPHEMEREAL_PUBLIC_KEY_SIZE, MAC_SIZE,
    MERKLE_NOTE_SIZE, NOTE_COMMITMENT_SIZE, NOTE_ENCRYPTION_KEY_SIZE, NOTE_LEN_TO_HASH,
    SHARED_KEY_PERSONALIZATION, SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_SIZE,
};
mod constants;

use blake2b_simd::Params as Blake2b;
//use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use jubjub::{AffinePoint, ExtendedPoint, Fr};

// ParserError should mirror parser_error_t from parser_common.
// At the moment, just implement OK or Error
#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum ParserError {
    ParserOk = 0,
    ParserUnexpectedError = 5,
}

#[repr(C)]
pub enum ConstantKey {
    SpendingKeyGenerator,
    ProofGenerationKeyGenerator,
    PublicKeyGenerator,
}

#[no_mangle]
pub extern "C" fn from_bytes_wide(input: &[u8; 64], output: &mut [u8; 32]) -> ParserError {
    let result = Fr::from_bytes_wide(input).to_bytes();
    output.copy_from_slice(&result[0..32]);
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn scalar_multiplication(
    input: &[u8; 32],
    key: ConstantKey,
    output: *mut [u8; 32],
) -> ParserError {
    let key_point = match key {
        ConstantKey::SpendingKeyGenerator => constants::SPENDING_KEY_GENERATOR,
        ConstantKey::ProofGenerationKeyGenerator => constants::PROOF_GENERATION_KEY_GENERATOR,
        ConstantKey::PublicKeyGenerator => constants::PUBLIC_KEY_GENERATOR,
    };

    let extended_point = key_point.multiply_bits(input);
    let result = AffinePoint::from(&extended_point);

    unsafe {
        let output_slice = &mut *output;
        output_slice.copy_from_slice(&result.to_bytes());
    }

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn randomizeKey(
    key: &[u8; 32],
    randomness: &[u8; 32],
    output: &mut [u8; 32],
) -> ParserError {
    let mut skfr = Fr::from_bytes(key).unwrap();
    let alphafr = Fr::from_bytes(randomness).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn compute_sbar(
    s: &[u8; 32],
    r: &[u8; 32],
    rsk: &[u8; 32],
    sbar: &mut [u8; 32],
) -> ParserError {
    let s_point = Fr::from_bytes(s).unwrap();
    let r_point = Fr::from_bytes(r).unwrap();
    let rsk_point = Fr::from_bytes(rsk).unwrap();

    let sbar_tmp = r_point + s_point * rsk_point;
    sbar.copy_from_slice(&sbar_tmp.to_bytes());

    ParserError::ParserOk
}

#[inline(never)]
fn hash_shared_secret(shared_secret: &[u8; 32], reference_public_key: &AffinePoint) -> [u8; 32] {
    let reference_bytes = reference_public_key.to_bytes();

    let mut hasher = Blake2b::new()
        .hash_length(32)
        .personal(DIFFIE_HELLMAN_PERSONALIZATION)
        .to_state();

    hasher.update(&shared_secret[..]);
    hasher.update(&reference_bytes);

    let mut hash_result = [0; 32];
    hash_result[..].copy_from_slice(hasher.finalize().as_ref());
    hash_result
}

#[inline(never)]
pub fn calculate_key_for_encryption_keys(
    outgoing_view_key: &[u8; 32],
    note: &[u8; NOTE_LEN_TO_HASH],
) -> Result<[u8; 32], ParserError> {
    let mut key_input = [0u8; 128];

    key_input[0..32].copy_from_slice(outgoing_view_key);
    key_input[32..128].copy_from_slice(note);

    // Store the hash state in a variable
    let hash_state = Blake2b::new()
        .hash_length(32)
        .personal(SHARED_KEY_PERSONALIZATION)
        .hash(&key_input);

    // Get the hash result as bytes
    let hash_result = hash_state.as_bytes();

    // Attempt to convert the hash result into an array and handle the error
    hash_result
        .try_into()
        .map_err(|_| ParserError::ParserUnexpectedError) // Return error if conversion fails
}

fn decrypt<const SIZE: usize>(
    key: &[u8; 32],
    ciphertext: &[u8],
    plaintext: &mut [u8; SIZE],
) -> ParserError {
    use chacha20poly1305::AeadInPlace;

    // Check if the ciphertext length is sufficient
    if ciphertext.len() < SIZE {
        return ParserError::ParserUnexpectedError; // Return an error if insufficient data
    }

    let decryptor = ChaCha20Poly1305::new(Key::from_slice(key));

    plaintext.copy_from_slice(&ciphertext[..SIZE]);

    // Attempt decryption
    match decryptor.decrypt_in_place_detached(
        &Nonce::default(),
        &[],
        plaintext,
        ciphertext[SIZE..].into(),
    ) {
        Ok(_) => ParserError::ParserOk,
        Err(_) => ParserError::ParserUnexpectedError, // Handle decryption failure
    }
}

#[no_mangle]
pub extern "C" fn decrypt_note_encryption_keys(
    ovk: &[u8; 32],
    note: &[u8; MERKLE_NOTE_SIZE],
    output: &mut [u8; ENCRYPTED_SHARED_KEY_SIZE],
) -> ParserError {
    let key_result =
        calculate_key_for_encryption_keys(ovk, &note[..NOTE_LEN_TO_HASH].try_into().unwrap());

    // Handle the result of calculate_key_for_encryption_keys
    let key = match key_result {
        Ok(k) => k,
        Err(_) => return ParserError::ParserUnexpectedError, // Return error if key calculation fails
    };

    let ciphertext: &[u8; NOTE_ENCRYPTION_KEY_SIZE] = note
        [MERKLE_NOTE_SIZE - NOTE_ENCRYPTION_KEY_SIZE..]
        .try_into()
        .unwrap();
    decrypt::<ENCRYPTED_SHARED_KEY_SIZE>(&key, ciphertext, output);

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn decrypt_note(
    note: &[u8; MERKLE_NOTE_SIZE],
    secret_key: &[u8; 32],
    other_public_key: &[u8; 32],
    reference_public_key: &[u8; 32],
    output: &mut [u8; ENCRYPTED_NOTE_SIZE],
) -> ParserError {
    let secret_key = Fr::from_bytes(secret_key);
    if secret_key.is_none().into() {
        return ParserError::ParserUnexpectedError;
    }
    let other_public_key = AffinePoint::from_bytes(*other_public_key);
    if other_public_key.is_none().into() {
        return ParserError::ParserUnexpectedError;
    }
    let reference_public_key = AffinePoint::from_bytes(*reference_public_key);
    if reference_public_key.is_none().into() {
        return ParserError::ParserUnexpectedError;
    }

    let shared_secret = other_public_key.unwrap() * secret_key.unwrap();
    let affine = AffinePoint::from(&shared_secret).to_bytes();
    let hash = hash_shared_secret(&affine, &reference_public_key.unwrap());

    let ciphertext: &[u8; ENCRYPTED_NOTE_SIZE_WITH_MAC] = note
        [ENCRYPTED_NOTE_OFFSET..ENCRYPTED_NOTE_OFFSET + ENCRYPTED_NOTE_SIZE_WITH_MAC]
        .try_into()
        .unwrap();
    decrypt::<ENCRYPTED_NOTE_SIZE>(&hash, ciphertext, output)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

fn debug(_msg: &str) {}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::println; // Make `println!` explicitly available for tests
}
