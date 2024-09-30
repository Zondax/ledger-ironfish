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

use constants::{
    DIFFIE_HELLMAN_PERSONALIZATION, ENCRYPTED_NOTE_SIZE, ENCRYPTED_SHARED_KEY_SIZE, MAC_SIZE,
    NOTE_ENCRYPTION_KEY_SIZE, SHARED_KEY_PERSONALIZATION, SPENDING_KEY_GENERATOR,
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

#[no_mangle]
pub extern "C" fn shared_secret(
    secret_key: &[u8; 32],
    other_public_key: &[u8; 32],
    reference_public_key: &[u8; 32],
    output: &mut [u8; 32],
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
    *output = hash_shared_secret(&affine, &reference_public_key.unwrap());

    ParserError::ParserOk
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
