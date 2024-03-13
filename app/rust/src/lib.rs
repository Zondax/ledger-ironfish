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
#![no_main]
#![no_builtins]
#![allow(dead_code, unused_imports)]

use core::panic::PanicInfo;

use constants::{SPENDING_KEY_GENERATOR};
mod constants;

use jubjub::{Fr, AffinePoint, ExtendedPoint};

fn debug(_msg: &str) {}

// ParserError should mirror parser_error_t from parser_common.
// At the moment, just implement OK or Error
#[repr(C)]
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
pub extern "C" fn scalar_multiplication(input: &[u8; 32], key: ConstantKey, output: *mut [u8; 32]) -> ParserError {
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}


#[cfg(test)]
mod tests {
    // use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    // use curve25519_dalek::edwards::EdwardsPoint;
    // use curve25519_dalek::scalar::Scalar;
    // use log::{debug, info};
    // use schnorrkel::{context::*, Keypair, PublicKey, SecretKey, Signature};

    // use crate::*;
    // use core::ops::Mul;

    // fn init_logging() {
    //     let _ = env_logger::builder().is_test(true).try_init();
    // }

    // fn ristretto_scalarmult(sk: &[u8], pk: &mut [u8]) {
    //     let mut seckey = [0u8; 32];
    //     seckey.copy_from_slice(&sk[0..32]);
    //     let pubkey = RISTRETTO_BASEPOINT_POINT
    //         .mul(Scalar::from_bits(seckey))
    //         .compress()
    //         .0;
    //     pk.copy_from_slice(&pubkey);
    // }

}
