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
#![allow(dead_code, unused_imports)]

use crate::constants::ParserError;
use ironfish_frost::participant::{Secret, IDENTITY_LEN, Identity};
use ironfish_frost::dkg;

#[no_mangle]
pub extern "C" fn privkey_to_identity(
    privkey_1: &[u8; 32],
    privkey_2: &[u8; 32],
    identity_bytes: &mut [u8; IDENTITY_LEN],
) -> ParserError {
    let secret: Secret = Secret::from_secret_keys(privkey_1, privkey_2);
    let identity = secret.to_identity();

    let identity_ser = identity.serialize();
    identity_bytes[0..IDENTITY_LEN].copy_from_slice(&identity_ser);

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn rs_dkg_round_1(
    self_identity_bytes: &mut [u8; IDENTITY_LEN],
    identity_1_bytes: &mut [u8; IDENTITY_LEN],
    identity_2_bytes: &mut [u8; IDENTITY_LEN],
    min_signers: u16,
    output: &mut [u8; 512]
) -> ParserError {
    let self_identity = Identity::deserialize_from(self_identity_bytes.as_slice()).unwrap();
    let identity_1 = Identity::deserialize_from(identity_1_bytes.as_slice()).unwrap();
    let identity_2 = Identity::deserialize_from(identity_2_bytes.as_slice()).unwrap();

    let (round1_secret_package, round1_public_package) = dkg::round1::round1(
        &self_identity,
        min_signers,
        &[identity_1, identity_2],
        thread_rng(),
    ).unwrap();

    let round1_public_package_vec = round1_public_package.serialize();
    output.copy_from_slice(&round1_public_package_vec.as_slice());

    ParserError::ParserOk
}

#[cfg(cpp_tests)]
mod tests {
    use super::*;
    extern crate std;
    use std::println; // Make `println!` explicitly available for tests
}