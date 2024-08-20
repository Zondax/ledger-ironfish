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

use alloc::vec;
use alloc::vec::Vec;
use crate::constants::{ParserError, VecIdentities};
use crate::bolos_local::rng::Trng;
use crate::bolos_local::zemu_log::zlog;
use ironfish_frost::participant::{Secret, IDENTITY_LEN, Identity};
use ironfish_frost::dkg;
use core::slice;
use crate::HEAP;

const ROUND1_2P_ENC_PACKAGE_LEN: usize = 520 / 2;
const ROUND1_2P_PUB_PACKAGE_LEN: usize = 856 / 2;

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
    privkey_1: &[u8; 32],
    privkey_2: &[u8; 32],
    identities: &VecIdentities,
    min_signers: u16,
    output: &mut [u8; 1000]
) -> ParserError {
    zlog("-- rs_dkg_round_1 --\x00");

    let secret: Secret = Secret::from_secret_keys(privkey_1, privkey_2);
    let self_identity = secret.to_identity();

    zlog("-- 0 --\x00");
    let mut identities_vec = Vec::new();
    zlog("-- 01 --\x00");
    let mut data_ptr = identities.data.ptr;


    zlog("-- 1 --\x00");

    for _i in 0..identities.elements {
        zlog("-- 11 --\x00");
        let identity_data = unsafe { slice::from_raw_parts(data_ptr, IDENTITY_LEN) };
        zlog("-- 12 --\x00");
        let identity = Identity::deserialize_from(identity_data).unwrap();
        zlog("-- 13 --\x00");
        identities_vec.push(identity);

        zlog("-- 14 --\x00");
        data_ptr = unsafe { data_ptr.add(IDENTITY_LEN) };
        zlog("-- 15 --\x00");
    }

    zlog("-- 2 --\x00");
    let mut rng = Trng {};

    let (round1_secret_package, round1_public_package) = dkg::round1::round1(
        &self_identity,
        min_signers,
        &identities_vec,
        &mut rng,
    ).unwrap();

    zlog("-- 3 --\x00");

    output[0..ROUND1_2P_ENC_PACKAGE_LEN].copy_from_slice(&round1_secret_package.as_slice());
    output[ROUND1_2P_ENC_PACKAGE_LEN..ROUND1_2P_ENC_PACKAGE_LEN+ROUND1_2P_PUB_PACKAGE_LEN].copy_from_slice(&round1_public_package.serialize().as_slice());

    zlog("-- 4 --\x00");
    ParserError::ParserOk
}

#[cfg(cpp_tests)]
mod tests {
    use super::*;
    extern crate std;
    use std::println; // Make `println!` explicitly available for tests
}