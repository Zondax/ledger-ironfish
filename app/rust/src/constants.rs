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

use jubjub::{AffineNielsPoint, AffinePoint, Fq};

pub const SPENDING_KEY_GENERATOR: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x47bf_4692_0a95_a753,
        0xd5b9_a7d3_ef8e_2827,
        0xd418_a7ff_2675_3b6a,
        0x0926_d4f3_2059_c712,
    ]),
    Fq::from_raw([
        0x3056_32ad_aaf2_b530,
        0x6d65_674d_cedb_ddbc,
        0x53bb_37d0_c21c_fd05,
        0x57a1_019e_6de9_b675,
    ]),
)
.to_niels();

pub const PROOF_GENERATION_KEY_GENERATOR: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3af2_dbef_b96e_2571,
        0xadf2_d038_f2fb_b820,
        0x7043_03f1_e890_6081,
        0x1457_a502_31cd_e2df,
    ]),
    Fq::from_raw([
        0x467a_f9f7_e05d_e8e7,
        0x50df_51ea_f5a1_49d2,
        0xdec9_0184_0f49_48cc,
        0x54b6_d107_18df_2a7a,
    ]),
)
.to_niels();

pub const PUBLIC_KEY_GENERATOR: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3edc_c85f_4d1a_44cd,
        0x77ff_8c90_a9a0_d8f4,
        0x0daf_03b5_47e2_022b,
        0x6dad_65e6_2328_d37a,
    ]),
    Fq::from_raw([
        0x5095_1f1f_eff0_8278,
        0xf0b7_03d5_3a3e_dd4e,
        0xca01_f580_9c00_eee2,
        0x6996_932c_ece1_f4bb,
    ]),
)
.to_niels();

pub const SHARED_KEY_PERSONALIZATION: &[u8; 16] = b"Iron Fish Keyenc";
pub const DIFFIE_HELLMAN_PERSONALIZATION: &[u8; 16] = b"Iron Fish shared";

pub const AFFINE_POINT_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;
pub const SCALAR_SIZE: usize = 32;
pub const MEMO_SIZE: usize = 32;
pub const AMOUNT_VALUE_SIZE: usize = 8;
pub const ASSET_ID_LENGTH: usize = 32;
pub const PUBLIC_ADDRESS_SIZE: usize = 32;
pub const EPHEMEREAL_PUBLIC_KEY_SIZE: usize = 32;
pub const NOTE_COMMITMENT_SIZE: usize = 32;
pub const ENCRYPTED_NOTE_SIZE: usize =
    SCALAR_SIZE + MEMO_SIZE + AMOUNT_VALUE_SIZE + ASSET_ID_LENGTH + PUBLIC_ADDRESS_SIZE;
pub const ENCRYPTED_NOTE_OFFSET: usize =
    VALUE_COMMITMENT_SIZE + NOTE_COMMITMENT_SIZE + EPHEMEREAL_PUBLIC_KEY_SIZE;
pub const ENCRYPTED_SHARED_KEY_SIZE: usize = 64;

pub const NOTE_ENCRYPTION_KEY_SIZE: usize = ENCRYPTED_SHARED_KEY_SIZE + MAC_SIZE;
pub const NOTE_LEN_TO_HASH: usize =
    VALUE_COMMITMENT_SIZE + NOTE_COMMITMENT_SIZE + EPHEMEREAL_PUBLIC_KEY_SIZE;
pub const VALUE_COMMITMENT_SIZE: usize = 32;
pub const MERKLE_NOTE_SIZE: usize = VALUE_COMMITMENT_SIZE
    + NOTE_COMMITMENT_SIZE
    + EPHEMEREAL_PUBLIC_KEY_SIZE
    + ENCRYPTED_NOTE_SIZE
    + MAC_SIZE
    + NOTE_ENCRYPTION_KEY_SIZE;
pub const ENCRYPTED_NOTE_SIZE_WITH_MAC: usize = ENCRYPTED_NOTE_SIZE + MAC_SIZE;
