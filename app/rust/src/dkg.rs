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

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

const VERSION_LEN: usize = 1;
const VERIFICATION_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
const ENCRYPTION_KEY_LEN: usize = 32;

const IDENTITY_LEN: usize = 128;

const VERSION: [u8; VERSION_LEN] = [0x72];

pub type Signature = ed25519_dalek::Signature;
pub type SignatureError = ed25519_dalek::SignatureError;

/// Returns the portion of identifier data that is signed by [`Secret::signing_key`]
fn authenticated_data(
    verification_key: &VerifyingKey,
    encryption_key: &PublicKey,
) -> [u8; VERSION_LEN + VERIFICATION_KEY_LEN + ENCRYPTION_KEY_LEN] {
    let mut data = [0u8; VERSION_LEN + VERIFICATION_KEY_LEN + ENCRYPTION_KEY_LEN];
    let parts = [
        &VERSION[..],
        verification_key.as_bytes(),
        encryption_key.as_bytes(),
    ];
    let mut slice = &mut data[..];
    for part in parts {
        slice[..part.len()].copy_from_slice(part);
        slice = &mut slice[part.len()..];
    }
    assert_eq!(slice.len(), 0);
    data
}

/// Secret keys of a participant.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct Secret {
    signing_key: SigningKey,
    decryption_key: StaticSecret,
    identity: Identity,
}

impl Secret {
    // #[must_use]
    pub fn from_private_key(priv_key_bytes: &[u8; 32]) -> Self {
        // Signing key
        let signing_key: SigningKey = SigningKey::from_bytes(&priv_key_bytes);

        // decryption key
        // TODO: check whether this key must be randomly generated or not
        // Can we use the sale key for signing?
        let tmp_priv_key = priv_key_bytes.clone();
        let decryption_key: StaticSecret = StaticSecret::from(tmp_priv_key);

        // identity
        let verification_key = signing_key.verifying_key();
        let encryption_key = PublicKey::from(&decryption_key);
        let authenticated_data = authenticated_data(&verification_key, &encryption_key);
        let signature = signing_key.sign(&authenticated_data);

        let identity = Identity::new(verification_key, encryption_key, signature).unwrap();

        Self {
            signing_key: signing_key,
            decryption_key: decryption_key,
            identity: identity,
        }
    }

    #[must_use]
    pub fn to_identity(&self) -> &Identity {
        &self.identity
    }
}

/// Public identity of a participant.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Identity {
    verification_key: VerifyingKey,
    encryption_key: PublicKey,
    signature: Signature,
}

impl Identity {
    pub fn new(
        verification_key: VerifyingKey,
        encryption_key: PublicKey,
        signature: Signature,
    ) -> Result<Self, SignatureError> {
        let id = Self {
            verification_key,
            encryption_key,
            signature,
        };
        id.verify().map(|_| id)
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        let authenticated_data = authenticated_data(&self.verification_key, &self.encryption_key);
        self.verification_key
            .verify(&authenticated_data, &self.signature)
    }

    pub fn to_bytes(&self, output: &mut [u8; IDENTITY_LEN]) {
        let verification_key_bytes = self.verification_key.to_bytes();
        let encryption_key_bytes = self.encryption_key.to_bytes();
        let signature_bytes = self.signature.to_bytes();
        output[0..32].copy_from_slice(&verification_key_bytes);
        output[32..64].copy_from_slice(&encryption_key_bytes);
        output[64..128].copy_from_slice(&signature_bytes);
    }
}

#[no_mangle]
pub extern "C" fn privkey_to_identity(
    privkey: &[u8; 32],
    identity_bytes: &mut [u8; 128],
) -> ParserError {
    let secret: Secret = Secret::from_private_key(privkey);
    let identity = secret.to_identity();
    identity.to_bytes(identity_bytes);

    ParserError::ParserOk
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::println; // Make `println!` explicitly available for tests
}
