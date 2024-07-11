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

use crate::{
    constants::SECRET_KEY_LENGTH,
    // errors::{InternalError, SignatureError},
    hazmat::ExpandedSecretKey,
    // signature::InternalSignature,
    verifying::VerifyingKey,
    // Signature,
};

/// ed25519 secret key as defined in [RFC8032 § 5.1.5]:
///
/// > The private key is 32 octets (256 bits, corresponding to b) of
/// > cryptographically secure random data.
///
/// [RFC8032 § 5.1.5]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
pub type SecretKey = [u8; SECRET_KEY_LENGTH];

/// ed25519 signing key which can be used to produce signatures.
// Invariant: `verifying_key` is always the public key of
// `secret_key`. This prevents the signing function oracle attack
// described in https://github.com/MystenLabs/ed25519-unsafe-libs
#[derive(Clone)]
pub struct SigningKey {
    /// The secret half of this signing key.
    pub(crate) secret_key: SecretKey,
    /// The public half of this signing key.
    pub(crate) verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Construct a [`SigningKey`] from a [`SecretKey`]
    ///
    #[inline]
    pub fn from_bytes(secret_key: &SecretKey) -> Self {
        let verifying_key = VerifyingKey::from(&ExpandedSecretKey::from(secret_key));
        Self {
            secret_key: *secret_key,
            verifying_key,
        }
    }
}

/// The spec-compliant way to define an expanded secret key. This computes `SHA512(sk)`, clamps the
/// first 32 bytes and uses it as a scalar, and uses the second 32 bytes as a domain separator for
/// hashing.
impl From<&SecretKey> for ExpandedSecretKey {
    #[allow(clippy::unwrap_used)]
    fn from(secret_key: &SecretKey) -> ExpandedSecretKey {
        let hash = Sha512::default().chain_update(secret_key).finalize();
        ExpandedSecretKey::from_bytes(hash.as_ref())
    }
}
