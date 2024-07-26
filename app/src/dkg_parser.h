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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sigutils.h>
#include <stdbool.h>

#include "coin.h"
#include "keys_def.h"
#include "parser_common.h"

#define VERSION 0x72

typedef struct {
    uint8_t verificationKey[KEY_LENGTH];
    uint8_t encryptionKey[KEY_LENGTH];
    uint8_t signature[ED25519_SIGNATURE_SIZE];
} Identity_t;

typedef struct {
    uint32_t len;
    bytes_t keys;
} EncryptedKeys_t;  // [uint32_t len | Vec<Keys(32)>]

typedef struct {
    bytes_t agreementKey;  // [u8; 32] PublicKey
    EncryptedKeys_t encryptedKeys;
    bytes_t cipherText;  // [uint32_t len | ciphertext]

} MultiRecipientBlob_t;

typedef struct {
    uint8_t version;
    bytes_t identity;
    bytes_t frostPackage;
    MultiRecipientBlob_t groupSecretKeyShardEncrypted;
    uint64_t checksum;  // little endian
} Round1PublicPackage_t;

// typedef struct {
//     Identifier_t identifier;
//     VecScalar_t coefficients;
//     VerifiableSecretSharingCommitment_t commitment;
//     uint16_t minSigners;
//     uint16_t maxSigners;
// } Round1SecretPackage_t;

// pub struct SecretPackage<C : Ciphersuite>{
//     /// The identifier of the participant holding the secret.
//     pub(crate) identifier : Identifier<C>,
//     /// Coefficients of the temporary secret polynomial for the participant.
//     /// These are (a_{i0}, ..., a_{i(t−1)})) which define the polynomial f_i(x)
//     pub(crate) coefficients : Vec<Scalar<C>>,
//     /// The public commitment for the participant (C_i)
//     pub(crate) commitment : VerifiableSecretSharingCommitment<C>,
//     /// The minimum number of signers.
//     pub(crate) min_signers : u16,
//     /// The total number of signers.
//     pub(crate) max_signers : u16,
// }

parser_error_t parseRound1PublicPackage(parser_context_t *ctx, Round1PublicPackage_t *round1PublicPackage);
parser_error_t parseRound1PrivatePackage(parser_context_t *ctx, Round1PublicPackage_t *round1PublicPackage);

#ifdef __cplusplus
}
#endif
