/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

#include <stddef.h>
#include <stdint.h>

// Move bytes_t definition to a different place?
#include "keys_def.h"

#define NAME_LENGTH     32
#define METADATA_LENGTH 96

typedef enum {
    V1 = 1,
    V2 = 2,
    InvalidTransactionVersion,
} transaction_version_e;

typedef struct {
    uint8_t rbar[32];
    uint8_t sbar[32];
} redjubjub_signature_t;

typedef struct {
    bytes_t publicKeyRandomness;      // size = 32
    bytes_t proof;                    // size = 384
    bytes_t valueCommitment;          // size = 160
    bytes_t rootHash;                 // size = 32
    uint32_t treeSize;                // size = 4
    bytes_t nullifier;                // size = 32
    redjubjub_signature_t signature;  // size = 64
} spend_description_t;                // 676

typedef struct {
    uint8_t assetId[32];  // size = 32
    uint64_t value;       // size = 8
} burn_description_t;
typedef struct {
    bytes_t proof;
    bytes_t merkleNote;
} output_description_t;

typedef struct {
    uint8_t name[NAME_LENGTH];
    uint8_t metadata[METADATA_LENGTH];
    public_address_t creator;
    uint8_t nonce;
    /// The byte representation of a blake2s hash of the asset info
    // uint8_t id[32];
} asset_t;

typedef struct {
    bytes_t publicKeyRandomness;      // size = 32
    bytes_t proof;                    // size = 384 / 2
    asset_t asset;                    // size = 32 + 96 + 32 + 1 + 32 = 193
    uint64_t value;                   // size = 8
    bytes_t owner;                    // size = 32
    OptBytes_t transferOwnershipTo;   // size = 1 | 33
    redjubjub_signature_t signature;  // size = 64
} mint_description_t;

typedef struct {
    uint64_t elements;
    bytes_t data;
} vec_spend_description_t;

typedef struct {
    uint64_t elements;
    bytes_t data;
} vec_burn_description_t;

typedef struct {
    uint64_t elements;
    bytes_t data;
} vec_output_description_t;

typedef struct {
    uint64_t elements;
    bytes_t data;
} vec_mint_description_t;

typedef struct {
    transaction_version_e transactionVersion;
    int64_t fee;
    /// List of spends, or input notes, that have been destroyed.
    vec_spend_description_t spends;
    /// List of outputs, or output notes that have been created.
    vec_output_description_t outputs;
    /// List of mint descriptions
    vec_mint_description_t mints;
    /// List of burn descriptions
    vec_burn_description_t burns;
    /// Signature calculated from accumulating randomness with all the spends
    /// and outputs when the transaction was created.
    // redjubjub_signature_t bindingSignature;
    /// This is the sequence in the chain the transaction will expire at and be
    /// removed from the mempool. A value of 0 indicates the transaction will
    /// not expire.
    uint32_t expiration;
    /// Randomized public key of the sender of the Transaction
    /// currently this value is the same for all spends[].owner and outputs[].sender
    /// This is used during verification of SpendDescriptions and OutputDescriptions, as
    /// well as signing of the SpendDescriptions. Referred to as
    /// `rk` in the literature Calculated from the authorizing key and
    /// the public_key_randomness.
    bytes_t randomizedPublicKey;  // redjubjub::PublicKey,
    bytes_t publicKeyRandomness;

    bytes_t bindingSignature;

    // Not part of the incoming txn but it's used to compute signatures
    uint8_t transactionHash[32];
} sign_tx_t;

typedef struct {
    union {
        sign_tx_t sign_tx;
    };
} parser_tx_t;

#ifdef __cplusplus
}
#endif
