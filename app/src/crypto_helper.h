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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "coin.h"
#include "keys_def.h"
#include "parser_common.h"
#include "zxerror.h"

#define ASSERT_CX_OK(CALL)                  \
    do {                                    \
        cx_err_t __cx_err = CALL;           \
        if (__cx_err != CX_OK) {            \
            return parser_unexpected_error; \
        }                                   \
    } while (0)

#define MODIFIER_ASK 0x00
#define MODIFIER_NSK 0x01
#define MODIFIER_OVK 0x02

parser_error_t convertKey(const uint8_t spendingKey[KEY_LENGTH], const uint8_t modifier, uint8_t outputKey[KEY_LENGTH],
                          bool reduceWideByte);
parser_error_t generate_key(const uint8_t expandedKey[KEY_LENGTH], constant_key_t keyType, uint8_t output[KEY_LENGTH]);
parser_error_t computeIVK(const ak_t ak, const nk_t nk, ivk_t ivk);

parser_error_t transaction_signature_hash(parser_tx_t *txObj, uint8_t output[HASH_LEN]);
zxerr_t crypto_signRedjubjub(const uint8_t randomizedPrivateKey[KEY_LENGTH], const uint8_t rng[RNG_LEN],
                             const uint8_t transactionHash[HASH_LEN], uint8_t output[REDJUBJUB_SIGNATURE_LEN]);

#ifdef __cplusplus
}
#endif
