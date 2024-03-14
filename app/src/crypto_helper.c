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
#include "crypto_helper.h"
#include "keys_personalizations.h"
#include <string.h>
#include "zxformat.h"

#include "rslib.h"

 #if defined (LEDGER_SPECIFIC)
    #include "cx.h"
    #include "cx_blake2b.h"
#endif
    #include "blake2.h"

static void swap_endian(uint8_t *data, int8_t len) {
    for (int8_t i = 0; i < len / 2; i++) {
        uint8_t t = data[len - i - 1];
        data[len - i - 1] = data[i];
        data[i] = t;
    }
}

parser_error_t convertKey(const uint8_t spendingKey[KEY_LENGTH], const uint8_t modifier, uint8_t outputKey[KEY_LENGTH], bool reduceWideByte) {
    uint8_t output[64] = {0};
#if defined (LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, (uint8_t *)EXPANDED_SPEND_BLAKE2_KEY, sizeof(EXPANDED_SPEND_BLAKE2_KEY)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, spendingKey, KEY_LENGTH));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, &modifier, 1));
    cx_blake2b_final(&ctx, output);
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, BLAKE2B_OUTPUT_LEN, (const uint8_t*)EXPANDED_SPEND_BLAKE2_KEY, sizeof(EXPANDED_SPEND_BLAKE2_KEY));
    blake2b_update(&state, spendingKey, KEY_LENGTH);
    blake2b_update(&state, &modifier, 1);
    blake2b_final(&state, output, sizeof(output));
#endif

    if (reduceWideByte) {
        from_bytes_wide(output, outputKey);
        swap_endian(outputKey, KEY_LENGTH);
    } else {
        memcpy(outputKey, output, KEY_LENGTH);
    }

    return parser_ok;
}

parser_error_t generate_key(const uint8_t expandedKey[KEY_LENGTH], constant_key_t keyType, uint8_t output[KEY_LENGTH]) {
    if (keyType >= InvalidKey) {
        return parser_value_out_of_range;
    }
    uint8_t tmpExpandedKey[KEY_LENGTH] = {0};
    memcpy(tmpExpandedKey, expandedKey, KEY_LENGTH);
    swap_endian(tmpExpandedKey, KEY_LENGTH);
    scalar_multiplication(tmpExpandedKey, keyType, output);
    return parser_ok;
}

parser_error_t computeIVK(const ak_t ak, const nk_t nk, ivk_t ivk) {
    blake2s_state state = {0};
    blake2s_init_with_personalization(&state, 32, (const uint8_t*)CRH_IVK_PERSONALIZATION, sizeof(CRH_IVK_PERSONALIZATION));
    blake2s_update(&state, ak, KEY_LENGTH);
    blake2s_update(&state, nk, KEY_LENGTH);
    blake2s_final(&state, ivk, KEY_LENGTH);

    ivk[31] &= 0x07;
    swap_endian(ivk, KEY_LENGTH);
    // if ivk == [0; 32] {
    //     return Err(IronfishError::new(IronfishErrorKind::InvalidViewingKey));
    // }
    return parser_ok;
}
