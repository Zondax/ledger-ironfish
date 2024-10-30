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

#include "parser.h"

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>
#include <zxtypes.h>

#include "coin.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "parser_common.h"
#include "parser_impl.h"
#include "parser_print_common.h"
#include "rslib.h"

// lookup table for future use
static const asset_id_lookpup_t asset_id_lookups[] = {
    {{0x51, 0xf3, 0x3a, 0x2f, 0x14, 0xf9, 0x27, 0x35, 0xe5, 0x62, 0xdc, 0x65, 0x8a, 0x56, 0x39, 0x27,
      0x9d, 0xdc, 0xa3, 0xd5, 0x07, 0x9a, 0x6d, 0x12, 0x42, 0xb2, 0xa5, 0x88, 0xa9, 0xcb, 0xf4, 0x4c},
     8,
     " IRON"},
    {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     8,
     " UNKNOWN"},

};

parser_error_t parser_verify_asset_id(uint8_t *asset_id, uint8_t *index) {
    for (size_t i = 0; i < sizeof(asset_id_lookups) / sizeof(asset_id_lookups[0]); i++) {
        if (MEMCMP(asset_id, PIC(asset_id_lookups[i].identifier), 32) == 0) {
            *index = i;
            return parser_ok;
        }
    }
    // Temporarly set to unknown asset
    *index = 1;
    return parser_ok;
}

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, parser_tx_t *tx_obj) {
    CHECK_ERROR(parser_init_context(ctx, data, dataLen));
    ctx->tx_obj = tx_obj;
    return _read(ctx, tx_obj);
}

parser_error_t parser_validate(parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems));

    char tmpKey[40] = {0};
    char tmpVal[40] = {0};

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount));
    }
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    UNUSED(ctx);

    // Txversion + (ownner + amount + asset id) * n_output + fee + expiration
    *num_items = 1 + ctx->tx_obj->outputs.elements * 2 + 2;

    if (*num_items == 0) {
        return parser_unexpected_number_items;
    }
    return parser_ok;
}

static void cleanOutput(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx) {
    if (displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

uint8_t out_idx = 0;
uint8_t prev_decrypted_out_idx = 0;
parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    UNUSED(pageIdx);
    *pageCount = 1;
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems));
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx));
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    uint64_t total_out_elements = ctx->tx_obj->outputs.elements * ELEMENTS_PER_OUTPUT;
    uint8_t tmp_idx = displayIdx;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Tx Version");
        snprintf(outVal, outValLen, "V%d", (uint8_t)ctx->tx_obj->transactionVersion);
        return parser_ok;
    }

    displayIdx -= 1;
    if (tmp_idx > 0 && tmp_idx <= total_out_elements) {
        tmp_idx = (displayIdx % ELEMENTS_PER_OUTPUT);
        out_idx = (displayIdx / ELEMENTS_PER_OUTPUT) + 1;

        if (prev_decrypted_out_idx != out_idx) {
            const uint8_t *output = ctx->tx_obj->outputs.data.ptr + ((out_idx - 1) * (192 + 328));
            CHECK_ERROR(crypto_decrypt_merkle_note(ctx->tx_obj, output + 192, ctx->tx_obj->ovk));
            prev_decrypted_out_idx = out_idx;
        }
    } else if (tmp_idx > total_out_elements) {
        tmp_idx -= total_out_elements - ELEMENTS_PER_OUTPUT + 1;
    }

    char buf[70] = {0};
    uint8_t asset_id_idx = 0;
    switch (tmp_idx) {
        case 0:
            snprintf(outKey, outKeyLen, "To %d", out_idx - 1);
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->outputs.decrypted_note.owner, 32);
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "Amount %d", out_idx - 1);
            CHECK_ERROR(parser_verify_asset_id(ctx->tx_obj->outputs.decrypted_note.asset_id, &asset_id_idx));
            CHECK_ERROR(printAmount64(ctx->tx_obj->outputs.decrypted_note.value, asset_id_lookups[asset_id_idx].decimals,
                                      PIC(asset_id_lookups[asset_id_idx].name), outVal, outValLen, pageIdx, pageCount));
            return parser_ok;
        case 2:
            snprintf(outKey, outKeyLen, "Fee");
            CHECK_ERROR(printAmount64(ctx->tx_obj->fee, asset_id_lookups[0].decimals, PIC(asset_id_lookups[0].name), outVal,
                                      outValLen, pageIdx, pageCount));
            return parser_ok;
        case 3:
            snprintf(outKey, outKeyLen, "Expiration");
            uint32_to_str(buf, sizeof(buf), ctx->tx_obj->expiration);
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_version:
            return "Unexpected version";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_duplicated_field:
            return "Unexpected duplicated field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_unexpected_chain:
            return "Unexpected chain";
        case parser_missing_field:
            return "missing field";

        case parser_display_idx_out_of_range:
            return "display index out of range";
        case parser_display_page_out_of_range:
            return "display page out of range";

        default:
            return "Unrecognized error code";
    }
}
