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
#include "parser_common.h"
#include "parser_impl.h"

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;
    ctx->tx_obj = NULL;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));

    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    switch (ctx->tx_type) {
        case sign_tx:{
            CHECK_ERROR(parser_init_context(ctx, data, dataLen));
            ctx->tx_obj = &parser_tx_obj;
            return _readSignTx(ctx, &(parser_tx_obj.sign_tx));
        }
        default:
            return parser_unsupported_tx;
    }
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
    *num_items = 5;
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


parser_error_t _getItemSignTx(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    UNUSED(pageIdx);
    *pageCount = 1;
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems));
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx));
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Spends");
            snprintf(outVal, outValLen, "%d", (uint8_t)parser_tx_obj.sign_tx.spends.elements);
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "Outputs");
            snprintf(outVal, outValLen, "%d", (uint8_t)parser_tx_obj.sign_tx.outputs.elements);
            return parser_ok;
        case 2:
            snprintf(outKey, outKeyLen, "Mints");
            snprintf(outVal, outValLen, "%d", (uint8_t)parser_tx_obj.sign_tx.mints.elements);
            return parser_ok;
        case 3:
            snprintf(outKey, outKeyLen, "Burns");
            snprintf(outVal, outValLen, "%d", (uint8_t)parser_tx_obj.sign_tx.burns.elements);
            return parser_ok;
        case 4: {
            snprintf(outKey, outKeyLen, "TxnHash");
            pageStringHex(outVal, outValLen, (const char *)parser_tx_obj.sign_tx.transactionHash,
                          sizeof(parser_tx_obj.sign_tx.transactionHash), pageIdx, pageCount);
            return parser_ok;
        }
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}

parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen, char *outVal,
                              uint16_t outValLen, uint8_t pageIdx,
                              uint8_t *pageCount) {
    switch (ctx->tx_type) {
        case sign_tx: {
            return _getItemSignTx(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        default:
            return parser_unsupported_tx;
    }
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
        case parser_unsupported_tx:
            return "Usupported transaction type";
        default:
            return "Unrecognized error code";
    }
}
