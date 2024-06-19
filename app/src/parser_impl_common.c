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
#include "parser_impl_common.h"

#include <zxmacros.h>

parser_error_t readByte(parser_context_t *ctx, uint8_t *byte) {
    if (byte == NULL || ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_error;
    }

    *byte = *(ctx->buffer + ctx->offset);
    ctx->offset++;
    return parser_ok;
}

parser_error_t readUint16(parser_context_t *ctx, uint16_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint16_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint16_t));
    ctx->offset += sizeof(uint16_t);
    return parser_ok;
}

parser_error_t readUint32(parser_context_t *ctx, uint32_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint32_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint32_t));
    ctx->offset += sizeof(uint32_t);
    return parser_ok;
}

parser_error_t readUint64(parser_context_t *ctx, uint64_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint64_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint64_t));
    ctx->offset += sizeof(uint64_t);
    return parser_ok;
}

parser_error_t readBytes(parser_context_t *ctx, const uint8_t **output, uint16_t outputLen) {
    if (ctx->offset + outputLen > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *output = ctx->buffer + ctx->offset;
    ctx->offset += outputLen;
    return parser_ok;
}

parser_error_t readInt64(parser_context_t *ctx, int64_t *value) {
    if (value == NULL || ctx->offset + sizeof(int64_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(int64_t));
    ctx->offset += sizeof(int64_t);
    return parser_ok;
}
