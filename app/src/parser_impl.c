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

#include "parser_impl.h"

#include "coin.h"
#include "crypto_helper.h"
#include "parser_impl_common.h"
#include "zxformat.h"
#include "zxmacros.h"

parser_tx_t parser_tx_obj;

static parser_error_t readTransactionVersion(parser_context_t *ctx, transaction_version_e *txVersion) {
    if (ctx == NULL || txVersion == NULL) {
        return parser_no_data;
    }

    uint8_t tmpVersion = 0xFF;
    CHECK_ERROR(readByte(ctx, &tmpVersion));

    if (tmpVersion != V1 && tmpVersion != V2) {
        return parser_value_out_of_range;
    }
    *txVersion = (transaction_version_e)tmpVersion;
    return parser_ok;
}

static parser_error_t readSpends(parser_context_t *ctx, vec_spend_description_t *spends) {
    if (ctx == NULL || spends == NULL) {
        return parser_no_data;
    }

    const uint16_t SPENDLEN = 32 + 192 + 32 + 32 + 4 + 32 + 64;
    spends->data.ptr = ctx->buffer + ctx->offset;
    spends->data.len = 0;
    const uint8_t *tmpPtr = NULL;
    for (uint64_t i = 0; i < spends->elements; i++) {
        CHECK_ERROR(readBytes(ctx, &tmpPtr, SPENDLEN));
        spends->data.len += SPENDLEN;
    }
    return parser_ok;
}

static parser_error_t readOutputs(parser_context_t *ctx, vec_output_description_t *outputs) {
    if (ctx == NULL || outputs == NULL) {
        return parser_no_data;
    }
    const uint16_t OUTPUTLEN = 192 + 328;
    outputs->data.ptr = ctx->buffer + ctx->offset;
    outputs->data.len = 0;
    const uint8_t *tmpPtr = NULL;
    for (uint64_t i = 0; i < outputs->elements; i++) {
        CHECK_ERROR(readBytes(ctx, &tmpPtr, OUTPUTLEN));
        outputs->data.len += OUTPUTLEN;
    }
    return parser_ok;
}

static parser_error_t readMints(parser_context_t *ctx, vec_mint_description_t *mints, transaction_version_e txnVersion) {
    if (ctx == NULL || mints == NULL) {
        return parser_no_data;
    }

    const uint16_t MINTLEN = 32 + 192 + 193 + 8;
    mints->data.ptr = ctx->buffer + ctx->offset;
    mints->data.len = 0;
    const uint8_t *tmpPtr = NULL;
    for (uint64_t i = 0; i < mints->elements; i++) {
        if (txnVersion == V1) {
            // Owner field only available for V2
            CHECK_ERROR(readBytes(ctx, &tmpPtr, MINTLEN - 32 + REDJUBJUB_SIGNATURE_LEN));
            mints->data.len += MINTLEN + REDJUBJUB_SIGNATURE_LEN;
        } else {
            CTX_CHECK_AVAIL(ctx, (MINTLEN + 1));
            const uint8_t transferOwnershipToLen = mints->data.ptr[MINTLEN] == 1 ? 33 : 1;
            CHECK_ERROR(readBytes(ctx, &tmpPtr, MINTLEN + transferOwnershipToLen + REDJUBJUB_SIGNATURE_LEN));
            mints->data.len += MINTLEN + transferOwnershipToLen + REDJUBJUB_SIGNATURE_LEN;
        }
    }
    return parser_ok;
}

static parser_error_t readBurns(parser_context_t *ctx, vec_burn_description_t *burns) {
    if (ctx == NULL || burns == NULL) {
        return parser_no_data;
    }

    const uint16_t BURNLEN = 32 + 8;
    burns->data.ptr = ctx->buffer + ctx->offset;
    burns->data.len = 0;
    const uint8_t *tmpPtr = NULL;
    for (uint64_t i = 0; i < burns->elements; i++) {
        CHECK_ERROR(readBytes(ctx, &tmpPtr, BURNLEN));
        burns->data.len += BURNLEN;
    }
    return parser_ok;
}

static parser_error_t readIdentities(parser_context_t *ctx, vec_identities_t *identities) {
    if (ctx == NULL || identities == NULL) {
        return parser_no_data;
    }

    identities->data.ptr = ctx->buffer + ctx->offset;
    identities->data.len = 0;
    const uint8_t *tmpPtr = NULL;
    for (uint64_t i = 0; i < identities->elements; i++) {
        CHECK_ERROR(readBytes(ctx, &tmpPtr, IDENTITY_LEN));
        identities->data.len += IDENTITY_LEN;
    }
    return parser_ok;
}

parser_error_t _readSignTx(parser_context_t *ctx, sign_tx_t *v) {
    CHECK_ERROR(readTransactionVersion(ctx, &v->transactionVersion));
    CHECK_ERROR(readUint64(ctx, &v->spends.elements));
    CHECK_ERROR(readUint64(ctx, &v->outputs.elements));
    CHECK_ERROR(readUint64(ctx, &v->mints.elements));
    CHECK_ERROR(readUint64(ctx, &v->burns.elements));
    CHECK_ERROR(readInt64(ctx, &v->fee));
    CHECK_ERROR(readUint32(ctx, &v->expiration));

    v->randomizedPublicKey.len = KEY_LENGTH;
    CHECK_ERROR(readBytes(ctx, &v->randomizedPublicKey.ptr, v->randomizedPublicKey.len));

    v->publicKeyRandomness.len = KEY_LENGTH;
    CHECK_ERROR(readBytes(ctx, &v->publicKeyRandomness.ptr, v->publicKeyRandomness.len));

    // Read Spends and Outputs
    CHECK_ERROR(readSpends(ctx, &v->spends));
    CHECK_ERROR(readOutputs(ctx, &v->outputs));

    // Read Mints and Burns
    CHECK_ERROR(readMints(ctx, &v->mints, v->transactionVersion));
    CHECK_ERROR(readBurns(ctx, &v->burns));

    v->bindingSignature.len = REDJUBJUB_SIGNATURE_LEN;
    CHECK_ERROR(readBytes(ctx, &v->bindingSignature.ptr, v->bindingSignature.len));

    if (ctx->bufferLen != ctx->offset) {
        return parser_unexpected_buffer_end;
    }

    CHECK_ERROR(transaction_signature_hash(v, v->transactionHash));
    return parser_ok;
}


parser_error_t _readDkgRound1(parser_context_t *ctx, dkg_round_1_t *v) {
    CHECK_ERROR(readByte(ctx, &v->identities.elements));
    CHECK_ERROR(readIdentities(ctx, &v->identities));
    CHECK_ERROR(readByte(ctx, &v->min_signers));

    // TODO check min_signers vs identities
    return parser_ok;
}
