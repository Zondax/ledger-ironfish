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

#include "dkg_parser.h"

#include "parser_impl_common.h"
#include "zxmacros.h"

static parser_error_t parseMultiRecipientBlob(parser_context_t *ctx, MultiRecipientBlob_t *groupSecretKeyShardEncrypted) {
    if (ctx == NULL || groupSecretKeyShardEncrypted == NULL) {
        return parser_no_data;
    }

    // Read agreementKey
    groupSecretKeyShardEncrypted->agreementKey.len = KEY_LENGTH;
    CHECK_ERROR(
        readBytes(ctx, &groupSecretKeyShardEncrypted->agreementKey.ptr, groupSecretKeyShardEncrypted->agreementKey.len));

    // Read encryptedKeys
    CHECK_ERROR(readUint32(ctx, &groupSecretKeyShardEncrypted->encryptedKeys.len));
    CHECK_ERROR(readBytes(ctx, &groupSecretKeyShardEncrypted->encryptedKeys.keys.ptr,
                          groupSecretKeyShardEncrypted->encryptedKeys.len * KEY_LENGTH));

    // Read cipherText
    uint32_t cipherTextLen = 0;
    CHECK_ERROR(readUint32(ctx, &cipherTextLen));
    if (cipherTextLen > UINT16_MAX) {
        return parser_unexpected_value;
    }
    groupSecretKeyShardEncrypted->cipherText.len = (uint16_t)cipherTextLen;
    CHECK_ERROR(readBytes(ctx, &groupSecretKeyShardEncrypted->cipherText.ptr, cipherTextLen));

    return parser_ok;
}

parser_error_t parseRound1PublicPackage(parser_context_t *ctx, Round1PublicPackage_t *round1PublicPackage) {
    if (ctx == NULL || round1PublicPackage == NULL) {
        return parser_no_data;
    }
    // read Version
    CHECK_ERROR(readByte(ctx, &round1PublicPackage->version));
    if (round1PublicPackage->version != VERSION) {
        return parser_value_out_of_range;
    }

    // read Identity
    round1PublicPackage->identity.len = IDENTITY_LEN;
    CHECK_ERROR(readBytes(ctx, &round1PublicPackage->identity.ptr, round1PublicPackage->identity.len));

    // read frost package
    uint32_t frostPackageLen = 0;
    CHECK_ERROR(readUint32(ctx, &frostPackageLen));
    if (frostPackageLen > UINT16_MAX) {
        return parser_unexpected_value;
    }
    round1PublicPackage->frostPackage.len = (uint16_t)frostPackageLen;
    CHECK_ERROR(readBytes(ctx, &round1PublicPackage->frostPackage.ptr, frostPackageLen));

    // read group secret key shard encrypted
    CHECK_ERROR(parseMultiRecipientBlob(ctx, &round1PublicPackage->groupSecretKeyShardEncrypted));
    // read checksum
    CHECK_ERROR(readUint64(ctx, &round1PublicPackage->checksum));

    return parser_ok;
}
