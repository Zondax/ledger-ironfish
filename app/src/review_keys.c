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

#include "review_keys.h"

#include <stdio.h>

#include "actions.h"
#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "keys_def.h"
#include "os.h"
#include "view.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"

zxerr_t getNumItemsPublicAddress(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    // Display [public address | path]
    *num_items = 2;
    return zxerr_ok;
}

zxerr_t getItemPublicAddress(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Address");
            const char *address = (const char *)G_io_apdu_buffer;
            pageStringHex(outVal, outValLen, address, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "HD Path");
            char buffer[200] = {0};
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            break;
        }

        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}

zxerr_t getNumItemsProofGenerationKey(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    // Display [ak | nsk | HD path]
    *num_items = 3;
    return zxerr_ok;
}

zxerr_t getItemProofGenerationKey(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "AuthKey");
            const uint8_t *ak = (const uint8_t *)G_io_apdu_buffer;
            formatBufferData(ak, KEY_LENGTH, outVal, outValLen, pageIdx, pageCount);

            break;
        case 1:
            snprintf(outKey, outKeyLen, "ProofAuthKey");
            const uint8_t *nsk = (const uint8_t *)G_io_apdu_buffer + KEY_LENGTH;
            formatBufferData(nsk, KEY_LENGTH, outVal, outValLen, pageIdx, pageCount);

            break;
        case 2: {
            snprintf(outKey, outKeyLen, "HD Path");
            char buffer[200] = {0};
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            break;
        }

        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}

zxerr_t getNumItemsViewKey(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    // Display [viewKey | ivk | ovk | HD path]
    *num_items = 4;
    return zxerr_ok;
}

zxerr_t getItemViewKey(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                       uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "ViewKey");
            const uint8_t *viewKey = (const uint8_t *)G_io_apdu_buffer;
            formatBufferData(viewKey, 2 * KEY_LENGTH, outVal, outValLen, pageIdx, pageCount);
            break;
        case 1:
            snprintf(outKey, outKeyLen, "IVK");
            const uint8_t *ivk = (const uint8_t *)G_io_apdu_buffer + 2 * KEY_LENGTH;
            formatBufferData(ivk, KEY_LENGTH, outVal, outValLen, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "OVK");
            const uint8_t *ovk = (const uint8_t *)G_io_apdu_buffer + 3 * KEY_LENGTH;
            formatBufferData(ovk, KEY_LENGTH, outVal, outValLen, pageIdx, pageCount);
            break;

        case 3: {
            snprintf(outKey, outKeyLen, "HD Path");
            char buffer[200] = {0};
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            break;
        }

        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}

void review_keys_menu(key_kind_e keyType) {
    const review_type_e reviewType = keyType == PublicAddress ? REVIEW_ADDRESS : REVIEW_GENERIC;

    void *getItemFunction = NULL;
    void *getNumItemFunction = NULL;

    switch (keyType) {
        case PublicAddress:
            getItemFunction = getItemPublicAddress;
            getNumItemFunction = getNumItemsPublicAddress;
            break;
        case ViewKeys:
            getItemFunction = getItemViewKey;
            getNumItemFunction = getNumItemsViewKey;
            break;
        case ProofGenerationKey:
            getItemFunction = getItemProofGenerationKey;
            getNumItemFunction = getNumItemsProofGenerationKey;
            break;

        default:
            break;
    }

    view_review_init(getItemFunction, getNumItemFunction, app_reply_cmd);
    view_review_show(reviewType);
}
