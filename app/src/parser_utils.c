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
#include "parser_utils.h"

#include "coin.h"
#include "crypto_helper.h"
#include "zxformat.h"
#include "zxmacros.h"

parser_error_t _toStringBalance(int64_t *amount, uint8_t decimalPlaces, const char postfix[], const char prefix[],
                                char *outValue, uint16_t outValueLen, uint8_t pageIdx, uint8_t *pageCount) {
    char bufferUI[200] = {0};
    if (int64_to_str(bufferUI, sizeof(bufferUI), *amount) != NULL) {
        return parser_unexpected_value;
    }

    if (intstr_to_fpstr_inplace(bufferUI, sizeof(bufferUI), decimalPlaces) == 0) {
        return parser_unexpected_value;
    }

    if (z_str3join(bufferUI, sizeof(bufferUI), prefix, postfix) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    number_inplace_trimming(bufferUI, 1);

    pageString(outValue, outValueLen, bufferUI, pageIdx, pageCount);
    return parser_ok;
}
