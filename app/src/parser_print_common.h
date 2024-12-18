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

#include "parser_common.h"

#ifdef __cplusplus
extern "C" {
#endif

parser_error_t printAmount64(uint64_t amount, uint8_t amount_decimals, const char *symbol, char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount);
#ifdef __cplusplus
}
#endif
