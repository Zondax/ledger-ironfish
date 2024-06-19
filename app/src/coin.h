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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// #{TODO} ---> Replace CLA, Token symbol, HDPATH, etc etc
#define CLA 0x59

// This instruction will work for requesting any of the sapling keys
#define INS_GET_KEYS            0x01

#define HDPATH_LEN_DEFAULT      3
#define HDPATH_0_DEFAULT        (0x80000000u | 0x2c)   // 44
#define HDPATH_1_DEFAULT        (0x80000000u | 0x53a)  // 1338

#define SECP256K1_PK_LEN        65u

#define HASH_LEN                32u
#define REDJUBJUB_SIGNATURE_LEN 64u

#define SK_LEN_25519            64u
#define SCALAR_LEN_ED25519      32u
#define SIG_PLUS_TYPE_LEN       65u

#define ED25519_SIGNATURE_SIZE  64u

#define PK_LEN_25519            32u

typedef enum {
    PublicAddress = 0,
    ViewKeys = 1,
    ProofGenerationKey = 2,
    InvalidKey,
} key_kind_e;

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER                "IRON "

#define MENU_MAIN_APP_LINE1        "Ironfish"
#define MENU_MAIN_APP_LINE2        "Ready"
#define APPVERSION_LINE1           "Ironfish"
#define APPVERSION_LINE2           "v" APPVERSION

#ifdef __cplusplus
}
#endif
