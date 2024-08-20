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
#include "dkg.h"

#include <os_io_seproxyhal.h>

#include "apdu_codes.h"
#include "crypto.h"
#include "keys_def.h"
#include "zxerror.h"

void handleDKGGetIdentity(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    const zxerr_t err = crypto_fillIdentity(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    *tx = IDENTITY_LEN;
    THROW(APDU_CODE_OK);
}