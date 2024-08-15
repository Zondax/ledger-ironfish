/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
 *   (c) 2016 Ledger
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

#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "app_main.h"
#include "coin.h"
#include "crypto.h"
#include "review_keys.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"
#include "rslib.h"

static bool tx_initialized = false;
static bool heap_initialized = false;

void extractHDPath(uint32_t rx, uint32_t offset) {
    tx_initialized = false;

    if ((rx - offset) != sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    memcpy(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;
    if (!mainnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];
    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            return false;
        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            tx_initialized = false;
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            tx_initialized = false;
            return true;
    }

    THROW(APDU_CODE_INVALIDP1P2);
}

__Z_INLINE void handleGetKeys(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);
    if (G_io_apdu_buffer[OFFSET_P2] >= InvalidKey) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    const key_kind_e requestedKeys = (key_kind_e)G_io_apdu_buffer[OFFSET_P2];

    // ViewKey will require explicit user confirmation to leave the device
    if (!requireConfirmation && requestedKeys == ViewKeys) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    zxerr_t zxerr = app_fill_keys(requestedKeys);
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    if (requireConfirmation) {
        review_keys_menu(requestedKeys);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = cmdResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSign(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSign\n");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    tx_context_sign_tx();
    const char *error_msg = tx_parse();
    CHECK_APP_CANARY()
    if (error_msg != NULL) {
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handle_getversion(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx) {
    G_io_apdu_buffer[0] = 0;

#if defined(APP_TESTING)
    G_io_apdu_buffer[0] = 0x01;
#endif

    G_io_apdu_buffer[1] = (LEDGER_MAJOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[2] = (LEDGER_MAJOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[3] = (LEDGER_MINOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[4] = (LEDGER_MINOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[5] = (LEDGER_PATCH_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[6] = (LEDGER_PATCH_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[7] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[8] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[9] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[10] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[11] = (TARGET_ID >> 0) & 0xFF;

    *tx += 12;
    THROW(APDU_CODE_OK);
}

void handleDKGRound1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    // Round 1 - 2 participants - 2 min participants
    // Encrypted Secret Package: 0fed8016dbed46190b94eb2bc9d941ff41ec8fc5cb7b77f318fdd3b08755523801000000586d870b963e731f47c7fb4ed16596a89611443994d36055ce33a080e7e7b39ebc000000f7465ea20f37accb68f2c6cdf98757c9fca0be73c48ab28e31e8832efe5854187685346d9b010ab924c5b2adf22412451e7e930be02f033d42cac93dc58059310614df76357b6f6eed84f153f3b81241b13343566b0672cf416843c5c14be66590abf6074943e87d26459f536fdd8c8e25d62627e85f72198c29bd00cb092a82934a2814c6ff132b50581ab97eb0a12633088d50544c8a15615f45d1d01ecebc101c080ff63622fb497234cbdce0957d5f71ddbb6e50ce537d8d129a
    // Public Package: 723670b493c9b5de4b59ba7210a62abc9e60fcf7237956b386ecae22e48c8bdfdc896c4f3fc34f57b68d37619bc9d0236835046ca5ca8c43926a047e9ca4f60045a4e9ac96b5788777f9262b29ba01158170c87a0e4ef0ca412e5af4d8f228268939115ab6705764567c94072bcf9f861cb0beaaa458d115685dba7f3e24473a0c8700000000c3d2051e0264888d42407fa2c7c88c9efe20ed2304004077749050cfcf610e148a91bfd7972f609649b5c484741824f3c50a4b203abebded789de0074e030fb678d962285c40a7d3c66908dc27fd0518201b003588f6aae8e41deae327606c46cc7d0fe831e2c5b632795c376d1915feebbfbf8348c87f6187f800cbfe76aeea29c91ccb2c0eba23874ac37cd6ef4a1f712ca085c87a3509819919f5d9ef3da54a702fb77c56020000001e0b07fef0d981d810ded9f5436a3a00ad8f0e8158e1fa6fb77379d36d210084fa08ed3dae153bd1351de50d86df2a2661b13d7592ad6b9fd68731b54a2b8f5330000000cb24dda2cfd5cecff34382da38a1b103dffd8ad2c6a9d4503c0496536d8b172e5f5a6bcedfd13e5d4649205f6fb3bbec8611fa3b79b190b1

    // Encrypted Secret Package: 4aebad1fa44d3bff47295af296b715668ecfcc8eb7edc69ce014546c64e95d00010000001ce7b85bfd3511ef287e93ca7c9ed3a4f6c6b944d39ccbb030c233e2774aacfabc0000004ee6f9a63484a23102bfe7412590ee525a74a943f593eb3fe206b81fa1bfbcad6614d6da077fd029db1d1af4b1f06644f4c182717f924bcaa9de2a6d169beb7bf1b73d9784b52264c320c76d4f3e4ffe1e001a8957f1a9439c0356bf8a4cdba232d3a6bec825a1ec57ff3e4facb2636b5523ae4c2619e131e79c8f3eccab71f4f71c843c133781af78245e9329fe2e80f03e58b0010724909e5770f0a4f0d663bb7f469b06f984a15ecf9c4d4b50866c8d6c97fabbb0712f81099244
    // Public Package: 723670b493c9b5de4b59ba7210a62abc9e60fcf7237956b386ecae22e48c8bdfdc896c4f3fc34f57b68d37619bc9d0236835046ca5ca8c43926a047e9ca4f60045a4e9ac96b5788777f9262b29ba01158170c87a0e4ef0ca412e5af4d8f228268939115ab6705764567c94072bcf9f861cb0beaaa458d115685dba7f3e24473a0c8700000000c3d2051e0231f4cc5379a17eb307ec7b3c286ee58fb40dc6877e9afa0343500f22d1b4211083b96e777ca1698df08559ad6ee5f22b3861cb5568ddecdae99080b217fdb2c040e3393d9e0efc4f637b8952e59302d2d13e14e9e0423a526c7e2f4a42b97f6432bcd61765dee2a255f826b105f4b37b595288b0cd127eb2f6ceb677f8849b820d6fe6f4fb9165adcdc7fa079de7f6bdeda7a47e9cb8a81d5d6abe6e5a48672f550200000043757bd3f0b505b0daa8912c64d319d105d1c5dc294b191c92774410c264a98b87386edc0046c9e644c14d8335fa7951be7f9d19d8347b29973e4c76a1fabad630000000f1fe79d6fbb57df9299d3714c397d750a14e61be81c23fb45eb548f86ce17e97562ef3d9b27f7539d87ee67d5961f7ee8611fa3b79b190b1

    zemu_log("handleDKGRound1\n");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    tx_context_dkg_round_1();
    const char *error_msg = tx_parse();
    CHECK_APP_CANARY()
    if (error_msg != NULL) {
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    // TODO implement me
    /*const zxerr_t err = crypto_fillIdentity(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    *tx = IDENTITY_LEN;*/
    THROW(APDU_CODE_OK);
}

#if defined(APP_TESTING)
void handleTest(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    THROW(APDU_CODE_OK);
}
#endif

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            if(!heap_initialized){
                heap_initialized = true;
                heap_init();
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx);
                    break;
                }

                case INS_GET_KEYS: {
                    CHECK_PIN_VALIDATED()
                    handleGetKeys(flags, tx, rx);
                    break;
                }

                case INS_SIGN: {
                    CHECK_PIN_VALIDATED()
                    handleSign(flags, tx, rx);
                    break;
                }

                case INS_GET_IDENTITY: {
                    CHECK_PIN_VALIDATED()
                    handleDKGGetIdentity(flags, tx, rx);
                    break;
                }

                case INS_DKG_ROUND_1: {
                    CHECK_PIN_VALIDATED()
                    handleDKGRound1(flags, tx, rx);
                    break;
                }

#if defined(APP_TESTING)
                case INS_TEST: {
                    handleTest(flags, tx, rx);
                    THROW(APDU_CODE_OK);
                    break;
                }
#endif
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw & 0xFF;
            *tx += 2;
        }
        FINALLY {
        }
    }
    END_TRY;
}
