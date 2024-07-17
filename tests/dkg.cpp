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
#include "gmock/gmock.h"
#include "hexutils.h"
#include "keys_def.h"
#include "rslib.h"
#include "utils.h"

using namespace std;

TEST(DKG, Round1) {
    // Given a privateKey check the fields from the Identity
    // TODO: the provided privateKey is derive using m/44'/1338'/0'/0'/0'
    // and it's shared between signingKey and decryptionKey. Check if this should be changed
    // to use a hash(privKey, personalization) for each key
    uint8_t serializedIdentity[128] = {0};
    uint8_t privkey_zemu[KEY_LENGTH] = {
        0xe8, 0x0d, 0xfa, 0x7e, 0xa0, 0x47, 0xb1, 0xe2, 0x10, 0xad, 0x70, 0x58, 0x63, 0xed, 0xa6, 0xa9,
        0x96, 0xc9, 0x7a, 0x36, 0xa0, 0x43, 0xee, 0x53, 0xde, 0x70, 0x6b, 0x63, 0x9c, 0x4b, 0x12, 0x57,
    };
    ASSERT_EQ(privkey_to_identity(privkey_zemu, serializedIdentity), parser_ok);
    // Identity = [verificationKey(32) |  encryptionKey(32) | signature(64)]
    const string verificationKey = toHexString(serializedIdentity, 32);
    const string encryptionKey = toHexString(serializedIdentity + 32, 32);
    const string signature = toHexString(serializedIdentity + 64, 64);

    EXPECT_EQ(verificationKey, "510338227d8ee51fa11e048b56ae479a655c5510b906b90d029112a11566bac7");
    EXPECT_EQ(encryptionKey, "1a213433ba962f813aa71fd3f9f75a768f80505011fe0410ac6539860409417f");
    EXPECT_EQ(signature,
              "fb83e3b749e44b07db79b722dbcaebbae231ec180733768ddc01d1ebbfaf7b2e6c32d81e7a6af022354ab514a0e7d9b4fbac7ae86a74e"
              "562434ba820d618050a");
}

TEST(DKG, Round2) {
    const string round1PublicPackage =
        "72510338227d8ee51fa11e048b56ae479a655c5510b906b90d029112a11566bac71a213433ba962f813aa71fd3f9f75a768f80505011fe0410a"
        "c6539860409417ffb83e3b749e44b07db79b722dbcaebbae231ec180733768ddc01d1ebbfaf7b2e6c32d81e7a6af022354ab514a0e7d9b4fbac"
        "7ae86a74e562434ba820d618050a8700000000c3d2051e029ee5183c7710cf13dd1f8faf379d6b75b1deff16bfbff7290246dbaad5e167983cd"
        "0fa8a17eae49e14357f699ccebbba4eab077cac461adff6af443df35493a240091b2b1e0b81f979cf38f518c3f9d37e2904b52a48996114cd84"
        "c307bdb288cc03d7b45f8686658b7fa281958d8cd6c55a428b4f966fdcc2d19ad7c6cb6c7808b446304b81395ef7817a6fd9f9d10e923fec4eb"
        "34159908058b22003c93ff457020000001ab38666c843ea4cf437e4d36e898cc3368ad019beed67e81c6e62f298fe66933325afb3f2335d518d"
        "b99ed9cbeafdd6fdd413a90b8eb871394021778fe508e930000000cddfdea098fce8a093d553edeb1087dca04558313282b2c91e19c99886d2b"
        "ea78fb0f4b6fdaaa63317981a7f5d54590f7589855f05a5226d";

    uint8_t serializedPublicPackage[500] = {0};
    const uint16_t publicPackageLen =
        parseHexString(serializedPublicPackage, sizeof(serializedPublicPackage), round1PublicPackage.c_str());
    parser_context_t ctx = {.buffer = serializedPublicPackage, .bufferLen = publicPackageLen, .offset = 0};

    Round1PublicPackage_t publicPackage = {0};
    ASSERT_EQ(parseRound1PublicPackage(&ctx, &publicPackage), parser_ok);
}
