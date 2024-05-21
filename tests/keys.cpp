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
#include "gmock/gmock.h"

#include <vector>
#include <iostream>
#include <hexutils.h>
#include "parser_txdef.h"
#include "keys_def.h"
#include "crypto_helper.h"
#include "rslib.h"

using namespace std;
struct IronfishKeys {
        string spendingKey;
        string spendAuthorizationKey;   //ask
        string proofAuthorizationKey;   //nsk
        string authorizing_key;         //ak
        string nullifier_deriving_key;  //nk
        string viewKey;                 //full viewing key (FVK)
        string incomingViewingKey;      //ivk
        string outgoingViewingKey;      //ovk
        string publicAddress;
};

string toHexString(const uint8_t* data, size_t length) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        hexStream << std::setw(2) << static_cast<int>(data[i]);
    }
    return hexStream.str();
}

// Generated using ironfish SDK (public_address_generation)
vector<IronfishKeys> testvectors {
    // Keys from Zemu tests
    {
        "80f29748c82d1d1c25dad6762a097bde5475ccd2bb67fd7e05f2ae1e964b1257",
        "fa8d9f48def148d99394a83b8725310d29e9e4cddfa5facfcb783a64e00c5304",
        "71c815e1b4713712d3fabd2c9e9fe9d4b250660e53eaeb6b27c838912aee1606",
        "ce113136c9b93cefbe3358e6b5a9e96867bd6cf3d399e4f7ccdb3467ebbfbf0d",
        "f0e8ca3ac4e83c26c4cc845d5fbf808f2ef9130b00c4ca275735f66c4c5f675a",
        "ce113136c9b93cefbe3358e6b5a9e96867bd6cf3d399e4f7ccdb3467ebbfbf0df0e8ca3ac4e83c26c4cc845d5fbf808f2ef9130b00c4ca275735f66c4c5f675a",
        "b00aa50592dffe73236a53bed8363be672ab267edee03946eb3d5f3b2c6f7501",
        "80215c397c1b80ed3cebc4045ffe788a02d03b284b332a26b2b3c126881d87a7",
        "673a8bfd38f977ea1e511a40656d2a7a832252bc40c14c2760ad90647d55b2ef"
    },
    // ---------------------------------------------
    {
        "f7d585b63ac9870c96280d7979b9aedf5d7cb35e2a0f413b3509c483d7e6be53",
        "8543934d3f6bea6d685862522639118cf4615af741beaa94c6d5dd034664100e",
        "228b9f4f8a69c5bb973e4ce7b21cfd3e84e83302b505ca9083355af96373ee09",
        "0d7c752dafff93e5fde725660f23e03591d6dee611c93edd2ece4cce93ec1b97",
        "88661680242923e927658a21c1e6fbd05c882ae79b8356bccc3f0db9d70fb59d",
        "0d7c752dafff93e5fde725660f23e03591d6dee611c93edd2ece4cce93ec1b9788661680242923e927658a21c1e6fbd05c882ae79b8356bccc3f0db9d70fb59d",
        "e1cb9e11c398d78938b561f737baa4b3f2083e356c8c33dced7615959f218f04",
        "3027dc497b8ac048b6511e8ec395f8ce9c642ffe5aafbfe20d10666c74ce393f",
        "a555d780f7ec15dc33bfbbfb8ddc192e5d8fb7eefc85da6bc0ebd08a0ee6b2b7"
    },
    {
        "3e99ca3ace3e7ccd021f8a37eecf3e42ad49983df7e44d0d9b38e0b320744001",
        "018bf86daf171e6bcd0aa73cbb770695dbbb93170629891a4e132c21a940a50b",
        "d7bd7730674dd8a9b08ea60529fc1845b93460c0dccb2c9edb7022998c1b5902",
        "e0a62456c98b02278de9907751ed41c71cfde877830b5be7c89f778e97030eab",
        "957941fe5f0b405e8b836cd2fbba0a7fc66af1b0dfa4df95dea834f4232e30e6",
        "e0a62456c98b02278de9907751ed41c71cfde877830b5be7c89f778e97030eab957941fe5f0b405e8b836cd2fbba0a7fc66af1b0dfa4df95dea834f4232e30e6",
        "42dcf21b58d493ae2455d89dd795ecdc5929cf459f5e5fb5f4a193359f4abb07",
        "6ac19c463f7f535a54be2b19fcf47d2a518933d180d149794caacbfd1b797316",
        "c7acfb1bfc07de1acd9be25e0676b9ae45da120accef8c255bd67637277eb64e"
    },
    {
        "446f9a5074219cd14b444e2644b9ec8df6daf54cc74959bef6baa828eb712f04",
        "c46dee4d3f8ea62e133c21f9bf1ff20bac68d0f5ec089d252a08f1176f5d5107",
        "70970d2df499da4b2f6070a511880ae80b464d6cb84d437ebd0001f54b60ee0d",
        "430a952593a443793f1da5728ff8a857eb045728209fd838e75dd96e540702d6",
        "d8c11802fbe9bcfee3f695017c92429f0815e5d03108366de2c9b791988596b6",
        "430a952593a443793f1da5728ff8a857eb045728209fd838e75dd96e540702d6d8c11802fbe9bcfee3f695017c92429f0815e5d03108366de2c9b791988596b6",
        "c120f8d342370a05ac09374374ebabf49f60c194082efabcaf47696dde661804",
        "6eea8fd4a905afbb48a962079ea0f6656da4ceeb57aad8eb14670cf355229711",
        "9a657eb4e8d60b01389bafdee77cb70fa9a5f50b21707f8bf409e7447406cf3a"
    },
    {
        "e9050dc4d9e4c3b97479629c24c124c9e53989e52e4045e7b279399e0ccf79c5",
        "5cce718949b9004c25f32e8aff55d3ec3220896f9131ceeea3cf11579aa4f907",
        "827a2f11c0261a348672691a71558c7debdf1054f87b0d1fd5651c250299830d",
        "6d2d0f261649fce1588d4197da214ec6ddc3c6f5df87f6d004b5abc9e9ab6b81",
        "a6004607769de6d712105e4942539ef2156da39a96b5005d9e196eb8c90e67b9",
        "6d2d0f261649fce1588d4197da214ec6ddc3c6f5df87f6d004b5abc9e9ab6b81a6004607769de6d712105e4942539ef2156da39a96b5005d9e196eb8c90e67b9",
        "47deb2137b12bd2b8162ff9bb07bb22a482a3f9021981ddc02d7134a2fc0b702",
        "82c40a23b5f12651bc1e70af7b50c637c28a3181f36027c5ff18f8556eea1fbd",
        "63ee1aca622465a686f628ec0e6619e052bd67ccbc750e1f9bffbeab986845cc"
    },
    {
        "0d0eb0d44dfd6e61cbf18089d583930f014dc3e0f76b19eeef9caf6b94b6eb05",
        "b9ff2224a7026b7ab12b580ee4d88ee036090ebaf122b1ac4b1e4e093bb4880c",
        "dd6b08b50f8ebbe6b29e4c232460180cc70838c7754c50d7fd22523814d80c05",
        "280d624f5e6284ccbc898fecdf1e5ec38968c0877d40669a153b7043f9716c28",
        "f1750cb27b1da3fa45ad382061923f5d348a497fd69bf3b6db5199c34bd0d28a",
        "280d624f5e6284ccbc898fecdf1e5ec38968c0877d40669a153b7043f9716c28f1750cb27b1da3fa45ad382061923f5d348a497fd69bf3b6db5199c34bd0d28a",
        "62a2c2a34c1c7ce05e86d44e9ab13e6cfe3d522856d0474fa7e180eb97d57204",
        "a753c8408c97ae42d7ac7ad720d8980c66ea73ace28160a98d387571dca5c670",
        "54096ecf6b46184072354378d0de54fc11f3bfdc576c1f26e6cc2709d245c31e"
    },
    {
        "3ae936117f25408eb108937955d012e9a95ede5bb2c6c0b60c11da0d82807ce9",
        "1347a988571d151f8657192e533b1e6d5dcef21cff9257a4e38e06115fd87c0b",
        "11d7336d65de29c4017a8154e256d463e8ff01f92aabaffc199c46d36c917804",
        "b503b50f2c4e1cbb121d73ebb0d38f3b356984fda8677241b424b61c4812104f",
        "d75967158476ac70d4eefda8fe5c2be55e1e6d5aa7a224b22d60a0a0e2ea2c5d",
        "b503b50f2c4e1cbb121d73ebb0d38f3b356984fda8677241b424b61c4812104fd75967158476ac70d4eefda8fe5c2be55e1e6d5aa7a224b22d60a0a0e2ea2c5d",
        "d67a742964eb69a554c3eb12e1d3a4a841c821cebb1c57ea2493db87aec51b00",
        "60411ee7088e55957712bcbe08755fca1ae1b44d6e4c38264816580a27e54398",
        "99cf7bc51f24387f641ef2a364fcb1a555b3745af4435519b81fa7920c473e9a"
    },
    {
        "17e9648c23f2cb3990b829418791994aa6f9c579f398bcd1fb0d61ec7e880f1f",
        "b30e18d131f4415f15d056f013ddee6a60454f860769998279de1d1fcc164303",
        "886031672c598d98377067b9f06312cc6499fd2dd660b0e34dfed053ff5e4905",
        "c62c4ba34dde66e72eea22680a9d4f3b17457784678d9bb68ddef96dcc0d7116",
        "ddc84ff0e62603a5d5dcdcee11d2fba7c74bf72ba9f150f83bc52c0afb609995",
        "c62c4ba34dde66e72eea22680a9d4f3b17457784678d9bb68ddef96dcc0d7116ddc84ff0e62603a5d5dcdcee11d2fba7c74bf72ba9f150f83bc52c0afb609995",
        "08a7046d96b88f679828140f7616afc1ce358e99f404448b47cd8adf1a04ba06",
        "439cb16c382b372cf5c1d050560e7cf037c95056fcd55970d7108c39a994dfcc",
        "6b815a83b050a3cd887904b39779885abde13f17d191a59981aaba9c2eba50cc"
    },
    {
        "4b1959fcdff3eb9ade5b424661d815a214fdd29586ab58fa8cc535ce96794af2",
        "7dacf24608f647cf225b901953cfa796dd5f207c02e045b76157d85eed710b0b",
        "a413b47bcff4498522d09d365416448eee59e74fa610d163ce7e690d394d0f0c",
        "cfe5afe860bfa33e23b80d08b076ab8f84502c4f6331863f4131bc6e0fd6e953",
        "ea0febe6d6c839c599f795dbc848576826cfe35b8a7777e1a808b11bc18f1b65",
        "cfe5afe860bfa33e23b80d08b076ab8f84502c4f6331863f4131bc6e0fd6e953ea0febe6d6c839c599f795dbc848576826cfe35b8a7777e1a808b11bc18f1b65",
        "405e917236693eacbf2a3cc4f6630282788df08d896764d81c987cd105319002",
        "a588913581be7b6ea2b1103a1d6f5d95e7e383bb855f7be3273f62f7f0a4e76c",
        "692a6f1be6f63649aa94869211e47002657bb2023156e53c6387f45fe50a5fa3"
    },
    {
        "0e9be9047b4305650fb7baa323241ce645af56667d3e73763eba2a94e4b10d0c",
        "77e6492f0bd0abfe835d842a38b7b77adb306e5a8f2d06bf9797835a42ac440e",
        "0e9ec263f816014cd189d5a5031055e178dd893e8f16e6b4112640796aa3c905",
        "a4a41eb4bd4f053739ba16be6910af8dff63d65c24ca61f7669f9fcb379e2fd5",
        "84e3a6d2bedb8e2b9c3c628465c90a5ddacf10ee65afd36472b65821b7b4620b",
        "a4a41eb4bd4f053739ba16be6910af8dff63d65c24ca61f7669f9fcb379e2fd584e3a6d2bedb8e2b9c3c628465c90a5ddacf10ee65afd36472b65821b7b4620b",
        "8f783059c5946b41f60c817e49c2b3ef9becd42f9372bf9f75f9a8d3ba9d8501",
        "a170e5e62d4c24e7f235b9c6f383900e8c01d5cbe0b3674369fa615fbd2b8442",
        "1a12e36a6c75464775de2f8118bf2f3394b893c6cfdfcfec0872dec45e52f6a8"
    },
    {
        "19916c7d5f1bf61b79c7a2d73f7e02e409bb08c9e557facffc3c304068b46a14",
        "4a447cb0c94c6359b7810b83300d24703bedb882a158618717146b91d70a480e",
        "ef98e6f74a7651d87d1803c870b533cbbedd422be7336ee3c87143ddec603403",
        "a63c3bc78ade1f1d3964c9020646d111e028d78e7ff9457a29ef7e920b448c3d",
        "110474227f16391810502261b7689395b54c2839b9e52dd8a6d6c43fe0d9bc63",
        "a63c3bc78ade1f1d3964c9020646d111e028d78e7ff9457a29ef7e920b448c3d110474227f16391810502261b7689395b54c2839b9e52dd8a6d6c43fe0d9bc63",
        "ea0540eba7a065d10c11c254cbe6790829119eb0bf746a1813df3248631c6403",
        "96cb603c147eab01785114d48773440a2196ac7e5b7a91902a8ede22f5b5af23",
        "131d303b31adaaad0aec1ae5914a2b0ef758145e26c0fc746c6b314ead7b0f4e"
    }
};


TEST(Keys, SpendingAuthorizationKey) {
    for (const auto& testcase : testvectors) {
        keys_t keys = {0};

        // Read spendingKey from testvectors
        parseHexString(keys.spendingKey, sizeof(keys.spendingKey), testcase.spendingKey.c_str());

        // Compute ask and nsk
        ASSERT_EQ(convertKey(keys.spendingKey, MODIFIER_ASK, keys.ask, true), parser_ok);
        const string ask = toHexString(keys.ask, 32);
        EXPECT_EQ(ask, testcase.spendAuthorizationKey);

        ASSERT_EQ(convertKey(keys.spendingKey, MODIFIER_NSK, keys.nsk, true), parser_ok);
        const string nsk = toHexString(keys.nsk, 32);
        EXPECT_EQ(nsk, testcase.proofAuthorizationKey);

        // Compute ak and nk
        generate_key(keys.ask, SpendingKeyGenerator, keys.ak);
        const string ak = toHexString(keys.ak, 32);
        EXPECT_EQ(ak, testcase.authorizing_key);

        generate_key(keys.nsk, ProofGenerationKeyGenerator, keys.nk);
        const string nk = toHexString(keys.nk, 32);
        EXPECT_EQ(nk, testcase.nullifier_deriving_key);

        const string viewKey = ak + nk;
        EXPECT_EQ(viewKey, testcase.viewKey);

        // Compute ivk and ovk
        computeIVK(keys.ak, keys.nk, keys.ivk);
        const string ivk = toHexString(keys.ivk, 32);
        EXPECT_EQ(ivk, testcase.incomingViewingKey);

        ASSERT_EQ(convertKey(keys.spendingKey, MODIFIER_OVK, keys.ovk, false), parser_ok);
        const string ovk = toHexString(keys.ovk, 32);
        EXPECT_EQ(ovk, testcase.outgoingViewingKey);


        ASSERT_EQ(generate_key(keys.ivk, PublicKeyGenerator, keys.address), parser_ok);
        const string address = toHexString(keys.address, 32);
        EXPECT_EQ(address, testcase.publicAddress);
    }
}
