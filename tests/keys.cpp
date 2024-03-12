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
        string spendAuthorizationKey;
        string proofAuthorizationKey;
        string authorizing_key;
        string nullifier_deriving_key;
        string viewKey;
        string incomingViewingKey;
        string outgoingViewingKey;
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
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "02dddb7d511f89769aaaefa94c08a0cc64f8f962fb1484fb58f24e3b6191a813",
        "0123383cde1dc45f757e9852e650b38d222563386c55335b322ca8aec65e4bda",
        "94c0bf0aff4653756184e7564d6bace42ba28ded17cb6969bd3db2b5bb813183",
        "be0383711ddcb0beaa8b7ef72fc20f1798f813e3008bb9d704a5da590d967ed7",
        "94c0bf0aff4653756184e7564d6bace42ba28ded17cb6969bd3db2b5bb813183be0383711ddcb0beaa8b7ef72fc20f1798f813e3008bb9d704a5da590d967ed7",
        "03171a55bcdd54018c224a261cdc99badce181a60ba4d4f6be401dc9841e07bb",
        "efd8642e69a4bf55196ed4d4528fcf50a842319284332f708fc1254c8358ae1e"
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "029b909181abb2a48bf09a6274179836eb125cb7b58ec9c049e2cc242b95dc77",
        "0af942f4f07578aa419d06ab11580238211e4ed5e78e21df08c26eb5d2c79cec",
        "46095954bc6e220bceb8e9dd92ad551c241df5fc78575e09b457a3b5c7ccfa59",
        "71a7ec7feae16363b6daff256f8033778fdff4404af51f4702f6bb3723441fc3",
        "46095954bc6e220bceb8e9dd92ad551c241df5fc78575e09b457a3b5c7ccfa5971a7ec7feae16363b6daff256f8033778fdff4404af51f4702f6bb3723441fc3",
        "01e8b953ebef20c9df67ac99075f7fff3bc2f1ca93822299d6f6247617e2efd4",
        "1824f96c702f47b199457273994c35d7e9343bc1a8aff9b4037fdd06d0b3a660"
    },
    {
        "71af0f431ad2b93fdc9bbe907b03314f607c09461c421a2873d4807f8841bbc7",
        "07e7ec847e4a0eb7bcdf8682568cac4aef8189d379e96154eb170289d1bb50fb",
        "0c76463c6c683187511a59c9a0bb72a398656f35aaefc4fb03509c513d09f960",
        "283e16fc078a556b2be63e7f4661474cbffa5397ececee7376e144abb5aff71e",
        "f68210181abe9d2d1178773eeda7d869f619db56b6ed928b79474b532158d267",
        "283e16fc078a556b2be63e7f4661474cbffa5397ececee7376e144abb5aff71ef68210181abe9d2d1178773eeda7d869f619db56b6ed928b79474b532158d267",
        "035c7bcf0c6f8ffd2c5afd44fda50eda233f0b2b9747154d66fe2a827a35a78d",
        "86be13371588a5e3803dc57678578aba2877f4b0212c994727197df2307d9691"
    },
    {
        "36dea1c88f60c02b01ab6a0494e16e6d939b44a2a3dd75e9e0360399dc8650f4",
        "0dbe2541a65fe65aa63170bb687b53edcd66173cd1850bb8e5a42b232a2b09db",
        "04eae190efdd076715dfd439acf64228e14e0fc96da8bf131eb71002c0d3233e",
        "c8117bd8d872097494bff6ce631e7d84bc5ab4113d2a04eeb24f1717fad833e1",
        "90a7eb4c20f5993c791de70d3da81501da041744c27a5ad135b3ea1618870330",
        "c8117bd8d872097494bff6ce631e7d84bc5ab4113d2a04eeb24f1717fad833e190a7eb4c20f5993c791de70d3da81501da041744c27a5ad135b3ea1618870330",
        "07d77856b0a3d2a7b6fdba054beeb199d7ddd9dd66ad3e6287f00b405b1535ec",
        "25f0fa2b575874eb93644e81c44c2631efe5a1ab5d1ab7258060847670367068"
    },
    {
        "b4334a7fb7f3795906688fef68dbbaf714739691fca288f722e54136ffa0d327",
        "0cccedb48d345c193a64a2a830277f00a8cf315b8ba3a9073dbb041bf8b6698e",
        "061af229deed0a4e5aa4632b88b6fdf8295163821d0fbf37c876fe3f2a86cd7c",
        "d2ee54d95d8410fe79968df4add0bbb46c7db66c256957b965d8f4295acd1cf1",
        "011abad7ce51e5163e5d46cccfa323d458ffb1c6fafb3bea42cb96df70378870",
        "d2ee54d95d8410fe79968df4add0bbb46c7db66c256957b965d8f4295acd1cf1011abad7ce51e5163e5d46cccfa323d458ffb1c6fafb3bea42cb96df70378870",
        "04f81f076f6d0d3509171033e837e966c48dbdbc85063ffc5ab4053fc7d00839",
        "323d72bcfa2f7b2702744c3253753d0b749849cf3aa4f179e65c7b7617f4b057"
    },
    {
        "994f855e8e49063b1c58e348bdf80f513cb2ea24d4d3b238f77484ede3c2d92a",
        "03f3a7fd902fa5d081fd04fdbd21c61f3434f9264213e19582c1078c45514b03",
        "01fe8df4ca283ac4e921ab95cffead22b9cc26b4144cb18c265a0eb187f4a727",
        "14f9260c82a77d7f171dfd97df572b4103cf91d89c15b55450144c99fb5d9d3e",
        "b430f67ce7fbd4d3a1126b7e339db35fe6060bbe98cbda062118a9fc166213a1",
        "14f9260c82a77d7f171dfd97df572b4103cf91d89c15b55450144c99fb5d9d3eb430f67ce7fbd4d3a1126b7e339db35fe6060bbe98cbda062118a9fc166213a1",
        "047228f8313b24db2ad37a552cc15279dd515d156ac39f57da1a4d4dd40a4a61",
        "c1068c4c44619ac9fa1294475de5f42d1f9257984c7792fdda241d7b127be8c8"
    },
    {
        "b75e9a8a5f24d3299a196cb4b4124a211dd4f253a9d227290b0b3f72313a5532",
        "041f1e202aa64ecb9151272257837b9b06866816246143d5fcd2567bd764d77a",
        "04acf490916df2031404a4b2ecc50f5c43d7d0838a8aef5cbafb370df6467ea6",
        "e616286d0f2729f3fa26a5f4d89fa03214b4310c7f7a40b9ed703361e6b40b3e",
        "98f87650c039a601e875ca924b8fd48a17b443da3ce0536bef019bdc20db2c1b",
        "e616286d0f2729f3fa26a5f4d89fa03214b4310c7f7a40b9ed703361e6b40b3e98f87650c039a601e875ca924b8fd48a17b443da3ce0536bef019bdc20db2c1b",
        "0163e0f0202685ec96529cf5c5edf69327a292f82c77ef3204814c6e939c9b7e",
        "784ffe8b8cd62e7be3e2b0a34e38ec63cd6b9739a2573c312daef3d7bb3ae262"
    },
    {
        "683f1521a8c6f76d4835f87ecee51cf899ec71555102e595e5bc2c8ed6c1ff82",
        "07917c5521adf7d07f284e376312f992ac71721cc162ecae09f5a53726e6b887",
        "080df08692a104f94ce208a328cdbcd9ed0b073d3c850987a4101c64d3c97f6c",
        "c9305843719d27ca9a35bd165651b210a087fe0a6c3e906dbb7e3018ec016e39",
        "cfd751257c062c86b1e4461ed2370ec98dd4f2e7e22331ce315f6ee1c42544c1",
        "c9305843719d27ca9a35bd165651b210a087fe0a6c3e906dbb7e3018ec016e39cfd751257c062c86b1e4461ed2370ec98dd4f2e7e22331ce315f6ee1c42544c1",
        "0428f0f7d4a43973d7535c47adbd16752fd54105ecf1e6e346a1ac029c4ca85b",
        "b4c1fa6741f7250188c42947a9012c0ca7f863695a93b1d71fb22dc063143c77"
    },
    {
        "c81b034031656bfceb51300a0088b012eafe1700b22f115d747e23d5e76f66dd",
        "078e175c2a111900c703685793183696fe8bf0ad341e285179fee178d694129a",
        "0041f378cfc074626c63ff318cf79faf18162c030f8655e36c53890a032e2457",
        "fee8c30df362ec50f8169441c95b860a00c8b9d57f020a9946c54ab47484c026",
        "aa46f2468269142649f58c42a272cbbdf3791c2dc0242c715ccd12acda2ab361",
        "fee8c30df362ec50f8169441c95b860a00c8b9d57f020a9946c54ab47484c026aa46f2468269142649f58c42a272cbbdf3791c2dc0242c715ccd12acda2ab361",
        "04c6e8fc3a669acacc5b0b078125cca65ca63424c06b3ac36565a65280958c3b",
        "c0cf9084ad644b5005fac345a40b38392759194bd7488f434af8ecbac9b6224f"
    },
    {
        "9e0de76b502d8fea848086e90cb776832516e68fa7715758410a11dac33279a5",
        "0590d7a189c8de9fa423dda7cd2c9d7513e47c76ae52f89ce41e01185fe1e6bb",
        "0be98efdb1a394a97922fbc9b687fd984d0db6cd4bba37a00157528fe0ba9b96",
        "f83d80b645d4fda5c5e5b598ce855f96abc8fb7c385a406f8c2d32b1cc4b089b",
        "3fa04bab93e6a17eb3b98b0371ac4c46194b1ab3b0f5472ae76e830e51b068c2",
        "f83d80b645d4fda5c5e5b598ce855f96abc8fb7c385a406f8c2d32b1cc4b089b3fa04bab93e6a17eb3b98b0371ac4c46194b1ab3b0f5472ae76e830e51b068c2",
        "06009065dc3b4eb05b3c238d20e2e6d897a2bd13e0359846c80fc0814b22667e",
        "fa46321b8da3da8282df1f8cdb980be5c9606e55200c110c8b500b330f84ecfc"
    },
    {
        "6171008a41c077d30853dbd4a365d44f5df46e3d84974acf64aec45d3dfa8518",
        "06074714498be4d8c55ca6b25de8ec2be2d4d60edc016f2f339db397a6e06cc6",
        "05b9dfc1859fe50046e6dd85dd496baeee26b7595732c422d2c2bd63eb8daf97",
        "8c3337ccc68bf985094ff4099f40d136662e840adcad8b3e4398ac1c2e3cc30b",
        "a3f9d913b854a7f8bfea0575b5447dad7caeb5384bcf127178ba2bfffe99cfd0",
        "8c3337ccc68bf985094ff4099f40d136662e840adcad8b3e4398ac1c2e3cc30ba3f9d913b854a7f8bfea0575b5447dad7caeb5384bcf127178ba2bfffe99cfd0",
        "0688006785e98dbc7754eff5e8077abbda8e3c731f91ad1a14d69fc5d2627783",
        "ff403d8ab3394b14a1d1dc35c07797755e27a39ad140ab32d046fc8f4636c74c"
    },
    {
        "eb18bb634960b813b7d876fb30fc13fb0786d6a43d4b66622c56665d2fbdaf76",
        "03f29b56313cda55b140e0438564846653cec507c32e605f12de186cb4520214",
        "0d2b2af96208d61b73c29ee85899a9bd1d05d4bf3758c3b56e123eb5787bc338",
        "c1a69c99d0b31e6e1f8084fd19985144a66fa7985614dfc524d2f8d2da293a3a",
        "6356136ea5c85f2c082c42e5db40de5f788eb5cf94992cc8d1f2391d1a646596",
        "c1a69c99d0b31e6e1f8084fd19985144a66fa7985614dfc524d2f8d2da293a3a6356136ea5c85f2c082c42e5db40de5f788eb5cf94992cc8d1f2391d1a646596",
        "05ad202783a7ecbb734eb405831a2a2fe32d6916135451a4e81a825cf6152666",
        "12e5048f89d52d5ed178d5da49e4e7fe6d597bffc855b56c72334f04a462c4d1"
    },
    {
        "6ed609b68227ccdb65f13f4119301fd03f392276aa50e6c5fbc1dd24eb448a6e",
        "0b5ee2715d224575fa47846bf5a6655d2f377c5a42e6e6561b1eef9f181c9909",
        "006d75e2183b7d4152c14a84e88ad44c67707176e0abd9a3c69c3cfe96afcfff",
        "57fe8e536aa4d64b2af0186be557aedabc88bc68471d1f92346bef86af459e10",
        "431cee7e49cf5097ea1c8c56b2e54fa9cdbb63310fac0a2b48a55842ab335e8e",
        "57fe8e536aa4d64b2af0186be557aedabc88bc68471d1f92346bef86af459e10431cee7e49cf5097ea1c8c56b2e54fa9cdbb63310fac0a2b48a55842ab335e8e",
        "033013c1407fecb398c16f144e4bba03efd5cbbf8ceead92f05b57cdd1a6b44c",
        "7ddee0eda90360658301542af1dbb08566db8e4bf0e4d3a8679fa01cf6361799"
    },
    {
        "7b94d9ceffcf2d7a764a16146ce7ce90cd710f717cd9812b8bc85555364c06f3",
        "0c8505f1ef2b5c18d93d95674b531098bc2bba4f18410e6920a0b016ea5009ba",
        "0bb1f088ff779da607dc22968ff239d6878e9f605dd3185861b4679ba0aa5702",
        "aeeeb23556eba42bf22632c7ba5f9871f9b34196f6c87091fb82111668edfd41",
        "36b6122e6dbe1d04f6cfa16edd03f25e54397cfa02f1d2fc3c529fd3888980e2",
        "aeeeb23556eba42bf22632c7ba5f9871f9b34196f6c87091fb82111668edfd4136b6122e6dbe1d04f6cfa16edd03f25e54397cfa02f1d2fc3c529fd3888980e2",
        "03a3e8d415ef18aca5f4b16e2d2b89ec7ec1439b062d217896625aeb0bbbb8a4",
        "88fcbdd13b18a27f1f0c0507384e1716d5004ef0edcbbe7e5fce63c3ba29a8c4"
    },
    {
        "4c7da515de11409b3101665a6c91fbccfc9f4ff77076b8dd71bcfef34533e9be",
        "000ff60e8c05f36fd4edb66a82e22152dd6d5cd887234e8a648e51acb3c7ca55",
        "0212a1850d2830b52aea267cc188fa5ed0a67d1e0e8a134cdee8900217be212c",
        "49a722eee2330bd3ec9f00ce2d76f51ede01db1f2584f02f941eff01ca3732af",
        "531bf079f72b51eeeec7a8ba7e17687fe1bdf2dd437abeed7d80d23675dcc89b",
        "49a722eee2330bd3ec9f00ce2d76f51ede01db1f2584f02f941eff01ca3732af531bf079f72b51eeeec7a8ba7e17687fe1bdf2dd437abeed7d80d23675dcc89b",
        "01b0c1949caefe5b1ae6619165c2c8b844cc48b60fad8bbc225301f1a5482236",
        "1c7b2453eb96c94a07337a4d6e233fa4d8bdab2f0129d5ebdbbbb6ff92fa5988"
    },
    {
        "bb20c0b30bfd58582994c99d5096928574786600de6e5068d6578793f810778c",
        "05605dc6766494b5adf665fc306dddefe84b8556fc7486879d5d1b06987f95ba",
        "0c8c40a559828fe9b87e650eaa4f37eebd3a0076085b141d232a49471d5e80bd",
        "0e2f36dc1d56cc8000175f330606849ad725aa8dfa775e618d57e76992dea3ef",
        "276a2d02fc6dd50fb4e7e471fd46e2c4c0545d48fd34dcdaf8b1361ea0f73618",
        "0e2f36dc1d56cc8000175f330606849ad725aa8dfa775e618d57e76992dea3ef276a2d02fc6dd50fb4e7e471fd46e2c4c0545d48fd34dcdaf8b1361ea0f73618",
        "072f1e5b04f3af53d19728dd147efcbf3693e5471798d44a0d304c546aa653e3",
        "87f244bce4971951a25a9cfcf5b17300314f737c274ff49ec3c7c1795759538b"
    },
};

TEST(Keys, SpendingAuthorizationKey) {
    for (const auto& testcase : testvectors) {
        spending_key_t spendingKey = {0};

        ask_t spendAuthorizationKey = {0};
        nsk_t proofAuthorizationKey = {0};

        ak_t authorizing_key = {0};
        nk_t nullifier_deriving_key = {0};

        ivk_t incomingViewingKey = {0};
        ovk_t outgoingViewingKey = {0};

        // Read spendingKey from testvectors
        parseHexString(spendingKey, sizeof(spendingKey), testcase.spendingKey.c_str());

        // Compute ask and nsk
        ASSERT_EQ(convertKey(spendingKey, MODIFIER_ASK, spendAuthorizationKey, true), parser_ok);
        const string ask = toHexString(spendAuthorizationKey, 32);
        EXPECT_EQ(ask, testcase.spendAuthorizationKey);

        ASSERT_EQ(convertKey(spendingKey, MODIFIER_NSK, proofAuthorizationKey, true), parser_ok);
        const string nsk = toHexString(proofAuthorizationKey, 32);
        EXPECT_EQ(nsk, testcase.proofAuthorizationKey);

        // Compute ak and nk
        generate_key(spendAuthorizationKey, SpendingKeyGenerator, authorizing_key);
        const string ak = toHexString(authorizing_key, 32);
        EXPECT_EQ(ak, testcase.authorizing_key);

        generate_key(proofAuthorizationKey, ProofGenerationKeyGenerator, nullifier_deriving_key);
        const string nk = toHexString(nullifier_deriving_key, 32);
        EXPECT_EQ(nk, testcase.nullifier_deriving_key);

        const string viewKey = ak + nk;
        EXPECT_EQ(viewKey, testcase.viewKey);

        // Compute ivk and ovk
        computeIVK(authorizing_key, nullifier_deriving_key, incomingViewingKey);
        const string ivk = toHexString(incomingViewingKey, 32);
        EXPECT_EQ(ivk, testcase.incomingViewingKey);

        ASSERT_EQ(convertKey(spendingKey, MODIFIER_OVK, outgoingViewingKey, false), parser_ok);
        const string ovk = toHexString(outgoingViewingKey, 32);
        EXPECT_EQ(ovk, testcase.outgoingViewingKey);
    }
}
