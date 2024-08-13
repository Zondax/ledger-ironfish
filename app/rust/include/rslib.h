#pragma once

#include <stdint.h>

#include "keys_def.h"
#include "parser_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Interface functions with jubjub crate */
parser_error_t from_bytes_wide(const uint8_t input[64], uint8_t output[32]);
parser_error_t scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);
parser_error_t randomizeKey(const uint8_t key[KEY_LENGTH], const uint8_t randomness[KEY_LENGTH], uint8_t output[KEY_LENGTH]);
parser_error_t compute_sbar(const uint8_t s[KEY_LENGTH], const uint8_t r[KEY_LENGTH], const uint8_t rsk[KEY_LENGTH],
                            uint8_t sbar[32]);

// Required to initialize a heap for alloc into the stack memory (necessary for alloc feature on embedded devices)
parser_error_t heap_init();

#ifdef __cplusplus
}
#endif
