#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "keys_def.h"

/* Interface functions with jubjub crate */
parser_error_t from_bytes_wide(const uint8_t input[64], uint8_t output[32]);
parser_error_t scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);
