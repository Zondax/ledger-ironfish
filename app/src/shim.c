#include "stdint.h"

__attribute__((section(".rodata"), aligned(16)))
uint8_t b = 0;

__attribute__((section(".rodata"), aligned(16)))
const uint8_t *__rust_no_alloc_shim_is_unstable = &b;