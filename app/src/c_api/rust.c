#include <inttypes.h>
#include <zxformat.h>
#include <zxmacros.h>

#include "coin.h"
#include "cx.h"
#include "os.h"
#include "zxerror.h"

#include <inttypes.h>
#include <stddef.h>

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
#include "lcx_rng.h"
unsigned char *bolos_cx_rng(uint8_t *buffer, size_t len) {
    cx_rng_no_throw(buffer, len);
    return buffer;
}
#endif
