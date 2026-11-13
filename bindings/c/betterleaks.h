#ifndef BETTERLEAKS_H
#define BETTERLEAKS_H

#include <stddef.h>
#include <stdint.h>

#define BL_ABI_VERSION 1
#define BL_OK 0
#define BL_INVALID_ARGUMENT 1
#define BL_CONFIG_ERROR 2
#define BL_SCAN_ERROR 3
#define BL_LIMIT_EXCEEDED 4
#define BL_INTERNAL_ERROR 5

typedef struct {
    uint8_t *data;
    size_t len;
} bl_buffer;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t bl_abi_version(void);

/* Inputs are borrowed only for the duration of the call and never modified.
 * A NULL input is valid only when its length is zero. All output pointers must
 * be non-NULL, writable, and distinct. Initialize output buffers to {NULL, 0}.
 * Every returned buffer (including errors) must be freed with bl_buffer_free.
 * Errors are UTF-8 text; successful scan results are schema-versioned JSON.
 * Zero options length selects defaults; zero attributes length means {}.
 * Nonzero-length options and attributes must be JSON objects.
 * On failure no scanner or partial scan result is returned.
 */
int32_t bl_scanner_new(uint8_t *options, size_t options_len,
                       uint64_t *out_scanner, bl_buffer *out_error);

/* Each scan limits detection to 100,000 candidates, 64 MiB of cumulative
 * allocation charges, 8 MiB of shared regex-index scratch, and 128 KiB per
 * source fragment. Filtered candidates and component/decoding work count too.
 * max_findings is checked after fragment filtering and before output copying.
 * Exceeding any limit returns BL_LIMIT_EXCEEDED without a partial result;
 * the scanner can be reused. Concurrent calls have independent budgets.
 * These charges are not a process-memory ceiling. See bindings/README.md for
 * the accounting scope; use process isolation for hard resource guarantees.
 */
int32_t bl_scanner_scan(uint64_t scanner, uint8_t *input, size_t input_len,
                        uint8_t *attributes, size_t attributes_len,
                        bl_buffer *out_result, bl_buffer *out_error);

/* Concurrent scans are supported. Free invalidates the handle for new calls;
 * calls that have already acquired the scanner finish normally. Handles are
 * never reused. An unknown or already-freed handle returns BL_INVALID_ARGUMENT.
 */
int32_t bl_scanner_free(uint64_t scanner);

/* Accepts {NULL, 0}. Other buffers must be returned by this library and freed
 * exactly once. Do not use the buffer afterward or another allocator to free it.
 */
void bl_buffer_free(bl_buffer buffer);

#ifdef __cplusplus
}
#endif
#endif
