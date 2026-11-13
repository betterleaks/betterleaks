#include "betterleaks.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    /* The caller supplies a disposable fixture path in its temporary directory. */
    assert(argc == 2);
    assert(bl_abi_version() == BL_ABI_VERSION);
    bl_buffer error = {0}, result = {0};
    uint64_t scanner = 0;
    assert(bl_scanner_new(NULL, 0, NULL, &error) == BL_INVALID_ARGUMENT);
    assert(bl_scanner_new(NULL, 1, &scanner, &error) == BL_INVALID_ARGUMENT);
    assert(scanner == 0 && error.len > 0);
    bl_buffer_free(error);

    assert(bl_scanner_new(NULL, 0, &scanner, &error) == BL_OK);
    assert(scanner != 0 && error.data == NULL && error.len == 0);
    uint8_t input[] = "prefix\0GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5\n";
    assert(bl_scanner_scan(scanner, input, sizeof(input) - 1, NULL, 0, &result, &error) == BL_OK);
    assert(result.len > 0 && result.data != NULL);
    assert(error.len == 0 && error.data == NULL);
    bl_buffer_free(result);

    assert(bl_scanner_scan(scanner, NULL, 0, NULL, 0, &result, &error) == BL_OK);
    bl_buffer_free(result);
    assert(bl_scanner_scan(scanner, NULL, 1, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    assert(result.len == 0 && error.len > 0);
    bl_buffer_free(error);
    assert(bl_scanner_scan(scanner, NULL, SIZE_MAX, NULL, 0, &result, &error) == BL_LIMIT_EXCEEDED);
    bl_buffer_free(error);
    uint8_t invalid_utf8[] = {0xff};
    assert(bl_scanner_scan(scanner, invalid_utf8, 1, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    bl_buffer_free(error);

    uint8_t *path = (uint8_t *)argv[1];
    size_t path_len = strlen(argv[1]);
    FILE *file = fopen(argv[1], "wb");
    assert(file != NULL);
    assert(fwrite(input, 1, sizeof(input) - 1, file) == sizeof(input) - 1);
    assert(fclose(file) == 0);
    assert(bl_scanner_scan_file(scanner, path, path_len, NULL, 0, &result, &error) == BL_OK);
    assert(result.data != NULL && result.len > 0 && error.data == NULL);
    bl_buffer_free(result);
    assert(bl_scanner_scan_file(scanner, path, path_len, NULL, 0, NULL, &error) == BL_INVALID_ARGUMENT);
    assert(bl_scanner_scan_file(scanner, path, path_len, NULL, 0, &result, &result) == BL_INVALID_ARGUMENT);
    assert(bl_scanner_scan_file(scanner, NULL, 0, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    assert(result.data == NULL && result.len == 0 && error.len > 0);
    bl_buffer_free(error);
    assert(bl_scanner_scan_file(scanner, NULL, 1, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    bl_buffer_free(error);
    assert(bl_scanner_scan_file(scanner, NULL, SIZE_MAX, NULL, 0, &result, &error) == BL_LIMIT_EXCEEDED);
    bl_buffer_free(error);
    assert(bl_scanner_scan_file(scanner, path, path_len + 1, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    bl_buffer_free(error);
    assert(bl_scanner_scan_file(scanner, invalid_utf8, 1, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    bl_buffer_free(error);
    assert(bl_scanner_scan_file(scanner, path, path_len, NULL, 1, &result, &error) == BL_INVALID_ARGUMENT);
    bl_buffer_free(error);
    file = fopen(argv[1], "wb");
    assert(file != NULL && fwrite(invalid_utf8, 1, 1, file) == 1);
    assert(fclose(file) == 0);
    assert(bl_scanner_scan_file(scanner, path, path_len, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    assert(result.data == NULL && result.len == 0);
    bl_buffer_free(error);
    assert(remove(argv[1]) == 0);
    assert(bl_scanner_scan_file(scanner, path, path_len, NULL, 0, &result, &error) == BL_SCAN_ERROR);
    bl_buffer_free(error);

    assert(bl_scanner_free(scanner) == BL_OK);
    assert(bl_scanner_free(scanner) == BL_INVALID_ARGUMENT);
    assert(bl_scanner_scan(scanner, NULL, 0, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    bl_buffer_free(error);
    assert(bl_scanner_scan_file(scanner, path, path_len, NULL, 0, &result, &error) == BL_INVALID_ARGUMENT);
    bl_buffer_free(error);
    bl_buffer_free((bl_buffer){0});
    puts("C ABI checks passed");
}
