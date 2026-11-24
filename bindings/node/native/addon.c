#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>

#include <dlfcn.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "betterleaks.h"

// Node can unload addons when the last Worker using them exits. The Go
// runtime keeps background threads for the process lifetime. Retain a loader
// reference, and share a single lazily compiled default scanner across Workers.
static pthread_once_t pin_once = PTHREAD_ONCE_INIT;
static void *module_handle;
static pthread_once_t scanner_once = PTHREAD_ONCE_INIT;
static uint64_t scanner;
static bl_buffer scanner_error;
static int32_t scanner_status;

static void pin_module(void) {
    Dl_info info;
    if (dladdr((void *)&pin_module, &info)) {
        module_handle = dlopen(info.dli_fname, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    }
}

static void create_scanner(void) {
    scanner_status = bl_scanner_new(NULL, 0, &scanner, &scanner_error);
}

typedef struct {
    napi_async_work work;
    napi_deferred deferred;
    bool file;
    size_t len;
    int32_t status;
    bl_buffer result;
    bl_buffer error;
    char input[];
} scan_task;

static void execute(napi_env env, void *data) {
    (void)env;
    scan_task *task = data;
    pthread_once(&scanner_once, create_scanner);
    task->status = scanner_status;
    if (task->status != BL_OK) return;

    uint8_t *input = (uint8_t *)task->input;
    if (task->file) {
        task->status = bl_scanner_scan_file(scanner, input, task->len, &task->result, &task->error);
    } else {
        task->status = bl_scanner_scan(scanner, input, task->len, NULL, 0, &task->result, &task->error);
    }
}

static void complete(napi_env env, napi_status status, void *data) {
    scan_task *task = data;
    napi_value value;
    if (status == napi_ok && task->status == BL_OK &&
        napi_create_string_utf8(env, (char *)task->result.data, task->result.len, &value) == napi_ok) {
        napi_resolve_deferred(env, task->deferred, value);
    } else {
        bl_buffer message = task->error;
        if (status == napi_ok && scanner_status != BL_OK) message = scanner_error;
        const char *text = message.data ? (char *)message.data : "Betterleaks scan did not complete";
        size_t len = message.data ? message.len : NAPI_AUTO_LENGTH;
        napi_value error;
        if (napi_create_string_utf8(env, text, len, &value) == napi_ok &&
            napi_create_error(env, NULL, value, &error) == napi_ok) {
            napi_reject_deferred(env, task->deferred, error);
        }
    }
    bl_buffer_free(task->result);
    bl_buffer_free(task->error);
    napi_delete_async_work(env, task->work);
    free(task);
}

static napi_value start_scan(napi_env env, napi_callback_info info, bool file) {
    napi_value input, name, promise;
    size_t argc = 1, len;
    if (napi_get_cb_info(env, info, &argc, &input, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_string_utf8(env, input, NULL, 0, &len) != napi_ok) {
        napi_throw_type_error(env, NULL, file ? "Expected a file path string" : "Expected a text string");
        return NULL;
    }
    // Bound allocation before copying the UTF-8 data for the asynchronous call.
    if (len > (file ? 1u << 20 : 8u << 20)) {
        napi_throw_range_error(env, NULL, file ? "Path exceeds 1 MiB" : "Text exceeds 8 MiB");
        return NULL;
    }
    scan_task *task = calloc(1, sizeof(*task) + len + 1);
    if (!task) {
        napi_throw_error(env, NULL, "Could not allocate Betterleaks scan");
        return NULL;
    }
    task->file = file;
    if (napi_get_value_string_utf8(env, input, task->input, len + 1, &task->len) != napi_ok ||
        napi_create_promise(env, &task->deferred, &promise) != napi_ok ||
        napi_create_string_utf8(env, file ? "betterleaks.scanFile" : "betterleaks.scanText",
                                NAPI_AUTO_LENGTH, &name) != napi_ok ||
        napi_create_async_work(env, NULL, name, execute, complete, task, &task->work) != napi_ok ||
        napi_queue_async_work(env, task->work) != napi_ok) {
        if (task->work) napi_delete_async_work(env, task->work);
        free(task);
        napi_throw_error(env, NULL, "Could not queue Betterleaks scan");
        return NULL;
    }
    return promise;
}

static napi_value scan_text(napi_env env, napi_callback_info info) {
    return start_scan(env, info, false);
}

static napi_value scan_file(napi_env env, napi_callback_info info) {
    return start_scan(env, info, true);
}

NAPI_MODULE_INIT() {
    pthread_once(&pin_once, pin_module);
    if (!module_handle || bl_abi_version() != BL_ABI_VERSION) {
        napi_throw_error(env, NULL, "Could not initialize the Betterleaks native library");
        return NULL;
    }
    const napi_property_descriptor methods[] = {
        {.utf8name = "scanText", .method = scan_text},
        {.utf8name = "scanFile", .method = scan_file},
    };
    if (napi_define_properties(env, exports, 2, methods) != napi_ok) {
        napi_throw_error(env, NULL, "Could not initialize Betterleaks methods");
        return NULL;
    }
    return exports;
}
