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
static napi_type_tag scanner_tag;
static pthread_once_t default_once = PTHREAD_ONCE_INIT;
static uint64_t default_scanner;
static bl_buffer default_error;
static int32_t default_status;

static void pin_module(void) {
    Dl_info info;
    if (dladdr((void *)&pin_module, &info)) {
        module_handle = dlopen(info.dli_fname, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    }
    // Each loaded copy has its own Go handle registry.
    scanner_tag = (napi_type_tag){(uintptr_t)&scanner_tag, UINT64_C(0x970fd538de8e4a19)};
}

static void create_default_scanner(void) {
    default_status = bl_scanner_new(NULL, 0, &default_scanner, &default_error);
}

// One reference belongs to the JS wrapper; each queued scan owns another.
// Only the owning Node environment changes this count. Workers only read id.
typedef struct {
    uint64_t id;
    size_t refs;
} scanner_ref;

static void release_scanner(scanner_ref *scanner) {
    if (scanner && --scanner->refs == 0) {
        bl_scanner_free(scanner->id);
        free(scanner);
    }
}

static void finalize_scanner(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    release_scanner(data);
}

static bool is_scanner(napi_env env, napi_value value) {
    bool matches = false;
    return napi_check_object_type_tag(env, value, &scanner_tag, &matches) == napi_ok && matches;
}

static napi_value close_scanner(napi_env env, napi_callback_info info) {
    napi_value self, undefined;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok || !is_scanner(env, self)) {
        napi_throw_type_error(env, NULL, "Expected a Betterleaks scanner");
        return NULL;
    }
    // Removing the wrap also removes its finalizer. Repeated closes are harmless.
    void *data;
    if (napi_remove_wrap(env, self, &data) == napi_ok) release_scanner(data);
    return napi_get_undefined(env, &undefined) == napi_ok ? undefined : NULL;
}

typedef enum { CREATE_SCANNER, SCAN_TEXT, SCAN_FILE } operation;
static const struct {
    const char *resource;
    const char *argument_error;
    size_t max_bytes;
    const char *size_error;
} operations[] = {
    [CREATE_SCANNER] = {"betterleaks.createScanner", "Expected scanner options JSON", 8u << 20, "Scanner options exceed 8 MiB"},
    [SCAN_TEXT] = {"betterleaks.scanText", "Expected a text string", 8u << 20, "Text exceeds 8 MiB"},
    [SCAN_FILE] = {"betterleaks.scanFile", "Expected a file path string", 1u << 20, "Path exceeds 1 MiB"},
};

typedef struct {
    napi_async_work work;
    napi_deferred deferred;
    operation op;
    scanner_ref *owner;
    uint64_t created;
    size_t len;
    int32_t status;
    bl_buffer result;
    bl_buffer error;
    bool default_failed;
    char input[];
} scan_task;

static napi_value scan_text(napi_env env, napi_callback_info info);
static napi_value scan_file(napi_env env, napi_callback_info info);

static napi_status wrap_scanner(napi_env env, scan_task *task, napi_value *value) {
    const napi_property_descriptor methods[] = {
        {.utf8name = "scanText", .method = scan_text, .data = &scanner_tag},
        {.utf8name = "scanFile", .method = scan_file, .data = &scanner_tag},
        {.utf8name = "close", .method = close_scanner},
    };
    scanner_ref *scanner = malloc(sizeof(*scanner));
    if (!scanner) return napi_generic_failure;
    *scanner = (scanner_ref){.id = task->created, .refs = 1};
    if (napi_create_object(env, value) != napi_ok ||
        napi_type_tag_object(env, *value, &scanner_tag) != napi_ok ||
        napi_define_properties(env, *value, 3, methods) != napi_ok ||
        napi_wrap(env, *value, scanner, finalize_scanner, NULL, NULL) != napi_ok) {
        free(scanner);
        return napi_generic_failure;
    }
    task->created = 0; // The wrapper now owns the handle.
    return napi_ok;
}

static void execute(napi_env env, void *data) {
    (void)env;
    scan_task *task = data;
    uint8_t *input = (uint8_t *)task->input;
    if (task->op == CREATE_SCANNER) {
        task->status = bl_scanner_new(input, task->len, &task->created, &task->error);
        return;
    }

    uint64_t id;
    if (task->owner) {
        id = task->owner->id;
    } else {
        pthread_once(&default_once, create_default_scanner);
        if (default_status != BL_OK) {
            task->status = default_status;
            task->default_failed = true;
            return;
        }
        id = default_scanner;
    }
    if (task->op == SCAN_FILE) {
        task->status = bl_scanner_scan_file(id, input, task->len, &task->result, &task->error);
    } else {
        task->status = bl_scanner_scan(id, input, task->len, NULL, 0, &task->result, &task->error);
    }
}

static void complete(napi_env env, napi_status status, void *data) {
    scan_task *task = data;
    napi_value value;
    if (status == napi_ok && task->status == BL_OK) {
        status = task->op == CREATE_SCANNER ? wrap_scanner(env, task, &value)
            : napi_create_string_utf8(env, (char *)task->result.data, task->result.len, &value);
    }
    if (status == napi_ok && task->status == BL_OK) {
        napi_resolve_deferred(env, task->deferred, value);
    } else {
        bl_buffer message = task->default_failed ? default_error : task->error;
        const char *text = message.data ? (char *)message.data : "Betterleaks operation did not complete";
        size_t len = message.data ? message.len : NAPI_AUTO_LENGTH;
        napi_value error;
        if (napi_create_string_utf8(env, text, len, &value) == napi_ok &&
            napi_create_error(env, NULL, value, &error) == napi_ok) {
            napi_reject_deferred(env, task->deferred, error);
        }
    }
    if (task->created) bl_scanner_free(task->created);
    release_scanner(task->owner);
    bl_buffer_free(task->result);
    bl_buffer_free(task->error);
    napi_delete_async_work(env, task->work);
    free(task);
}

static napi_value start_work(napi_env env, napi_callback_info info, operation op) {
    napi_value input, self, name, promise;
    void *method_data, *owner = NULL;
    size_t argc = 1, len;
    if (napi_get_cb_info(env, info, &argc, &input, &self, &method_data) != napi_ok || argc != 1 ||
        napi_get_value_string_utf8(env, input, NULL, 0, &len) != napi_ok) {
        napi_throw_type_error(env, NULL, operations[op].argument_error);
        return NULL;
    }
    if (method_data && (!is_scanner(env, self) || napi_unwrap(env, self, &owner) != napi_ok || !owner)) {
        napi_throw_error(env, NULL, "Betterleaks scanner is closed or invalid");
        return NULL;
    }
    // Bound allocation before copying input for the asynchronous call.
    if (len > operations[op].max_bytes) {
        napi_throw_range_error(env, NULL, operations[op].size_error);
        return NULL;
    }
    scan_task *task = calloc(1, sizeof(*task) + len + 1);
    if (!task) {
        napi_throw_error(env, NULL, "Could not allocate Betterleaks work");
        return NULL;
    }
    task->op = op;
    task->owner = owner;
    if (task->owner) task->owner->refs++;
    if (napi_get_value_string_utf8(env, input, task->input, len + 1, &task->len) != napi_ok ||
        napi_create_promise(env, &task->deferred, &promise) != napi_ok ||
        napi_create_string_utf8(env, operations[op].resource, NAPI_AUTO_LENGTH, &name) != napi_ok ||
        napi_create_async_work(env, NULL, name, execute, complete, task, &task->work) != napi_ok ||
        napi_queue_async_work(env, task->work) != napi_ok) {
        if (task->work) napi_delete_async_work(env, task->work);
        release_scanner(task->owner);
        free(task);
        napi_throw_error(env, NULL, "Could not queue Betterleaks work");
        return NULL;
    }
    return promise;
}

static napi_value create_scanner(napi_env env, napi_callback_info info) {
    return start_work(env, info, CREATE_SCANNER);
}

static napi_value scan_text(napi_env env, napi_callback_info info) {
    return start_work(env, info, SCAN_TEXT);
}

static napi_value scan_file(napi_env env, napi_callback_info info) {
    return start_work(env, info, SCAN_FILE);
}

NAPI_MODULE_INIT() {
    pthread_once(&pin_once, pin_module);
    if (!module_handle || bl_abi_version() != BL_ABI_VERSION) {
        napi_throw_error(env, NULL, "Could not initialize the Betterleaks native library");
        return NULL;
    }
    const napi_property_descriptor methods[] = {
        {.utf8name = "createScanner", .method = create_scanner},
        {.utf8name = "scanText", .method = scan_text},
        {.utf8name = "scanFile", .method = scan_file},
    };
    if (napi_define_properties(env, exports, 3, methods) != napi_ok) {
        napi_throw_error(env, NULL, "Could not initialize Betterleaks methods");
        return NULL;
    }
    return exports;
}
