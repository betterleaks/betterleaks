//go:build cgo && betterleaks_ffi

// Build explicitly with -tags betterleaks_ffi -buildmode=c-archive. Keeping this
// opt-in preserves the CLI's CGO_ENABLED=0 build and normal Go package graph.
package main

/*
#include "betterleaks.h"
#include <stdlib.h>
#if defined(__linux__) && defined(BL_LIBC_GNU)
#include <features.h>
#if !defined(__GLIBC__)
#error "The GNU target requires a glibc compiler/sysroot"
#endif
#endif
*/
import "C"

import (
	"errors"
	"unsafe"
)

func copyInput(data *C.uint8_t, length C.size_t, limit int) ([]byte, error) {
	if uint64(length) > uint64(limit) {
		return nil, failure(statusLimit, "input buffer exceeds its size limit")
	}
	if length == 0 {
		return nil, nil
	}
	if data == nil {
		return nil, failure(statusInvalid, "non-empty input has a null pointer")
	}
	// All limits fit C.int. Copy before starting any Go workers so the caller's
	// buffer cannot be retained by Go after this native call returns.
	return C.GoBytes(unsafe.Pointer(data), C.int(length)), nil
}

func outputBuffer(data []byte) C.bl_buffer {
	if len(data) == 0 {
		return C.bl_buffer{}
	}
	return C.bl_buffer{data: (*C.uint8_t)(C.CBytes(data)), len: C.size_t(len(data))}
}

func writeError(out *C.bl_buffer, err error) C.int32_t {
	*out = outputBuffer([]byte(err.Error()))
	var api *apiError
	if errors.As(err, &api) {
		return C.int32_t(api.status)
	}
	return C.BL_INTERNAL_ERROR
}

// Recover only panics in the calling goroutine. Fatal runtime failures and
// panics in engine workers are not isolated from the embedding application.
func recoverCall(status *C.int32_t, outError *C.bl_buffer) {
	if recover() != nil {
		*status = writeError(outError, failure(statusInternal, "internal panic in native bridge"))
	}
}

//export bl_abi_version
func bl_abi_version() C.uint32_t { return abiVersion }

//export bl_scanner_new
func bl_scanner_new(options *C.uint8_t, optionsLen C.size_t, outScanner *C.uint64_t, outError *C.bl_buffer) (status C.int32_t) {
	if outScanner == nil || outError == nil {
		return C.BL_INVALID_ARGUMENT
	}
	*outScanner, *outError = 0, C.bl_buffer{}
	defer recoverCall(&status, outError)
	data, err := copyInput(options, optionsLen, maxOptionsBytes)
	if err != nil {
		return writeError(outError, err)
	}
	scanner, err := newScanner(data)
	if err != nil {
		return writeError(outError, err)
	}
	handle, err := registerScanner(scanner)
	if err != nil {
		return writeError(outError, err)
	}
	*outScanner = C.uint64_t(handle)
	return C.BL_OK
}

//export bl_scanner_scan
func bl_scanner_scan(handle C.uint64_t, input *C.uint8_t, inputLen C.size_t,
	attributes *C.uint8_t, attributesLen C.size_t, outResult, outError *C.bl_buffer) (status C.int32_t) {
	if outResult == nil || outError == nil || outResult == outError {
		return C.BL_INVALID_ARGUMENT
	}
	*outResult, *outError = C.bl_buffer{}, C.bl_buffer{}
	defer recoverCall(&status, outError)
	scanner, err := lookupScanner(uint64(handle))
	if err != nil {
		return writeError(outError, err)
	}
	data, err := copyInput(input, inputLen, scanner.maxInputBytes)
	if err != nil {
		return writeError(outError, err)
	}
	attrs, err := copyInput(attributes, attributesLen, maxAttributeBytes)
	if err != nil {
		return writeError(outError, err)
	}
	encoded, err := scanner.scan(data, attrs)
	if err != nil {
		return writeError(outError, err)
	}
	*outResult = outputBuffer(encoded)
	return C.BL_OK
}

//export bl_scanner_free
func bl_scanner_free(handle C.uint64_t) C.int32_t {
	if !deleteScanner(uint64(handle)) {
		return C.BL_INVALID_ARGUMENT
	}
	return C.BL_OK
}

//export bl_buffer_free
func bl_buffer_free(buffer C.bl_buffer) { C.free(unsafe.Pointer(buffer.data)) }

func main() {}
