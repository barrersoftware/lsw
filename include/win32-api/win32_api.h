/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * Win32 API - Function mapping and stubs
 */

#ifndef LSW_WIN32_API_H
#define LSW_WIN32_API_H

#include <stddef.h>
#include <stdint.h>

// API function mapping
typedef struct {
    const char* dll_name;
    const char* function_name;
    void* implementation;
} win32_api_mapping_t;

// Initialize Win32 API system
void win32_api_init(void);

// Set kernel fd for syscalls
void win32_api_set_kernel_fd(int fd);

// Resolve a function by DLL and name (returns NULL if not found)
void* win32_api_resolve(const char* dll_name, const char* function_name);

// Resolve a function by name across all tables (ignores DLL name) — for GetProcAddress
void* win32_api_resolve_any(const char* function_name);

// Resolve a function by DLL name and ordinal number (returns generic_stub if unknown)
void* win32_api_resolve_ordinal(const char* dll_name, uint16_t ordinal);

// Get the address of the generic (do-nothing) stub — used for unresolved ordinals
void* win32_api_get_generic_stub(void);

// Resolve a DATA-export symbol (global variable) from msvcrt/ucrtbase.
// Returns the *address* of a static variable stub, or NULL if not a known data symbol.
// The PE import resolver calls this BEFORE falling back to function-stub resolution.
void* win32_api_resolve_data(const char* dll_name, const char* sym);

// Populate CRT data stubs (__argc, __argv, _environ, _acmdln, _pctype ...) from
// the real process argc/argv.  Called after win32_set_command_line().
void win32_crt_data_init(int argc, char** argv);

// Set the path of the main PE executable (called by the PE loader before import resolution).
// Used by LoadStringW MUI lookup and GetModuleFileNameW/A.
void lsw_set_exe_path(const char* path);

// Register PE image info for x64 C++ exception dispatch.
// Called by the PE loader after mapping the image so that _CxxThrowException
// can walk the .pdata table to find matching catch blocks.
void win32_api_set_pe_image_info(uint64_t image_base,
                                  void*    pdata_va,
                                  uint32_t pdata_size,
                                  uint32_t image_size);

// Get all API mappings
const win32_api_mapping_t* win32_api_get_mappings(size_t* count);

#endif // LSW_WIN32_API_H
