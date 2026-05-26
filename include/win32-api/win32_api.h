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

// Get all API mappings
const win32_api_mapping_t* win32_api_get_mappings(size_t* count);

#endif // LSW_WIN32_API_H
