/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#ifndef LSW_REGISTRY_H
#define LSW_REGISTRY_H

#include "lsw_types.h"
#include <stdint.h>

/*
 * LSW Registry Emulation
 * 
 * What: Windows Registry emulation on Linux
 * Why: Windows apps expect registry to exist
 * How: Store key/value pairs in files, provide Windows-compatible API
 * 
 * Philosophy: Simple file-based storage, not complex database
 */

// ============================================================================
// SECTION: Registry API
// ============================================================================

/**
 * Open registry key
 * 
 * What: Open a key for reading/writing
 * Why: Windows apps use RegOpenKey
 * How: Map to file path, open if exists
 * 
 * Example:
 *   HKEY_LOCAL_MACHINE\Software\MyApp → ~/.local/share/lsw/registry/HKLM/Software/MyApp
 */
lsw_status_t lsw_reg_open_key(
    lsw_hkey_t hkey,
    const char* subkey,
    HANDLE* out_handle
);

/**
 * Create registry key
 * 
 * What: Create new key if it doesn't exist
 * Why: Apps create their own keys
 * How: Create directory structure
 */
lsw_status_t lsw_reg_create_key(
    lsw_hkey_t hkey,
    const char* subkey,
    HANDLE* out_handle
);

/**
 * Close registry key
 * 
 * What: Close an open key handle
 * Why: Release resources
 * How: Close file descriptor
 */
lsw_status_t lsw_reg_close_key(HANDLE handle);

/**
 * Read registry value
 * 
 * What: Read value from registry key
 * Why: Apps read configuration from registry
 * How: Read from file storage
 * 
 * Example:
 *   RegQueryValue("Version") → Read from file
 */
lsw_status_t lsw_reg_query_value(
    HANDLE handle,
    const char* value_name,
    lsw_reg_type_t* type,
    void* data,
    size_t* data_size
);

/**
 * Write registry value
 * 
 * What: Write value to registry key
 * Why: Apps save configuration
 * How: Write to file storage
 */
lsw_status_t lsw_reg_set_value(
    HANDLE handle,
    const char* value_name,
    lsw_reg_type_t type,
    const void* data,
    size_t data_size
);

/**
 * Delete registry value
 * 
 * What: Remove value from key
 * Why: Apps clean up old settings
 * How: Remove from file storage
 */
lsw_status_t lsw_reg_delete_value(
    HANDLE handle,
    const char* value_name
);

/**
 * Delete registry key
 * 
 * What: Remove entire key and subkeys
 * Why: Uninstallation
 * How: Remove directory tree
 */
lsw_status_t lsw_reg_delete_key(
    lsw_hkey_t hkey,
    const char* subkey
);

/**
 * Enumerate registry keys
 * 
 * What: List subkeys of a key
 * Why: Apps browse registry
 * How: List directories
 */
lsw_status_t lsw_reg_enum_keys(
    HANDLE handle,
    uint32_t index,
    char* name_buffer,
    size_t buffer_size
);

/**
 * Enumerate registry values
 * 
 * What: List values in a key
 * Why: Apps enumerate settings
 * How: List files in directory
 */
lsw_status_t lsw_reg_enum_values(
    HANDLE handle,
    uint32_t index,
    char* name_buffer,
    size_t buffer_size,
    lsw_reg_type_t* type
);

// ============================================================================
// SECTION: Utility Functions
// ============================================================================

/**
 * Get registry path
 * 
 * What: Convert registry key to filesystem path
 * Why: Internal mapping
 * How: Build path from hkey and subkey
 * 
 * Example:
 *   HKLM\Software\Test → ~/.local/share/lsw/registry/HKLM/Software/Test
 */
lsw_status_t lsw_reg_get_path(
    lsw_hkey_t hkey,
    const char* subkey,
    char* path_buffer,
    size_t buffer_size
);

/**
 * Initialize registry system
 * 
 * What: Set up registry directories
 * Why: First-time setup
 * How: Create base directory structure
 */
lsw_status_t lsw_reg_init(void);

#endif // LSW_REGISTRY_H
