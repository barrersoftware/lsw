/*
 * Copyright (c) 2025 BarrerSoftware
 * 
 * This file is part of LSW (Linux Subsystem for Windows).
 * 
 * Licensed under the BarrerSoftware License (BSL) v1.0
 * 
 * If it's free, it's free. Period.
 */

#ifndef LSW_FILESYSTEM_H
#define LSW_FILESYSTEM_H

#include "lsw_types.h"

/*
 * LSW Filesystem Translation Layer
 * 
 * Translates Windows paths to Linux paths and vice versa.
 * Handles drive letters, case sensitivity, and path separators.
 * 
 * Example:
 *   Windows: C:\Windows\System32\notepad.exe
 *   Linux:   /mnt/c/Windows/System32/notepad.exe
 */

// ============================================================================
// SECTION: Path Translation
// ============================================================================

/**
 * Convert Windows path to Linux path
 * 
 * What: Translates C:\path to /mnt/c/path
 * Why: Windows apps expect Windows-style paths
 * How: Replace backslashes, map drive letters
 * 
 * @param windows_path Input Windows path (e.g., "C:\Windows\notepad.exe")
 * @param linux_path Output Linux path buffer
 * @param buffer_size Size of output buffer
 * @return LSW_SUCCESS or error code
 */
lsw_status_t lsw_fs_win_to_linux(
    const char* windows_path,
    char* linux_path,
    size_t buffer_size
);

/**
 * Convert Linux path to Windows path
 * 
 * What: Translates /mnt/c/path to C:\path
 * Why: Some operations need Windows format
 * How: Reverse of win_to_linux
 */
lsw_status_t lsw_fs_linux_to_win(
    const char* linux_path,
    char* windows_path,
    size_t buffer_size
);

// ============================================================================
// SECTION: Path Operations
// ============================================================================

/**
 * Normalize Windows path
 * 
 * What: Converts path to consistent format
 * Why: Handle different separator styles
 * How: Replace forward slashes, resolve .. and .
 */
lsw_status_t lsw_fs_normalize_path(
    const char* input_path,
    char* output_path,
    size_t buffer_size
);

/**
 * Check if path exists
 * 
 * What: Verifies file or directory exists
 * Why: Validate before operations
 * How: Stat the translated path
 */
bool lsw_fs_path_exists(const char* windows_path);

/**
 * Get drive letter from path
 * 
 * What: Extracts drive letter (C, D, etc.)
 * Why: Needed for drive mapping
 * How: Parse first part of Windows path
 */
char lsw_fs_get_drive_letter(const char* windows_path);

// ============================================================================
// SECTION: Prefix Management
// ============================================================================

/**
 * Initialize LSW prefix structure
 * 
 * What: Creates ~/.lsw/drives/c/ directory structure
 * Why: Windows apps need Windows-like filesystem
 * How: Create standard Windows folders (Windows, Program Files, etc.)
 * 
 * Creates:
 *   ~/.lsw/drives/c/Windows/System32
 *   ~/.lsw/drives/c/Windows/Temp
 *   ~/.lsw/drives/c/Program Files
 *   ~/.lsw/drives/c/Users/<username>
 *   ~/.lsw/registry
 */
lsw_status_t lsw_fs_init_prefix(void);

// ============================================================================
// SECTION: Special Folders
// ============================================================================

/**
 * Get Windows special folder path
 * 
 * What: Returns path for System folders
 * Why: Apps need to find Windows, System32, etc.
 * How: Map to Linux equivalents
 * 
 * Examples:
 *   WINDOWS    -> /mnt/c/Windows
 *   SYSTEM32   -> /mnt/c/Windows/System32
 *   PROGRAMFILES -> /mnt/c/Program Files
 */
lsw_status_t lsw_fs_get_special_folder(
    const char* folder_name,
    char* path_buffer,
    size_t buffer_size
);

#endif // LSW_FILESYSTEM_H
