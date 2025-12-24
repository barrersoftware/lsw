/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#include "lsw_filesystem.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <ctype.h>

// ============================================================================
// SECTION: Path Translation
// ============================================================================

/**
 * Convert Windows path to Linux path
 * 
 * What: C:\Windows\System32 → /mnt/c/Windows/System32
 * Why: Linux kernel needs Linux paths
 * How: Map drive letter, replace backslashes
 */
lsw_status_t lsw_fs_win_to_linux(
    const char* windows_path,
    char* linux_path,
    size_t buffer_size
) {
    if (!windows_path || !linux_path || buffer_size == 0) {
        return LSW_ERROR_INVALID_PARAMETER;
    }

    // Check for drive letter (C:, D:, etc.)
    if (strlen(windows_path) >= 2 && windows_path[1] == ':') {
        char drive = tolower(windows_path[0]);
        
        // Build Linux path: /mnt/c/...
        int written = snprintf(linux_path, buffer_size, "/mnt/%c", drive);
        if (written < 0 || (size_t)written >= buffer_size) {
            return LSW_ERROR_INVALID_PARAMETER;
        }
        
        // Skip drive letter (C:)
        const char* path_part = windows_path + 2;
        
        // Copy rest of path, converting backslashes to forward slashes
        size_t pos = written;
        while (*path_part && pos < buffer_size - 1) {
            if (*path_part == '\\') {
                linux_path[pos++] = '/';
            } else {
                linux_path[pos++] = *path_part;
            }
            path_part++;
        }
        linux_path[pos] = '\0';
        
    } else {
        // No drive letter - might be relative path
        // Just convert backslashes
        size_t i;
        for (i = 0; i < buffer_size - 1 && windows_path[i]; i++) {
            linux_path[i] = (windows_path[i] == '\\') ? '/' : windows_path[i];
        }
        linux_path[i] = '\0';
    }
    
    return LSW_SUCCESS;
}

/**
 * Convert Linux path to Windows path
 * 
 * What: /mnt/c/Windows → C:\Windows
 * Why: Some Windows APIs expect Windows paths
 * How: Reverse of win_to_linux
 */
lsw_status_t lsw_fs_linux_to_win(
    const char* linux_path,
    char* windows_path,
    size_t buffer_size
) {
    if (!linux_path || !windows_path || buffer_size == 0) {
        return LSW_ERROR_INVALID_PARAMETER;
    }

    // Check for /mnt/ prefix
    if (strncmp(linux_path, "/mnt/", 5) == 0 && linux_path[6] == '/') {
        char drive = toupper(linux_path[5]);
        
        // Build Windows path: C:\...
        int written = snprintf(windows_path, buffer_size, "%c:", drive);
        if (written < 0 || (size_t)written >= buffer_size) {
            return LSW_ERROR_INVALID_PARAMETER;
        }
        
        // Copy rest, converting slashes to backslashes
        const char* path_part = linux_path + 6;  // Skip /mnt/c
        size_t pos = written;
        while (*path_part && pos < buffer_size - 1) {
            windows_path[pos++] = (*path_part == '/') ? '\\' : *path_part;
            path_part++;
        }
        windows_path[pos] = '\0';
        
    } else {
        // Not a /mnt path - convert slashes anyway
        size_t i;
        for (i = 0; i < buffer_size - 1 && linux_path[i]; i++) {
            windows_path[i] = (linux_path[i] == '/') ? '\\' : linux_path[i];
        }
        windows_path[i] = '\0';
    }
    
    return LSW_SUCCESS;
}

// ============================================================================
// SECTION: Path Operations
// ============================================================================

/**
 * Normalize Windows path
 * 
 * What: Standardize path format
 * Why: Handle different input styles
 * How: Convert all to backslashes, resolve . and ..
 */
lsw_status_t lsw_fs_normalize_path(
    const char* input_path,
    char* output_path,
    size_t buffer_size
) {
    if (!input_path || !output_path || buffer_size == 0) {
        return LSW_ERROR_INVALID_PARAMETER;
    }

    // Convert forward slashes to backslashes
    size_t i;
    for (i = 0; i < buffer_size - 1 && input_path[i]; i++) {
        output_path[i] = (input_path[i] == '/') ? '\\' : input_path[i];
    }
    output_path[i] = '\0';
    
    // TODO: Resolve . and .. components
    
    return LSW_SUCCESS;
}

/**
 * Check if path exists
 * 
 * What: Verify file/directory exists
 * Why: Validate before operations
 * How: Translate to Linux path, stat it
 */
bool lsw_fs_path_exists(const char* windows_path) {
    if (!windows_path) {
        return false;
    }

    // Translate to Linux path
    char linux_path[LSW_MAX_PATH];
    if (lsw_fs_win_to_linux(windows_path, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        return false;
    }
    
    // Check if it exists
    struct stat st;
    return (stat(linux_path, &st) == 0);
}

/**
 * Get drive letter from path
 * 
 * What: Extract C from C:\Windows
 * Why: Needed for drive operations
 * How: Check second character for colon
 */
char lsw_fs_get_drive_letter(const char* windows_path) {
    if (!windows_path || strlen(windows_path) < 2) {
        return '\0';
    }
    
    if (windows_path[1] == ':') {
        return toupper(windows_path[0]);
    }
    
    return '\0';
}

// ============================================================================
// SECTION: Special Folders
// ============================================================================

/**
 * Get Windows special folder path
 * 
 * What: Return path for system folders
 * Why: Apps need to find Windows, System32, etc.
 * How: Map to Linux mount points
 */
lsw_status_t lsw_fs_get_special_folder(
    const char* folder_name,
    char* path_buffer,
    size_t buffer_size
) {
    if (!folder_name || !path_buffer || buffer_size == 0) {
        return LSW_ERROR_INVALID_PARAMETER;
    }

    // Common Windows special folders
    if (strcmp(folder_name, "WINDOWS") == 0) {
        snprintf(path_buffer, buffer_size, "C:\\Windows");
    } else if (strcmp(folder_name, "SYSTEM32") == 0) {
        snprintf(path_buffer, buffer_size, "C:\\Windows\\System32");
    } else if (strcmp(folder_name, "PROGRAMFILES") == 0) {
        snprintf(path_buffer, buffer_size, "C:\\Program Files");
    } else if (strcmp(folder_name, "PROGRAMFILES_X86") == 0) {
        snprintf(path_buffer, buffer_size, "C:\\Program Files (x86)");
    } else if (strcmp(folder_name, "TEMP") == 0) {
        snprintf(path_buffer, buffer_size, "C:\\Windows\\Temp");
    } else {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    return LSW_SUCCESS;
}
