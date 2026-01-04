/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#include "lsw_filesystem.h"
#include "lsw_config.h"
#include "lsw_log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>

// Global config (loaded at startup)
static lsw_config_t g_config;
static bool g_config_loaded = false;

// Ensure config is loaded
static void ensure_config(void) {
    if (!g_config_loaded) {
        lsw_config_load(&g_config);
        g_config_loaded = true;
    }
}

// ============================================================================
// SECTION: Path Translation
// ============================================================================

/**
 * Convert Windows path to Linux path
 * 
 * What: C:\Windows\System32 → <drive_root>/Windows/System32
 * Why: Linux kernel needs Linux paths
 * How: Look up drive mapping in config, replace backslashes
 */
lsw_status_t lsw_fs_win_to_linux(
    const char* windows_path,
    char* linux_path,
    size_t buffer_size
) {
    if (!windows_path || !linux_path || buffer_size == 0) {
        return LSW_ERROR_INVALID_PARAMETER;
    }

    // Load config if needed
    ensure_config();

    // Check for drive letter (C:, D:, etc.)
    if (strlen(windows_path) >= 2 && windows_path[1] == ':') {
        char drive = toupper(windows_path[0]);
        
        // Get drive root from config
        const char* drive_root = lsw_config_get_drive_root(&g_config, drive);
        if (!drive_root) {
            // Unknown drive
            return LSW_ERROR_INVALID_PARAMETER;
        }
        
        // Build Linux path: <drive_root>/...
        // Handle root drive (/) specially to avoid double slash
        size_t pos = 0;
        if (strcmp(drive_root, "/") == 0) {
            // Root drive - don't add extra slash
            linux_path[pos++] = '/';
        } else {
            // Non-root drive - copy full path
            int written = snprintf(linux_path, buffer_size, "%s", drive_root);
            if (written < 0 || (size_t)written >= buffer_size) {
                return LSW_ERROR_INVALID_PARAMETER;
            }
            pos = written;
        }
        
        // Skip drive letter (C:) and leading backslash if present
        const char* path_part = windows_path + 2;
        if (*path_part == '\\' || *path_part == '/') {
            path_part++;  // Skip the leading slash
        }
        
        // Add separator slash between drive root and path
        if (pos > 0 && linux_path[pos-1] != '/') {
            linux_path[pos++] = '/';
        }
        
        // Copy rest of path, converting backslashes to forward slashes
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
 * What: <drive_root>/Windows → C:\Windows  
 * Why: Some Windows APIs expect Windows paths
 * How: Detect which drive root matches, build Windows path
 */
lsw_status_t lsw_fs_linux_to_win(
    const char* linux_path,
    char* windows_path,
    size_t buffer_size
) {
    if (!linux_path || !windows_path || buffer_size == 0) {
        return LSW_ERROR_INVALID_PARAMETER;
    }

    // Load config if needed
    ensure_config();

    // Check if path starts with C: drive root
    const char* c_root = g_config.c_drive_root;
    size_t c_root_len = strlen(c_root);
    
    if (strncmp(linux_path, c_root, c_root_len) == 0) {
        // It's on C: drive
        const char* path_part = linux_path + c_root_len;
        
        // Build Windows path: C:\...
        int written = snprintf(windows_path, buffer_size, "C:");
        if (written < 0 || (size_t)written >= buffer_size) {
            return LSW_ERROR_INVALID_PARAMETER;
        }
        
        // Copy rest, converting slashes to backslashes
        size_t pos = written;
        while (*path_part && pos < buffer_size - 1) {
            windows_path[pos++] = (*path_part == '/') ? '\\' : *path_part;
            path_part++;
        }
        windows_path[pos] = '\0';
        
    } else {
        // Not a known drive - convert slashes anyway
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

// ============================================================================
// SECTION: Prefix Management
// ============================================================================

/**
 * Initialize LSW prefix structure
 * Creates ~/.lsw/drives/c/ with Windows directory structure
 */
lsw_status_t lsw_fs_init_prefix(void) {
    ensure_config();
    
    LSW_LOG_INFO("Initializing LSW prefix structure");
    
    // Config already handles SUDO_USER detection
    const char* c_root = g_config.c_drive_root;
    
    LSW_LOG_INFO("C: drive root: %s", c_root);
    
    // Extract home from c_root (remove /.lsw/drives/c suffix)
    char home[LSW_MAX_PATH];
    strncpy(home, c_root, sizeof(home) - 1);
    home[sizeof(home) - 1] = '\0';
    
    // Find the /.lsw part and truncate there
    char* lsw_pos = strstr(home, "/.lsw");
    if (!lsw_pos) {
        LSW_LOG_WARN("Could not find /.lsw in path: %s", c_root);
        return LSW_ERROR_INVALID_PARAMETER;
    }
    *lsw_pos = '\0';
    
    LSW_LOG_INFO("User home: %s", home);
    
    char path[LSW_MAX_PATH];
    
    // Create base: ~/.lsw/
    snprintf(path, sizeof(path), "%s/.lsw", home);
    LSW_LOG_INFO("Creating: %s", path);
    mkdir(path, 0755);
    
    // Create: ~/.lsw/drives/
    snprintf(path, sizeof(path), "%s/.lsw/drives", home);
    LSW_LOG_INFO("Creating: %s", path);
    mkdir(path, 0755);
    
    // Create: C: drive root
    LSW_LOG_INFO("Creating: %s", c_root);
    mkdir(c_root, 0755);
    
    LSW_LOG_INFO("LSW prefix initialized successfully");
    
    // Create: Windows/
    snprintf(path, sizeof(path), "%s/Windows", c_root);
    mkdir(path, 0755);
    
    // Create: Windows/System32/
    snprintf(path, sizeof(path), "%s/Windows/System32", c_root);
    mkdir(path, 0755);
    
    // Create: Windows/Temp/
    snprintf(path, sizeof(path), "%s/Windows/Temp", c_root);
    mkdir(path, 0755);
    
    // Create: Program Files/
    snprintf(path, sizeof(path), "%s/Program Files", c_root);
    mkdir(path, 0755);
    
    // Create: Users/
    snprintf(path, sizeof(path), "%s/Users", c_root);
    mkdir(path, 0755);
    
    const char* user = getenv("USER");
    if (user) {
        snprintf(path, sizeof(path), "%s/Users/%s", c_root, user);
        mkdir(path, 0755);
    }
    
    // Create: Registry
    snprintf(path, sizeof(path), "%s/.lsw/registry", home);
    mkdir(path, 0755);
    
    return LSW_SUCCESS;
}
