/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#include "lsw_registry.h"
#include "lsw_config.h"
#include "lsw_log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

// ============================================================================
// SECTION: Registry Storage Structure
// ============================================================================

/*
 * Registry Storage Design:
 * 
 * What: Simple file-based key/value storage
 * Why: Don't need complex database for registry
 * How: Each key is a directory, each value is a file
 * 
 * Example:
 *   HKLM\Software\MyApp\Version = "1.0"
 *   
 *   Stored as:
 *   ~/.local/share/lsw/registry/
 *     HKLM/
 *       Software/
 *         MyApp/
 *           Version.value     (contains "1.0")
 *           Version.type      (contains type info)
 */

// Registry handle structure
typedef struct {
    char path[LSW_MAX_PATH];  // Filesystem path to this key
    bool is_open;
} lsw_reg_handle_t;

// Handle table (simple for now)
#define MAX_HANDLES 256
static lsw_reg_handle_t g_handles[MAX_HANDLES];
static bool g_registry_initialized = false;

// ============================================================================
// SECTION: Internal Functions
// ============================================================================

/**
 * Get hkey name
 * 
 * What: Convert hkey enum to string
 * Why: Build filesystem paths
 * How: Switch on enum
 */
static const char* hkey_to_string(lsw_hkey_t hkey) {
    switch (hkey) {
        case LSW_HKEY_CLASSES_ROOT:   return "HKCR";
        case LSW_HKEY_CURRENT_USER:   return "HKCU";
        case LSW_HKEY_LOCAL_MACHINE:  return "HKLM";
        case LSW_HKEY_USERS:          return "HKU";
        case LSW_HKEY_CURRENT_CONFIG: return "HKCC";
        default:                      return NULL;
    }
}

/**
 * Allocate handle
 * 
 * What: Find free handle slot
 * Why: Track open keys
 * How: Linear search through handle table
 */
static HANDLE alloc_handle(const char* path) {
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (!g_handles[i].is_open) {
            g_handles[i].is_open = true;
            strncpy(g_handles[i].path, path, sizeof(g_handles[i].path) - 1);
            g_handles[i].path[sizeof(g_handles[i].path) - 1] = '\0';
            return (HANDLE)(intptr_t)(i + 1);  // Handle 0 is invalid
        }
    }
    return NULL;  // No free handles
}

/**
 * Get handle
 * 
 * What: Look up handle structure
 * Why: Access handle data
 * How: Convert handle to index
 */
static lsw_reg_handle_t* get_handle(HANDLE handle) {
    if (!handle) return NULL;
    
    int index = (int)(intptr_t)handle - 1;
    if (index < 0 || index >= MAX_HANDLES) return NULL;
    if (!g_handles[index].is_open) return NULL;
    
    return &g_handles[index];
}

/**
 * Create directory recursively
 * 
 * What: mkdir -p functionality
 * Why: Registry keys are nested
 * How: Create parent dirs first
 */
static lsw_status_t mkdir_recursive(const char* path) {
    char tmp[LSW_MAX_PATH];
    char* p;
    size_t len = strlen(path);
    
    if (len >= sizeof(tmp)) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    strncpy(tmp, path, sizeof(tmp));
    
    // Create each directory in path
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);  // Ignore errors - dir might exist
            *p = '/';
        }
    }
    
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        LSW_LOG_ERROR("Failed to create directory: %s", tmp);
        return LSW_ERROR_REGISTRY_ERROR;
    }
    
    return LSW_SUCCESS;
}

// ============================================================================
// SECTION: Public API Implementation
// ============================================================================

/**
 * Initialize registry system
 * 
 * What: Create base registry directories
 * Why: First-time setup
 * How: Create HKLM, HKCU, etc. directories
 */
lsw_status_t lsw_reg_init(void) {
    if (g_registry_initialized) {
        return LSW_SUCCESS;
    }
    
    // Get registry base path from config
    lsw_config_t config;
    lsw_config_load(&config);
    
    LSW_LOG_INFO("Initializing registry at: %s", config.registry_path);
    
    // Create base directory
    lsw_status_t status = mkdir_recursive(config.registry_path);
    if (status != LSW_SUCCESS) {
        return status;
    }
    
    // Create hive directories
    const char* hives[] = {"HKLM", "HKCU", "HKCR", "HKU", "HKCC"};
    for (size_t i = 0; i < sizeof(hives) / sizeof(hives[0]); i++) {
        char path[LSW_MAX_PATH];
        snprintf(path, sizeof(path), "%s/%s", config.registry_path, hives[i]);
        mkdir_recursive(path);
    }
    
    // Initialize handle table
    memset(g_handles, 0, sizeof(g_handles));
    
    g_registry_initialized = true;
    LSW_LOG_INFO("Registry initialized successfully");
    
    return LSW_SUCCESS;
}

/**
 * Get registry path
 * 
 * What: Convert HKLM\Software\Test to filesystem path
 * Why: Map registry to files
 * How: Build path from config + hkey + subkey
 */
lsw_status_t lsw_reg_get_path(
    lsw_hkey_t hkey,
    const char* subkey,
    char* path_buffer,
    size_t buffer_size
) {
    if (!path_buffer || buffer_size == 0) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Ensure registry is initialized
    lsw_reg_init();
    
    // Get config for registry base path
    lsw_config_t config;
    lsw_config_load(&config);
    
    // Get hkey name
    const char* hkey_name = hkey_to_string(hkey);
    if (!hkey_name) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Build path: <registry_base>/<HKEY>/<subkey>
    if (subkey && subkey[0]) {
        snprintf(path_buffer, buffer_size, "%s/%s/%s",
                config.registry_path, hkey_name, subkey);
    } else {
        snprintf(path_buffer, buffer_size, "%s/%s",
                config.registry_path, hkey_name);
    }
    
    // Convert backslashes to forward slashes for Linux paths
    for (char* p = path_buffer; *p; p++) {
        if (*p == '\\') *p = '/';
    }
    
    return LSW_SUCCESS;
}

/**
 * Open registry key
 * 
 * What: Open existing key
 * Why: Read values from key
 * How: Check if directory exists, allocate handle
 */
lsw_status_t lsw_reg_open_key(
    lsw_hkey_t hkey,
    const char* subkey,
    HANDLE* out_handle
) {
    if (!out_handle) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Ensure registry initialized
    lsw_reg_init();
    
    // Get filesystem path
    char path[LSW_MAX_PATH];
    lsw_status_t status = lsw_reg_get_path(hkey, subkey, path, sizeof(path));
    if (status != LSW_SUCCESS) {
        return status;
    }
    
    // Check if key exists
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        LSW_LOG_DEBUG("Registry key not found: %s", path);
        return LSW_ERROR_FILE_NOT_FOUND;
    }
    
    // Allocate handle
    HANDLE handle = alloc_handle(path);
    if (!handle) {
        LSW_LOG_ERROR("No free registry handles");
        return LSW_ERROR_OUT_OF_MEMORY;
    }
    
    *out_handle = handle;
    LSW_LOG_DEBUG("Opened registry key: %s", path);
    
    return LSW_SUCCESS;
}

/**
 * Create registry key
 * 
 * What: Create new key or open existing
 * Why: Apps create their own keys
 * How: Create directory, allocate handle
 */
lsw_status_t lsw_reg_create_key(
    lsw_hkey_t hkey,
    const char* subkey,
    HANDLE* out_handle
) {
    if (!out_handle) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Ensure registry initialized
    lsw_reg_init();
    
    // Get filesystem path
    char path[LSW_MAX_PATH];
    lsw_status_t status = lsw_reg_get_path(hkey, subkey, path, sizeof(path));
    if (status != LSW_SUCCESS) {
        return status;
    }
    
    // Create directory (recursive)
    status = mkdir_recursive(path);
    if (status != LSW_SUCCESS) {
        return status;
    }
    
    // Allocate handle
    HANDLE handle = alloc_handle(path);
    if (!handle) {
        LSW_LOG_ERROR("No free registry handles");
        return LSW_ERROR_OUT_OF_MEMORY;
    }
    
    *out_handle = handle;
    LSW_LOG_DEBUG("Created registry key: %s", path);
    
    return LSW_SUCCESS;
}

/**
 * Close registry key
 * 
 * What: Release handle
 * Why: Free resources
 * How: Mark handle as closed
 */
lsw_status_t lsw_reg_close_key(HANDLE handle) {
    lsw_reg_handle_t* h = get_handle(handle);
    if (!h) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    h->is_open = false;
    LSW_LOG_DEBUG("Closed registry key: %s", h->path);
    
    return LSW_SUCCESS;
}

// ============================================================================
// SECTION: Value Operations (simplified for now)
// ============================================================================

/**
 * Set registry value
 * 
 * What: Write value to key
 * Why: Apps save configuration
 * How: Write to file in key directory
 */
lsw_status_t lsw_reg_set_value(
    HANDLE handle,
    const char* value_name,
    lsw_reg_type_t type,
    const void* data,
    size_t data_size
) {
    lsw_reg_handle_t* h = get_handle(handle);
    if (!h || !value_name || !data) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Build value file path
    char value_path[LSW_MAX_PATH];
    snprintf(value_path, sizeof(value_path), "%s/%s.value", h->path, value_name);
    
    // Write value data
    FILE* f = fopen(value_path, "wb");
    if (!f) {
        LSW_LOG_ERROR("Failed to write registry value: %s", value_path);
        return LSW_ERROR_REGISTRY_ERROR;
    }
    
    // Write type and size first
    fwrite(&type, sizeof(type), 1, f);
    fwrite(&data_size, sizeof(data_size), 1, f);
    
    // Write actual data
    fwrite(data, data_size, 1, f);
    fclose(f);
    
    LSW_LOG_DEBUG("Set registry value: %s = %zu bytes", value_name, data_size);
    
    return LSW_SUCCESS;
}

/**
 * Query registry value
 * 
 * What: Read value from key
 * Why: Apps read configuration
 * How: Read from file in key directory
 */
lsw_status_t lsw_reg_query_value(
    HANDLE handle,
    const char* value_name,
    lsw_reg_type_t* type,
    void* data,
    size_t* data_size
) {
    lsw_reg_handle_t* h = get_handle(handle);
    if (!h || !value_name || !data_size) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Build value file path
    char value_path[LSW_MAX_PATH];
    snprintf(value_path, sizeof(value_path), "%s/%s.value", h->path, value_name);
    
    // Read value data
    FILE* f = fopen(value_path, "rb");
    if (!f) {
        LSW_LOG_DEBUG("Registry value not found: %s", value_path);
        return LSW_ERROR_FILE_NOT_FOUND;
    }
    
    // Read type and size
    lsw_reg_type_t stored_type;
    size_t stored_size;
    fread(&stored_type, sizeof(stored_type), 1, f);
    fread(&stored_size, sizeof(stored_size), 1, f);
    
    if (type) *type = stored_type;
    
    // Check buffer size
    if (data && *data_size >= stored_size) {
        fread(data, stored_size, 1, f);
    }
    
    *data_size = stored_size;
    fclose(f);
    
    LSW_LOG_DEBUG("Queried registry value: %s = %zu bytes", value_name, stored_size);
    
    return LSW_SUCCESS;
}

// TODO: Implement remaining functions (delete, enum) as needed

// ============================================================================
// SECTION: Registry Environment Population
// ============================================================================

/**
 * Populate default registry environment
 * 
 * What: Pre-populate registry with Windows system keys
 * Why: Apps expect these keys to exist
 * How: Create standard Windows registry structure
 */
lsw_status_t lsw_reg_populate_environment(void) {
    LSW_LOG_INFO("Populating registry with default environment");
    
    HANDLE hkey;
    lsw_status_t status;
    DWORD dword_value;
    
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
    status = lsw_reg_create_key(LSW_HKEY_LOCAL_MACHINE, 
                                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 
                                 &hkey);
    if (status == LSW_SUCCESS) {
        const char* product_name = "Windows 10 Pro";
        lsw_reg_set_value(hkey, "ProductName", LSW_REG_SZ, 
                         product_name, strlen(product_name) + 1);
        
        const char* version = "10.0";
        lsw_reg_set_value(hkey, "CurrentVersion", LSW_REG_SZ,
                         version, strlen(version) + 1);
        
        const char* build = "19045";
        lsw_reg_set_value(hkey, "CurrentBuildNumber", LSW_REG_SZ,
                         build, strlen(build) + 1);
        
        const char* program_files = "C:\\Program Files";
        lsw_reg_set_value(hkey, "ProgramFilesDir", LSW_REG_SZ,
                         program_files, strlen(program_files) + 1);
        
        lsw_reg_close_key(hkey);
        LSW_LOG_INFO("Created Windows CurrentVersion keys");
    }
    
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    status = lsw_reg_create_key(LSW_HKEY_LOCAL_MACHINE,
                                 "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                 &hkey);
    if (status == LSW_SUCCESS) {
        dword_value = 10;
        lsw_reg_set_value(hkey, "CurrentMajorVersionNumber", LSW_REG_DWORD,
                         &dword_value, sizeof(dword_value));
        
        dword_value = 0;
        lsw_reg_set_value(hkey, "CurrentMinorVersionNumber", LSW_REG_DWORD,
                         &dword_value, sizeof(dword_value));
        
        const char* build_lab = "19045.lsw.barrersoftware";
        lsw_reg_set_value(hkey, "BuildLab", LSW_REG_SZ,
                         build_lab, strlen(build_lab) + 1);
        
        lsw_reg_close_key(hkey);
        LSW_LOG_INFO("Created Windows NT CurrentVersion keys");
    }
    
    // System environment
    status = lsw_reg_create_key(LSW_HKEY_LOCAL_MACHINE,
                                 "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                                 &hkey);
    if (status == LSW_SUCCESS) {
        const char* arch = "AMD64";
        lsw_reg_set_value(hkey, "PROCESSOR_ARCHITECTURE", LSW_REG_SZ,
                         arch, strlen(arch) + 1);
        
        char num_proc[16];
        snprintf(num_proc, sizeof(num_proc), "%ld", sysconf(_SC_NPROCESSORS_ONLN));
        lsw_reg_set_value(hkey, "NUMBER_OF_PROCESSORS", LSW_REG_SZ,
                         num_proc, strlen(num_proc) + 1);
        
        const char* windir = "C:\\Windows";
        lsw_reg_set_value(hkey, "windir", LSW_REG_SZ,
                         windir, strlen(windir) + 1);
        lsw_reg_set_value(hkey, "SystemRoot", LSW_REG_SZ,
                         windir, strlen(windir) + 1);
        
        lsw_reg_close_key(hkey);
        LSW_LOG_INFO("Created system environment variables");
    }
    
    LSW_LOG_INFO("Registry environment population complete");
    return LSW_SUCCESS;
}
