/*
 * Copyright (c) 2025 BarrerSoftware
 * 
 * This file is part of LSW (Linux Subsystem for Windows).
 * 
 * Licensed under the BarrerSoftware License (BSL) v1.0
 * 
 * This software is FREE and must remain FREE forever.
 * You may use, modify, and distribute it, but you MAY NOT
 * sell it or charge for access to it.
 * 
 * See LICENSE file for full terms.
 * 
 * If it's free, it's free. Period.
 */

#ifndef LSW_TYPES_H
#define LSW_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * LSW Common Types and Definitions
 * 
 * Core data types used throughout the LSW project.
 * Designed for clarity and cross-platform compatibility.
 */

// ============================================================================
// SECTION: Basic Types
// ============================================================================

// Windows-compatible basic types
typedef uint8_t  BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef int32_t  LONG;
typedef void*    HANDLE;
typedef char*    LPSTR;
typedef const char* LPCSTR;

// Boolean type (Windows compatibility)
#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

// ============================================================================
// SECTION: Status Codes
// ============================================================================

typedef enum {
    LSW_SUCCESS = 0,
    LSW_ERROR_INVALID_PARAMETER,
    LSW_ERROR_OUT_OF_MEMORY,
    LSW_ERROR_FILE_NOT_FOUND,
    LSW_ERROR_ACCESS_DENIED,
    LSW_ERROR_INVALID_EXECUTABLE,
    LSW_ERROR_UNSUPPORTED_FORMAT,
    LSW_ERROR_REGISTRY_ERROR,
    LSW_ERROR_DLL_LOAD_FAILED,
    LSW_ERROR_UNKNOWN
} lsw_status_t;

// ============================================================================
// SECTION: Windows Version
// ============================================================================

typedef enum {
    LSW_WIN_XP = 0,
    LSW_WIN_VISTA,
    LSW_WIN_7,
    LSW_WIN_8,
    LSW_WIN_8_1,
    LSW_WIN_10,
    LSW_WIN_11,
    LSW_WIN_AUTO  // Auto-detect
} lsw_windows_version_t;

// ============================================================================
// SECTION: Path Types
// ============================================================================

#define LSW_MAX_PATH 4096

typedef struct {
    char windows_path[LSW_MAX_PATH];  // e.g., "C:\Windows\System32"
    char linux_path[LSW_MAX_PATH];    // e.g., "/mnt/c/Windows/System32"
} lsw_path_t;

// ============================================================================
// SECTION: Registry Types
// ============================================================================

typedef enum {
    LSW_REG_NONE = 0,
    LSW_REG_SZ,        // String
    LSW_REG_EXPAND_SZ, // Expandable string
    LSW_REG_BINARY,    // Binary data
    LSW_REG_DWORD,     // 32-bit number
    LSW_REG_QWORD      // 64-bit number
} lsw_reg_type_t;

typedef enum {
    LSW_HKEY_CLASSES_ROOT = 0,
    LSW_HKEY_CURRENT_USER,
    LSW_HKEY_LOCAL_MACHINE,
    LSW_HKEY_USERS,
    LSW_HKEY_CURRENT_CONFIG
} lsw_hkey_t;

// ============================================================================
// SECTION: PE Format Types
// ============================================================================

typedef struct {
    WORD  machine;               // Architecture (x86, x64, ARM)
    WORD  number_of_sections;    // Number of PE sections
    DWORD time_date_stamp;       // Compilation timestamp
    DWORD pointer_to_symbol_table;
    DWORD number_of_symbols;
    WORD  size_of_optional_header;
    WORD  characteristics;       // PE characteristics flags
} lsw_pe_header_t;

typedef struct {
    WORD  magic;                 // PE32 or PE32+ magic
    BYTE  major_linker_version;
    BYTE  minor_linker_version;
    DWORD size_of_code;
    DWORD size_of_initialized_data;
    DWORD size_of_uninitialized_data;
    DWORD address_of_entry_point;
    DWORD base_of_code;
    QWORD image_base;
    DWORD section_alignment;
    DWORD file_alignment;
    WORD  major_os_version;
    WORD  minor_os_version;
    WORD  major_subsystem_version;
    WORD  minor_subsystem_version;
    DWORD size_of_image;
    DWORD size_of_headers;
    DWORD checksum;
    WORD  subsystem;
    WORD  dll_characteristics;
} lsw_pe_optional_header_t;

// ============================================================================
// SECTION: Process Information
// ============================================================================

typedef struct {
    uint32_t           pid;              // Process ID
    char               name[256];        // Process name
    lsw_windows_version_t win_version;   // Target Windows version
    void*              base_address;     // Process base address
    size_t             memory_size;      // Allocated memory
    bool               is_64bit;         // 64-bit process?
} lsw_process_info_t;

// ============================================================================
// SECTION: Logging and Debug
// ============================================================================

typedef enum {
    LSW_LOG_ERROR = 0,
    LSW_LOG_WARN,
    LSW_LOG_INFO,
    LSW_LOG_DEBUG,
    LSW_LOG_TRACE
} lsw_log_level_t;

// ============================================================================
// SECTION: Configuration
// ============================================================================

typedef struct {
    lsw_windows_version_t default_win_version;
    lsw_log_level_t       log_level;
    bool                  debug_mode;
    bool                  verbose;
    char                  registry_path[LSW_MAX_PATH];
} lsw_config_t;

#endif // LSW_TYPES_H
