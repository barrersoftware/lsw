/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#ifndef LSW_CONFIG_H
#define LSW_CONFIG_H

#include "lsw_types.h"
#include <stdbool.h>

/*
 * LSW Configuration System
 * 
 * Config-driven behavior, not hardcoded paths.
 * Philosophy: Make it configurable, sensible defaults.
 */

// ============================================================================
// SECTION: Configuration Structure
// ============================================================================

typedef struct lsw_config {
    // Filesystem configuration
    char c_drive_root[LSW_MAX_PATH];      // Where C: drive maps to (default: "/")
    char d_drive_root[LSW_MAX_PATH];      // Where D: drive maps to (optional)
    char registry_path[LSW_MAX_PATH];     // Registry storage location
    
    // Windows emulation
    lsw_windows_version_t default_win_version;
    bool auto_detect_version;             // Try to detect from PE header
    
    // CPU emulation
    uint32_t emulated_cpu_speed_mhz;      // Target CPU speed (0 = native)
    bool     enable_cpu_throttling;       // Enable speed limiting
    
    // Behavior
    lsw_log_level_t log_level;
    bool debug_mode;
    bool verbose;
    bool strict_mode;                     // Strict Windows compatibility
    
    // Paths
    char windows_dir[LSW_MAX_PATH];       // Fake Windows directory
    char system32_dir[LSW_MAX_PATH];      // Fake System32 directory
    char program_files[LSW_MAX_PATH];     // Fake Program Files
    char temp_dir[LSW_MAX_PATH];          // Temp directory
} lsw_config_t;

// ============================================================================
// SECTION: Configuration Functions
// ============================================================================

/**
 * Load configuration
 * 
 * What: Read config from file or use defaults
 * Why: User-configurable behavior
 * How: Parse config file, fall back to defaults
 * 
 * Config file locations (in order):
 *   1. ./lsw.conf (current directory)
 *   2. ~/.config/lsw/lsw.conf (user config)
 *   3. /etc/lsw/lsw.conf (system config)
 */
lsw_status_t lsw_config_load(lsw_config_t* config);

/**
 * Get default configuration
 * 
 * What: Initialize with sensible defaults
 * Why: Work out of the box
 * How: Set reasonable values
 */
void lsw_config_defaults(lsw_config_t* config);

/**
 * Save configuration
 * 
 * What: Write config to file
 * Why: Persist user settings
 * How: Write to user config directory
 */
lsw_status_t lsw_config_save(const lsw_config_t* config);

/**
 * Get drive root path
 * 
 * What: Get Linux path for drive letter
 * Why: Centralized drive mapping
 * How: Look up in config
 * 
 * Example:
 *   'C' -> "/" or "/opt/lsw/drives/c"
 */
const char* lsw_config_get_drive_root(const lsw_config_t* config, char drive_letter);

#endif // LSW_CONFIG_H
