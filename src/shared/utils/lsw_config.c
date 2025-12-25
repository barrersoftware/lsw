/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#include "lsw_config.h"
#include "lsw_log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

// ============================================================================
// SECTION: Default Configuration
// ============================================================================

/**
 * Get default configuration
 * 
 * What: Sensible defaults that work out of box
 * Why: User shouldn't need to configure anything
 * How: Set values that make sense for most users
 */
void lsw_config_defaults(lsw_config_t* config) {
    if (!config) return;
    
    memset(config, 0, sizeof(lsw_config_t));
    
    // Filesystem - C: drive maps to root by default
    strncpy(config->c_drive_root, "/", sizeof(config->c_drive_root));
    
    // D: drive optional (user can configure)
    config->d_drive_root[0] = '\0';
    
    // Registry in user's home directory
    const char* home = getenv("HOME");
    if (home) {
        snprintf(config->registry_path, sizeof(config->registry_path),
                "%s/.local/share/lsw/registry", home);
    } else {
        strncpy(config->registry_path, "/tmp/lsw/registry", 
               sizeof(config->registry_path));
    }
    
    // Windows emulation defaults
    config->default_win_version = LSW_WIN_10;
    config->auto_detect_version = true;
    
    // CPU emulation defaults
    config->emulated_cpu_speed_mhz = 0;   // 0 = native speed (no throttling)
    config->enable_cpu_throttling = false;
    
    // Logging
    config->log_level = LSW_LOG_INFO;
    config->debug_mode = false;
    config->verbose = false;
    config->strict_mode = false;
    
    // Fake Windows directories (relative to C: drive root)
    strncpy(config->windows_dir, "Windows", sizeof(config->windows_dir));
    strncpy(config->system32_dir, "Windows/System32", sizeof(config->system32_dir));
    strncpy(config->program_files, "Program Files", sizeof(config->program_files));
    strncpy(config->temp_dir, "tmp", sizeof(config->temp_dir));
    
    LSW_LOG_DEBUG("Initialized default configuration");
    LSW_LOG_DEBUG("  C: drive root: %s", config->c_drive_root);
    LSW_LOG_DEBUG("  Registry: %s", config->registry_path);
}

// ============================================================================
// SECTION: Configuration Loading
// ============================================================================

/**
 * Load configuration from file
 * 
 * What: Read config file if it exists
 * Why: User customization
 * How: Try multiple locations, parse INI-style format
 */
lsw_status_t lsw_config_load(lsw_config_t* config) {
    if (!config) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Start with defaults
    lsw_config_defaults(config);
    
    // Try config file locations
    const char* config_paths[] = {
        "./lsw.conf",                              // Current directory
        NULL,                                       // User config (set below)
        "/etc/lsw/lsw.conf",                       // System config
        NULL
    };
    
    // Build user config path
    char user_config[LSW_MAX_PATH];
    const char* home = getenv("HOME");
    if (home) {
        snprintf(user_config, sizeof(user_config), 
                "%s/.config/lsw/lsw.conf", home);
        config_paths[1] = user_config;
    }
    
    // Try each location
    for (int i = 0; config_paths[i]; i++) {
        struct stat st;
        if (stat(config_paths[i], &st) == 0) {
            LSW_LOG_INFO("Loading config from: %s", config_paths[i]);
            // TODO: Parse config file
            // For now, just use defaults
            return LSW_SUCCESS;
        }
    }
    
    LSW_LOG_INFO("No config file found, using defaults");
    return LSW_SUCCESS;
}

// ============================================================================
// SECTION: Drive Mapping
// ============================================================================

/**
 * Get drive root path
 * 
 * What: Get Linux path for drive letter
 * Why: Centralized drive mapping logic
 * How: Look up in config structure
 */
const char* lsw_config_get_drive_root(const lsw_config_t* config, char drive_letter) {
    if (!config) {
        return "/";  // Safe default
    }
    
    char upper = toupper(drive_letter);
    
    switch (upper) {
        case 'C':
            return config->c_drive_root;
        case 'D':
            return config->d_drive_root[0] ? config->d_drive_root : NULL;
        default:
            return NULL;
    }
}

// ============================================================================
// SECTION: Configuration Saving
// ============================================================================

/**
 * Save configuration
 * 
 * What: Write config to user directory
 * Why: Persist user settings
 * How: Create directory if needed, write INI format
 */
lsw_status_t lsw_config_save(const lsw_config_t* config) {
    if (!config) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // Get user config directory
    const char* home = getenv("HOME");
    if (!home) {
        LSW_LOG_ERROR("Cannot save config: HOME not set");
        return LSW_ERROR_ACCESS_DENIED;
    }
    
    char config_dir[LSW_MAX_PATH];
    char config_file[LSW_MAX_PATH];
    
    snprintf(config_dir, sizeof(config_dir), "%s/.config/lsw", home);
    snprintf(config_file, sizeof(config_file), "%s/lsw.conf", config_dir);
    
    // Create directory if needed
    mkdir(config_dir, 0755);
    
    // Open file for writing
    FILE* f = fopen(config_file, "w");
    if (!f) {
        LSW_LOG_ERROR("Cannot write config file: %s", config_file);
        return LSW_ERROR_ACCESS_DENIED;
    }
    
    // Write INI-style config
    fprintf(f, "# LSW Configuration\n");
    fprintf(f, "# https://lsw.barrersoftware.com\n\n");
    
    fprintf(f, "[filesystem]\n");
    fprintf(f, "c_drive = %s\n", config->c_drive_root);
    if (config->d_drive_root[0]) {
        fprintf(f, "d_drive = %s\n", config->d_drive_root);
    }
    fprintf(f, "registry = %s\n\n", config->registry_path);
    
    fprintf(f, "[windows]\n");
    fprintf(f, "version = %d\n", config->default_win_version);
    fprintf(f, "auto_detect = %s\n\n", config->auto_detect_version ? "true" : "false");
    
    fprintf(f, "[cpu]\n");
    fprintf(f, "# CPU speed emulation (0 = native speed, no throttling)\n");
    fprintf(f, "# Examples: 5 (IBM PC), 25 (486), 100 (Pentium), 500 (Pentium III)\n");
    fprintf(f, "speed_mhz = %u\n", config->emulated_cpu_speed_mhz);
    fprintf(f, "throttling = %s\n\n", config->enable_cpu_throttling ? "true" : "false");
    
    fprintf(f, "[logging]\n");
    fprintf(f, "level = %d\n", config->log_level);
    fprintf(f, "debug = %s\n", config->debug_mode ? "true" : "false");
    
    fclose(f);
    
    LSW_LOG_INFO("Configuration saved to: %s", config_file);
    return LSW_SUCCESS;
}
