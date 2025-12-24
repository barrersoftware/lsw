/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#ifndef LSW_LOG_H
#define LSW_LOG_H

#include "lsw_types.h"
#include <stdio.h>

/*
 * LSW Logging System
 * 
 * Simple, clear logging for debugging and user feedback.
 * Philosophy: Error messages should be helpful, not cryptic.
 */

// Global log level
extern lsw_log_level_t g_lsw_log_level;

// ============================================================================
// SECTION: Logging Macros
// ============================================================================

#define LSW_LOG_ERROR(...) lsw_log(LSW_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LSW_LOG_WARN(...)  lsw_log(LSW_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LSW_LOG_INFO(...)  lsw_log(LSW_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LSW_LOG_DEBUG(...) lsw_log(LSW_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LSW_LOG_TRACE(...) lsw_log(LSW_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

// ============================================================================
// SECTION: Logging Functions
// ============================================================================

/**
 * Core logging function
 * 
 * What: Output log message if level is enabled
 * Why: Debugging and user feedback
 * How: Check level, format message, write to stderr
 */
void lsw_log(
    lsw_log_level_t level,
    const char* file,
    int line,
    const char* format,
    ...
);

/**
 * Set log level
 * 
 * What: Control verbosity of output
 * Why: Users want different detail levels
 * How: Set global log level variable
 */
void lsw_log_set_level(lsw_log_level_t level);

/**
 * Get log level name
 * 
 * What: Convert level enum to string
 * Why: For display purposes
 * How: Switch statement
 */
const char* lsw_log_level_name(lsw_log_level_t level);

#endif // LSW_LOG_H
