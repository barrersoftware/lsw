/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#include "lsw_log.h"
#include <stdarg.h>
#include <time.h>
#include <string.h>

// Global log level (default: INFO)
lsw_log_level_t g_lsw_log_level = LSW_LOG_INFO;

// ANSI color codes for pretty output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_GRAY    "\033[0;37m"

/**
 * Core logging function
 * 
 * What: Output formatted log message
 * Why: Debug and inform users
 * How: Format with colors, timestamp, location
 */
void lsw_log(
    lsw_log_level_t level,
    const char* file,
    int line,
    const char* format,
    ...
) {
    // Skip if level too low
    if (level > g_lsw_log_level) {
        return;
    }

    // Get timestamp
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_buffer[32];
    strftime(time_buffer, sizeof(time_buffer), "%H:%M:%S", tm_info);
    
    // Choose color based on level
    const char* color;
    const char* level_name;
    
    switch (level) {
        case LSW_LOG_ERROR:
            color = COLOR_RED;
            level_name = "ERROR";
            break;
        case LSW_LOG_WARN:
            color = COLOR_YELLOW;
            level_name = "WARN ";
            break;
        case LSW_LOG_INFO:
            color = COLOR_BLUE;
            level_name = "INFO ";
            break;
        case LSW_LOG_DEBUG:
            color = COLOR_GRAY;
            level_name = "DEBUG";
            break;
        case LSW_LOG_TRACE:
            color = COLOR_GRAY;
            level_name = "TRACE";
            break;
        default:
            color = COLOR_RESET;
            level_name = "?????";
    }
    
    // Extract filename from full path
    const char* filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;
    
    // Print header: [TIME] LEVEL filename:line
    fprintf(stderr, "%s[%s] %s%s %s:%d%s ",
            color, time_buffer, level_name, COLOR_RESET,
            filename, line, COLOR_GRAY);
    
    // Print message
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    
    fprintf(stderr, "%s\n", COLOR_RESET);
}

/**
 * Set log level
 */
void lsw_log_set_level(lsw_log_level_t level) {
    g_lsw_log_level = level;
}

/**
 * Get log level name
 */
const char* lsw_log_level_name(lsw_log_level_t level) {
    switch (level) {
        case LSW_LOG_ERROR: return "ERROR";
        case LSW_LOG_WARN:  return "WARN";
        case LSW_LOG_INFO:  return "INFO";
        case LSW_LOG_DEBUG: return "DEBUG";
        case LSW_LOG_TRACE: return "TRACE";
        default:            return "UNKNOWN";
    }
}
