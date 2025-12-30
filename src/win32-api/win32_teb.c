/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * Win32 TEB/PEB - Thread Environment Block implementation
 */

#include "win32_teb.h"
#include "lsw_log.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

// Thread-local storage for TEB
static __thread win32_teb_t* current_teb = NULL;
static __thread win32_peb_t* current_peb = NULL;

int win32_teb_init(void) {
    if (current_teb) {
        return 0; // Already initialized
    }
    
    // Allocate TEB
    current_teb = calloc(1, sizeof(win32_teb_t));
    if (!current_teb) {
        LSW_LOG_ERROR("Failed to allocate TEB");
        return -1;
    }
    
    // Allocate PEB
    current_peb = calloc(1, sizeof(win32_peb_t));
    if (!current_peb) {
        LSW_LOG_ERROR("Failed to allocate PEB");
        free(current_teb);
        current_teb = NULL;
        return -1;
    }
    
    // Initialize TEB
    current_teb->Self = current_teb; // Points to itself at offset 0x30
    current_teb->ProcessEnvironmentBlock = current_peb;
    current_teb->ProcessId = getpid();
    current_teb->ThreadId = gettid();
    
    // Set up a fake stack
    current_teb->StackBase = (void*)0x7fffffffffff;
    current_teb->StackLimit = (void*)0x7ffffff00000;
    
    // Initialize PEB
    current_peb->BeingDebugged = 0;
    current_peb->ImageBaseAddress = NULL; // Will be set by PE loader
    
    LSW_LOG_DEBUG("TEB initialized at %p, PEB at %p", current_teb, current_peb);
    LSW_LOG_DEBUG("PID=%lu, TID=%lu", current_teb->ProcessId, current_teb->ThreadId);
    
    // Note: We can't actually set %gs to point to TEB on Linux userspace
    // The CRT code will need to be patched or we need to use ptrace
    // For now, just having the structure allocated helps with some stubs
    
    return 0;
}

win32_teb_t* win32_teb_get(void) {
    return current_teb;
}
