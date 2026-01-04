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
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <errno.h>

// Syscall for arch_prctl
#ifndef SYS_arch_prctl
#define SYS_arch_prctl 158
#endif

// Thread-local storage for TEB
static __thread win32_teb_t* current_teb = NULL;
static __thread win32_peb_t* current_peb = NULL;
static __thread win32_process_params_t* current_params = NULL;
static __thread char* command_line_buffer = NULL;

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
    current_teb->LastErrorValue = 0; // No error initially
    current_teb->CountOfOwnedCriticalSections = 0;
    current_teb->CurrentLocale = 0x0409; // English (US)
    
    // Set up a fake stack
    current_teb->StackBase = (void*)0x7fffffffffff;
    current_teb->StackLimit = (void*)0x7ffffff00000;
    
    // Initialize all TLS slots to NULL
    memset(current_teb->TlsSlots, 0, sizeof(current_teb->TlsSlots));
    
    // Initialize PEB
    current_peb->BeingDebugged = 0;
    current_peb->ImageBaseAddress = NULL; // Will be set by PE loader
    current_peb->NumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    current_peb->ProcessHeap = malloc(1); // Dummy heap pointer
    
    // Allocate process parameters
    current_params = calloc(1, sizeof(win32_process_params_t));
    if (!current_params) {
        LSW_LOG_ERROR("Failed to allocate process parameters");
        free(current_peb);
        free(current_teb);
        current_peb = NULL;
        current_teb = NULL;
        return -1;
    }
    current_peb->ProcessParameters = current_params;
    
    LSW_LOG_INFO("TEB initialized at %p, PEB at %p", current_teb, current_peb);
    LSW_LOG_INFO("PID=%lu, TID=%lu, Processors=%u", 
                 current_teb->ProcessId, current_teb->ThreadId, current_peb->NumberOfProcessors);
    
    // Set GS register to point to TEB (x64 Windows uses gs:)
    // This allows Windows code to access TEB via gs:0x30, etc.
    long ret = syscall(SYS_arch_prctl, ARCH_SET_GS, current_teb);
    if (ret != 0) {
        LSW_LOG_WARN("Failed to set GS register: %s (error %d)", strerror(errno), errno);
        LSW_LOG_WARN("TEB allocated but not accessible via gs: register");
        LSW_LOG_WARN("Windows code that accesses TEB may crash");
    } else {
        LSW_LOG_INFO("✅ GS register set to TEB at %p", current_teb);
        LSW_LOG_INFO("Windows code can now access TEB via gs: segment");
    }
    
    return 0;
}

win32_teb_t* win32_teb_get(void) {
    return current_teb;
}

void win32_set_command_line(int argc, char** argv) {
    if (!current_params) {
        LSW_LOG_ERROR("Process parameters not initialized");
        return;
    }
    
    // Free old command line if exists
    if (command_line_buffer) {
        free(command_line_buffer);
        command_line_buffer = NULL;
    }
    
    // Build Windows-style command line from argv
    // Format: "program.exe" arg1 arg2 "arg with spaces"
    size_t total_len = 0;
    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            total_len += strlen(argv[i]) + 3; // +3 for quotes and space
        }
    }
    
    command_line_buffer = malloc(total_len + 1);
    if (!command_line_buffer) {
        LSW_LOG_ERROR("Failed to allocate command line buffer");
        return;
    }
    
    char* ptr = command_line_buffer;
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) continue;
        
        // Add quotes if arg contains spaces
        int has_space = strchr(argv[i], ' ') != NULL;
        if (has_space) *ptr++ = '"';
        
        strcpy(ptr, argv[i]);
        ptr += strlen(argv[i]);
        
        if (has_space) *ptr++ = '"';
        
        // Add space between args (but not after last one)
        if (i < argc - 1) *ptr++ = ' ';
    }
    *ptr = '\0';
    
    current_params->CommandLine = command_line_buffer;
    current_params->Length = strlen(command_line_buffer);
    current_params->MaximumLength = total_len + 1;
    
    LSW_LOG_INFO("Command line set: '%s'", command_line_buffer);
}

const char* win32_get_command_line(void) {
    if (!current_params || !current_params->CommandLine) {
        return "";
    }
    return current_params->CommandLine;
}
