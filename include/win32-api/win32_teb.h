/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * Win32 TEB/PEB - Thread Environment Block structures
 */

#ifndef LSW_WIN32_TEB_H
#define LSW_WIN32_TEB_H

#include <stdint.h>

// Minimal TEB (Thread Environment Block) structure
// Located at %gs:0 on x64, %fs:0 on x86
typedef struct {
    void* ExceptionList;              // 0x00
    void* StackBase;                   // 0x08
    void* StackLimit;                  // 0x10
    void* SubSystemTib;                // 0x18
    void* FiberData;                   // 0x20
    void* ArbitraryUserPointer;        // 0x28
    void* Self;                        // 0x30 - Points to itself
    void* EnvironmentPointer;          // 0x38
    uint64_t ProcessId;                // 0x40
    uint64_t ThreadId;                 // 0x48
    void* ActiveRpcHandle;             // 0x50
    void* ThreadLocalStoragePointer;   // 0x58
    void* ProcessEnvironmentBlock;     // 0x60 - PEB pointer
} win32_teb_t;

// Minimal PEB (Process Environment Block) structure
typedef struct {
    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    uint8_t BitField;
    void* Mutant;
    void* ImageBaseAddress;
    void* Ldr;
    void* ProcessParameters;
} win32_peb_t;

// Initialize TEB/PEB for current thread
int win32_teb_init(void);

// Get current TEB
win32_teb_t* win32_teb_get(void);

#endif // LSW_WIN32_TEB_H
