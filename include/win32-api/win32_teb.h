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
    uint32_t LastErrorValue;           // 0x68 - GetLastError value
    uint32_t CountOfOwnedCriticalSections; // 0x6C
    void* CsrClientThread;             // 0x70
    void* Win32ThreadInfo;             // 0x78
    uint32_t User32Reserved[26];       // 0x80
    uint32_t UserReserved[5];          // 0xE8
    void* WOW32Reserved;               // 0xFC / 0x100
    uint32_t CurrentLocale;            // 0x104
    uint32_t FpSoftwareStatusRegister; // 0x108
    void* ReservedForDebuggerInstrumentation[16]; // 0x10C
    void* SystemReserved1[30];         // 0x18C
    void* PlaceholderCompatibilityMode; // 0x280
    void* PlaceholderReserved[3];      // 0x288
    void* TlsSlots[64];                // 0x1480 - TLS storage
    void* TlsLinks[2];                 // 0x1680
    void* Vdm;                         // 0x1690
    void* ReservedForNtRpc;            // 0x1698
    void* DbgSsReserved[2];            // 0x16A0
} win32_teb_t;

// Minimal PEB (Process Environment Block) structure  
typedef struct {
    uint8_t InheritedAddressSpace;     // 0x00
    uint8_t ReadImageFileExecOptions;  // 0x01
    uint8_t BeingDebugged;             // 0x02
    uint8_t BitField;                  // 0x03
    void* Mutant;                      // 0x08
    void* ImageBaseAddress;            // 0x10
    void* Ldr;                         // 0x18 - PEB_LDR_DATA
    void* ProcessParameters;           // 0x20 - RTL_USER_PROCESS_PARAMETERS
    void* SubSystemData;               // 0x28
    void* ProcessHeap;                 // 0x30
    void* FastPebLock;                 // 0x38
    void* AtlThunkSListPtr;            // 0x40
    void* IFEOKey;                     // 0x48
    uint32_t CrossProcessFlags;        // 0x50
    uint32_t Padding1;                 // 0x54
    void* KernelCallbackTable;         // 0x58
    uint32_t SystemReserved;           // 0x60
    uint32_t AtlThunkSListPtr32;       // 0x64
    void* ApiSetMap;                   // 0x68
    uint32_t TlsExpansionCounter;      // 0x70
    uint32_t Padding2;                 // 0x74
    void* TlsBitmap;                   // 0x78
    uint32_t TlsBitmapBits[2];         // 0x80
    void* ReadOnlySharedMemoryBase;    // 0x88
    void* SharedData;                  // 0x90
    void** ReadOnlyStaticServerData;   // 0x98
    void* AnsiCodePageData;            // 0xA0
    void* OemCodePageData;             // 0xA8
    void* UnicodeCaseTableData;        // 0xB0
    uint32_t NumberOfProcessors;       // 0xB8
    uint32_t NtGlobalFlag;             // 0xBC
} win32_peb_t;

// Initialize TEB/PEB for current thread
int win32_teb_init(void);

// Get current TEB
win32_teb_t* win32_teb_get(void);

#endif // LSW_WIN32_TEB_H
