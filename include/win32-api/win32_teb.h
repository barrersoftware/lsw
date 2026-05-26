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

/*
 * Windows x64 TEB layout (Thread Environment Block).
 * Critical offsets that Windows apps read directly via gs:offset:
 *   gs:0x030  NtTib.Self          → pointer to this TEB
 *   gs:0x060  ProcessEnvironmentBlock (PEB*)
 *   gs:0x068  LastErrorValue      (GetLastError)
 *   gs:0x1480 TlsSlots[64]        (TlsGetValue / TlsSetValue)
 *
 * Padding between 0x110 and 0x1480 fills the real TEB fields we
 * do not need to expose individually (SystemReserved, GdiHandles, etc.)
 */
typedef struct __attribute__((packed)) {
    /* NT_TIB — 0x000..0x037 */
    void*    ExceptionList;              // 0x000
    void*    StackBase;                  // 0x008
    void*    StackLimit;                 // 0x010
    void*    SubSystemTib;               // 0x018
    void*    FiberData;                  // 0x020
    void*    ArbitraryUserPointer;       // 0x028
    void*    Self;                       // 0x030 ← gs:0x30 = TEB*

    /* TEB fields — 0x038..0x06f */
    void*    EnvironmentPointer;         // 0x038
    uint64_t ProcessId;                  // 0x040
    uint64_t ThreadId;                   // 0x048
    void*    ActiveRpcHandle;            // 0x050
    void*    ThreadLocalStoragePointer;  // 0x058
    void*    ProcessEnvironmentBlock;    // 0x060 ← gs:0x60 = PEB*
    uint32_t LastErrorValue;             // 0x068 ← gs:0x68 = GetLastError
    uint32_t CountOfOwnedCriticalSections; // 0x06c

    /* 0x070..0x0ff */
    void*    CsrClientThread;            // 0x070
    void*    Win32ThreadInfo;            // 0x078
    uint32_t User32Reserved[26];         // 0x080  (26*4 = 0x68) → 0x0e8
    uint32_t UserReserved[5];            // 0x0e8  (5*4  = 0x14) → 0x0fc
    uint8_t  _pad_0fc[4];               // 0x0fc  align next ptr to 0x100
    void*    WOW32Reserved;              // 0x100
    uint32_t CurrentLocale;              // 0x108
    uint32_t FpSoftwareStatusRegister;   // 0x10c

    /* 0x110..0x147f  — bulk padding to reach TlsSlots */
    uint8_t  _pad_110[0x1480 - 0x110];  // 0x1370 bytes

    /* TLS — 0x1480..0x167f */
    void*    TlsSlots[64];               // 0x1480  (64*8 = 0x200) → 0x1680
    void*    TlsLinks[2];                // 0x1680
    void*    Vdm;                        // 0x1690
    void*    ReservedForNtRpc;           // 0x1698
    void*    DbgSsReserved[2];           // 0x16a0
} win32_teb_t;

/* Verify the offsets that Windows apps depend on at compile time. */
_Static_assert(__builtin_offsetof(win32_teb_t, Self)
               == 0x030, "TEB.Self must be at 0x030");
_Static_assert(__builtin_offsetof(win32_teb_t, ProcessEnvironmentBlock)
               == 0x060, "TEB.PEB must be at 0x060");
_Static_assert(__builtin_offsetof(win32_teb_t, LastErrorValue)
               == 0x068, "TEB.LastError must be at 0x068");
_Static_assert(__builtin_offsetof(win32_teb_t, TlsSlots)
               == 0x1480, "TEB.TlsSlots must be at 0x1480");

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

// RTL_USER_PROCESS_PARAMETERS structure (simplified)
typedef struct {
    uint32_t MaximumLength;
    uint32_t Length;
    uint32_t Flags;
    uint32_t DebugFlags;
    void* ConsoleHandle;
    uint32_t ConsoleFlags;
    void* StandardInput;
    void* StandardOutput;
    void* StandardError;
    char* CurrentDirectory;          // Simplified - should be UNICODE_STRING
    char* DllPath;
    char* ImagePathName;
    char* CommandLine;               // Full command line string
    void* Environment;
    uint32_t StartingX;
    uint32_t StartingY;
    uint32_t CountX;
    uint32_t CountY;
    uint32_t CountCharsX;
    uint32_t CountCharsY;
    uint32_t FillAttribute;
    uint32_t WindowFlags;
    uint32_t ShowWindowFlags;
} win32_process_params_t;

// Initialize TEB/PEB for current thread
int win32_teb_init(void);

// Get current TEB
win32_teb_t* win32_teb_get(void);

// Set command line (called by PE loader)
void win32_set_command_line(int argc, char** argv);

// Get command line (for GetCommandLineA/W)
const char* win32_get_command_line(void);

#endif // LSW_WIN32_TEB_H
