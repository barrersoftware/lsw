/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 *
 * ntdll.dll Compatibility Layer
 *
 * Windows applications can import directly from ntdll.dll instead of going
 * through KERNEL32.  This file provides the ntdll-side stubs that are most
 * commonly imported by modern MSVC-compiled executables.
 *
 * Design notes:
 * - All functions carry __attribute__((ms_abi)) so the 64-bit Windows ABI
 *   (RCX/RDX/R8/R9 / SSE) is used rather than the Linux System V ABI.
 * - Heap functions are backed by the system malloc/free — this matches what
 *   KERNEL32 HeapAlloc/HeapFree already do.
 * - Critical-section functions delegate to the pthread_mutex_t inside the
 *   CRITICAL_SECTION structure (same layout as in win32_api.c).
 * - NT_STATUS success == 0 (STATUS_SUCCESS).  Failure values follow the
 *   Windows NTSTATUS convention: 0xC0000xxx.
 */

#define _GNU_SOURCE  /* clock_gettime, timegm, strdup */

#include "win32_api.h"
#include "lsw_log.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include "lsw_filesystem.h"

/* NTSTATUS constants */
#define STATUS_SUCCESS                  0x00000000
#define STATUS_UNSUCCESSFUL             0xC0000001
#define STATUS_NOT_IMPLEMENTED          0xC0000002
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_NO_MEMORY                0xC0000017
#define STATUS_BUFFER_OVERFLOW          0x80000005
#define STATUS_NO_MORE_FILES            0x80000006
#define STATUS_NOT_SUPPORTED            0xC00000BB
#define STATUS_OBJECT_NAME_NOT_FOUND    0xC0000034
#define STATUS_ACCESS_DENIED            0xC0000022
#define STATUS_END_OF_FILE              0xC0000011

typedef uint32_t NTSTATUS;
typedef uint32_t DWORD;
typedef void*    HANDLE;

/* Forward declaration — full definition is below in "UNICODE_STRING helpers" */
typedef struct lsw_unicode_string_s lsw_unicode_string_t;

/* ------------------------------------------------------------------
 * NT kernel structures used by NtOpenFile, NtCreateFile, NtQueryDirectoryFile
 * Layout verified against Windows x64 ABI.
 * ------------------------------------------------------------------ */

/* OBJECT_ATTRIBUTES (48 bytes on x64) */
typedef struct {
    uint32_t              Length;           /* = sizeof(OBJECT_ATTRIBUTES) = 48 */
    uint32_t              _pad0;
    void*                 RootDirectory;
    lsw_unicode_string_t* ObjectName;
    uint32_t              Attributes;
    uint32_t              _pad1;
    void*                 SecurityDescriptor;
    void*                 SecurityQualityOfService;
} lsw_object_attributes_t;

/* IO_STATUS_BLOCK (16 bytes): union is 8 bytes (void*), Information at offset 8 */
typedef struct {
    union { int32_t Status; void* Pointer; };
    uint64_t              Information;
} lsw_io_status_t;

/* FILE_DIRECTORY_INFORMATION (info class 1) — fixed part is 72 bytes */
typedef struct {
    uint32_t  NextEntryOffset;
    uint32_t  FileIndex;
    int64_t   CreationTime;
    int64_t   LastAccessTime;
    int64_t   LastWriteTime;
    int64_t   ChangeTime;
    int64_t   EndOfFile;
    int64_t   AllocationSize;
    uint32_t  FileAttributes;
    uint32_t  FileNameLength;   /* bytes */
    uint16_t  FileName[1];
} lsw_file_dir_info_t;

/* FILE_FULL_DIRECTORY_INFORMATION (info class 2) — fixed part 76 bytes */
typedef struct {
    uint32_t  NextEntryOffset;
    uint32_t  FileIndex;
    int64_t   CreationTime;
    int64_t   LastAccessTime;
    int64_t   LastWriteTime;
    int64_t   ChangeTime;
    int64_t   EndOfFile;
    int64_t   AllocationSize;
    uint32_t  FileAttributes;
    uint32_t  FileNameLength;
    uint32_t  EaSize;
    uint16_t  FileName[1];
} lsw_file_full_dir_info_t;

/* FILE_BOTH_DIRECTORY_INFORMATION (info class 3) — fixed part 94 bytes */
typedef struct {
    uint32_t  NextEntryOffset;
    uint32_t  FileIndex;
    int64_t   CreationTime;
    int64_t   LastAccessTime;
    int64_t   LastWriteTime;
    int64_t   ChangeTime;
    int64_t   EndOfFile;
    int64_t   AllocationSize;
    uint32_t  FileAttributes;
    uint32_t  FileNameLength;
    uint32_t  EaSize;
    uint8_t   ShortNameLength;
    uint8_t   _pad2;
    uint16_t  ShortName[12];
    uint16_t  FileName[1];
} lsw_file_both_dir_info_t;

/* FILE_ID_BOTH_DIRECTORY_INFORMATION (info class 37) — same as BOTH + 8-byte FileId */
typedef struct {
    uint32_t  NextEntryOffset;
    uint32_t  FileIndex;
    int64_t   CreationTime;
    int64_t   LastAccessTime;
    int64_t   LastWriteTime;
    int64_t   ChangeTime;
    int64_t   EndOfFile;
    int64_t   AllocationSize;
    uint32_t  FileAttributes;
    uint32_t  FileNameLength;
    uint32_t  EaSize;
    uint8_t   ShortNameLength;
    uint8_t   _pad2;
    uint16_t  ShortName[12];
    int64_t   FileId;
    uint16_t  FileName[1];
} lsw_file_id_both_dir_info_t;

/* FILE_NAMES_INFORMATION (info class 12) */
typedef struct {
    uint32_t  NextEntryOffset;
    uint32_t  FileIndex;
    uint32_t  FileNameLength;
    uint16_t  FileName[1];
} lsw_file_names_info_t;

/* Windows FILETIME epoch offset from Unix epoch (100-ns intervals) */
#define FILETIME_EPOCH_DIFF  116444736000000000ULL

/* Convert Unix timespec to Windows FILETIME (100-ns intervals since 1601-01-01) */
static int64_t timespec_to_filetime(const struct timespec* ts) {
    return (int64_t)((uint64_t)ts->tv_sec * 10000000ULL +
                     (uint64_t)ts->tv_nsec / 100ULL +
                     FILETIME_EPOCH_DIFF);
}

/* Windows FILE_ATTRIBUTE_* constants */
#define FILE_ATTRIBUTE_READONLY    0x00000001
#define FILE_ATTRIBUTE_HIDDEN      0x00000002
#define FILE_ATTRIBUTE_SYSTEM      0x00000004
#define FILE_ATTRIBUTE_DIRECTORY   0x00000010
#define FILE_ATTRIBUTE_ARCHIVE     0x00000020
#define FILE_ATTRIBUTE_NORMAL      0x00000080

/* NtCreateFile CreateDisposition values */
#define FILE_SUPERSEDE    0
#define FILE_OPEN         1
#define FILE_CREATE       2
#define FILE_OPEN_IF      3
#define FILE_OVERWRITE    4
#define FILE_OVERWRITE_IF 5

/* NtCreateFile CreateOptions flags */
#define FILE_DIRECTORY_FILE       0x00000001
#define FILE_NON_DIRECTORY_FILE   0x00000040

/* -----------------------------------------------------------------------
 * NT path helpers
 * ----------------------------------------------------------------------- */

/* Convert a wide-char NT path (\??\C:\path or \??\UNC\server\share\path)
 * to a multibyte Windows path (C:\path or \\server\share\path).
 * Returns 0 on success, -1 on failure. */
static int lsw_nt_wide_to_win_mb(const uint16_t* nt_wide, char* out, size_t outsz) {
    if (!nt_wide || !out || outsz == 0) return -1;
    /* Measure NT path length */
    size_t len = 0;
    while (nt_wide[len]) len++;

    /* Strip \??\ or \??\UNC\ prefix */
    const uint16_t prefix1[] = { '\\','?','?','\\', 0 };      /* \??\ */
    const uint16_t prefix2[] = { '\\','?','?','\\','U','N','C','\\', 0 }; /* \??\UNC\ */

    const uint16_t* src = nt_wide;
    int is_unc = 0;
    if (len >= 8) {
        int match = 1;
        for (int i = 0; i < 8; i++) if (src[i] != prefix2[i]) { match = 0; break; }
        if (match) { src += 8; len -= 8; is_unc = 1; }
    }
    if (!is_unc && len >= 4) {
        int match = 1;
        for (int i = 0; i < 4; i++) if (src[i] != prefix1[i]) { match = 0; break; }
        if (match) { src += 4; len -= 4; }
    }

    /* Convert remaining wide path to multibyte */
    char tmp[4096] = {0};
    size_t i;
    for (i = 0; i < len && i < sizeof(tmp)-1; i++) {
        uint16_t wc = src[i];
        if (wc == '/' || wc == '\\') tmp[i] = '\\';
        else if (wc < 128) tmp[i] = (char)wc;
        else tmp[i] = '?'; /* non-ASCII fallback */
    }
    tmp[i] = '\0';

    if (is_unc) {
        snprintf(out, outsz, "\\\\%s", tmp);
    } else {
        snprintf(out, outsz, "%s", tmp);
    }
    return 0;
}

/* Convert an NT path (wide char) to a Linux path.
 * Returns 0 on success, -1 on error. */
static int lsw_nt_path_to_linux(const uint16_t* nt_wide, char* linux_out, size_t outsz) {
    char win_path[4096];
    if (lsw_nt_wide_to_win_mb(nt_wide, win_path, sizeof(win_path)) != 0) return -1;
    if (lsw_fs_win_to_linux(win_path, linux_out, outsz) != LSW_SUCCESS) return -1;
    return 0;
}

/* ------------------------------------------------------------------
 * Heap functions (RtlAllocateHeap / RtlFreeHeap / RtlReAllocateHeap)
 * The "heap" handle is ignored — we always use the process heap which
 * is backed by glibc malloc.
 * ------------------------------------------------------------------ */

void* __attribute__((ms_abi)) lsw_RtlAllocateHeap(void* heap, uint32_t flags, size_t size) {
    (void)heap;
    void* p = (flags & 0x8) ? calloc(1, size) : malloc(size); /* 0x8 = HEAP_ZERO_MEMORY */
    LSW_LOG_DEBUG("RtlAllocateHeap(size=%zu) -> %p", size, p);
    return p;
}

int __attribute__((ms_abi)) lsw_RtlFreeHeap(void* heap, uint32_t flags, void* ptr) {
    (void)heap; (void)flags;
    free(ptr);
    return 1; /* TRUE */
}

void* __attribute__((ms_abi)) lsw_RtlReAllocateHeap(void* heap, uint32_t flags, void* ptr, size_t size) {
    (void)heap;
    void* p = realloc(ptr, size);
    if (!p && (flags & 0x8)) p = calloc(1, size);
    return p;
}

size_t __attribute__((ms_abi)) lsw_RtlSizeHeap(void* heap, uint32_t flags, const void* ptr) {
    (void)heap; (void)flags; (void)ptr;
    return 0; /* malloc_usable_size not portable — return 0 */
}

void* __attribute__((ms_abi)) lsw_RtlCreateHeap(
    uint32_t flags, void* base, size_t reserve, size_t commit,
    void* lock, void* params) {
    (void)flags; (void)base; (void)reserve; (void)commit; (void)lock; (void)params;
    return (void*)1; /* Non-NULL "handle" */
}

int __attribute__((ms_abi)) lsw_RtlDestroyHeap(void* heap) {
    (void)heap;
    return 0; /* success */
}

/* ------------------------------------------------------------------
 * CRITICAL_SECTION helpers (RtlInitializeCriticalSection etc.)
 * Windows CRITICAL_SECTION (48 bytes on x64):
 *   offset 0: PRTL_CRITICAL_SECTION_DEBUG DebugInfo (8 bytes)
 *   offset 8: LONG LockCount               (4 bytes)
 *   offset12: LONG RecursionCount          (4 bytes)
 *   offset16: HANDLE OwningThread          (8 bytes)
 *   offset24: HANDLE LockSemaphore         (8 bytes)  ← we store pthread_mutex_t*
 *   offset32: ULONG_PTR SpinCount          (8 bytes)
 * We embed a malloc'd pthread_mutex_t at offset 24 (LockSemaphore field).
 * ------------------------------------------------------------------ */
typedef struct {
    void*    debug_info;       /* offset  0 */
    int32_t  lock_count;       /* offset  8 */
    int32_t  recursion_count;  /* offset 12 */
    void*    owning_thread;    /* offset 16 */
    void*    lock_semaphore;   /* offset 24 — stores pthread_mutex_t* */
    uint64_t spin_count;       /* offset 32 */
} lsw_cs_t;

NTSTATUS __attribute__((ms_abi)) lsw_RtlInitializeCriticalSection(lsw_cs_t* cs) {
    if (!cs) return STATUS_INVALID_PARAMETER;
    memset(cs, 0, sizeof(*cs));
    pthread_mutex_t* m = malloc(sizeof(pthread_mutex_t));
    if (!m) return STATUS_NO_MEMORY;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
    cs->lock_semaphore = m;
    cs->lock_count     = -1; /* Windows convention: -1 = not owned */
    return STATUS_SUCCESS;
}

NTSTATUS __attribute__((ms_abi)) lsw_RtlInitializeCriticalSectionEx(
    lsw_cs_t* cs, uint32_t spin, uint32_t flags) {
    (void)spin; (void)flags;
    return lsw_RtlInitializeCriticalSection(cs);
}

NTSTATUS __attribute__((ms_abi)) lsw_RtlInitializeCriticalSectionAndSpinCount(
    lsw_cs_t* cs, uint32_t spin) {
    (void)spin;
    return lsw_RtlInitializeCriticalSection(cs);
}

NTSTATUS __attribute__((ms_abi)) lsw_RtlDeleteCriticalSection(lsw_cs_t* cs) {
    if (!cs) return STATUS_INVALID_PARAMETER;
    if (cs->lock_semaphore) {
        pthread_mutex_destroy((pthread_mutex_t*)cs->lock_semaphore);
        free(cs->lock_semaphore);
        cs->lock_semaphore = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS __attribute__((ms_abi)) lsw_RtlEnterCriticalSection(lsw_cs_t* cs) {
    if (!cs || !cs->lock_semaphore) return STATUS_INVALID_PARAMETER;
    pthread_mutex_lock((pthread_mutex_t*)cs->lock_semaphore);
    cs->recursion_count++;
    return STATUS_SUCCESS;
}

NTSTATUS __attribute__((ms_abi)) lsw_RtlLeaveCriticalSection(lsw_cs_t* cs) {
    if (!cs || !cs->lock_semaphore) return STATUS_INVALID_PARAMETER;
    if (cs->recursion_count > 0) cs->recursion_count--;
    pthread_mutex_unlock((pthread_mutex_t*)cs->lock_semaphore);
    return STATUS_SUCCESS;
}

int __attribute__((ms_abi)) lsw_RtlTryEnterCriticalSection(lsw_cs_t* cs) {
    if (!cs || !cs->lock_semaphore) return 0;
    int r = pthread_mutex_trylock((pthread_mutex_t*)cs->lock_semaphore);
    if (r == 0) { cs->recursion_count++; return 1; }
    return 0;
}

/* ------------------------------------------------------------------
 * UNICODE_STRING helpers
 * Windows UNICODE_STRING: Length(2) + MaximumLength(2) + padding(4) + Buffer*(8)
 * ------------------------------------------------------------------ */
typedef struct lsw_unicode_string_s {
    uint16_t  Length;         /* bytes, not chars */
    uint16_t  MaximumLength;
    uint32_t  _pad;
    uint16_t* Buffer;
} lsw_unicode_string_t;

void __attribute__((ms_abi)) lsw_RtlInitUnicodeString(lsw_unicode_string_t* us, const uint16_t* src) {
    if (!us) return;
    if (!src) {
        us->Length = 0; us->MaximumLength = 0; us->Buffer = NULL;
        return;
    }
    size_t len = 0;
    while (src[len]) len++;
    us->Length        = (uint16_t)(len * 2);
    us->MaximumLength = (uint16_t)(len * 2 + 2);
    us->Buffer        = (uint16_t*)src; /* points into existing buffer */
}

/* ------------------------------------------------------------------
 * IP address conversion stubs (used by ipconfig, netsh, etc.)
 * ------------------------------------------------------------------ */

/* RtlIpv4AddressToStringExW: IN_ADDR -> wide string with optional port */
uint16_t* __attribute__((ms_abi)) lsw_RtlIpv4AddressToStringExW(
    const uint8_t* addr, uint16_t port, uint16_t* buf, uint32_t* buf_len)
{
    if (!buf || !buf_len || *buf_len < 22) {
        if (buf_len) *buf_len = 22;
        return NULL;
    }
    char tmp[22];
    int n;
    if (port)
        n = snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u:%u", addr[0], addr[1], addr[2], addr[3], (unsigned)ntohs(port));
    else
        n = snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    for (int i = 0; i <= n; i++) buf[i] = (uint16_t)(unsigned char)tmp[i];
    *buf_len = (uint32_t)n + 1;
    return buf;
}

/* RtlIpv6AddressToStringW: in6_addr -> wide string (no port) */
uint16_t* __attribute__((ms_abi)) lsw_RtlIpv6AddressToStringW(
    const uint8_t* addr, uint16_t* buf)
{
    if (!buf) return NULL;
    char tmp[46];
    snprintf(tmp, sizeof(tmp), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
        addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    for (int i = 0; tmp[i]; i++) buf[i] = (uint16_t)(unsigned char)tmp[i];
    buf[strlen(tmp)] = 0;
    return buf;
}

/* RtlIpv6AddressToStringExW: in6_addr -> wide string with optional port/scope */
NTSTATUS __attribute__((ms_abi)) lsw_RtlIpv6AddressToStringExW(
    const uint8_t* addr, uint32_t scope_id, uint16_t port,
    uint16_t* buf, uint32_t* buf_len)
{
    if (!buf || !buf_len || *buf_len < 48) {
        if (buf_len) *buf_len = 48;
        return STATUS_INVALID_PARAMETER;
    }
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
        addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    if (scope_id) n += snprintf(tmp + n, sizeof(tmp) - n, "%%%u", scope_id);
    if (port)     n += snprintf(tmp + n, sizeof(tmp) - n, ":%u", (unsigned)ntohs(port));
    for (int i = 0; i <= n; i++) buf[i] = (uint16_t)(unsigned char)tmp[i];
    *buf_len = (uint32_t)n + 1;
    return STATUS_SUCCESS;
}

/* RtlStringFromGUID: GUID -> L"{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" */
NTSTATUS __attribute__((ms_abi)) lsw_RtlStringFromGUID(
    const uint8_t* guid, lsw_unicode_string_t* us)
{
    if (!guid || !us) return STATUS_INVALID_PARAMETER;
    /* GUID layout: 4+2+2+8 bytes = Data1 Data2 Data3 Data4[8] */
    uint32_t d1 = ((uint32_t)guid[0]) | ((uint32_t)guid[1]<<8) | ((uint32_t)guid[2]<<16) | ((uint32_t)guid[3]<<24);
    uint16_t d2 = (uint16_t)(guid[4] | (guid[5]<<8));
    uint16_t d3 = (uint16_t)(guid[6] | (guid[7]<<8));
    char tmp[40];
    snprintf(tmp, sizeof(tmp), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        d1, d2, d3, guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]);
    int n = (int)strlen(tmp);
    uint16_t* wbuf = (uint16_t*)malloc((n + 1) * sizeof(uint16_t));
    if (!wbuf) return STATUS_NO_MEMORY;
    for (int i = 0; i <= n; i++) wbuf[i] = (uint16_t)(unsigned char)tmp[i];
    us->Buffer        = wbuf;
    us->Length        = (uint16_t)(n * 2);
    us->MaximumLength = (uint16_t)((n + 1) * 2);
    return STATUS_SUCCESS;
}

/* RtlQueryFeatureConfiguration: stub — return STATUS_NOT_FOUND so callers skip feature */
NTSTATUS __attribute__((ms_abi)) lsw_RtlQueryFeatureConfiguration(
    uint32_t feature_id, uint32_t feature_type, void* change_stamp, void* config)
{
    (void)feature_id; (void)feature_type; (void)change_stamp; (void)config;
    return 0xC0000034; /* STATUS_OBJECT_NAME_NOT_FOUND */
}

/* RtlRegisterFeatureConfigurationChangeNotification: return SUCCESS so WIL stops looping */
NTSTATUS __attribute__((ms_abi)) lsw_RtlRegisterFeatureConfigurationChangeNotification(
    void* callback, void* context, void* event, void* handle_out)
{
    (void)callback; (void)context; (void)event;
    if (handle_out) *(void**)handle_out = NULL;
    return STATUS_SUCCESS;
}

/* WilFailureNotifyWatchers: WIL internal — no-op so failure notification doesn't loop */
void __attribute__((ms_abi)) lsw_WilFailureNotifyWatchers(void* failure_info)
{
    (void)failure_info;
}

void __attribute__((ms_abi)) lsw_RtlFreeUnicodeString(lsw_unicode_string_t* us) {
    if (us && us->Buffer) {
        free(us->Buffer);
        us->Buffer        = NULL;
        us->Length        = 0;
        us->MaximumLength = 0;
    }
}

NTSTATUS __attribute__((ms_abi)) lsw_RtlUnicodeStringToAnsiString(
    void* ansi, const lsw_unicode_string_t* uni, int alloc)
{
    (void)ansi; (void)uni; (void)alloc;
    return STATUS_NOT_IMPLEMENTED; /* stub */
}

NTSTATUS __attribute__((ms_abi)) lsw_RtlAnsiStringToUnicodeString(
    lsw_unicode_string_t* uni, const void* ansi, int alloc)
{
    (void)uni; (void)ansi; (void)alloc;
    return STATUS_NOT_IMPLEMENTED; /* stub */
}

/* RtlUnicodeToOemN — convert UTF-16LE buffer to OEM/ANSI
 * Prototype: NTSTATUS RtlUnicodeToOemN(PCHAR OemString, ULONG MaxBytesInOemString,
 *                                       PULONG BytesInOemString, PCWCH UnicodeString,
 *                                       ULONG BytesInUnicodeString)
 */
NTSTATUS __attribute__((ms_abi)) lsw_RtlUnicodeToOemN(
    char* OemString, uint32_t MaxBytes, uint32_t* BytesOut,
    const uint16_t* UnicodeString, uint32_t BytesIn)
{
    if (!OemString || !UnicodeString || MaxBytes == 0) return 0xC000000D; /* STATUS_INVALID_PARAMETER */
    uint32_t src_chars = BytesIn / 2;
    uint32_t out = 0;
    for (uint32_t i = 0; i < src_chars && out + 1 < MaxBytes; i++) {
        uint16_t c = UnicodeString[i];
        if (c == 0) break;
        OemString[out++] = (c < 0x100) ? (char)c : '?';
    }
    OemString[out] = '\0';
    if (BytesOut) *BytesOut = out;
    return 0; /* STATUS_SUCCESS */
}

/* RtlMultiByteToUnicodeN — convert ANSI/OEM to UTF-16LE
 * Prototype: NTSTATUS RtlMultiByteToUnicodeN(PWCH UnicodeString, ULONG MaxBytesInUnicodeString,
 *                                             PULONG BytesInUnicodeString, PCSTR MultiByteString,
 *                                             ULONG BytesInMultiByteString)
 */
NTSTATUS __attribute__((ms_abi)) lsw_RtlMultiByteToUnicodeN(
    uint16_t* UnicodeString, uint32_t MaxBytes, uint32_t* BytesOut,
    const char* MultiByteString, uint32_t BytesIn)
{
    if (!UnicodeString || !MultiByteString || MaxBytes < 2) return 0xC000000D;
    uint32_t max_chars = MaxBytes / 2;
    uint32_t out = 0;
    for (uint32_t i = 0; i < BytesIn && out + 1 < max_chars; i++) {
        unsigned char c = (unsigned char)MultiByteString[i];
        if (c == 0) break;
        UnicodeString[out++] = (uint16_t)c;
    }
    UnicodeString[out] = 0;
    if (BytesOut) *BytesOut = out * 2;
    return 0; /* STATUS_SUCCESS */
}

/* RtlIpv4StringToAddressW — parse IPv4 dotted-decimal string
 * Prototype: NTSTATUS RtlIpv4StringToAddressW(PCWSTR S, BOOLEAN Strict,
 *                                              PCWSTR *Terminator, IN_ADDR *Addr)
 */
NTSTATUS __attribute__((ms_abi)) lsw_RtlIpv4StringToAddressW(
    const uint16_t* S, uint8_t Strict, const uint16_t** Terminator, uint32_t* Addr)
{
    if (!S || !Addr) return 0xC000000D;
    // Convert wide to narrow
    char narrow[64] = {0};
    for (int i = 0; i < 63 && S[i]; i++) narrow[i] = (char)S[i];
    struct in_addr a;
    if (inet_pton(AF_INET, narrow, &a) == 1) {
        *Addr = a.s_addr;
        if (Terminator) {
            // Advance past the address string
            int i = 0;
            while (S[i] && (S[i] == '.' || (S[i] >= '0' && S[i] <= '9'))) i++;
            *Terminator = S + i;
        }
        return 0;
    }
    return 0xC0000005; /* STATUS_ACCESS_VIOLATION placeholder - invalid format */
}

/* ------------------------------------------------------------------ * NtStatus → Win32 error code conversion
 * ------------------------------------------------------------------ */
uint32_t __attribute__((ms_abi)) lsw_RtlNtStatusToDosError(NTSTATUS status) {
    if (status == STATUS_SUCCESS)         return 0;   /* ERROR_SUCCESS */
    if (status == STATUS_INVALID_PARAMETER) return 87; /* ERROR_INVALID_PARAMETER */
    if (status == STATUS_NO_MEMORY)        return 8;   /* ERROR_NOT_ENOUGH_MEMORY */
    if (status == STATUS_NOT_IMPLEMENTED)  return 1;   /* ERROR_INVALID_FUNCTION */
    return 1; /* generic */
}

uint32_t __attribute__((ms_abi)) lsw_RtlNtStatusToDosErrorNoTeb(NTSTATUS status) {
    return lsw_RtlNtStatusToDosError(status);
}

/* ------------------------------------------------------------------
 * LdrLoadDll / LdrGetProcedureAddress — user-mode DLL loader stubs
 * These mirror the KERNEL32 LoadLibrary / GetProcAddress.
 * ------------------------------------------------------------------ */
extern void* lsw_LoadLibraryA(const char* name);
extern void* lsw_GetProcAddress(void* module, const char* name);

NTSTATUS __attribute__((ms_abi)) lsw_LdrLoadDll(
    const uint16_t* search_path, uint32_t* flags,
    const lsw_unicode_string_t* mod_name, void** handle)
{
    (void)search_path; (void)flags;
    if (!mod_name || !mod_name->Buffer || !handle) return STATUS_INVALID_PARAMETER;
    /* Convert UTF-16 name to ASCII */
    char buf[256] = {0};
    uint32_t i = 0;
    uint32_t len = mod_name->Length / 2;
    while (i < len && i < 255) { buf[i] = (char)(mod_name->Buffer[i] & 0xFF); i++; }
    *handle = lsw_LoadLibraryA(buf);
    return *handle ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS __attribute__((ms_abi)) lsw_LdrGetProcedureAddress(
    void* module, const void* proc_name, uint32_t ordinal, void** address)
{
    (void)ordinal;
    if (!address) return STATUS_INVALID_PARAMETER;
    if (proc_name) {
        /* proc_name can be ANSI_STRING or ordinal — treat as C string */
        *address = lsw_GetProcAddress(module, (const char*)proc_name);
    } else {
        *address = NULL;
    }
    return *address ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------
 * NtCurrentTeb — Return Thread Environment Block pointer.
 * LSW sets up a minimal TEB per-thread.  For now we return a static
 * all-zeros TEB which prevents NULL-deref crashes.
 * ------------------------------------------------------------------ */
static __thread uint8_t g_teb[4096] = {0};

void* __attribute__((ms_abi)) lsw_NtCurrentTeb(void) {
    return (void*)g_teb;
}

void* __attribute__((ms_abi)) lsw_RtlGetCurrentPeb(void) {
    /* PEB lives at TEB+0x60; return a static dummy */
    static uint8_t g_peb[4096] = {0};
    return (void*)g_peb;
}

/* ------------------------------------------------------------------
 * RtlUnwind / RtlUnwindEx — SEH unwinding stubs.
 * Without real stack-walk support these can only do a best-effort
 * abort.  Apps that rely on SEH will fail gracefully rather than
 * crashing with a SIGSEGV.
 * ------------------------------------------------------------------ */
void __attribute__((ms_abi)) lsw_RtlUnwind(
    void* target_frame, void* target_ip, void* exception_record, void* return_value)
{
    (void)target_frame; (void)target_ip; (void)exception_record; (void)return_value;
    LSW_LOG_WARN("RtlUnwind called — SEH unwinding not supported; continuing");
}

void __attribute__((ms_abi)) lsw_RtlUnwindEx(
    void* target_frame, void* target_ip, void* exception_record,
    void* return_value, void* context_record, void* history_table)
{
    (void)target_frame; (void)target_ip; (void)exception_record;
    (void)return_value; (void)context_record; (void)history_table;
    LSW_LOG_WARN("RtlUnwindEx called — SEH not supported; continuing");
}

void __attribute__((ms_abi)) lsw_RtlRaiseException(void* exception_record) {
    (void)exception_record;
    LSW_LOG_ERROR("RtlRaiseException called — aborting");
    abort();
}

/* ------------------------------------------------------------------
 * RtlAddFunctionTable / RtlDeleteFunctionTable — x64 exception tables.
 * Required by the MSVC CRT for stack unwinding (.pdata registration).
 * We accept them but do nothing; real unwinding is not yet supported.
 * ------------------------------------------------------------------ */
int __attribute__((ms_abi)) lsw_RtlAddFunctionTable(
    void* func_table, uint32_t entry_count, uint64_t base_address)
{
    (void)func_table; (void)entry_count; (void)base_address;
    LSW_LOG_DEBUG("RtlAddFunctionTable: %u entries at base 0x%llx (no-op)",
                  entry_count, (unsigned long long)base_address);
    return 1; /* TRUE — "success" */
}

int __attribute__((ms_abi)) lsw_RtlDeleteFunctionTable(void* func_table) {
    (void)func_table;
    return 1;
}

int __attribute__((ms_abi)) lsw_RtlInstallFunctionTableCallback(
    uint64_t table_id, uint64_t base, uint32_t length, void* callback, void* ctx, const uint16_t* out_of_process_dll)
{
    (void)table_id; (void)base; (void)length; (void)callback; (void)ctx; (void)out_of_process_dll;
    return 1;
}

void* __attribute__((ms_abi)) lsw_RtlLookupFunctionEntry(
    uint64_t control_pc, uint64_t* image_base, void* history_table)
{
    (void)control_pc; (void)history_table;
    if (image_base) *image_base = 0;
    return NULL;
}

void __attribute__((ms_abi)) lsw_RtlCaptureContext(void* context_record) {
    (void)context_record;
    /* Would need to save all registers — stub for now */
}

void __attribute__((ms_abi)) lsw_RtlRestoreContext(void* context_record, void* exception_record) {
    (void)context_record; (void)exception_record;
    LSW_LOG_WARN("RtlRestoreContext: not supported");
    abort();
}

/* ------------------------------------------------------------------
 * RtlCopyMemory / RtlFillMemory / RtlZeroMemory (ntdll originals)
 * ------------------------------------------------------------------ */
void __attribute__((ms_abi)) lsw_ntdll_RtlCopyMemory(void* d, const void* s, size_t n)  { memcpy(d, s, n); }
void __attribute__((ms_abi)) lsw_ntdll_RtlFillMemory(void* d, size_t n, int c)          { memset(d, c, n); }
void __attribute__((ms_abi)) lsw_ntdll_RtlZeroMemory(void* d, size_t n)                 { memset(d, 0, n); }
void __attribute__((ms_abi)) lsw_ntdll_RtlMoveMemory(void* d, const void* s, size_t n) { memmove(d, s, n); }

size_t __attribute__((ms_abi)) lsw_RtlCompareMemory(const void* a, const void* b, size_t n) {
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    for (size_t i = 0; i < n; i++) {
        if (pa[i] != pb[i]) return i;
    }
    return n;
}

/* ------------------------------------------------------------------
 * NtTerminateProcess
 * ------------------------------------------------------------------ */
NTSTATUS __attribute__((ms_abi)) lsw_NtTerminateProcess(void* handle, NTSTATUS exit_status) {
    (void)handle;
    LSW_LOG_INFO("NtTerminateProcess: exit_status=0x%08x", exit_status);
    exit((int)exit_status);
    return STATUS_SUCCESS; /* unreachable */
}

/* ------------------------------------------------------------------
 * NtQueryInformationProcess — returns basic process info
 * class 0 = ProcessBasicInformation (PBI): ExitStatus, PEB, Affinity,
 *           Priority, UniqueProcessId, InheritedFromUniqueProcessId
 * ------------------------------------------------------------------ */
typedef struct {
    int32_t   ExitStatus;
    void*     PebBaseAddress;
    uintptr_t AffinityMask;
    int32_t   BasePriority;
    uintptr_t UniqueProcessId;
    uintptr_t InheritedFromUniqueProcessId;
} LSW_PROCESS_BASIC_INFORMATION;

NTSTATUS __attribute__((ms_abi)) lsw_NtQueryInformationProcess(
    void* handle, uint32_t info_class,
    void* buf, uint32_t len, uint32_t* ret_len)
{
    if (ret_len) *ret_len = 0;
    if (!buf || len == 0) return STATUS_SUCCESS;
    memset(buf, 0, len);
    if (info_class == 0) { /* ProcessBasicInformation */
        if (len >= sizeof(LSW_PROCESS_BASIC_INFORMATION)) {
            LSW_PROCESS_BASIC_INFORMATION* pbi = (LSW_PROCESS_BASIC_INFORMATION*)buf;
            pbi->ExitStatus                   = 259; /* STILL_ACTIVE */
            pbi->UniqueProcessId              = (uintptr_t)getpid();
            pbi->InheritedFromUniqueProcessId = (uintptr_t)getppid();
            pbi->BasePriority                 = 8; /* NORMAL_PRIORITY_CLASS */
            pbi->AffinityMask                 = 0x3F; /* 6 cores */
            if (ret_len) *ret_len = sizeof(LSW_PROCESS_BASIC_INFORMATION);
        }
    }
    LSW_LOG_DEBUG("NtQueryInformationProcess(handle=%p, class=%u)", handle, info_class);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtQuerySystemInformation — minimal stub
 * Needed by the CRT and various profiling tools.
 * ------------------------------------------------------------------ */
NTSTATUS __attribute__((ms_abi)) lsw_NtQuerySystemInformation(
    uint32_t info_class, void* buf, uint32_t len, uint32_t* ret_len)
{
    (void)info_class; (void)len;
    if (ret_len) *ret_len = 0;
    if (buf)     memset(buf, 0, len > 0 ? len : 0);
    LSW_LOG_DEBUG("NtQuerySystemInformation(class=%u) -> stub", info_class);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtQueryVirtualMemory — stub
 * ------------------------------------------------------------------ */
NTSTATUS __attribute__((ms_abi)) lsw_NtQueryVirtualMemory(
    void* process, void* base_addr, uint32_t info_class,
    void* buf, size_t len, size_t* ret_len)
{
    (void)process; (void)base_addr; (void)info_class; (void)len;
    if (ret_len) *ret_len = 0;
    if (buf)     memset(buf, 0, len > 0 ? len : 0);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * RtlGetNtVersionNumbers
 * Returns Windows 10 (10.0.19041) version info.
 * ------------------------------------------------------------------ */
void __attribute__((ms_abi)) lsw_RtlGetNtVersionNumbers(
    uint32_t* major, uint32_t* minor, uint32_t* build)
{
    if (major) *major = 10;
    if (minor) *minor = 0;
    if (build) *build = 0xF0000000 | 19041; /* high nibble = reserved */
}

/* ------------------------------------------------------------------
 * Misc ntdll stubs
 * ------------------------------------------------------------------ */
void __attribute__((ms_abi)) lsw_DbgBreakPoint(void) {
    LSW_LOG_WARN("DbgBreakPoint called — no debugger attached, continuing");
}

void __attribute__((ms_abi)) lsw_DbgPrint(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LSW_LOG_DEBUG("[ntdll DbgPrint]");
    (void)fmt;
    va_end(ap);
}

/* NtClose — close real file/dir handles */
int __attribute__((ms_abi)) lsw_NtClose(void* handle) {
    if (!handle || (intptr_t)handle == -1) return STATUS_SUCCESS;
    /* Directory handle */
    lsw_nt_dir_handle_t* dh = (lsw_nt_dir_handle_t*)handle;
    if ((uintptr_t)handle >= 0x10000u && dh->magic == LSW_DIR_MAGIC) {
        if (dh->dirp) closedir((DIR*)dh->dirp);
        dh->magic = 0;
        free(dh);
        return STATUS_SUCCESS;
    }
    /* Raw file descriptor */
    intptr_t fd = (intptr_t)handle;
    if (fd > 2 && fd < 65536) close((int)fd);
    return STATUS_SUCCESS;
}

void __attribute__((ms_abi)) lsw_RtlExitUserProcess(uint32_t exit_code) {
    exit((int)exit_code);
}

void __attribute__((ms_abi)) lsw_RtlExitUserThread(uint32_t exit_code) {
    pthread_exit((void*)(uintptr_t)exit_code);
}

int __attribute__((ms_abi)) lsw_RtlQueryEnvironmentVariable(
    void* env, const uint16_t* name, uint32_t name_len, uint16_t* val, uint32_t val_len, uint32_t* ret_len)
{
    (void)env; (void)name; (void)name_len; (void)val; (void)val_len;
    if (ret_len) *ret_len = 0;
    return (int)STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------
 * String init stubs
 * ------------------------------------------------------------------ */

typedef struct { uint16_t Length; uint16_t MaximumLength; char* Buffer; } LSW_ANSI_STRING;
typedef struct { uint16_t Length; uint16_t MaximumLength; uint16_t* Buffer; } LSW_UNICODE_STRING;

void __attribute__((ms_abi)) lsw_RtlInitAnsiString(LSW_ANSI_STRING* s, const char* str) {
    if (!s) return;
    s->Buffer = (char*)str;
    if (str) {
        size_t len = strlen(str);
        s->Length = (uint16_t)(len > 65534 ? 65534 : len);
        s->MaximumLength = s->Length + 1;
    } else {
        s->Length = 0; s->MaximumLength = 0;
    }
}
void __attribute__((ms_abi)) lsw_RtlInitString(LSW_ANSI_STRING* s, const char* str) {
    lsw_RtlInitAnsiString(s, str);
}

/* RtlxOemStringToUnicodeSize: returns byte size of UTF-16 buffer needed */
uint32_t __attribute__((ms_abi)) lsw_RtlxOemStringToUnicodeSize(LSW_ANSI_STRING* s) {
    if (!s) return 2;
    return (uint32_t)(s->Length + 1) * 2;
}

/* RtlOemStringToUnicodeString: OEM (Latin-1) → UTF-16LE */
int __attribute__((ms_abi)) lsw_RtlOemStringToUnicodeString(LSW_UNICODE_STRING* dest,
    LSW_ANSI_STRING* src, int allocDest) {
    if (!src || !dest) return (int)STATUS_INVALID_PARAMETER;
    uint32_t needed = (uint32_t)(src->Length + 1) * 2;
    if (allocDest) {
        dest->Buffer = (uint16_t*)malloc(needed);
        if (!dest->Buffer) return (int)STATUS_NO_MEMORY;
        dest->MaximumLength = (uint16_t)needed;
    } else {
        if (!dest->Buffer || dest->MaximumLength < needed) return (int)STATUS_BUFFER_OVERFLOW;
    }
    dest->Length = (uint16_t)(src->Length * 2);
    for (uint16_t i = 0; i < src->Length; i++)
        dest->Buffer[i] = (uint16_t)(uint8_t)src->Buffer[i];
    dest->Buffer[src->Length] = 0;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * Time stubs
 * ------------------------------------------------------------------ */
#define EPOCH_DIFF_100NS  116444736000000000ULL  /* 100-ns intervals 1601→1970 */

void __attribute__((ms_abi)) lsw_NtQuerySystemTime(uint64_t* SystemTime) {
    if (!SystemTime) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    *SystemTime = (uint64_t)ts.tv_sec * 10000000ULL
                + (uint64_t)(ts.tv_nsec / 100)
                + EPOCH_DIFF_100NS;
}

int __attribute__((ms_abi)) lsw_RtlTimeToSecondsSince1970(uint64_t* Time, uint32_t* Seconds) {
    if (!Time || !Seconds) return 0; /* FALSE */
    uint64_t secs = *Time / 10000000ULL;
    if (secs < (EPOCH_DIFF_100NS / 10000000ULL)) { *Seconds = 0; return 0; }
    *Seconds = (uint32_t)(secs - (EPOCH_DIFF_100NS / 10000000ULL));
    return 1; /* TRUE */
}

/* TIME_FIELDS: Year,Month,Day,Hour,Minute,Second,Milliseconds,Weekday (each 16-bit) */
typedef struct {
    uint16_t Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday;
} LSW_TIME_FIELDS;

int __attribute__((ms_abi)) lsw_RtlTimeFieldsToTime(LSW_TIME_FIELDS* tf, uint64_t* Time) {
    if (!tf || !Time) return 0;
    struct tm t = {0};
    t.tm_year = tf->Year - 1900;
    t.tm_mon  = tf->Month - 1;
    t.tm_mday = tf->Day;
    t.tm_hour = tf->Hour;
    t.tm_min  = tf->Minute;
    t.tm_sec  = tf->Second;
    time_t unix_t = timegm(&t);
    if (unix_t == (time_t)-1) { *Time = 0; return 0; }
    *Time = ((uint64_t)unix_t + EPOCH_DIFF_100NS / 10000000ULL) * 10000000ULL
            + (uint64_t)tf->Milliseconds * 10000ULL;
    return 1; /* TRUE */
}

/* ------------------------------------------------------------------
 * RtlTimeToElapsedTimeFields — convert 100-ns ticks to TIME_FIELDS
 * Used by tasklist.exe to format elapsed CPU time.
 * ------------------------------------------------------------------ */
void __attribute__((ms_abi)) lsw_RtlTimeToElapsedTimeFields(
    uint64_t* Time, LSW_TIME_FIELDS* Fields)
{
    if (!Time || !Fields) return;
    uint64_t ticks   = *Time;
    uint64_t ms      = ticks / 10000ULL;
    uint64_t secs    = ms / 1000; ms %= 1000;
    uint64_t mins    = secs / 60; secs %= 60;
    uint64_t hours   = mins / 60; mins %= 60;
    uint64_t days    = hours / 24; hours %= 24;
    Fields->Milliseconds = (uint16_t)ms;
    Fields->Second       = (uint16_t)secs;
    Fields->Minute       = (uint16_t)mins;
    Fields->Hour         = (uint16_t)hours;
    Fields->Day          = (uint16_t)days;
    Fields->Month        = 0;
    Fields->Year         = 0;
    Fields->Weekday      = 0;
}

/* ------------------------------------------------------------------
 * RtlLargeIntegerToChar — convert LARGE_INTEGER to string
 * Signature: NTSTATUS RtlLargeIntegerToChar(PLARGE_INTEGER Value, ULONG Base,
 *            LONG Length, PCHAR String);
 * ------------------------------------------------------------------ */
int32_t __attribute__((ms_abi)) lsw_RtlLargeIntegerToChar(
    int64_t* Value, uint32_t Base, int32_t Length, char* String)
{
    if (!Value || !String || Length <= 0) return 0xC000000D; /* STATUS_INVALID_PARAMETER */
    if (Base == 0) Base = 10;
    int64_t v = *Value;
    char buf[66]; int pos = 0;
    int neg = (v < 0 && Base == 10);
    uint64_t uv = neg ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
    if (uv == 0) { buf[pos++] = '0'; }
    else while (uv > 0) {
        int d = (int)(uv % Base);
        buf[pos++] = (d < 10) ? ('0' + d) : ('a' + d - 10);
        uv /= Base;
    }
    if (neg) buf[pos++] = '-';
    /* reverse */
    for (int i = 0, j = pos-1; i < j; i++, j--) { char t = buf[i]; buf[i] = buf[j]; buf[j] = t; }
    buf[pos] = '\0';
    if (pos + 1 > Length) return 0xC0000023; /* STATUS_BUFFER_TOO_SMALL */
    for (int i = 0; i <= pos; i++) String[i] = buf[i];
    return 0; /* STATUS_SUCCESS */
}

/* ------------------------------------------------------------------
 * RtlQueryPackageIdentity — we are not a packaged app
 * ------------------------------------------------------------------ */
int32_t __attribute__((ms_abi)) lsw_RtlQueryPackageIdentity(void* TokenObject,
    uint16_t* PackageFullName, uint64_t* PackageSize,
    uint16_t* AppId, uint64_t* AppIdSize, uint8_t* DynamicId) {
    (void)TokenObject; (void)PackageFullName; (void)PackageSize;
    (void)AppId; (void)AppIdSize; (void)DynamicId;
    return 0xC0000225; /* STATUS_NOT_FOUND */
}

/* ------------------------------------------------------------------
 * Thread / token stubs (privilege management — no-ops on Linux)
 * ------------------------------------------------------------------ */
int __attribute__((ms_abi)) lsw_NtSetInformationThread(void* hThread, int cls, void* info, uint32_t len) {
    (void)hThread; (void)cls; (void)info; (void)len;
    return STATUS_SUCCESS;
}
int __attribute__((ms_abi)) lsw_NtAdjustPrivilegesToken(void* TokenHandle, int DisableAllPrivileges,
    void* NewState, uint32_t BufferLength, void* PreviousState, uint32_t* ReturnLength) {
    (void)TokenHandle; (void)DisableAllPrivileges; (void)NewState;
    (void)BufferLength; (void)PreviousState;
    if (ReturnLength) *ReturnLength = 0;
    return STATUS_SUCCESS;
}
int __attribute__((ms_abi)) lsw_NtDuplicateToken(void* ExistingTokenHandle, uint32_t DesiredAccess,
    void* ObjectAttributes, int EffectiveOnly, int TokenType, void** NewTokenHandle) {
    (void)ExistingTokenHandle; (void)DesiredAccess; (void)ObjectAttributes;
    (void)EffectiveOnly; (void)TokenType;
    if (NewTokenHandle) *NewTokenHandle = NULL;
    return (int)STATUS_NOT_IMPLEMENTED;
}
int __attribute__((ms_abi)) lsw_NtOpenProcessToken(void* ProcessHandle, uint32_t DesiredAccess,
    void** TokenHandle) {
    (void)ProcessHandle; (void)DesiredAccess;
    if (TokenHandle) *TokenHandle = NULL;
    return (int)STATUS_NOT_IMPLEMENTED;
}

/* ------------------------------------------------------------------
 * SID helper stubs
 * ------------------------------------------------------------------ */
typedef struct {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    uint8_t IdentifierAuthority[6];
    uint32_t SubAuthority[1]; /* flexible */
} LSW_SID;

uint8_t* __attribute__((ms_abi)) lsw_RtlSubAuthorityCountSid(LSW_SID* sid) {
    if (!sid) return NULL;
    return &sid->SubAuthorityCount;
}
int __attribute__((ms_abi)) lsw_RtlInitializeSid(LSW_SID* sid, void* auth, uint8_t nSubAuthority) {
    if (!sid) return (int)STATUS_INVALID_PARAMETER;
    sid->Revision = 1;
    sid->SubAuthorityCount = nSubAuthority;
    if (auth) memcpy(sid->IdentifierAuthority, auth, 6);
    else memset(sid->IdentifierAuthority, 0, 6);
    return STATUS_SUCCESS;
}
uint32_t __attribute__((ms_abi)) lsw_RtlLengthRequiredSid(uint32_t nSubAuthority) {
    return 8 + 4 * nSubAuthority;
}
uint32_t* __attribute__((ms_abi)) lsw_RtlSubAuthoritySid(LSW_SID* sid, uint32_t n) {
    if (!sid) return NULL;
    return &sid->SubAuthority[n];
}
uint32_t __attribute__((ms_abi)) lsw_RtlLengthSid(LSW_SID* sid) {
    if (!sid) return 0;
    return 8 + 4 * (uint32_t)sid->SubAuthorityCount;
}
int __attribute__((ms_abi)) lsw_RtlCopySid(uint32_t destLen, LSW_SID* dest, LSW_SID* src) {
    if (!dest || !src) return (int)STATUS_INVALID_PARAMETER;
    uint32_t needed = lsw_RtlLengthSid(src);
    if (destLen < needed) return (int)STATUS_BUFFER_OVERFLOW;
    memcpy(dest, src, needed);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * RtlGetNtProductType
 * ------------------------------------------------------------------ */
int __attribute__((ms_abi)) lsw_RtlGetNtProductType(uint32_t* type) {
    if (type) *type = 1; /* NtProductWinNt */
    return 1; /* TRUE */
}

/* ------------------------------------------------------------------
 * Rtl Dynamic Hash Table
 *
 * netstat.exe and other tools use RtlCreateHashTableEx +
 * RtlEnumerateEntryHashTable to walk the TCP/UDP connection tables
 * via IPHLPAPI.  On Linux there are no such tables, so we provide
 * a minimal implementation that returns an empty (but valid) table.
 * This prevents the NULL-deref crash while still letting netstat
 * run to completion (it will show "no connections").
 * ------------------------------------------------------------------ */

/* Minimal opaque hash-table header — callers just need a non-NULL
 * pointer and NumEntries == 0 to skip the enumeration loop. */
typedef struct {
    uint32_t Flags;
    uint32_t Shift;
    uint32_t TableSize;
    uint32_t Pivot;
    uint32_t DivisorMask;
    uint32_t NumEntries;        /* 0 — empty table */
    uint32_t NonEmptyBuckets;
    uint32_t NumEnumerators;
    void*    Directory;
} lsw_rtl_hash_table_t;

/* bool RtlCreateHashTableEx(table**, tableSize, divisor, flags) */
int __attribute__((ms_abi)) lsw_RtlCreateHashTableEx(
    lsw_rtl_hash_table_t** out, uint32_t table_size, uint32_t divisor, uint32_t flags)
{
    (void)table_size; (void)divisor; (void)flags;
    if (!out) return 0;
    lsw_rtl_hash_table_t* t = calloc(1, sizeof(*t));
    if (!t) return 0;
    t->TableSize = 1;
    *out = t;
    return 1; /* TRUE */
}

/* void RtlDeleteHashTable(table) */
void __attribute__((ms_abi)) lsw_RtlDeleteHashTable(lsw_rtl_hash_table_t* table) {
    free(table);
}

/* entry* RtlEnumerateEntryHashTable(table, enumerator) — always empty */
void* __attribute__((ms_abi)) lsw_RtlEnumerateEntryHashTable(
    lsw_rtl_hash_table_t* table, void* enumerator)
{
    (void)table; (void)enumerator;
    return NULL; /* no entries */
}

/* entry* RtlGetNextEntryHashTable(table, enumerator) — always empty */
void* __attribute__((ms_abi)) lsw_RtlGetNextEntryHashTable(
    lsw_rtl_hash_table_t* table, void* enumerator)
{
    (void)table; (void)enumerator;
    return NULL;
}

/* void RtlEndEnumerationHashTable(table, enumerator) */
void __attribute__((ms_abi)) lsw_RtlEndEnumerationHashTable(
    lsw_rtl_hash_table_t* table, void* enumerator)
{
    (void)table; (void)enumerator;
}

/* void RtlInitEnumerationHashTable / RtlInitHashTableEnumeration — alias */
void __attribute__((ms_abi)) lsw_RtlInitEnumerationHashTable(
    lsw_rtl_hash_table_t* table, void* enumerator)
{
    (void)table; (void)enumerator;
}

/* entry* RtlLookupEntryHashTable(table, signature, context) */
void* __attribute__((ms_abi)) lsw_RtlLookupEntryHashTable(
    lsw_rtl_hash_table_t* table, uintptr_t signature, void* context)
{
    (void)table; (void)signature; (void)context;
    return NULL;
}

/* bool RtlRemoveEntryHashTable(table, entry, context) */
int __attribute__((ms_abi)) lsw_RtlRemoveEntryHashTable(
    lsw_rtl_hash_table_t* table, void* entry, void* context)
{
    (void)table; (void)entry; (void)context;
    return 0; /* FALSE — entry not found */
}

/* bool RtlInsertEntryHashTable(table, entry, signature, context) */
int __attribute__((ms_abi)) lsw_RtlInsertEntryHashTable(
    lsw_rtl_hash_table_t* table, void* entry, uintptr_t signature, void* context)
{
    (void)table; (void)entry; (void)signature; (void)context;
    return 0; /* FALSE — not supported */
}

/* ------------------------------------------------------------------
 * RtlResourceX stubs (RtlAcquireResourceExclusive, etc.)
 * ------------------------------------------------------------------ */
int __attribute__((ms_abi)) lsw_RtlAcquireResourceExclusive(void* resource, int wait) {
    (void)resource; (void)wait;
    return 1; /* TRUE */
}

int __attribute__((ms_abi)) lsw_RtlAcquireResourceShared(void* resource, int wait) {
    (void)resource; (void)wait;
    return 1;
}

void __attribute__((ms_abi)) lsw_RtlReleaseResource(void* resource) {
    (void)resource;
}

void __attribute__((ms_abi)) lsw_RtlDeleteResource(void* resource) {
    (void)resource;
}

int __attribute__((ms_abi)) lsw_RtlInitializeResource(void* resource) {
    (void)resource;
    return 1;
}

/* ------------------------------------------------------------------
 * NT file/security stubs (used by robocopy, xcopy, etc.)
 * ------------------------------------------------------------------ */
/* -----------------------------------------------------------------------
 * NtOpenFile — open a file or directory from an NT-style path.
 * ObjectAttributes->ObjectName holds a \??\C:\path style wide-char path.
 * We translate that to a Linux path and call open() / opendir().
 * ----------------------------------------------------------------------- */
int32_t __attribute__((ms_abi)) lsw_NtOpenFile(
    void** handle, uint32_t access, void* obj_attrs_raw,
    void* io_status_raw, uint32_t share, uint32_t open_opts)
{
    (void)access; (void)share;
    lsw_io_status_t* io = (lsw_io_status_t*)io_status_raw;
    if (handle) *handle = (void*)(intptr_t)-1;

    lsw_object_attributes_t* oa = (lsw_object_attributes_t*)obj_attrs_raw;
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer) {
        if (io) { io->Status = STATUS_INVALID_PARAMETER; io->Information = 0; }
        return STATUS_INVALID_PARAMETER;
    }

    char linux_path[4096];
    /* Handle RootDirectory-relative paths */
    if (oa->RootDirectory && oa->RootDirectory != (void*)(intptr_t)-1 &&
        (intptr_t)oa->RootDirectory > 0) {
        /* Relative open: resolve against parent dir fd */
        char name_mb[1024] = {0};
        const uint16_t* wname = oa->ObjectName->Buffer;
        size_t wlen = oa->ObjectName->Length / 2;
        for (size_t i = 0; i < wlen && i < sizeof(name_mb)-1; i++)
            name_mb[i] = (wname[i] < 128) ? (char)wname[i] : '?';
        /* Get parent path from dir handle */
        lsw_nt_dir_handle_t* pdh = (lsw_nt_dir_handle_t*)oa->RootDirectory;
        if ((uintptr_t)oa->RootDirectory >= 0x10000u && pdh->magic == LSW_DIR_MAGIC) {
            char parpath[4096];
            if (fcntl(pdh->dirfd, F_GETFD) >= 0) {
                /* Build path via /proc/self/fd */
                char fdpath[64];
                snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", pdh->dirfd);
                ssize_t r = readlink(fdpath, parpath, sizeof(parpath)-1);
                if (r > 0) { parpath[r] = '\0'; snprintf(linux_path, sizeof(linux_path), "%s/%s", parpath, name_mb); }
                else snprintf(linux_path, sizeof(linux_path), "%s", name_mb);
            } else snprintf(linux_path, sizeof(linux_path), "%s", name_mb);
        } else snprintf(linux_path, sizeof(linux_path), "%s", name_mb);
    } else {
        if (lsw_nt_path_to_linux(oa->ObjectName->Buffer, linux_path, sizeof(linux_path)) != 0) {
            LSW_LOG_WARN("NtOpenFile: path translation failed");
            if (io) { io->Status = STATUS_OBJECT_NAME_NOT_FOUND; io->Information = 0; }
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    /* Normalize: strip trailing slashes */
    size_t plen = strlen(linux_path);
    while (plen > 1 && linux_path[plen-1] == '/') linux_path[--plen] = '\0';

    LSW_LOG_DEBUG("NtOpenFile: %s (opts=0x%x)", linux_path, open_opts);

    /* Stat the path to decide file vs directory */
    struct stat st;
    if (stat(linux_path, &st) != 0) {
        LSW_LOG_WARN("NtOpenFile: stat failed for %s: %s", linux_path, strerror(errno));
        int32_t ns = (errno == ENOENT) ? STATUS_OBJECT_NAME_NOT_FOUND
                   : (errno == EACCES) ? STATUS_ACCESS_DENIED
                   : STATUS_UNSUCCESSFUL;
        if (io) { io->Status = ns; io->Information = 0; }
        return ns;
    }

    if (S_ISDIR(st.st_mode) || (open_opts & FILE_DIRECTORY_FILE)) {
        /* Directory — open with opendir() and wrap in a typed handle */
        DIR* dp = opendir(linux_path);
        if (!dp) {
            LSW_LOG_WARN("NtOpenFile: opendir(%s) failed: %s", linux_path, strerror(errno));
            if (io) { io->Status = STATUS_ACCESS_DENIED; io->Information = 0; }
            return STATUS_ACCESS_DENIED;
        }
        lsw_nt_dir_handle_t* dh = (lsw_nt_dir_handle_t*)malloc(sizeof(*dh));
        if (!dh) { closedir(dp); return STATUS_NO_MEMORY; }
        dh->magic = LSW_DIR_MAGIC;
        dh->dirp  = (void*)dp;
        dh->dirfd = dirfd(dp);
        if (handle) *handle = (void*)dh;
        if (io) { io->Status = STATUS_SUCCESS; io->Information = 1; /* FILE_OPENED */ }
        LSW_LOG_DEBUG("NtOpenFile: opened dir %s -> handle %p", linux_path, (void*)dh);
        return STATUS_SUCCESS;
    }

    /* Regular file — open with open() and return fd as handle */
    int flags = O_RDONLY;
    if (access & 0x40000000) flags = O_RDWR;    /* FILE_WRITE_DATA / GENERIC_WRITE */
    else if (access & 0x80000000) flags = O_RDONLY; /* GENERIC_READ */
    int fd = open(linux_path, flags);
    if (fd < 0) {
        LSW_LOG_WARN("NtOpenFile: open(%s) failed: %s", linux_path, strerror(errno));
        int32_t ns = (errno == ENOENT) ? STATUS_OBJECT_NAME_NOT_FOUND
                   : (errno == EACCES) ? STATUS_ACCESS_DENIED
                   : STATUS_UNSUCCESSFUL;
        if (io) { io->Status = ns; io->Information = 0; }
        return ns;
    }
    if (handle) *handle = (void*)(intptr_t)fd;
    if (io) { io->Status = STATUS_SUCCESS; io->Information = 1; /* FILE_OPENED */ }
    LSW_LOG_DEBUG("NtOpenFile: opened file %s -> fd %d", linux_path, fd);
    return STATUS_SUCCESS;
}

/* NtCreateFile — create or open a file/directory */
int32_t __attribute__((ms_abi)) lsw_NtCreateFile(
    void** handle, uint32_t access, void* obj_attrs_raw,
    void* io_status_raw, void* alloc_size, uint32_t file_attrs,
    uint32_t share, uint32_t disposition, uint32_t create_opts,
    void* ea_buf, uint32_t ea_len)
{
    (void)alloc_size; (void)file_attrs; (void)share; (void)ea_buf; (void)ea_len;
    lsw_io_status_t* io = (lsw_io_status_t*)io_status_raw;
    if (handle) *handle = (void*)(intptr_t)-1;

    lsw_object_attributes_t* oa = (lsw_object_attributes_t*)obj_attrs_raw;
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer) {
        if (io) { io->Status = STATUS_INVALID_PARAMETER; io->Information = 0; }
        return STATUS_INVALID_PARAMETER;
    }

    char linux_path[4096];
    if (lsw_nt_path_to_linux(oa->ObjectName->Buffer, linux_path, sizeof(linux_path)) != 0) {
        if (io) { io->Status = STATUS_OBJECT_NAME_NOT_FOUND; io->Information = 0; }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    size_t plen = strlen(linux_path);
    while (plen > 1 && linux_path[plen-1] == '/') linux_path[--plen] = '\0';

    LSW_LOG_DEBUG("NtCreateFile: %s (disp=%u opts=0x%x)", linux_path, disposition, create_opts);

    if (create_opts & FILE_DIRECTORY_FILE) {
        /* Create/open directory */
        if (disposition == FILE_CREATE || disposition == FILE_OPEN_IF) {
            mkdir(linux_path, 0755); /* ignore error if exists */
        }
        DIR* dp = opendir(linux_path);
        if (!dp) {
            if (io) { io->Status = STATUS_OBJECT_NAME_NOT_FOUND; io->Information = 0; }
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        lsw_nt_dir_handle_t* dh = (lsw_nt_dir_handle_t*)malloc(sizeof(*dh));
        if (!dh) { closedir(dp); return STATUS_NO_MEMORY; }
        dh->magic = LSW_DIR_MAGIC;
        dh->dirp  = (void*)dp;
        dh->dirfd = dirfd(dp);
        if (handle) *handle = (void*)dh;
        if (io) { io->Status = STATUS_SUCCESS; io->Information = 1; }
        return STATUS_SUCCESS;
    }

    /* File open/create */
    int flags = 0;
    int create_new = 0;
    switch (disposition) {
        case FILE_SUPERSEDE:    flags = O_CREAT | O_TRUNC;  create_new = 1; break;
        case FILE_OPEN:         flags = 0;                  break;
        case FILE_CREATE:       flags = O_CREAT | O_EXCL;   create_new = 1; break;
        case FILE_OPEN_IF:      flags = O_CREAT;            create_new = 1; break;
        case FILE_OVERWRITE:    flags = O_TRUNC;            break;
        case FILE_OVERWRITE_IF: flags = O_CREAT | O_TRUNC;  create_new = 1; break;
        default:                flags = 0; break;
    }
    if (access & 0xC0000000UL) { /* GENERIC_READ|WRITE */
        if ((access & 0x40000000) || create_new) flags |= O_RDWR;
        else flags |= O_RDONLY;
    } else {
        flags |= O_RDWR;
    }
    int fd = open(linux_path, flags, 0644);
    if (fd < 0) {
        LSW_LOG_WARN("NtCreateFile: open(%s) failed: %s", linux_path, strerror(errno));
        int32_t ns = (errno == ENOENT || errno == ENOTDIR) ? STATUS_OBJECT_NAME_NOT_FOUND
                   : (errno == EACCES) ? STATUS_ACCESS_DENIED
                   : (errno == EEXIST) ? 0xC0000035 /* STATUS_OBJECT_NAME_COLLISION */
                   : STATUS_UNSUCCESSFUL;
        if (io) { io->Status = ns; io->Information = 0; }
        return ns;
    }
    if (handle) *handle = (void*)(intptr_t)fd;
    if (io) {
        io->Status = STATUS_SUCCESS;
        io->Information = (create_new && !(flags & O_EXCL)) ? 2 : 1; /* FILE_CREATED / FILE_OPENED */
    }
    LSW_LOG_DEBUG("NtCreateFile: %s -> fd %d", linux_path, fd);
    return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * NtQueryDirectoryFile — enumerate directory entries.
 * Supports FileDirectoryInformation (1), FileFullDirectoryInformation (2),
 * FileBothDirectoryInformation (3), FileNamesInformation (12),
 * FileIdBothDirectoryInformation (37).
 * ----------------------------------------------------------------------- */
int32_t __attribute__((ms_abi)) lsw_NtQueryDirectoryFile(
    void* handle, void* event, void* apc_routine, void* apc_ctx,
    void* io_status_raw, void* file_info, uint32_t len, int info_class,
    int single, void* file_name_raw, int restart)
{
    (void)event; (void)apc_routine; (void)apc_ctx;
    lsw_io_status_t* io = (lsw_io_status_t*)io_status_raw;

    /* Windows BOOLEAN is 1 byte; the int parameter may have garbage in upper bytes */
    int restart_flag = (uint8_t)restart;
    int single_flag  = (uint8_t)single;

    LSW_LOG_DEBUG("NtQueryDirectoryFile: handle=%p class=%d len=%u restart=%d single=%d",
                  handle, info_class, len, restart_flag, single_flag);

    /* Validate handle is a dir handle */
    lsw_nt_dir_handle_t* dh = (lsw_nt_dir_handle_t*)handle;
    if (!dh || (uintptr_t)handle < 0x10000u || dh->magic != LSW_DIR_MAGIC || !dh->dirp) {
        LSW_LOG_WARN("NtQueryDirectoryFile: invalid handle %p (magic=%08x)", handle, dh ? dh->magic : 0);
        if (io) { io->Status = STATUS_INVALID_PARAMETER; io->Information = 0; }
        return STATUS_INVALID_PARAMETER;
    }
    DIR* dp = (DIR*)dh->dirp;

    /* Optional file name filter */
    char filter_mb[256] = {0};
    int has_filter = 0;
    if (file_name_raw) {
        lsw_unicode_string_t* fn = (lsw_unicode_string_t*)file_name_raw;
        if (fn->Buffer && fn->Length > 0) {
            size_t wlen = fn->Length / 2;
            for (size_t i = 0; i < wlen && i < sizeof(filter_mb)-1; i++)
                filter_mb[i] = (fn->Buffer[i] < 128) ? (char)fn->Buffer[i] : '?';
            has_filter = 1;
        }
    }

    if (restart_flag) rewinddir(dp);

    uint8_t* buf = (uint8_t*)file_info;
    uint32_t buf_used = 0;
    uint32_t last_entry_offset = 0; /* offset of last entry's NextEntryOffset field */
    int entries_written = 0;

    /* Fixed header sizes for each info class */
    uint32_t fixed_sz;
    switch (info_class) {
        case 1:  fixed_sz = offsetof(lsw_file_dir_info_t,        FileName); break;
        case 2:  fixed_sz = offsetof(lsw_file_full_dir_info_t,   FileName); break;
        case 3:  fixed_sz = offsetof(lsw_file_both_dir_info_t,   FileName); break;
        case 12: fixed_sz = offsetof(lsw_file_names_info_t,      FileName); break;
        case 37: fixed_sz = offsetof(lsw_file_id_both_dir_info_t,FileName); break;
        default: fixed_sz = offsetof(lsw_file_dir_info_t,        FileName); break;
    }

    while (1) {
        struct dirent* de = readdir(dp);
        if (!de) break; /* end of directory */

        const char* name = de->d_name;
        /* Apply filter (simple wildcard: * matches all) */
        if (has_filter && strcmp(filter_mb, "*") != 0 &&
            strcasecmp(filter_mb, name) != 0) continue;

        /* Convert name to wide */
        uint16_t wname[512];
        uint32_t wlen = 0;
        for (; name[wlen] && wlen < 511; wlen++) wname[wlen] = (uint8_t)name[wlen];
        uint32_t fname_bytes = wlen * 2;

        /* Compute entry size (aligned to 8 bytes) */
        uint32_t entry_sz = (fixed_sz + fname_bytes + 7) & ~7u;
        if (buf_used + entry_sz > len) {
            if (entries_written == 0) {
                if (io) { io->Status = STATUS_BUFFER_OVERFLOW; io->Information = 0; }
                return (int32_t)0x80000005; /* STATUS_BUFFER_OVERFLOW */
            }
            /* Put back this entry by seeking back — can't in readdir, just stop */
            break;
        }

        /* Stat the file for metadata */
        struct stat st;
        int have_stat = (fstatat(dh->dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0);

        uint32_t attrs = 0;
        int64_t size = 0, alloc = 0;
        int64_t ctime_ft = 0, atime_ft = 0, mtime_ft = 0;
        if (have_stat) {
            if (S_ISDIR(st.st_mode)) attrs |= FILE_ATTRIBUTE_DIRECTORY;
            else attrs |= FILE_ATTRIBUTE_ARCHIVE;
            if (!(st.st_mode & S_IWUSR)) attrs |= FILE_ATTRIBUTE_READONLY;
            if (!attrs) attrs = FILE_ATTRIBUTE_NORMAL;
            size  = (int64_t)st.st_size;
            alloc = (int64_t)((st.st_blocks * 512 + 4095) & ~(int64_t)4095);
            ctime_ft = timespec_to_filetime(&st.st_ctim);
            atime_ft = timespec_to_filetime(&st.st_atim);
            mtime_ft = timespec_to_filetime(&st.st_mtim);
        } else {
            if (de->d_type == DT_DIR) attrs = FILE_ATTRIBUTE_DIRECTORY;
            else attrs = FILE_ATTRIBUTE_ARCHIVE;
        }

        /* Fill in entry */
        uint8_t* p = buf + buf_used;
        memset(p, 0, entry_sz);
        last_entry_offset = buf_used;

        switch (info_class) {
        case 2: {
            lsw_file_full_dir_info_t* e = (lsw_file_full_dir_info_t*)p;
            e->NextEntryOffset = entry_sz;
            e->CreationTime    = ctime_ft;
            e->LastAccessTime  = atime_ft;
            e->LastWriteTime   = mtime_ft;
            e->ChangeTime      = mtime_ft;
            e->EndOfFile       = size;
            e->AllocationSize  = alloc;
            e->FileAttributes  = attrs;
            e->FileNameLength  = fname_bytes;
            e->EaSize          = 0;
            memcpy(e->FileName, wname, fname_bytes);
            break;
        }
        case 3: {
            lsw_file_both_dir_info_t* e = (lsw_file_both_dir_info_t*)p;
            e->NextEntryOffset = entry_sz;
            e->CreationTime    = ctime_ft;
            e->LastAccessTime  = atime_ft;
            e->LastWriteTime   = mtime_ft;
            e->ChangeTime      = mtime_ft;
            e->EndOfFile       = size;
            e->AllocationSize  = alloc;
            e->FileAttributes  = attrs;
            e->FileNameLength  = fname_bytes;
            e->EaSize          = 0;
            e->ShortNameLength = 0;
            memcpy(e->FileName, wname, fname_bytes);
            break;
        }
        case 37: {
            lsw_file_id_both_dir_info_t* e = (lsw_file_id_both_dir_info_t*)p;
            e->NextEntryOffset = entry_sz;
            e->CreationTime    = ctime_ft;
            e->LastAccessTime  = atime_ft;
            e->LastWriteTime   = mtime_ft;
            e->ChangeTime      = mtime_ft;
            e->EndOfFile       = size;
            e->AllocationSize  = alloc;
            e->FileAttributes  = attrs;
            e->FileNameLength  = fname_bytes;
            e->EaSize          = 0;
            e->ShortNameLength = 0;
            e->FileId          = have_stat ? (int64_t)st.st_ino : 0;
            memcpy(e->FileName, wname, fname_bytes);
            break;
        }
        case 12: {
            lsw_file_names_info_t* e = (lsw_file_names_info_t*)p;
            e->NextEntryOffset = entry_sz;
            e->FileNameLength  = fname_bytes;
            memcpy(e->FileName, wname, fname_bytes);
            break;
        }
        default: { /* class 1 and unknown */
            lsw_file_dir_info_t* e = (lsw_file_dir_info_t*)p;
            e->NextEntryOffset = entry_sz;
            e->CreationTime    = ctime_ft;
            e->LastAccessTime  = atime_ft;
            e->LastWriteTime   = mtime_ft;
            e->ChangeTime      = mtime_ft;
            e->EndOfFile       = size;
            e->AllocationSize  = alloc;
            e->FileAttributes  = attrs;
            e->FileNameLength  = fname_bytes;
            memcpy(e->FileName, wname, fname_bytes);
            break;
        }
        }

        LSW_LOG_DEBUG("NtQueryDirectoryFile:  entry[%d]='%s' attrs=0x%x size=%lld", entries_written, name, attrs, (long long)size);
        buf_used += entry_sz;
        entries_written++;
        if (single_flag) break; /* ReturnSingleEntry */
    }

    if (entries_written == 0) {
        if (io) { io->Status = STATUS_NO_MORE_FILES; io->Information = 0; }
        return (int32_t)0x80000006; /* STATUS_NO_MORE_FILES */
    }

    /* Clear NextEntryOffset of last entry to mark end of chain */
    *(uint32_t*)(buf + last_entry_offset) = 0;

    if (io) { io->Status = STATUS_SUCCESS; io->Information = buf_used; }
    LSW_LOG_DEBUG("NtQueryDirectoryFile: returned %d entries, %u bytes used", entries_written, buf_used);
    return STATUS_SUCCESS;
}

/* NtReadFile — read from a file handle */
int32_t __attribute__((ms_abi)) lsw_NtReadFile(
    void* handle, void* event, void* apc, void* apc_ctx,
    void* io_status_raw, void* buffer, uint32_t length,
    int64_t* byte_offset, uint32_t* key)
{
    (void)event; (void)apc; (void)apc_ctx; (void)key;
    lsw_io_status_t* io = (lsw_io_status_t*)io_status_raw;

    /* Resolve fd */
    int fd = -1;
    if ((uintptr_t)handle < 0x10000u) {
        fd = (int)(intptr_t)handle;
    }
    if (fd < 0) {
        if (io) { io->Status = STATUS_INVALID_PARAMETER; io->Information = 0; }
        return STATUS_INVALID_PARAMETER;
    }

    if (byte_offset && *byte_offset >= 0) lseek(fd, (off_t)*byte_offset, SEEK_SET);

    ssize_t r = read(fd, buffer, length);
    if (r < 0) {
        if (io) { io->Status = STATUS_UNSUCCESSFUL; io->Information = 0; }
        return STATUS_UNSUCCESSFUL;
    }
    if (r == 0) {
        if (io) { io->Status = STATUS_END_OF_FILE; io->Information = 0; }
        return STATUS_END_OF_FILE;
    }
    if (io) { io->Status = STATUS_SUCCESS; io->Information = (uint64_t)r; }
    return STATUS_SUCCESS;
}

/* NtWriteFile — write to a file handle */
int32_t __attribute__((ms_abi)) lsw_NtWriteFile(
    void* handle, void* event, void* apc, void* apc_ctx,
    void* io_status_raw, const void* buffer, uint32_t length,
    int64_t* byte_offset, uint32_t* key)
{
    (void)event; (void)apc; (void)apc_ctx; (void)key;
    lsw_io_status_t* io = (lsw_io_status_t*)io_status_raw;

    int fd = -1;
    if ((uintptr_t)handle < 0x10000u) fd = (int)(intptr_t)handle;
    if (fd < 0) {
        if (io) { io->Status = STATUS_INVALID_PARAMETER; io->Information = 0; }
        return STATUS_INVALID_PARAMETER;
    }

    if (byte_offset && *byte_offset >= 0) lseek(fd, (off_t)*byte_offset, SEEK_SET);

    ssize_t r = write(fd, buffer, length);
    if (r < 0) {
        if (io) { io->Status = STATUS_UNSUCCESSFUL; io->Information = 0; }
        return STATUS_UNSUCCESSFUL;
    }
    if (io) { io->Status = STATUS_SUCCESS; io->Information = (uint64_t)r; }
    return STATUS_SUCCESS;
}

/* NtQueryInformationFile — handles common info classes needed by file tools */
int32_t __attribute__((ms_abi)) lsw_NtQueryInformationFile(
    void* handle, void* io_status, void* file_info, uint32_t len, int info_class)
{
    if (!file_info || len == 0) return (int32_t)0xC000000D; /* STATUS_INVALID_PARAMETER */

    /* Handle may be a raw fd OR an lsw_nt_dir_handle_t* from NtOpenFile */
    int fd = -1;
    lsw_nt_dir_handle_t* dh = (lsw_nt_dir_handle_t*)handle;
    if ((uintptr_t)handle >= 0x10000u && dh && dh->magic == LSW_DIR_MAGIC)
        fd = dh->dirfd;
    else if ((uintptr_t)handle < 65536u)
        fd = (int)(intptr_t)handle;

    LSW_LOG_DEBUG("NtQueryInformationFile: handle=%p class=%d fd=%d", handle, info_class, fd);

    struct stat st;
    int have_stat = (fd >= 0 && fstat(fd, &st) == 0);
    uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t ft = have_stat ? (uint64_t)st.st_mtime * 10000000ULL + epoch_offset : epoch_offset;

    memset(file_info, 0, len);
    if (io_status) { *(uint32_t*)io_status = 0; ((uint32_t*)io_status)[1] = 0; }

    switch (info_class) {
    case 4: { /* FileBasicInformation: 4×int64 timestamps + uint32 attributes = 40 bytes */
        if (len < 40) return (int32_t)0xC0000023; /* STATUS_BUFFER_TOO_SMALL */
        int64_t* p = (int64_t*)file_info;
        p[0] = (int64_t)ft; p[1] = (int64_t)ft; p[2] = (int64_t)ft; p[3] = (int64_t)ft;
        *(uint32_t*)(p + 4) = have_stat ? (S_ISDIR(st.st_mode) ? 0x10 : 0x80) : 0x80;
        return 0;
    }
    case 5: { /* FileStandardInformation: AllocationSize[8] EndOfFile[8] Links[4] Del[1] Dir[1] = 24 bytes */
        if (len < 24) return (int32_t)0xC0000023;
        int64_t* p = (int64_t*)file_info;
        int64_t sz = have_stat ? (int64_t)st.st_size : 0;
        p[0] = (sz + 4095) & ~4095LL;
        p[1] = sz;
        uint32_t* lk = (uint32_t*)(p + 2); lk[0] = 1;
        uint8_t* bp = (uint8_t*)(lk + 1); bp[0] = 0; bp[1] = (have_stat && S_ISDIR(st.st_mode)) ? 1 : 0;
        return 0;
    }
    case 6: { /* FileInternalInformation: FileId[8] */
        if (len < 8) return (int32_t)0xC0000023;
        *(int64_t*)file_info = have_stat ? (int64_t)st.st_ino : 0;
        return 0;
    }
    case 9: { /* FileNameInformation: FileNameLength[4] + FileName[] — return empty */
        if (len < 4) return (int32_t)0xC0000023;
        *(uint32_t*)file_info = 0;
        return 0;
    }
    default:
        LSW_LOG_DEBUG("NtQueryInformationFile: unhandled class %d", info_class);
        return (int32_t)0xC00000BB; /* STATUS_NOT_SUPPORTED */
    }
}

/* NtSetInformationProcess — stub returns STATUS_SUCCESS */
int32_t __attribute__((ms_abi)) lsw_NtSetInformationProcess(
    void* handle, int info_class, void* info, uint32_t len)
{
    (void)handle; (void)info_class; (void)info; (void)len;
    return 0; /* STATUS_SUCCESS */
}

/* NtQuerySecurityObject — stub returns STATUS_NOT_SUPPORTED */
int32_t __attribute__((ms_abi)) lsw_NtQuerySecurityObject(
    void* handle, uint32_t info, void* sec_desc, uint32_t len, uint32_t* needed)
{
    (void)handle; (void)info; (void)sec_desc; (void)len;
    if (needed) *needed = 0;
    return (int32_t)0xC00000BB;
}

/* RtlGetDaclSecurityDescriptor — stub; sets output to NULL (no DACL) */
int32_t __attribute__((ms_abi)) lsw_RtlGetDaclSecurityDescriptor(
    void* sec_desc, int* dacl_present, void** dacl, int* defaulted)
{
    (void)sec_desc;
    if (dacl_present) *dacl_present = 0;
    if (dacl) *dacl = NULL;
    if (defaulted) *defaulted = 0;
    return 0;
}

/* RtlSetControlSecurityDescriptor — stub; returns success */
int32_t __attribute__((ms_abi)) lsw_RtlSetControlSecurityDescriptor(
    void* sec_desc, uint16_t ctrl_bits_of_interest, uint16_t ctrl_bits_to_set)
{
    (void)sec_desc; (void)ctrl_bits_of_interest; (void)ctrl_bits_to_set;
    return 0;
}

/* RtlGetSaclSecurityDescriptor — stub; reports no SACL */
int32_t __attribute__((ms_abi)) lsw_RtlGetSaclSecurityDescriptor(
    void* sec_desc, int* sacl_present, void** sacl, int* defaulted)
{
    (void)sec_desc;
    if (sacl_present) *sacl_present = 0;
    if (sacl) *sacl = NULL;
    if (defaulted) *defaulted = 0;
    return 0;
}

/* RtlGetControlSecurityDescriptor — stub; returns SE_SELF_RELATIVE (0x8000) */
int32_t __attribute__((ms_abi)) lsw_RtlGetControlSecurityDescriptor(
    void* sec_desc, uint16_t* control, uint32_t* revision)
{
    (void)sec_desc;
    if (control) *control = 0x8000; /* SE_SELF_RELATIVE */
    if (revision) *revision = 1;
    return 0;
}

/* RtlDosPathNameToRelativeNtPathName_U — convert DOS path to NT \??\ path.
 * See: https://learn.microsoft.com/en-us/windows/win32/devnotes/rtldospathnametontpathname-u
 * Allocates NtFileName->Buffer with malloc(); caller frees via RtlFreeUnicodeString.
 * RelativeName is zeroed (we don't support relative root handles). */
int __attribute__((ms_abi)) lsw_RtlDosPathNameToRelativeNtPathName_U(
    const wchar_t* dos_path_wchar, lsw_unicode_string_t* nt_path,
    wchar_t** file_part, void* relative_name_raw)
{
    if (!dos_path_wchar || !nt_path) return 0; /* FALSE */

    /* Windows passes UTF-16 (2-byte wchar_t); Linux wchar_t is 4 bytes.
     * Always treat the input as uint16_t* to avoid stride mismatches. */
    const uint16_t* dos_path = (const uint16_t*)dos_path_wchar;

    /* Zero out RelativeName if provided */
    if (relative_name_raw) memset(relative_name_raw, 0, 40);

    /* Measure dos_path length (in UTF-16 code units) */
    size_t dlen = 0;
    while (dos_path[dlen]) dlen++;

    /* Determine NT prefix to prepend */
    static const uint16_t pfx_ntpath[]  = { '\\','?','?','\\', 0 };   /* \??\ */
    static const uint16_t pfx_unc[]     = { '\\','?','?','\\','U','N','C','\\', 0 };
    static const uint16_t pfx_empty[]   = { 0 };
    const uint16_t* nt_prefix = pfx_ntpath;
    size_t prefix_len = 4;

    /* Check if it's already an NT path (\??\...) */
    if (dlen >= 4 && dos_path[0]=='\\' && dos_path[1]=='?' && dos_path[2]=='?' && dos_path[3]=='\\') {
        nt_prefix = pfx_empty;
        prefix_len = 0;
    }
    /* Extended-length path (\\?\...) → \??\... — check BEFORE UNC */
    else if (dlen >= 4 && dos_path[0]=='\\' && dos_path[1]=='\\' && dos_path[2]=='?' && dos_path[3]=='\\') {
        nt_prefix = pfx_ntpath;
        prefix_len = 4;
        dos_path += 4;
        dlen -= 4;
    }
    /* UNC path (\\server\share) → \??\UNC\server\share */
    else if (dlen >= 2 && dos_path[0]=='\\' && dos_path[1]=='\\') {
        nt_prefix = pfx_unc;
        prefix_len = 8;
        dos_path += 2; /* skip leading \\ */
        dlen -= 2;
    }

    size_t total_wchars = prefix_len + dlen; /* not counting null */
    size_t total_bytes  = total_wchars * sizeof(uint16_t);

    uint16_t* buf = (uint16_t*)malloc(total_bytes + sizeof(uint16_t)); /* +1 for null */
    if (!buf) return 0;

    /* Copy prefix */
    for (size_t i = 0; i < prefix_len; i++) buf[i] = nt_prefix[i];
    /* Copy dos path, normalising forward slashes to backslashes */
    for (size_t i = 0; i < dlen; i++) {
        uint16_t wc = dos_path[i];
        buf[prefix_len + i] = (wc == '/') ? '\\' : wc;
    }
    buf[total_wchars] = 0; /* null terminator */

    nt_path->Length        = (uint16_t)total_bytes;
    nt_path->MaximumLength = (uint16_t)(total_bytes + sizeof(uint16_t));
    nt_path->Buffer        = buf;

    /* FilePart: pointer into buf at last path component after final \ */
    if (file_part) {
        *file_part = NULL;
        /* Only set if last char is not '\' (not a bare directory path) */
        if (total_wchars > 0 && buf[total_wchars-1] != '\\') {
            uint16_t* p = buf + total_wchars;
            while (p > buf && *(p-1) != '\\') p--;
            *file_part = (wchar_t*)p;
        }
    }

    LSW_LOG_DEBUG("RtlDosPathNameToRelativeNtPathName_U: len=%zu buf=%p", total_wchars, (void*)buf);
    return 1; /* TRUE */
}

/* NtSetSecurityObject — stub; returns STATUS_SUCCESS */
int32_t __attribute__((ms_abi)) lsw_NtSetSecurityObject(
    void* handle, uint32_t info, void* sec_desc)
{
    (void)handle; (void)info; (void)sec_desc;
    return 0;
}

/* NtSetEaFile — stub; returns STATUS_SUCCESS */
int32_t __attribute__((ms_abi)) lsw_NtSetEaFile(
    void* handle, void* io_status, void* buf, uint32_t len)
{
    (void)handle; (void)io_status; (void)buf; (void)len;
    return 0;
}

/* Convert Windows FILETIME (100-ns intervals since 1601) to timespec */
static struct timespec filetime_to_timespec(int64_t ft) {
    struct timespec ts = {0, 0};
    if (ft <= 0) return ts;
    uint64_t u = (uint64_t)ft - FILETIME_EPOCH_DIFF;
    ts.tv_sec  = (time_t)(u / 10000000ULL);
    ts.tv_nsec = (long)((u % 10000000ULL) * 100ULL);
    return ts;
}

/* NtSetInformationFile — implements FileBasicInformation (class 4) for timestamp/attr setting */
int32_t __attribute__((ms_abi)) lsw_NtSetInformationFile(
    void* handle, void* io_status, void* info, uint32_t len, int info_class)
{
    if (io_status) { lsw_io_status_t* ios = (lsw_io_status_t*)io_status; ios->Status = 0; ios->Information = 0; }

    /* Resolve fd */
    int fd = -1;
    lsw_nt_dir_handle_t* dh = (lsw_nt_dir_handle_t*)handle;
    if ((uintptr_t)handle >= 0x10000u && dh && dh->magic == LSW_DIR_MAGIC)
        fd = dh->dirfd;
    else if ((uintptr_t)handle < 65536u)
        fd = (int)(intptr_t)handle;

    if (info_class == 4 && info && len >= 40 && fd >= 0) {
        /* FileBasicInformation: CreationTime[8] LastAccessTime[8] LastWriteTime[8] ChangeTime[8] Attributes[4] */
        int64_t* p = (int64_t*)info;
        int64_t atime_ft = p[1];  /* LastAccessTime */
        int64_t mtime_ft = p[2];  /* LastWriteTime */
        uint32_t attrs   = *(uint32_t*)(p + 4);

        struct timespec times[2];
        times[0] = (atime_ft > 0) ? filetime_to_timespec(atime_ft) : (struct timespec){0, UTIME_OMIT};
        times[1] = (mtime_ft > 0) ? filetime_to_timespec(mtime_ft) : (struct timespec){0, UTIME_OMIT};

        if (futimens(fd, times) != 0)
            LSW_LOG_DEBUG("NtSetInformationFile: futimens failed fd=%d: %s", fd, strerror(errno));

        /* Apply read-only attribute if requested */
        if (attrs & 0x1) { /* FILE_ATTRIBUTE_READONLY */
            struct stat st;
            if (fstat(fd, &st) == 0) {
                mode_t m = st.st_mode & ~(S_IWUSR | S_IWGRP | S_IWOTH);
                fchmod(fd, m);
            }
        }
        return 0;
    }

    LSW_LOG_DEBUG("NtSetInformationFile: handle=%p class=%d len=%u", handle, info_class, len);
    return 0;
}

/* NtQueryVolumeInformationFile — handles common volume info classes */
int32_t __attribute__((ms_abi)) lsw_NtQueryVolumeInformationFile(
    void* handle, void* io_status, void* info, uint32_t len, int info_class)
{
    if (!info || len == 0) return (int32_t)0xC000000D; /* STATUS_INVALID_PARAMETER */
    memset(info, 0, len);
    if (io_status) { *(uint32_t*)io_status = 0; ((uint32_t*)io_status)[1] = 0; }

    switch (info_class) {
    case 1: { /* FileFsVolumeInformation: VolumeCreationTime[8] SerialNumber[4] LabelLen[4] Supports[1] pad[3] Label[] */
        if (len < 18) return (int32_t)0xC0000023;
        uint32_t* p = (uint32_t*)info;
        *(uint64_t*)p = 0; /* VolumeCreationTime */
        p[2] = 0xDEADBEEF; /* VolumeSerialNumber */
        p[3] = 0;           /* VolumeLabelLength (empty) */
        ((uint8_t*)p)[16] = 0; /* SupportsObjects = FALSE */
        return 0;
    }
    case 3: { /* FileFsSizeInformation: Total[8] Available[8] SectorsPerUnit[4] BytesPerSector[4] = 24 bytes */
        if (len < 24) return (int32_t)0xC0000023;
        int64_t* p = (int64_t*)info;
        int fd = (int)(intptr_t)handle;
        struct statvfs sv;
        if (fd >= 0 && fd < 65536 && fstatvfs(fd, &sv) == 0) {
            p[0] = (int64_t)sv.f_blocks; /* TotalAllocationUnits */
            p[1] = (int64_t)sv.f_bavail; /* AvailableAllocationUnits */
            uint32_t* u = (uint32_t*)(p + 2);
            u[0] = (uint32_t)sv.f_frsize / 512; if (!u[0]) u[0] = 8; /* SectorsPerUnit */
            u[1] = 512; /* BytesPerSector */
        } else {
            p[0] = 1000000; p[1] = 500000;
            uint32_t* u = (uint32_t*)(p + 2); u[0] = 8; u[1] = 512;
        }
        return 0;
    }
    case 5: { /* FileFsAttributeInformation: Flags[4] MaxName[4] NameLen[4] Name[] */
        if (len < 12) return (int32_t)0xC0000023;
        uint32_t* p = (uint32_t*)info;
        p[0] = 0x00000003; /* FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES */
        p[1] = 255;        /* MaximumComponentNameLength */
        p[2] = 0;          /* FileSystemNameLength (empty) */
        return 0;
    }
    default:
        LSW_LOG_DEBUG("NtQueryVolumeInformationFile: unhandled class %d", info_class);
        return (int32_t)0xC00000BB; /* STATUS_NOT_SUPPORTED */
    }
}

/* NtQueryEaFile — stub; returns STATUS_NO_EAS_ON_FILE */
int32_t __attribute__((ms_abi)) lsw_NtQueryEaFile(
    void* handle, void* io_status, void* buf, uint32_t len,
    int ret_single, void* ea_list, uint32_t ea_list_len,
    uint32_t* ea_index, int restart)
{
    (void)handle; (void)io_status; (void)buf; (void)len;
    (void)ret_single; (void)ea_list; (void)ea_list_len;
    (void)ea_index; (void)restart;
    return (int32_t)0xC0000052; /* STATUS_NO_EAS_ON_FILE */
}


/* ------------------------------------------------------------------
 * API table — called by win32_api.c win32_api_register_ntdll()
 * The Makefile picks up all .c files in src/win32-api/ so the
 * api_mappings[] table in win32_api.c simply needs additional entries
 * for each symbol below.  To keep the single-table design, we declare
 * a secondary table here that win32_api_init can append.
 * ------------------------------------------------------------------ */

/*
 * ntdll API mapping table — declared extern in win32_api.c via
 * the WIN32_SOURCES wildcard build rule.  The entries are added
 * to the main dispatch via win32_api_ntdll_mappings[] and the
 * ntdll section in api_mappings[] in win32_api.c.
 */
const win32_api_mapping_t win32_api_ntdll_mappings[] = {
    /* Heap */
    {"ntdll.dll", "RtlAllocateHeap",               (void*)lsw_RtlAllocateHeap},
    {"ntdll.dll", "RtlFreeHeap",                   (void*)lsw_RtlFreeHeap},
    {"ntdll.dll", "RtlReAllocateHeap",             (void*)lsw_RtlReAllocateHeap},
    {"ntdll.dll", "RtlSizeHeap",                   (void*)lsw_RtlSizeHeap},
    {"ntdll.dll", "RtlCreateHeap",                 (void*)lsw_RtlCreateHeap},
    {"ntdll.dll", "RtlDestroyHeap",                (void*)lsw_RtlDestroyHeap},
    /* Critical section */
    {"ntdll.dll", "RtlInitializeCriticalSection",          (void*)lsw_RtlInitializeCriticalSection},
    {"ntdll.dll", "RtlInitializeCriticalSectionEx",        (void*)lsw_RtlInitializeCriticalSectionEx},
    {"ntdll.dll", "RtlInitializeCriticalSectionAndSpinCount", (void*)lsw_RtlInitializeCriticalSectionAndSpinCount},
    {"ntdll.dll", "RtlDeleteCriticalSection",              (void*)lsw_RtlDeleteCriticalSection},
    {"ntdll.dll", "RtlEnterCriticalSection",               (void*)lsw_RtlEnterCriticalSection},
    {"ntdll.dll", "RtlLeaveCriticalSection",               (void*)lsw_RtlLeaveCriticalSection},
    {"ntdll.dll", "RtlTryEnterCriticalSection",            (void*)lsw_RtlTryEnterCriticalSection},
    /* Unicode string */
    {"ntdll.dll", "RtlInitUnicodeString",          (void*)lsw_RtlInitUnicodeString},
    {"ntdll.dll", "RtlFreeUnicodeString",          (void*)lsw_RtlFreeUnicodeString},
    {"ntdll.dll", "RtlStringFromGUID",             (void*)lsw_RtlStringFromGUID},
    {"ntdll.dll", "RtlUnicodeStringToAnsiString",  (void*)lsw_RtlUnicodeStringToAnsiString},
    {"ntdll.dll", "RtlAnsiStringToUnicodeString",  (void*)lsw_RtlAnsiStringToUnicodeString},
    /* IP address conversion */
    {"ntdll.dll", "RtlIpv4AddressToStringExW",     (void*)lsw_RtlIpv4AddressToStringExW},
    {"ntdll.dll", "RtlIpv6AddressToStringW",       (void*)lsw_RtlIpv6AddressToStringW},
    {"ntdll.dll", "RtlIpv6AddressToStringExW",     (void*)lsw_RtlIpv6AddressToStringExW},
    /* Feature configuration */
    {"ntdll.dll", "RtlQueryFeatureConfiguration",                    (void*)lsw_RtlQueryFeatureConfiguration},
    {"ntdll.dll", "RtlRegisterFeatureConfigurationChangeNotification",(void*)lsw_RtlRegisterFeatureConfigurationChangeNotification},
    {"ntdll.dll", "WilFailureNotifyWatchers",                        (void*)lsw_WilFailureNotifyWatchers},
    /* NTSTATUS */
    {"ntdll.dll", "RtlNtStatusToDosError",         (void*)lsw_RtlNtStatusToDosError},
    {"ntdll.dll", "RtlNtStatusToDosErrorNoTeb",    (void*)lsw_RtlNtStatusToDosErrorNoTeb},
    /* Loader */
    {"ntdll.dll", "LdrLoadDll",                    (void*)lsw_LdrLoadDll},
    {"ntdll.dll", "LdrGetProcedureAddress",        (void*)lsw_LdrGetProcedureAddress},
    /* TEB/PEB */
    {"ntdll.dll", "NtCurrentTeb",                  (void*)lsw_NtCurrentTeb},
    {"ntdll.dll", "RtlGetCurrentPeb",              (void*)lsw_RtlGetCurrentPeb},
    /* SEH / unwinding */
    {"ntdll.dll", "RtlUnwind",                     (void*)lsw_RtlUnwind},
    {"ntdll.dll", "RtlUnwindEx",                   (void*)lsw_RtlUnwindEx},
    {"ntdll.dll", "RtlRaiseException",             (void*)lsw_RtlRaiseException},
    {"ntdll.dll", "RtlAddFunctionTable",           (void*)lsw_RtlAddFunctionTable},
    {"ntdll.dll", "RtlDeleteFunctionTable",        (void*)lsw_RtlDeleteFunctionTable},
    {"ntdll.dll", "RtlInstallFunctionTableCallback", (void*)lsw_RtlInstallFunctionTableCallback},
    {"ntdll.dll", "RtlLookupFunctionEntry",        (void*)lsw_RtlLookupFunctionEntry},
    {"ntdll.dll", "RtlCaptureContext",             (void*)lsw_RtlCaptureContext},
    {"ntdll.dll", "RtlRestoreContext",             (void*)lsw_RtlRestoreContext},
    /* Memory */
    {"ntdll.dll", "RtlCopyMemory",                 (void*)lsw_ntdll_RtlCopyMemory},
    {"ntdll.dll", "RtlFillMemory",                 (void*)lsw_ntdll_RtlFillMemory},
    {"ntdll.dll", "RtlZeroMemory",                 (void*)lsw_ntdll_RtlZeroMemory},
    {"ntdll.dll", "RtlMoveMemory",                 (void*)lsw_ntdll_RtlMoveMemory},
    {"ntdll.dll", "RtlCompareMemory",              (void*)lsw_RtlCompareMemory},
    /* Version */
    {"ntdll.dll", "RtlGetNtVersionNumbers",        (void*)lsw_RtlGetNtVersionNumbers},
    /* Debug */
    {"ntdll.dll", "DbgBreakPoint",                 (void*)lsw_DbgBreakPoint},
    {"ntdll.dll", "DbgPrint",                      (void*)lsw_DbgPrint},
    /* Process / thread */
    {"ntdll.dll", "NtTerminateProcess",            (void*)lsw_NtTerminateProcess},
    {"ntdll.dll", "NtQuerySystemInformation",      (void*)lsw_NtQuerySystemInformation},
    {"ntdll.dll", "NtQueryInformationProcess",     (void*)lsw_NtQueryInformationProcess},
    {"ntdll.dll", "NtQueryVirtualMemory",          (void*)lsw_NtQueryVirtualMemory},
    {"ntdll.dll", "NtClose",                       (void*)lsw_NtClose},
    {"ntdll.dll", "RtlExitUserProcess",            (void*)lsw_RtlExitUserProcess},
    {"ntdll.dll", "RtlExitUserThread",             (void*)lsw_RtlExitUserThread},
    {"ntdll.dll", "RtlQueryEnvironmentVariable",   (void*)lsw_RtlQueryEnvironmentVariable},
    /* String init */
    {"ntdll.dll", "RtlInitAnsiString",             (void*)lsw_RtlInitAnsiString},
    {"ntdll.dll", "RtlInitString",                 (void*)lsw_RtlInitString},
    {"ntdll.dll", "RtlOemStringToUnicodeString",   (void*)lsw_RtlOemStringToUnicodeString},
    {"ntdll.dll", "RtlxOemStringToUnicodeSize",    (void*)lsw_RtlxOemStringToUnicodeSize},
    /* Time */
    {"ntdll.dll", "NtQuerySystemTime",             (void*)lsw_NtQuerySystemTime},
    {"ntdll.dll", "RtlTimeToSecondsSince1970",     (void*)lsw_RtlTimeToSecondsSince1970},
    {"ntdll.dll", "RtlTimeFieldsToTime",           (void*)lsw_RtlTimeFieldsToTime},
    {"ntdll.dll", "RtlTimeToElapsedTimeFields",    (void*)lsw_RtlTimeToElapsedTimeFields},
    /* Thread / token (no-ops) */
    {"ntdll.dll", "NtSetInformationThread",        (void*)lsw_NtSetInformationThread},
    {"ntdll.dll", "NtAdjustPrivilegesToken",       (void*)lsw_NtAdjustPrivilegesToken},
    {"ntdll.dll", "NtDuplicateToken",              (void*)lsw_NtDuplicateToken},
    {"ntdll.dll", "NtOpenProcessToken",            (void*)lsw_NtOpenProcessToken},
    /* SID helpers */
    {"ntdll.dll", "RtlSubAuthorityCountSid",       (void*)lsw_RtlSubAuthorityCountSid},
    {"ntdll.dll", "RtlInitializeSid",              (void*)lsw_RtlInitializeSid},
    {"ntdll.dll", "RtlLengthRequiredSid",          (void*)lsw_RtlLengthRequiredSid},
    {"ntdll.dll", "RtlSubAuthoritySid",            (void*)lsw_RtlSubAuthoritySid},
    {"ntdll.dll", "RtlLengthSid",                  (void*)lsw_RtlLengthSid},
    {"ntdll.dll", "RtlCopySid",                    (void*)lsw_RtlCopySid},
    /* Product type */
    {"ntdll.dll", "RtlGetNtProductType",           (void*)lsw_RtlGetNtProductType},
    /* Integer conversion */
    {"ntdll.dll", "RtlLargeIntegerToChar",         (void*)lsw_RtlLargeIntegerToChar},
    /* Package identity — always fails, not a packaged app */
    {"ntdll.dll", "RtlQueryPackageIdentity",       (void*)lsw_RtlQueryPackageIdentity},
    /* String conversion */
    {"ntdll.dll", "RtlUnicodeToOemN",              (void*)lsw_RtlUnicodeToOemN},
    {"ntdll.dll", "RtlMultiByteToUnicodeN",        (void*)lsw_RtlMultiByteToUnicodeN},
    {"ntdll.dll", "RtlIpv4StringToAddressW",       (void*)lsw_RtlIpv4StringToAddressW},
    /* Rtl Dynamic Hash Table */
    {"ntdll.dll", "RtlCreateHashTableEx",          (void*)lsw_RtlCreateHashTableEx},
    {"ntdll.dll", "RtlDeleteHashTable",             (void*)lsw_RtlDeleteHashTable},
    {"ntdll.dll", "RtlEnumerateEntryHashTable",     (void*)lsw_RtlEnumerateEntryHashTable},
    {"ntdll.dll", "RtlGetNextEntryHashTable",       (void*)lsw_RtlGetNextEntryHashTable},
    {"ntdll.dll", "RtlEndEnumerationHashTable",     (void*)lsw_RtlEndEnumerationHashTable},
    {"ntdll.dll", "RtlInitEnumerationHashTable",    (void*)lsw_RtlInitEnumerationHashTable},
    {"ntdll.dll", "RtlLookupEntryHashTable",        (void*)lsw_RtlLookupEntryHashTable},
    {"ntdll.dll", "RtlRemoveEntryHashTable",        (void*)lsw_RtlRemoveEntryHashTable},
    {"ntdll.dll", "RtlInsertEntryHashTable",        (void*)lsw_RtlInsertEntryHashTable},
    /* Rtl Resource */
    {"ntdll.dll", "RtlAcquireResourceExclusive",   (void*)lsw_RtlAcquireResourceExclusive},
    {"ntdll.dll", "RtlAcquireResourceShared",       (void*)lsw_RtlAcquireResourceShared},
    {"ntdll.dll", "RtlReleaseResource",             (void*)lsw_RtlReleaseResource},
    {"ntdll.dll", "RtlDeleteResource",              (void*)lsw_RtlDeleteResource},
    {"ntdll.dll", "RtlInitializeResource",          (void*)lsw_RtlInitializeResource},
    /* NT file/security stubs */
    {"ntdll.dll", "NtOpenFile",                     (void*)lsw_NtOpenFile},
    {"ntdll.dll", "NtCreateFile",                   (void*)lsw_NtCreateFile},
    {"ntdll.dll", "NtReadFile",                     (void*)lsw_NtReadFile},
    {"ntdll.dll", "NtWriteFile",                    (void*)lsw_NtWriteFile},
    {"ntdll.dll", "NtQueryDirectoryFile",            (void*)lsw_NtQueryDirectoryFile},
    {"ntdll.dll", "NtQueryInformationFile",          (void*)lsw_NtQueryInformationFile},
    {"ntdll.dll", "NtSetInformationProcess",                (void*)lsw_NtSetInformationProcess},
    {"ntdll.dll", "NtQuerySecurityObject",                  (void*)lsw_NtQuerySecurityObject},
    {"ntdll.dll", "RtlGetDaclSecurityDescriptor",           (void*)lsw_RtlGetDaclSecurityDescriptor},
    {"ntdll.dll", "RtlSetControlSecurityDescriptor",        (void*)lsw_RtlSetControlSecurityDescriptor},
    {"ntdll.dll", "RtlGetSaclSecurityDescriptor",           (void*)lsw_RtlGetSaclSecurityDescriptor},
    {"ntdll.dll", "RtlGetControlSecurityDescriptor",        (void*)lsw_RtlGetControlSecurityDescriptor},
    {"ntdll.dll", "RtlDosPathNameToRelativeNtPathName_U",   (void*)lsw_RtlDosPathNameToRelativeNtPathName_U},
    {"ntdll.dll", "NtSetSecurityObject",                    (void*)lsw_NtSetSecurityObject},
    {"ntdll.dll", "NtSetEaFile",                            (void*)lsw_NtSetEaFile},
    {"ntdll.dll", "NtSetInformationFile",                   (void*)lsw_NtSetInformationFile},
    {"ntdll.dll", "NtQueryVolumeInformationFile",           (void*)lsw_NtQueryVolumeInformationFile},
    {"ntdll.dll", "NtQueryEaFile",                          (void*)lsw_NtQueryEaFile},
    /* Sentinel */
    {NULL, NULL, NULL}
};

const size_t win32_api_ntdll_mappings_count =
    (sizeof(win32_api_ntdll_mappings) / sizeof(win32_api_ntdll_mappings[0])) - 1;
