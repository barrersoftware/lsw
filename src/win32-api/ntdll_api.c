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
#include <arpa/inet.h>

/* NTSTATUS constants */
#define STATUS_SUCCESS                  0x00000000
#define STATUS_UNSUCCESSFUL             0xC0000001
#define STATUS_NOT_IMPLEMENTED          0xC0000002
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_NO_MEMORY                0xC0000017
#define STATUS_BUFFER_OVERFLOW          0x80000005

typedef uint32_t NTSTATUS;
typedef uint32_t DWORD;
typedef void*    HANDLE;

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
typedef struct {
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

/* RtlQueryFeatureConfiguration: stub — not implemented, return not-found */
NTSTATUS __attribute__((ms_abi)) lsw_RtlQueryFeatureConfiguration(
    uint32_t feature_id, uint32_t feature_type, void* change_stamp, void* config)
{
    (void)feature_id; (void)feature_type; (void)change_stamp; (void)config;
    return STATUS_NOT_IMPLEMENTED;
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

/* ------------------------------------------------------------------
 * NtStatus → Win32 error code conversion
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

int __attribute__((ms_abi)) lsw_NtClose(void* handle) {
    (void)handle;
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
    {"ntdll.dll", "RtlQueryFeatureConfiguration",  (void*)lsw_RtlQueryFeatureConfiguration},
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
    /* Sentinel */
    {NULL, NULL, NULL}
};

const size_t win32_api_ntdll_mappings_count =
    (sizeof(win32_api_ntdll_mappings) / sizeof(win32_api_ntdll_mappings[0])) - 1;
