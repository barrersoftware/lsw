/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * Win32 API - Function mapping implementation
 */

#include "win32_api.h"
#include "lsw_log.h"
#include "shared/lsw_kernel_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <locale.h>
#include <signal.h>
#include <wchar.h>
#include <sys/ioctl.h>
#include <errno.h>

// Syscall structure (from kernel module)
struct lsw_syscall_request {
    uint32_t syscall_number;
    uint32_t arg_count;
    uint64_t args[8];
    uint64_t return_value;
    int32_t error_code;
};

// Syscall numbers
#define LSW_SYSCALL_NtWriteFile 0x0008

// ioctl command  
#define LSW_IOCTL_MAGIC 'L'
#define LSW_IOCTL_SYSCALL _IOWR(LSW_IOCTL_MAGIC, 5, struct lsw_syscall_request)

// Global kernel fd for syscalls
static int g_kernel_fd = -1;

void win32_api_set_kernel_fd(int fd) {
    g_kernel_fd = fd;
    LSW_LOG_INFO("Win32 API: kernel fd set to %d", fd);
}

// msvcrt.dll stub implementations - map to libc
void* lsw_malloc(size_t size) {
    return malloc(size);
}

void lsw_free(void* ptr) {
    free(ptr);
}

void* lsw_calloc(size_t num, size_t size) {
    return calloc(num, size);
}

void* lsw_memcpy(void* dest, const void* src, size_t n) {
    return memcpy(dest, src, n);
}

void* lsw_memset(void* s, int c, size_t n) {
    return memset(s, c, n);
}

size_t lsw_strlen(const char* s) {
    return strlen(s);
}

int lsw_printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int result = vprintf(format, args);
    va_end(args);
    return result;
}

int lsw_fprintf(FILE* stream, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int result = vfprintf(stream, format, args);
    va_end(args);
    return result;
}

void lsw_exit(int status) {
    exit(status);
}

void lsw_abort(void) {
    abort();
}

// CRT initialization stubs - minimal implementations to get past CRT init
static char** lsw_environ = NULL;
static int lsw_argc = 0;
static char** lsw_argv = NULL;

int lsw__getmainargs(int* argc, char*** argv, char*** env, int do_wildcard, void* startinfo) {
    (void)do_wildcard;
    (void)startinfo;
    
    if (!lsw_argv) {
        lsw_argc = 1;
        lsw_argv = malloc(sizeof(char*) * 2);
        lsw_argv[0] = "program.exe";
        lsw_argv[1] = NULL;
    }
    
    if (!lsw_environ) {
        lsw_environ = malloc(sizeof(char*));
        lsw_environ[0] = NULL;
    }
    
    *argc = lsw_argc;
    *argv = lsw_argv;
    *env = lsw_environ;
    
    return 0;
}

char** lsw__initenv(void) {
    if (!lsw_environ) {
        lsw_environ = malloc(sizeof(char*));
        lsw_environ[0] = NULL;
    }
    return lsw_environ;
}

void* lsw__iob_func(void) {
    // Windows CRT expects __iob_func to return pointer to FILE array
    // Array is: [stdin, stdout, stderr, ...]
    // But we need to return actual FILE* pointers, not void*
    static FILE* iob[3] = {0};
    if (!iob[0]) {
        iob[0] = stdin;
        iob[1] = stdout;
        iob[2] = stderr;
    }
    return (void*)iob;
}

void lsw__set_app_type(int type) {
    (void)type;
    // Stub - do nothing
}

void lsw__setusermatherr(void* handler) {
    (void)handler;
    // Stub - do nothing
}

void lsw__amsg_exit(int code) {
    exit(code);
}

void lsw__cexit(void) {
    // Stub - CRT cleanup, do nothing
}

static int lsw_commode = 0;
int* lsw__commode_ptr(void) {
    return &lsw_commode;
}

static int lsw_fmode = 0;
int* lsw__fmode_ptr(void) {
    return &lsw_fmode;
}

int* lsw__errno_func(void) {
    static __thread int err = 0;
    return &err;
}

typedef void (*func_ptr)(void);

void lsw__initterm(func_ptr* start, func_ptr* end) {
    // Call all initializers in the table
    // Check for NULL pointers - PE may pass NULL if no initializers
    if (!start || !end || start >= end) {
        return; // No initializers to call
    }
    
    while (start < end) {
        if (*start) {
            (*start)();
        }
        start++;
    }
}

void lsw__lock(int locknum) {
    (void)locknum;
    // Stub - single threaded for now
}

void lsw__unlock(int locknum) {
    (void)locknum;
    // Stub - single threaded for now
}

int lsw__onexit(void* func) {
    (void)func;
    // Stub - should register exit handler
    return 0;
}

void* lsw___C_specific_handler(void) {
    // Exception handler - stub
    return NULL;
}

int* lsw___lc_codepage_func(void) {
    static int codepage = 437; // OEM US
    return &codepage;
}

int* lsw___mb_cur_max_func(void) {
    static int mb_cur_max = 1;
    return &mb_cur_max;
}

// KERNEL32 stubs
int lsw_IsDBCSLeadByteEx(unsigned int codepage, unsigned char testchar) {
    (void)codepage;
    (void)testchar;
    return 0; // Not DBCS for now
}

int lsw_MultiByteToWideChar(unsigned int codepage, unsigned long flags, const char* src, int srclen, wchar_t* dst, int dstlen) {
    (void)codepage;
    (void)flags;
    
    if (!dst) {
        // Return required size
        return srclen >= 0 ? srclen : (int)strlen(src);
    }
    
    int len = srclen >= 0 ? srclen : (int)strlen(src);
    if (len > dstlen) len = dstlen;
    
    for (int i = 0; i < len; i++) {
        dst[i] = (wchar_t)(unsigned char)src[i];
    }
    
    return len;
}

int lsw_WideCharToMultiByte(unsigned int codepage, unsigned long flags, const wchar_t* src, int srclen, char* dst, int dstlen, const char* defchar, int* used_default) {
    (void)codepage;
    (void)flags;
    (void)defchar;
    (void)used_default;
    
    if (!dst) {
        // Return required size
        return srclen >= 0 ? srclen : (int)wcslen(src);
    }
    
    int len = srclen >= 0 ? srclen : (int)wcslen(src);
    if (len > dstlen) len = dstlen;
    
    for (int i = 0; i < len; i++) {
        dst[i] = (char)(src[i] & 0xFF);
    }
    
    return len;
}

void* lsw_TlsGetValue(unsigned long index) {
    (void)index;
    return NULL; // No TLS for now
}

int lsw_VirtualQuery(const void* addr, void* buffer, size_t length) {
    (void)addr;
    (void)buffer;
    (void)length;
    return 0; // Stub
}

// KERNEL32.dll stub implementations
void lsw_Sleep(uint32_t milliseconds) {
    usleep(milliseconds * 1000);
}

uint32_t lsw_GetLastError(void) {
    // Return success for now
    return 0;
}

void lsw_SetUnhandledExceptionFilter(void* handler) {
    (void)handler;
    // Stub - do nothing for now
}

void lsw_InitializeCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_init(mutex, NULL);
}

void lsw_DeleteCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_destroy(mutex);
}

void lsw_EnterCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_lock(mutex);
}

void lsw_LeaveCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_unlock(mutex);
}

int lsw_VirtualProtect(void* addr, size_t size, uint32_t new_protect, uint32_t* old_protect) {
    (void)addr; (void)size; (void)new_protect; (void)old_protect;
    // Stub - return success
    return 1;
}

// KERNEL32 Console I/O Functions
#define STD_INPUT_HANDLE  ((void*)(uintptr_t)(-10))
#define STD_OUTPUT_HANDLE ((void*)(uintptr_t)(-11))
#define STD_ERROR_HANDLE  ((void*)(uintptr_t)(-12))

void* lsw_GetStdHandle(uint32_t std_handle) {
    // Win32: STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    switch (std_handle) {
        case (uint32_t)-10: return STD_INPUT_HANDLE;
        case (uint32_t)-11: return STD_OUTPUT_HANDLE;
        case (uint32_t)-12: return STD_ERROR_HANDLE;
        default: return NULL;
    }
}

int lsw_WriteFile(void* handle, const void* buffer, uint32_t bytes_to_write, uint32_t* bytes_written, void* overlapped) {
    (void)overlapped; // Not used for console I/O
    
    LSW_LOG_INFO("WriteFile called: handle=%p, bytes=%u", handle, bytes_to_write);
    
    if (!handle || !buffer) {
        if (bytes_written) *bytes_written = 0;
        return 0;
    }
    
    // If kernel fd is available, route through kernel module
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing WriteFile through kernel module!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtWriteFile;
        req.arg_count = 3;
        req.args[0] = (uint64_t)(uintptr_t)handle;
        req.args[1] = (uint64_t)(uintptr_t)buffer;
        req.args[2] = bytes_to_write;
        
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0) {
            LSW_LOG_INFO("Kernel syscall returned: %lld", req.return_value);
            if (bytes_written) *bytes_written = (uint32_t)req.return_value;
            return 1; // Success
        } else {
            LSW_LOG_ERROR("Kernel ioctl failed: %s", strerror(errno));
        }
    }
    
    // Fallback to direct userspace implementation
    LSW_LOG_WARN("Using userspace fallback for WriteFile");
    
    // Map Win32 handles to file descriptors
    int fd = -1;
    if (handle == STD_OUTPUT_HANDLE) {
        fd = STDOUT_FILENO;
    } else if (handle == STD_ERROR_HANDLE) {
        fd = STDERR_FILENO;
    } else {
        // Assume it's a raw file descriptor for now
        fd = (int)(uintptr_t)handle;
    }
    
    ssize_t result = write(fd, buffer, bytes_to_write);
    if (result < 0) {
        if (bytes_written) *bytes_written = 0;
        return 0; // Failure
    }
    
    if (bytes_written) *bytes_written = (uint32_t)result;
    return 1; // Success
}

int lsw_lstrlenA(const char* str) {
    if (!str) return 0;
    return (int)strlen(str);
}

// Disable pedantic warnings for function pointer to void* casts
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

// Global API mapping table
static const win32_api_mapping_t api_mappings[] = {
    // msvcrt.dll - CRT functions
    {"msvcrt.dll", "malloc", (void*)lsw_malloc},
    {"msvcrt.dll", "free", (void*)lsw_free},
    {"msvcrt.dll", "calloc", (void*)lsw_calloc},
    {"msvcrt.dll", "memcpy", (void*)lsw_memcpy},
    {"msvcrt.dll", "memset", (void*)lsw_memset},
    {"msvcrt.dll", "strlen", (void*)lsw_strlen},
    {"msvcrt.dll", "exit", (void*)lsw_exit},
    {"msvcrt.dll", "abort", (void*)lsw_abort},
    {"msvcrt.dll", "printf", (void*)printf},
    {"msvcrt.dll", "fprintf", (void*)lsw_fprintf},
    {"msvcrt.dll", "vfprintf", (void*)vfprintf},
    {"msvcrt.dll", "fwrite", (void*)fwrite},
    {"msvcrt.dll", "fputc", (void*)fputc},
    {"msvcrt.dll", "strerror", (void*)strerror},
    {"msvcrt.dll", "strncmp", (void*)strncmp},
    {"msvcrt.dll", "wcslen", (void*)wcslen},
    {"msvcrt.dll", "localeconv", (void*)localeconv},
    {"msvcrt.dll", "signal", (void*)signal},
    
    // msvcrt.dll - CRT initialization
    {"msvcrt.dll", "__getmainargs", (void*)lsw__getmainargs},
    {"msvcrt.dll", "__initenv", (void*)lsw__initenv},
    {"msvcrt.dll", "__iob_func", (void*)lsw__iob_func},
    {"msvcrt.dll", "__set_app_type", (void*)lsw__set_app_type},
    {"msvcrt.dll", "__setusermatherr", (void*)lsw__setusermatherr},
    {"msvcrt.dll", "_amsg_exit", (void*)lsw__amsg_exit},
    {"msvcrt.dll", "_cexit", (void*)lsw__cexit},
    {"msvcrt.dll", "_commode", (void*)lsw__commode_ptr},
    {"msvcrt.dll", "_fmode", (void*)lsw__fmode_ptr},
    {"msvcrt.dll", "_errno", (void*)lsw__errno_func},
    {"msvcrt.dll", "_initterm", (void*)lsw__initterm},
    {"msvcrt.dll", "_lock", (void*)lsw__lock},
    {"msvcrt.dll", "_unlock", (void*)lsw__unlock},
    {"msvcrt.dll", "_onexit", (void*)lsw__onexit},
    {"msvcrt.dll", "__C_specific_handler", (void*)lsw___C_specific_handler},
    {"msvcrt.dll", "___lc_codepage_func", (void*)lsw___lc_codepage_func},
    {"msvcrt.dll", "___mb_cur_max_func", (void*)lsw___mb_cur_max_func},
    
    // KERNEL32.dll
    {"KERNEL32.dll", "Sleep", (void*)lsw_Sleep},
    {"KERNEL32.dll", "GetLastError", (void*)lsw_GetLastError},
    {"KERNEL32.dll", "SetUnhandledExceptionFilter", (void*)lsw_SetUnhandledExceptionFilter},
    {"KERNEL32.dll", "InitializeCriticalSection", (void*)lsw_InitializeCriticalSection},
    {"KERNEL32.dll", "DeleteCriticalSection", (void*)lsw_DeleteCriticalSection},
    {"KERNEL32.dll", "EnterCriticalSection", (void*)lsw_EnterCriticalSection},
    {"KERNEL32.dll", "LeaveCriticalSection", (void*)lsw_LeaveCriticalSection},
    {"KERNEL32.dll", "VirtualProtect", (void*)lsw_VirtualProtect},
    {"KERNEL32.dll", "GetStdHandle", (void*)lsw_GetStdHandle},
    {"KERNEL32.dll", "WriteFile", (void*)lsw_WriteFile},
    {"KERNEL32.dll", "lstrlenA", (void*)lsw_lstrlenA},
    {"KERNEL32.dll", "IsDBCSLeadByteEx", (void*)lsw_IsDBCSLeadByteEx},
    {"KERNEL32.dll", "MultiByteToWideChar", (void*)lsw_MultiByteToWideChar},
    {"KERNEL32.dll", "WideCharToMultiByte", (void*)lsw_WideCharToMultiByte},
    {"KERNEL32.dll", "TlsGetValue", (void*)lsw_TlsGetValue},
    {"KERNEL32.dll", "VirtualQuery", (void*)lsw_VirtualQuery},
};

#pragma GCC diagnostic pop

static const size_t api_mappings_count = sizeof(api_mappings) / sizeof(api_mappings[0]);

// Generic stub for unresolved functions
static int generic_stub(void) {
    LSW_LOG_WARN("Called unresolved Win32 API function - returning 0");
    return 0;
}

void win32_api_init(void) {
    LSW_LOG_INFO("Initialized %zu Win32 API mappings", api_mappings_count);
}

void* win32_api_resolve(const char* dll_name, const char* function_name) {
    for (size_t i = 0; i < api_mappings_count; i++) {
        if (strcasecmp(api_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(api_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved %s!%s -> %p", dll_name, function_name, api_mappings[i].implementation);
            return api_mappings[i].implementation;
        }
    }
    
    LSW_LOG_WARN("Could not resolve %s!%s - returning stub", dll_name, function_name);
    // Cast through uintptr_t to avoid pedantic warning
    return (void*)(uintptr_t)generic_stub;
}

const win32_api_mapping_t* win32_api_get_mappings(size_t* count) {
    if (count) {
        *count = api_mappings_count;
    }
    return api_mappings;
}
