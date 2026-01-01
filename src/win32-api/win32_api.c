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
#include <sys/mman.h>
#include <fcntl.h>
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
void* __attribute__((ms_abi)) lsw_malloc(size_t size) {
    return malloc(size);
}

void __attribute__((ms_abi)) lsw_free(void* ptr) {
    free(ptr);
}

void* __attribute__((ms_abi)) lsw_calloc(size_t num, size_t size) {
    return calloc(num, size);
}

void* __attribute__((ms_abi)) lsw_memcpy(void* dest, const void* src, size_t n) {
    return memcpy(dest, src, n);
}

void* __attribute__((ms_abi)) lsw_memset(void* s, int c, size_t n) {
    return memset(s, c, n);
}

size_t __attribute__((ms_abi)) lsw_strlen(const char* s) {
    return strlen(s);
}

int __attribute__((ms_abi)) lsw_printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int result = vprintf(format, args);
    va_end(args);
    return result;
}

// Declare vfprintf first since fprintf uses it
int __attribute__((ms_abi)) lsw_vfprintf(FILE* stream, const char* format, va_list ap) {
    // Check if this is our fake FILE structure
    typedef struct {
        char* _ptr;
        int _cnt;
        char* _base;
        int _flag;
        int _file;
        int _charbuf;
        int _bufsiz;
        char* _tmpfname;
    } fake_FILE;
    
    fake_FILE* fake = (fake_FILE*)stream;
    
    // Check if it's one of our fake stdio FILE structures (fd 0-2)
    if (fake && fake->_file >= 0 && fake->_file <= 2) {
        // Use vdprintf() to write formatted output directly to fd
        return vdprintf(fake->_file, format, ap);
    }
    
    // Otherwise use real vfprintf
    return vfprintf(stream, format, ap);
}

int __attribute__((ms_abi)) lsw_fprintf(FILE* stream, const char* format, ...) {
    va_list args;
    va_start(args, format);
    // Use our vfprintf which handles fake FILE structures
    int result = lsw_vfprintf(stream, format, args);
    va_end(args);
    return result;
}

void __attribute__((ms_abi)) lsw_exit(int status) {
    exit(status);
}

void __attribute__((ms_abi)) lsw_abort(void) {
    abort();
}

// More stdio/string wrappers that need MS ABI
int __attribute__((ms_abi)) lsw_fputc(int c, FILE* stream) {
    // Check if this is our fake FILE structure
    typedef struct {
        char* _ptr;
        int _cnt;
        char* _base;
        int _flag;
        int _file;
        int _charbuf;
        int _bufsiz;
        char* _tmpfname;
    } fake_FILE;
    
    fake_FILE* fake = (fake_FILE*)stream;
    
    // Check if it's one of our fake stdio FILE structures (fd 0-2)
    if (fake && fake->_file >= 0 && fake->_file <= 2) {
        // Use Linux write() directly to the fd
        char ch = (char)c;
        ssize_t written = write(fake->_file, &ch, 1);
        return (written == 1) ? c : EOF;
    }
    
    // Otherwise use real fputc
    return fputc(c, stream);
}

size_t __attribute__((ms_abi)) lsw_fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    // Check if this is our fake FILE structure
    typedef struct {
        char* _ptr;
        int _cnt;
        char* _base;
        int _flag;
        int _file;
        int _charbuf;
        int _bufsiz;
        char* _tmpfname;
    } fake_FILE;
    
    fake_FILE* fake = (fake_FILE*)stream;
    
    // Check if it's one of our fake stdio FILE structures (fd 0-2)
    if (fake && fake->_file >= 0 && fake->_file <= 2) {
        // Use Linux write() directly
        size_t total = size * nmemb;
        ssize_t written = write(fake->_file, ptr, total);
        return written > 0 ? (size_t)written / size : 0;
    }
    
    // Otherwise use real fwrite
    return fwrite(ptr, size, nmemb, stream);
}

char* __attribute__((ms_abi)) lsw_strerror(int errnum) {
    return strerror(errnum);
}

int __attribute__((ms_abi)) lsw_strncmp(const char* s1, const char* s2, size_t n) {
    return strncmp(s1, s2, n);
}

size_t __attribute__((ms_abi)) lsw_wcslen(const wchar_t* s) {
    return wcslen(s);
}

struct lconv* __attribute__((ms_abi)) lsw_localeconv(void) {
    return localeconv();
}

void (*__attribute__((ms_abi)) lsw_signal(int signum, void (*handler)(int)))(int) {
    return signal(signum, handler);
}

// CRT initialization stubs - minimal implementations to get past CRT init
static char** lsw_environ = NULL;
static int lsw_argc = 0;
static char** lsw_argv = NULL;

int __attribute__((ms_abi)) lsw__getmainargs(int* argc, char*** argv, char*** env, int do_wildcard, void* startinfo) {
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

char** __attribute__((ms_abi)) lsw__initenv(void) {
    if (!lsw_environ) {
        lsw_environ = malloc(sizeof(char*));
        lsw_environ[0] = NULL;
    }
    return lsw_environ;
}

void* __attribute__((ms_abi)) lsw__iob_func(void) {
    // Windows CRT expects __iob_func to return pointer to FILE array
    // Windows FILE structure (_iobuf) is about 48 bytes on x64
    // We create fake FILE structures with proper size for pointer arithmetic
    typedef struct {
        char* _ptr;       // Current position in buffer
        int _cnt;         // Characters left in buffer  
        char* _base;      // Base of buffer
        int _flag;        // File status flags
        int _file;        // File descriptor
        int _charbuf;     // Char buffer for ungetch
        int _bufsiz;      // Buffer size
        char* _tmpfname;  // Temporary filename
    } fake_FILE;
    
    static fake_FILE fake_files[3] = {
        {NULL, 0, NULL, 0, 0, 0, 0, NULL},  // stdin
        {NULL, 0, NULL, 0, 1, 0, 0, NULL},  // stdout  
        {NULL, 0, NULL, 0, 2, 0, 0, NULL},  // stderr
    };
    
    return (void*)fake_files;
}

void __attribute__((ms_abi)) lsw__set_app_type(int type) {
    (void)type;
    // Stub - do nothing
}

void __attribute__((ms_abi)) lsw__setusermatherr(void* handler) {
    (void)handler;
    // Stub - do nothing
}

void __attribute__((ms_abi)) lsw__amsg_exit(int code) {
    exit(code);
}

void __attribute__((ms_abi)) lsw__cexit(void) {
    // Stub - CRT cleanup, do nothing
}

int lsw_commode = 0;  // Make non-static for direct access
int* __attribute__((ms_abi)) lsw__commode_ptr(void) {
    return &lsw_commode;
}

int lsw_fmode = 0;  // Make non-static for direct access
int* __attribute__((ms_abi)) lsw__fmode_ptr(void) {
    return &lsw_fmode;
}

int* __attribute__((ms_abi)) lsw__errno_func(void) {
    static __thread int err = 0;
    return &err;
}

typedef void (*func_ptr)(void);

void __attribute__((ms_abi)) lsw__initterm(func_ptr* start, func_ptr* end) {
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

void __attribute__((ms_abi)) lsw__lock(int locknum) {
    (void)locknum;
    // Stub - single threaded for now
}

void __attribute__((ms_abi)) lsw__unlock(int locknum) {
    (void)locknum;
    // Stub - single threaded for now
}

int __attribute__((ms_abi)) lsw__onexit(void* func) {
    (void)func;
    // Stub - should register exit handler
    return 0;
}

void* __attribute__((ms_abi)) lsw___C_specific_handler(void) {
    // Exception handler - stub
    return NULL;
}

int* __attribute__((ms_abi)) lsw___lc_codepage_func(void) {
    static int codepage = 437; // OEM US
    return &codepage;
}

int* __attribute__((ms_abi)) lsw___mb_cur_max_func(void) {
    static int mb_cur_max = 1;
    return &mb_cur_max;
}

// KERNEL32 stubs
int __attribute__((ms_abi)) lsw_IsDBCSLeadByteEx(unsigned int codepage, unsigned char testchar) {
    (void)codepage;
    (void)testchar;
    return 0; // Not DBCS for now
}

int __attribute__((ms_abi)) lsw_MultiByteToWideChar(unsigned int codepage, unsigned long flags, const char* src, int srclen, wchar_t* dst, int dstlen) {
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

int __attribute__((ms_abi)) lsw_WideCharToMultiByte(unsigned int codepage, unsigned long flags, const wchar_t* src, int srclen, char* dst, int dstlen, const char* defchar, int* used_default) {
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

void* __attribute__((ms_abi)) lsw_TlsGetValue(unsigned long index) {
    (void)index;
    return NULL; // No TLS for now
}

int __attribute__((ms_abi)) lsw_VirtualQuery(const void* addr, void* buffer, size_t length) {
    (void)addr;
    (void)buffer;
    (void)length;
    return 0; // Stub
}

// KERNEL32.dll stub implementations
void __attribute__((ms_abi)) lsw_Sleep(uint32_t milliseconds) {
    usleep(milliseconds * 1000);
}

uint32_t __attribute__((ms_abi)) lsw_GetLastError(void) {
    // Return success for now
    return 0;
}

void __attribute__((ms_abi)) lsw_SetUnhandledExceptionFilter(void* handler) {
    (void)handler;
    // Stub - do nothing for now
}

void __attribute__((ms_abi)) lsw_InitializeCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_init(mutex, NULL);
}

void __attribute__((ms_abi)) lsw_DeleteCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_destroy(mutex);
}

void __attribute__((ms_abi)) lsw_EnterCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_lock(mutex);
}

void __attribute__((ms_abi)) lsw_LeaveCriticalSection(void* cs) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)cs;
    pthread_mutex_unlock(mutex);
}

int __attribute__((ms_abi)) lsw_VirtualProtect(void* addr, size_t size, uint32_t new_protect, uint32_t* old_protect) {
    (void)addr; (void)size; (void)new_protect; (void)old_protect;
    // Stub - return success
    return 1;
}

// Memory management functions
void* __attribute__((ms_abi)) lsw_VirtualAlloc(void* addr, size_t size, uint32_t alloc_type, uint32_t protect) {
    (void)addr; (void)alloc_type; (void)protect;
    // Simple implementation using mmap
    void* result = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED) {
        return NULL;
    }
    LSW_LOG_INFO("VirtualAlloc: size=%zu, result=%p", size, result);
    return result;
}

int __attribute__((ms_abi)) lsw_VirtualFree(void* addr, size_t size, uint32_t free_type) {
    (void)size; (void)free_type;
    // Simple implementation using munmap
    if (addr) {
        munmap(addr, size ? size : 4096); // If size is 0, unmap at least a page
    }
    LSW_LOG_INFO("VirtualFree: addr=%p", addr);
    return 1; // Success
}

// File I/O functions
#define GENERIC_READ    0x80000000
#define GENERIC_WRITE   0x40000000
#define CREATE_ALWAYS   2
#define OPEN_EXISTING   3
#define INVALID_HANDLE_VALUE ((void*)(intptr_t)-1)

void* __attribute__((ms_abi)) lsw_CreateFileA(const char* filename, uint32_t access, uint32_t share_mode, 
                                                void* security, uint32_t creation, uint32_t flags, void* template_file) {
    (void)share_mode; (void)security; (void)flags; (void)template_file;
    
    int flags_unix = 0;
    if (access & GENERIC_WRITE) {
        if (creation == CREATE_ALWAYS) {
            flags_unix = O_WRONLY | O_CREAT | O_TRUNC;
        } else {
            flags_unix = O_WRONLY;
        }
    } else if (access & GENERIC_READ) {
        flags_unix = O_RDONLY;
    }
    
    int fd = open(filename, flags_unix, 0644);
    if (fd < 0) {
        LSW_LOG_WARN("CreateFileA failed: %s (errno=%d)", filename, errno);
        return INVALID_HANDLE_VALUE;
    }
    
    LSW_LOG_INFO("CreateFileA: %s -> fd=%d", filename, fd);
    return (void*)(intptr_t)fd;
}

int __attribute__((ms_abi)) lsw_CloseHandle(void* handle) {
    if (handle == INVALID_HANDLE_VALUE || !handle) {
        return 0;
    }
    
    // Check if it's a file descriptor
    intptr_t fd = (intptr_t)handle;
    if (fd >= 0 && fd < 1024) {
        close((int)fd);
        LSW_LOG_INFO("CloseHandle: fd=%d", (int)fd);
        return 1;
    }
    
    // For other handles (events, etc.), just return success for now
    LSW_LOG_INFO("CloseHandle: handle=%p (non-fd)", handle);
    return 1;
}

// Synchronization functions
void* __attribute__((ms_abi)) lsw_CreateEventA(void* security, int manual_reset, int initial_state, const char* name) {
    (void)security; (void)manual_reset; (void)initial_state; (void)name;
    // Simple stub - return a fake handle
    static int event_counter = 1000;
    void* handle = (void*)(intptr_t)(event_counter++);
    LSW_LOG_INFO("CreateEventA: name=%s -> handle=%p", name ? name : "(null)", handle);
    return handle;
}

int __attribute__((ms_abi)) lsw_SetEvent(void* handle) {
    LSW_LOG_INFO("SetEvent: handle=%p", handle);
    return 1; // Success
}

// Process functions
uint32_t __attribute__((ms_abi)) lsw_GetCurrentProcessId(void) {
    uint32_t pid = (uint32_t)getpid();
    LSW_LOG_INFO("GetCurrentProcessId: %u", pid);
    return pid;
}

void* __attribute__((ms_abi)) lsw_GetModuleHandleA(const char* module_name) {
    // For kernel32.dll, return a fake handle
    // For NULL, return the base address (we'll use a fake value)
    if (!module_name) {
        LSW_LOG_INFO("GetModuleHandleA: NULL -> 0x140000000 (base)");
        return (void*)0x140000000;
    }
    LSW_LOG_INFO("GetModuleHandleA: %s -> 0x7FF000000", module_name);
    return (void*)0x7FF000000; // Fake DLL base
}

// KERNEL32 Console I/O Functions
#define STD_INPUT_HANDLE  ((void*)(uintptr_t)(-10))
#define STD_OUTPUT_HANDLE ((void*)(uintptr_t)(-11))
#define STD_ERROR_HANDLE  ((void*)(uintptr_t)(-12))

void* __attribute__((ms_abi)) lsw_GetStdHandle(uint32_t std_handle) {
    // Win32: STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    switch (std_handle) {
        case (uint32_t)-10: return STD_INPUT_HANDLE;
        case (uint32_t)-11: return STD_OUTPUT_HANDLE;
        case (uint32_t)-12: return STD_ERROR_HANDLE;
        default: return NULL;
    }
}

int __attribute__((ms_abi)) lsw_WriteFile(void* handle, const void* buffer, uint32_t bytes_to_write, uint32_t* bytes_written, void* overlapped) {
    (void)overlapped; // Not used for console I/O
    
    LSW_LOG_INFO("WriteFile called: handle=%p, buffer=%p, bytes=%u", handle, buffer, bytes_to_write);
    LSW_LOG_INFO("  Buffer content (first 32 bytes): %.32s", buffer ? (const char*)buffer : "(null)");
    LSW_LOG_INFO("  bytes_written ptr: %p", bytes_written);
    
    if (!handle || !buffer) {
        if (bytes_written) *bytes_written = 0;
        return 0;
    }
    
    // If kernel fd is available, route through kernel module
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing WriteFile through kernel module!");
        LSW_LOG_INFO("  Packing args: handle=0x%lx, buffer=0x%lx, size=%u", 
                     (uint64_t)(uintptr_t)handle, (uint64_t)(uintptr_t)buffer, bytes_to_write);
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtWriteFile;
        req.arg_count = 3;
        req.args[0] = (uint64_t)(uintptr_t)handle;
        req.args[1] = (uint64_t)(uintptr_t)buffer;
        req.args[2] = bytes_to_write;
        
        LSW_LOG_INFO("  Request prepared: syscall=0x%x, args=[0x%lx, 0x%lx, %lu]",
                     req.syscall_number, req.args[0], req.args[1], req.args[2]);
        
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

int __attribute__((ms_abi)) lsw_lstrlenA(const char* str) {
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
    {"msvcrt.dll", "printf", (void*)lsw_printf},
    {"msvcrt.dll", "fprintf", (void*)lsw_fprintf},
    {"msvcrt.dll", "vfprintf", (void*)lsw_vfprintf},
    {"msvcrt.dll", "fwrite", (void*)lsw_fwrite},
    {"msvcrt.dll", "fputc", (void*)lsw_fputc},
    {"msvcrt.dll", "strerror", (void*)lsw_strerror},
    {"msvcrt.dll", "strncmp", (void*)lsw_strncmp},
    {"msvcrt.dll", "wcslen", (void*)lsw_wcslen},
    {"msvcrt.dll", "localeconv", (void*)lsw_localeconv},
    {"msvcrt.dll", "signal", (void*)lsw_signal},
    
    // msvcrt.dll - CRT initialization
    {"msvcrt.dll", "__getmainargs", (void*)lsw__getmainargs},
    {"msvcrt.dll", "__initenv", (void*)lsw__initenv},
    {"msvcrt.dll", "__iob_func", (void*)lsw__iob_func},
    {"msvcrt.dll", "__set_app_type", (void*)lsw__set_app_type},
    {"msvcrt.dll", "__setusermatherr", (void*)lsw__setusermatherr},
    {"msvcrt.dll", "_amsg_exit", (void*)lsw__amsg_exit},
    {"msvcrt.dll", "_cexit", (void*)lsw__cexit},
    {"msvcrt.dll", "_commode", (void*)&lsw_commode},  // Direct pointer to variable
    {"msvcrt.dll", "_fmode", (void*)&lsw_fmode},      // Direct pointer to variable
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
    {"KERNEL32.dll", "VirtualAlloc", (void*)lsw_VirtualAlloc},
    {"KERNEL32.dll", "VirtualFree", (void*)lsw_VirtualFree},
    {"KERNEL32.dll", "CreateFileA", (void*)lsw_CreateFileA},
    {"KERNEL32.dll", "CloseHandle", (void*)lsw_CloseHandle},
    {"KERNEL32.dll", "CreateEventA", (void*)lsw_CreateEventA},
    {"KERNEL32.dll", "SetEvent", (void*)lsw_SetEvent},
    {"KERNEL32.dll", "GetCurrentProcessId", (void*)lsw_GetCurrentProcessId},
    {"KERNEL32.dll", "GetModuleHandleA", (void*)lsw_GetModuleHandleA},
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
