/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * Win32 API - Function mapping implementation
 */

#include "win32_api.h"
#include "win32_teb.h"
#include "lsw_log.h"
#include "shared/lsw_kernel_client.h"
#include "shared/lsw_filesystem.h"
#include "shared/lsw_registry.h"
#include "kernel-module/lsw_syscall.h"
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>

// ioctl command  
#define LSW_IOCTL_MAGIC 'L'
#define LSW_IOCTL_SYSCALL _IOWR(LSW_IOCTL_MAGIC, 5, struct lsw_syscall_request)

// Code page constants
#define CP_ACP 0        // ANSI code page
#define CP_UTF8 65001   // UTF-8 code page

// Windows File Attributes
#define FILE_ATTRIBUTE_READONLY             0x00000001
#define FILE_ATTRIBUTE_HIDDEN               0x00000002
#define FILE_ATTRIBUTE_SYSTEM               0x00000004
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020
#define FILE_ATTRIBUTE_NORMAL               0x00000080
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100
#define INVALID_FILE_ATTRIBUTES             0xFFFFFFFF

// WIN32_FIND_DATAW structure
typedef struct {
    uint32_t dwFileAttributes;
    uint64_t ftCreationTime;
    uint64_t ftLastAccessTime;
    uint64_t ftLastWriteTime;
    uint32_t nFileSizeHigh;
    uint32_t nFileSizeLow;
    uint32_t dwReserved0;
    uint32_t dwReserved1;
    wchar_t cFileName[260];
    wchar_t cAlternateFileName[14];
} WIN32_FIND_DATAW;

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

int __attribute__((ms_abi)) lsw_strcmp(const char* s1, const char* s2) {
    return strcmp(s1, s2);
}

int __attribute__((ms_abi)) lsw_strncmp(const char* s1, const char* s2, size_t n) {
    return strncmp(s1, s2, n);
}

char* __attribute__((ms_abi)) lsw_strstr(const char* haystack, const char* needle) {
    return strstr(haystack, needle);
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
    
    if (!src) {
        return 0;
    }
    
    // Windows wchar_t is UTF-16 (2 bytes), Linux wchar_t is UTF-32 (4 bytes)
    // We need to treat the input as uint16_t* (UTF-16)
    const uint16_t* src16 = (const uint16_t*)src;
    
    // Calculate source length if not provided
    size_t actual_srclen;
    if (srclen == -1) {
        // Count UTF-16 characters until null terminator
        actual_srclen = 0;
        while (src16[actual_srclen] != 0) {
            actual_srclen++;
        }
    } else {
        actual_srclen = (size_t)srclen;
    }
    
    if (!dst) {
        // Return required size (pessimistic: assume each char needs 3 bytes in UTF-8)
        return (int)(actual_srclen * 3 + 1);
    }
    
    // UTF-16 to UTF-8 conversion
    size_t src_idx = 0;
    size_t dst_idx = 0;
    
    while (src_idx < actual_srclen && dst_idx < (size_t)(dstlen - 1)) {
        uint16_t wc = src16[src_idx];
        
        // Check for null terminator
        if (wc == 0) {
            break;
        }
        
        if (wc < 0x80) {
            // ASCII range (0x00-0x7F) - 1 byte
            dst[dst_idx++] = (char)wc;
        } else if (wc < 0x800) {
            // 2-byte UTF-8 sequence (0x80-0x7FF)
            if (dst_idx + 2 > (size_t)dstlen) break;
            dst[dst_idx++] = (char)(0xC0 | ((wc >> 6) & 0x1F));
            dst[dst_idx++] = (char)(0x80 | (wc & 0x3F));
        } else if (wc < 0xD800 || wc >= 0xE000) {
            // 3-byte UTF-8 sequence (0x800-0xFFFF, excluding surrogates)
            if (dst_idx + 3 > (size_t)dstlen) break;
            dst[dst_idx++] = (char)(0xE0 | ((wc >> 12) & 0x0F));
            dst[dst_idx++] = (char)(0x80 | ((wc >> 6) & 0x3F));
            dst[dst_idx++] = (char)(0x80 | (wc & 0x3F));
        } else {
            // Surrogate pair handling (for characters > 0xFFFF)
            // For now, replace with '?'
            dst[dst_idx++] = '?';
        }
        
        src_idx++;
    }
    
    dst[dst_idx] = '\0';
    
    if (used_default) {
        *used_default = 0;
    }
    
    return (int)dst_idx;
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
    (void)share_mode; (void)security; (void)template_file;
    
    // Translate Windows path to Linux path
    char linux_path[LSW_MAX_PATH];
    if (lsw_fs_win_to_linux(filename, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        LSW_LOG_WARN("CreateFileA path translation failed: %s", filename);
        return INVALID_HANDLE_VALUE;
    }
    
    LSW_LOG_INFO("CreateFileA: %s -> %s", filename, linux_path);
    
    // Route through kernel module if available
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing CreateFileA through kernel NtCreateFile!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtCreateFile;
        req.arg_count = 4;
        req.args[0] = (uint64_t)(uintptr_t)linux_path;  // Path pointer
        req.args[1] = access;                            // Access flags
        req.args[2] = creation;                          // Creation disposition
        req.args[3] = flags;                             // Flags
        
        LSW_LOG_INFO("  Kernel NtCreateFile: path=%s, access=0x%x, creation=%u", 
                     linux_path, access, creation);
        
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0) {
            uint64_t handle = req.return_value;
            if (handle != (uint64_t)-1 && handle != 0) {
                // Success! Return the kernel handle
                LSW_LOG_INFO("Kernel NtCreateFile success: handle=0x%llx", handle);
                return (void*)(uintptr_t)handle;
            }
            // Kernel call succeeded but returned error - fall through to userspace
            LSW_LOG_WARN("Kernel NtCreateFile failed: error=%d, falling back to userspace", req.error_code);
        } else {
            LSW_LOG_ERROR("Kernel ioctl failed for NtCreateFile: %s, falling back to userspace", strerror(errno));
        }
    }
    
    // Fallback to userspace implementation
    LSW_LOG_WARN("Using userspace fallback for CreateFileA");
    
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
    
    int fd = open(linux_path, flags_unix, 0644);
    if (fd < 0) {
        LSW_LOG_WARN("CreateFileA userspace fallback failed: %s (errno=%d)", linux_path, errno);
        return INVALID_HANDLE_VALUE;
    }
    
    LSW_LOG_INFO("CreateFileA userspace fallback: fd=%d", fd);
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

int __attribute__((ms_abi)) lsw_WriteConsoleA(void* handle, const void* buffer, uint32_t chars_to_write, uint32_t* chars_written, void* reserved) {
    (void)reserved;
    
    if (!handle || !buffer) {
        if (chars_written) *chars_written = 0;
        return 0;
    }
    
    // Console I/O always handled in userspace
    // kernel_write() to stdout/stderr fails with -EPIPE in kernel context
    int fd = -1;
    if (handle == STD_OUTPUT_HANDLE) {
        fd = STDOUT_FILENO;
    } else if (handle == STD_ERROR_HANDLE) {
        fd = STDERR_FILENO;
    } else {
        if (chars_written) *chars_written = 0;
        return 0;
    }
    
    ssize_t result = write(fd, buffer, chars_to_write);
    if (result < 0) {
        if (chars_written) *chars_written = 0;
        return 0;
    }
    
    if (chars_written) *chars_written = (uint32_t)result;
    return 1;
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

int __attribute__((ms_abi)) lsw_ReadFile(void* handle, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read, void* overlapped) {
    (void)overlapped; // Not used yet
    
    LSW_LOG_INFO("ReadFile called: handle=%p, buffer=%p, bytes=%u", handle, buffer, bytes_to_read);
    
    if (!handle || !buffer) {
        if (bytes_read) *bytes_read = 0;
        return 0;
    }
    
    // If kernel fd is available, route through kernel module
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing ReadFile through kernel NtReadFile!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtReadFile;
        req.arg_count = 3;
        req.args[0] = (uint64_t)(uintptr_t)handle;
        req.args[1] = (uint64_t)(uintptr_t)buffer;  // Pass buffer address
        req.args[2] = bytes_to_read;
        
        LSW_LOG_INFO("  Request: syscall=0x%x, args=[0x%lx, 0x%lx, %lu]",
                     req.syscall_number, req.args[0], req.args[1], req.args[2]);
        
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0) {
            LSW_LOG_INFO("Kernel NtReadFile returned: %lld bytes", req.return_value);
            if (bytes_read) *bytes_read = (uint32_t)req.return_value;
            return 1; // Success
        } else {
            LSW_LOG_ERROR("Kernel ioctl failed for NtReadFile: %s", strerror(errno));
        }
    }
    
    // Fallback to userspace implementation
    LSW_LOG_WARN("Using userspace fallback for ReadFile");
    
    int fd = -1;
    if (handle == STD_INPUT_HANDLE) {
        fd = STDIN_FILENO;
    } else {
        fd = (int)(uintptr_t)handle;
    }
    
    ssize_t result = read(fd, buffer, bytes_to_read);
    if (result < 0) {
        if (bytes_read) *bytes_read = 0;
        return 0; // Failure
    }
    
    if (bytes_read) *bytes_read = (uint32_t)result;
    return 1; // Success
}

uint32_t __attribute__((ms_abi)) lsw_GetFileSize(void* handle, uint32_t* file_size_high) {
    LSW_LOG_INFO("GetFileSize called: handle=%p", handle);
    
    if (!handle || handle == (void*)-1) {
        LSW_LOG_ERROR("GetFileSize: invalid handle");
        if (file_size_high) *file_size_high = 0;
        return 0xFFFFFFFF; // INVALID_FILE_SIZE
    }
    
    // Route through kernel
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing GetFileSize through kernel!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_LswGetFileSize;
        req.arg_count = 1;
        req.args[0] = (uint64_t)(uintptr_t)handle;
        
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0) {
            uint64_t size = req.return_value;
            uint32_t size_low = (uint32_t)(size & 0xFFFFFFFF);
            uint32_t size_high = (uint32_t)(size >> 32);
            
            if (file_size_high) {
                *file_size_high = size_high;
            }
            
            LSW_LOG_INFO("GetFileSize: %llu bytes (low=0x%x, high=0x%x)", size, size_low, size_high);
            return size_low;
        } else {
            LSW_LOG_ERROR("Kernel ioctl failed for GetFileSize: %s", strerror(errno));
        }
    }
    
    // Fallback: shouldn't reach here with kernel mode
    if (file_size_high) *file_size_high = 0;
    return 0xFFFFFFFF;
}

uint32_t __attribute__((ms_abi)) lsw_SetFilePointer(void* handle, int32_t distance_to_move, int32_t* distance_to_move_high, uint32_t move_method) {
    LSW_LOG_INFO("SetFilePointer: handle=%p, distance=%d, method=%u", handle, distance_to_move, move_method);
    
    if (!handle || handle == (void*)-1) {
        LSW_LOG_ERROR("SetFilePointer: invalid handle");
        return 0xFFFFFFFF;
    }
    
    // Build 64-bit offset
    int64_t offset = distance_to_move;
    if (distance_to_move_high) {
        offset |= ((int64_t)*distance_to_move_high) << 32;
    }
    
    // Route through kernel
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing SetFilePointer through kernel!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_LswSetFilePointer;
        req.arg_count = 3;
        req.args[0] = (uint64_t)(uintptr_t)handle;
        req.args[1] = (uint64_t)offset;
        req.args[2] = move_method;
        
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0) {
            uint64_t new_pos = req.return_value;
            uint32_t pos_low = (uint32_t)(new_pos & 0xFFFFFFFF);
            uint32_t pos_high = (uint32_t)(new_pos >> 32);
            
            if (distance_to_move_high) {
                *distance_to_move_high = pos_high;
            }
            
            LSW_LOG_INFO("SetFilePointer: new position=%llu (low=0x%x, high=0x%x)", new_pos, pos_low, pos_high);
            return pos_low;
        } else {
            LSW_LOG_ERROR("Kernel ioctl failed for SetFilePointer: %s", strerror(errno));
        }
    }
    
    // Fallback
    return 0xFFFFFFFF;
}

int __attribute__((ms_abi)) lsw_DeleteFileA(const char* filename) {
    LSW_LOG_INFO("DeleteFileA called: %s", filename ? filename : "(null)");
    
    if (!filename) {
        LSW_LOG_ERROR("DeleteFileA: null filename");
        return 0; // FALSE
    }
    
    // Translate Windows path to Linux path
    char linux_path[4096];
    if (lsw_fs_win_to_linux(filename, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("DeleteFileA: path translation failed for %s", filename);
        return 0;
    }
    
    LSW_LOG_INFO("DeleteFileA: %s -> %s", filename, linux_path);
    
    if (unlink(linux_path) != 0) {
        LSW_LOG_ERROR("DeleteFileA: unlink failed: %s", strerror(errno));
        return 0; // FALSE
    }
    
    LSW_LOG_INFO("DeleteFileA: successfully deleted %s", linux_path);
    return 1; // TRUE
}

// Wide-char file operations
void* __attribute__((ms_abi)) lsw_CreateFileW(const wchar_t* filename, uint32_t access, uint32_t share_mode,
                                                void* security, uint32_t creation, uint32_t flags, void* template_file) {
    LSW_LOG_INFO("CreateFileW called");
    
    if (!filename) {
        LSW_LOG_ERROR("CreateFileW: null filename");
        return INVALID_HANDLE_VALUE;
    }
    
    // Convert wide-char to multi-byte
    char filename_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_mb, sizeof(filename_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("CreateFileW: WideCharToMultiByte failed");
        return INVALID_HANDLE_VALUE;
    }
    
    LSW_LOG_INFO("CreateFileW: %s", filename_mb);
    
    // Call CreateFileA with converted path
    return lsw_CreateFileA(filename_mb, access, share_mode, security, creation, flags, template_file);
}

int __attribute__((ms_abi)) lsw_DeleteFileW(const wchar_t* filename) {
    LSW_LOG_INFO("DeleteFileW called");
    
    if (!filename) {
        LSW_LOG_ERROR("DeleteFileW: null filename");
        return 0; // FALSE
    }
    
    // Convert wide-char to multi-byte
    char filename_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_mb, sizeof(filename_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("DeleteFileW: WideCharToMultiByte failed");
        return 0;
    }
    
    LSW_LOG_INFO("DeleteFileW: %s", filename_mb);
    
    // Call DeleteFileA with converted path
    return lsw_DeleteFileA(filename_mb);
}

int __attribute__((ms_abi)) lsw_CopyFileW(const wchar_t* existing_file, const wchar_t* new_file, int fail_if_exists) {
    LSW_LOG_INFO("CopyFileW called");
    
    if (!existing_file || !new_file) {
        LSW_LOG_ERROR("CopyFileW: null filename");
        return 0; // FALSE
    }
    
    // Convert wide-char paths to multi-byte
    char existing_mb[LSW_MAX_PATH];
    char new_mb[LSW_MAX_PATH];
    
    if (lsw_WideCharToMultiByte(CP_UTF8, 0, existing_file, -1, existing_mb, sizeof(existing_mb), NULL, NULL) == 0) {
        LSW_LOG_ERROR("CopyFileW: WideCharToMultiByte failed for source");
        return 0;
    }
    
    if (lsw_WideCharToMultiByte(CP_UTF8, 0, new_file, -1, new_mb, sizeof(new_mb), NULL, NULL) == 0) {
        LSW_LOG_ERROR("CopyFileW: WideCharToMultiByte failed for dest");
        return 0;
    }
    
    // Translate Windows paths to Linux paths
    char existing_linux[LSW_MAX_PATH];
    char new_linux[LSW_MAX_PATH];
    
    if (lsw_fs_win_to_linux(existing_mb, existing_linux, sizeof(existing_linux)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("CopyFileW: path translation failed for source");
        return 0;
    }
    
    if (lsw_fs_win_to_linux(new_mb, new_linux, sizeof(new_linux)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("CopyFileW: path translation failed for dest");
        return 0;
    }
    
    LSW_LOG_INFO("CopyFileW: %s -> %s (fail_if_exists=%d)", existing_linux, new_linux, fail_if_exists);
    
    // Check if destination exists and fail_if_exists is set
    if (fail_if_exists) {
        struct stat st;
        if (stat(new_linux, &st) == 0) {
            LSW_LOG_WARN("CopyFileW: destination exists and fail_if_exists=TRUE");
            return 0;
        }
    }
    
    // Open source file
    int src_fd = open(existing_linux, O_RDONLY);
    if (src_fd < 0) {
        LSW_LOG_ERROR("CopyFileW: failed to open source: %s", strerror(errno));
        return 0;
    }
    
    // Get source file permissions
    struct stat src_stat;
    if (fstat(src_fd, &src_stat) != 0) {
        LSW_LOG_ERROR("CopyFileW: fstat failed: %s", strerror(errno));
        close(src_fd);
        return 0;
    }
    
    // Open/create destination file
    int dst_fd = open(new_linux, O_WRONLY | O_CREAT | O_TRUNC, src_stat.st_mode);
    if (dst_fd < 0) {
        LSW_LOG_ERROR("CopyFileW: failed to create destination: %s", strerror(errno));
        close(src_fd);
        return 0;
    }
    
    // Copy file contents
    char buffer[8192];
    ssize_t bytes_read;
    int success = 1;
    
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t bytes_written = write(dst_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            LSW_LOG_ERROR("CopyFileW: write failed: %s", strerror(errno));
            success = 0;
            break;
        }
    }
    
    if (bytes_read < 0) {
        LSW_LOG_ERROR("CopyFileW: read failed: %s", strerror(errno));
        success = 0;
    }
    
    close(src_fd);
    close(dst_fd);
    
    if (!success) {
        // Clean up failed copy
        unlink(new_linux);
        return 0;
    }
    
    LSW_LOG_INFO("CopyFileW: successfully copied file");
    return 1; // TRUE
}

// Directory operations
int __attribute__((ms_abi)) lsw_CreateDirectoryW(const wchar_t* pathname, void* security_attributes) {
    LSW_LOG_INFO("CreateDirectoryW called");
    
    (void)security_attributes;  // Not used
    
    if (!pathname) {
        LSW_LOG_ERROR("CreateDirectoryW: null pathname");
        return 0; // FALSE
    }
    
    // Convert wide-char to multi-byte
    char pathname_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, pathname, -1, pathname_mb, sizeof(pathname_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("CreateDirectoryW: WideCharToMultiByte failed");
        return 0;
    }
    
    // Translate Windows path to Linux path
    char linux_path[LSW_MAX_PATH];
    if (lsw_fs_win_to_linux(pathname_mb, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("CreateDirectoryW: path translation failed");
        return 0;
    }
    
    LSW_LOG_INFO("CreateDirectoryW: %s -> %s", pathname_mb, linux_path);
    
    // Create directory with standard permissions
    if (mkdir(linux_path, 0755) != 0) {
        if (errno == EEXIST) {
            LSW_LOG_WARN("CreateDirectoryW: directory already exists: %s", linux_path);
            // Windows returns FALSE if directory exists
            return 0;
        }
        LSW_LOG_ERROR("CreateDirectoryW: mkdir failed: %s", strerror(errno));
        return 0;
    }
    
    LSW_LOG_INFO("CreateDirectoryW: successfully created directory");
    return 1; // TRUE
}

int __attribute__((ms_abi)) lsw_RemoveDirectoryW(const wchar_t* pathname) {
    LSW_LOG_INFO("RemoveDirectoryW called");
    
    if (!pathname) {
        LSW_LOG_ERROR("RemoveDirectoryW: null pathname");
        return 0; // FALSE
    }
    
    // Convert wide-char to multi-byte
    char pathname_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, pathname, -1, pathname_mb, sizeof(pathname_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("RemoveDirectoryW: WideCharToMultiByte failed");
        return 0;
    }
    
    // Translate Windows path to Linux path
    char linux_path[LSW_MAX_PATH];
    if (lsw_fs_win_to_linux(pathname_mb, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("RemoveDirectoryW: path translation failed");
        return 0;
    }
    
    LSW_LOG_INFO("RemoveDirectoryW: %s -> %s", pathname_mb, linux_path);
    
    // Remove directory (must be empty)
    if (rmdir(linux_path) != 0) {
        LSW_LOG_ERROR("RemoveDirectoryW: rmdir failed: %s", strerror(errno));
        return 0;
    }
    
    LSW_LOG_INFO("RemoveDirectoryW: successfully removed directory");
    return 1; // TRUE
}

// File attribute operations
uint32_t __attribute__((ms_abi)) lsw_GetFileAttributesW(const wchar_t* filename) {
    LSW_LOG_INFO("GetFileAttributesW called");
    
    if (!filename) {
        LSW_LOG_ERROR("GetFileAttributesW: null filename");
        return INVALID_FILE_ATTRIBUTES;
    }
    
    // Convert wide-char to multi-byte
    char filename_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_mb, sizeof(filename_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("GetFileAttributesW: WideCharToMultiByte failed");
        return INVALID_FILE_ATTRIBUTES;
    }
    
    // Translate Windows path to Linux path
    char linux_path[LSW_MAX_PATH];
    if (lsw_fs_win_to_linux(filename_mb, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("GetFileAttributesW: path translation failed");
        return INVALID_FILE_ATTRIBUTES;
    }
    
    LSW_LOG_INFO("GetFileAttributesW: %s -> %s", filename_mb, linux_path);
    
    // Get file stats
    struct stat st;
    if (stat(linux_path, &st) != 0) {
        LSW_LOG_WARN("GetFileAttributesW: stat failed: %s", strerror(errno));
        return INVALID_FILE_ATTRIBUTES;
    }
    
    // Translate Linux file mode to Windows attributes
    uint32_t attrs = 0;
    
    // Check if directory
    if (S_ISDIR(st.st_mode)) {
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }
    
    // Check if read-only (write permission for owner)
    if (!(st.st_mode & S_IWUSR)) {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }
    
    // Check if hidden (Unix convention: starts with .)
    const char* basename = strrchr(linux_path, '/');
    if (basename && basename[1] == '.') {
        attrs |= FILE_ATTRIBUTE_HIDDEN;
    }
    
    // Default to NORMAL if no special attributes
    if (attrs == 0) {
        attrs = FILE_ATTRIBUTE_NORMAL;
    }
    
    LSW_LOG_INFO("GetFileAttributesW: attributes=0x%x", attrs);
    return attrs;
}

int __attribute__((ms_abi)) lsw_SetFileAttributesW(const wchar_t* filename, uint32_t attributes) {
    LSW_LOG_INFO("SetFileAttributesW called: attributes=0x%x", attributes);
    
    if (!filename) {
        LSW_LOG_ERROR("SetFileAttributesW: null filename");
        return 0; // FALSE
    }
    
    // Convert wide-char to multi-byte
    char filename_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_mb, sizeof(filename_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("SetFileAttributesW: WideCharToMultiByte failed");
        return 0;
    }
    
    // Translate Windows path to Linux path
    char linux_path[LSW_MAX_PATH];
    if (lsw_fs_win_to_linux(filename_mb, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("SetFileAttributesW: path translation failed");
        return 0;
    }
    
    LSW_LOG_INFO("SetFileAttributesW: %s -> %s", filename_mb, linux_path);
    
    // Get current file mode
    struct stat st;
    if (stat(linux_path, &st) != 0) {
        LSW_LOG_ERROR("SetFileAttributesW: stat failed: %s", strerror(errno));
        return 0;
    }
    
    mode_t new_mode = st.st_mode;
    
    // Handle READONLY attribute
    if (attributes & FILE_ATTRIBUTE_READONLY) {
        // Remove write permissions
        new_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
    } else {
        // Add write permission for owner
        new_mode |= S_IWUSR;
    }
    
    // Apply new permissions
    if (chmod(linux_path, new_mode) != 0) {
        LSW_LOG_ERROR("SetFileAttributesW: chmod failed: %s", strerror(errno));
        return 0;
    }
    
    LSW_LOG_INFO("SetFileAttributesW: successfully set attributes");
    return 1; // TRUE
}

// ============================================================================
// Path/Environment APIs (KERNEL32)
// ============================================================================

// KERNEL32.dll!GetWindowsDirectoryA - Get Windows directory path
DWORD __attribute__((ms_abi)) lsw_GetWindowsDirectoryA(char* buffer, DWORD size) {
    LSW_LOG_INFO("GetWindowsDirectoryA called: buffer=%p, size=%u", buffer, size);
    
    // Windows directory is C:\Windows -> ~/.lsw/drives/c/Windows
    const char* win_dir = "C:\\Windows";
    size_t len = strlen(win_dir);
    
    if (!buffer || size == 0) {
        // Return required size including null terminator
        return (DWORD)(len + 1);
    }
    
    if (size <= len) {
        // Buffer too small - return required size
        return (DWORD)(len + 1);
    }
    
    strcpy(buffer, win_dir);
    LSW_LOG_INFO("GetWindowsDirectoryA: returning '%s'", buffer);
    return (DWORD)len;
}

// KERNEL32.dll!GetWindowsDirectoryW - Get Windows directory path (wide-char)
DWORD __attribute__((ms_abi)) lsw_GetWindowsDirectoryW(wchar_t* buffer, DWORD size) {
    LSW_LOG_INFO("GetWindowsDirectoryW called: buffer=%p, size=%u", buffer, size);
    
    const wchar_t* win_dir = L"C:\\Windows";
    size_t len = wcslen(win_dir);
    
    if (!buffer || size == 0) {
        return (DWORD)(len + 1);
    }
    
    if (size <= len) {
        return (DWORD)(len + 1);
    }
    
    wcscpy(buffer, win_dir);
    LSW_LOG_INFO("GetWindowsDirectoryW: returning wide-char path");
    return (DWORD)len;
}

// KERNEL32.dll!GetSystemDirectoryA - Get System32 directory path
DWORD __attribute__((ms_abi)) lsw_GetSystemDirectoryA(char* buffer, DWORD size) {
    LSW_LOG_INFO("GetSystemDirectoryA called: buffer=%p, size=%u", buffer, size);
    
    const char* sys_dir = "C:\\Windows\\System32";
    size_t len = strlen(sys_dir);
    
    if (!buffer || size == 0) {
        return (DWORD)(len + 1);
    }
    
    if (size <= len) {
        return (DWORD)(len + 1);
    }
    
    strcpy(buffer, sys_dir);
    LSW_LOG_INFO("GetSystemDirectoryA: returning '%s'", buffer);
    return (DWORD)len;
}

// KERNEL32.dll!GetSystemDirectoryW - Get System32 directory path (wide-char)
DWORD __attribute__((ms_abi)) lsw_GetSystemDirectoryW(wchar_t* buffer, DWORD size) {
    LSW_LOG_INFO("GetSystemDirectoryW called: buffer=%p, size=%u", buffer, size);
    
    const wchar_t* sys_dir = L"C:\\Windows\\System32";
    size_t len = wcslen(sys_dir);
    
    if (!buffer || size == 0) {
        return (DWORD)(len + 1);
    }
    
    if (size <= len) {
        return (DWORD)(len + 1);
    }
    
    wcscpy(buffer, sys_dir);
    LSW_LOG_INFO("GetSystemDirectoryW: returning wide-char path");
    return (DWORD)len;
}

// KERNEL32.dll!GetTempPathA - Get temporary directory path
DWORD __attribute__((ms_abi)) lsw_GetTempPathA(DWORD size, char* buffer) {
    LSW_LOG_INFO("GetTempPathA called: size=%u, buffer=%p", size, buffer);
    
    // Check TEMP/TMP environment variables, fallback to C:\Temp
    const char* temp_path = getenv("TEMP");
    if (!temp_path) temp_path = getenv("TMP");
    if (!temp_path) temp_path = "C:\\Temp";
    
    size_t len = strlen(temp_path);
    
    // Ensure path ends with backslash
    int needs_slash = (temp_path[len-1] != '\\');
    size_t total_len = len + (needs_slash ? 1 : 0);
    
    if (!buffer || size == 0) {
        return (DWORD)(total_len + 1);
    }
    
    if (size <= total_len) {
        return (DWORD)(total_len + 1);
    }
    
    strcpy(buffer, temp_path);
    if (needs_slash) {
        buffer[len] = '\\';
        buffer[len+1] = '\0';
    }
    
    LSW_LOG_INFO("GetTempPathA: returning '%s'", buffer);
    return (DWORD)total_len;
}

// KERNEL32.dll!GetTempPathW - Get temporary directory path (wide-char)
DWORD __attribute__((ms_abi)) lsw_GetTempPathW(DWORD size, wchar_t* buffer) {
    LSW_LOG_INFO("GetTempPathW called: size=%u, buffer=%p", size, buffer);
    
    // Get ANSI version first
    char temp_ansi[LSW_MAX_PATH];
    DWORD ansi_len = lsw_GetTempPathA(sizeof(temp_ansi), temp_ansi);
    
    if (ansi_len == 0) {
        return 0;
    }
    
    // Convert to wide-char
    int wide_len = lsw_MultiByteToWideChar(CP_UTF8, 0, temp_ansi, -1, NULL, 0);
    if (wide_len == 0) {
        return 0;
    }
    
    if (!buffer || size == 0) {
        return (DWORD)wide_len;
    }
    
    if (size < (DWORD)wide_len) {
        return (DWORD)wide_len;
    }
    
    lsw_MultiByteToWideChar(CP_UTF8, 0, temp_ansi, -1, buffer, size);
    LSW_LOG_INFO("GetTempPathW: returning wide-char path");
    return (DWORD)(wide_len - 1); // Don't count null terminator
}

// KERNEL32.dll!GetEnvironmentVariableA - Get environment variable
DWORD __attribute__((ms_abi)) lsw_GetEnvironmentVariableA(const char* name, char* buffer, DWORD size) {
    LSW_LOG_INFO("GetEnvironmentVariableA called: name='%s', size=%u", name ? name : "(null)", size);
    
    if (!name) {
        return 0;
    }
    
    const char* value = getenv(name);
    if (!value) {
        LSW_LOG_INFO("GetEnvironmentVariableA: variable '%s' not found", name);
        return 0; // Variable not found
    }
    
    size_t len = strlen(value);
    
    if (!buffer || size == 0) {
        return (DWORD)(len + 1);
    }
    
    if (size <= len) {
        return (DWORD)(len + 1);
    }
    
    strcpy(buffer, value);
    LSW_LOG_INFO("GetEnvironmentVariableA: '%s' = '%s'", name, value);
    return (DWORD)len;
}

// KERNEL32.dll!GetEnvironmentVariableW - Get environment variable (wide-char)
DWORD __attribute__((ms_abi)) lsw_GetEnvironmentVariableW(const wchar_t* name, wchar_t* buffer, DWORD size) {
    LSW_LOG_INFO("GetEnvironmentVariableW called");
    
    if (!name) {
        return 0;
    }
    
    // Convert name to multi-byte
    char name_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, name, -1, name_mb, sizeof(name_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("GetEnvironmentVariableW: name conversion failed");
        return 0;
    }
    
    // Get ANSI value
    char value_ansi[LSW_MAX_PATH];
    DWORD ansi_len = lsw_GetEnvironmentVariableA(name_mb, value_ansi, sizeof(value_ansi));
    
    if (ansi_len == 0) {
        return 0; // Not found
    }
    
    // Convert to wide-char
    int wide_len = lsw_MultiByteToWideChar(CP_UTF8, 0, value_ansi, -1, NULL, 0);
    if (wide_len == 0) {
        return 0;
    }
    
    if (!buffer || size == 0) {
        return (DWORD)wide_len;
    }
    
    if (size < (DWORD)wide_len) {
        return (DWORD)wide_len;
    }
    
    lsw_MultiByteToWideChar(CP_UTF8, 0, value_ansi, -1, buffer, size);
    LSW_LOG_INFO("GetEnvironmentVariableW: successfully converted");
    return (DWORD)(wide_len - 1);
}

// KERNEL32.dll!SetEnvironmentVariableA - Set environment variable
int __attribute__((ms_abi)) lsw_SetEnvironmentVariableA(const char* name, const char* value) {
    LSW_LOG_INFO("SetEnvironmentVariableA called: name='%s', value='%s'", 
                 name ? name : "(null)", value ? value : "(null)");
    
    if (!name) {
        return 0; // FALSE
    }
    
    int result;
    if (value) {
        // Set the variable
        result = setenv(name, value, 1); // 1 = overwrite
    } else {
        // Delete the variable
        result = unsetenv(name);
    }
    
    if (result == 0) {
        LSW_LOG_INFO("SetEnvironmentVariableA: success");
        return 1; // TRUE
    } else {
        LSW_LOG_ERROR("SetEnvironmentVariableA: failed: %s", strerror(errno));
        return 0; // FALSE
    }
}

// KERNEL32.dll!SetEnvironmentVariableW - Set environment variable (wide-char)
int __attribute__((ms_abi)) lsw_SetEnvironmentVariableW(const wchar_t* name, const wchar_t* value) {
    LSW_LOG_INFO("SetEnvironmentVariableW called");
    
    if (!name) {
        return 0;
    }
    
    // Convert name to multi-byte
    char name_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, name, -1, name_mb, sizeof(name_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("SetEnvironmentVariableW: name conversion failed");
        return 0;
    }
    
    char* value_mb = NULL;
    char value_buf[LSW_MAX_PATH];
    if (value) {
        result = lsw_WideCharToMultiByte(CP_UTF8, 0, value, -1, value_buf, sizeof(value_buf), NULL, NULL);
        if (result == 0) {
            LSW_LOG_ERROR("SetEnvironmentVariableW: value conversion failed");
            return 0;
        }
        value_mb = value_buf;
    }
    
    return lsw_SetEnvironmentVariableA(name_mb, value_mb);
}

// KERNEL32.dll!ExpandEnvironmentStringsA - Expand environment variable references
DWORD __attribute__((ms_abi)) lsw_ExpandEnvironmentStringsA(const char* src, char* dst, DWORD size) {
    LSW_LOG_INFO("ExpandEnvironmentStringsA called: src='%s', size=%u", src ? src : "(null)", size);
    
    if (!src) {
        return 0;
    }
    
    // Simple implementation: expand %VAR% patterns
    char temp[LSW_MAX_PATH * 2];
    size_t dst_pos = 0;
    const char* p = src;
    
    while (*p && dst_pos < sizeof(temp) - 1) {
        if (*p == '%') {
            // Find closing %
            const char* end = strchr(p + 1, '%');
            if (end) {
                // Extract variable name
                size_t var_len = end - p - 1;
                char var_name[256];
                if (var_len < sizeof(var_name)) {
                    strncpy(var_name, p + 1, var_len);
                    var_name[var_len] = '\0';
                    
                    // Get variable value
                    const char* var_value = getenv(var_name);
                    if (var_value) {
                        // Copy value
                        size_t value_len = strlen(var_value);
                        if (dst_pos + value_len < sizeof(temp)) {
                            strcpy(temp + dst_pos, var_value);
                            dst_pos += value_len;
                            p = end + 1;
                            continue;
                        }
                    }
                }
            }
        }
        
        // Copy character as-is
        temp[dst_pos++] = *p++;
    }
    temp[dst_pos] = '\0';
    
    size_t result_len = strlen(temp);
    
    if (!dst || size == 0) {
        return (DWORD)(result_len + 1);
    }
    
    if (size <= result_len) {
        return (DWORD)(result_len + 1);
    }
    
    strcpy(dst, temp);
    LSW_LOG_INFO("ExpandEnvironmentStringsA: '%s' -> '%s'", src, dst);
    return (DWORD)(result_len + 1); // Windows returns length including null terminator
}

// KERNEL32.dll!ExpandEnvironmentStringsW - Expand environment variable references (wide-char)
DWORD __attribute__((ms_abi)) lsw_ExpandEnvironmentStringsW(const wchar_t* src, wchar_t* dst, DWORD size) {
    LSW_LOG_INFO("ExpandEnvironmentStringsW called");
    
    if (!src) {
        return 0;
    }
    
    // Convert source to multi-byte
    char src_mb[LSW_MAX_PATH * 2];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, src, -1, src_mb, sizeof(src_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("ExpandEnvironmentStringsW: source conversion failed");
        return 0;
    }
    
    // Expand in ANSI
    char expanded_ansi[LSW_MAX_PATH * 2];
    DWORD ansi_len = lsw_ExpandEnvironmentStringsA(src_mb, expanded_ansi, sizeof(expanded_ansi));
    if (ansi_len == 0) {
        return 0;
    }
    
    // Convert back to wide-char
    int wide_len = lsw_MultiByteToWideChar(CP_UTF8, 0, expanded_ansi, -1, NULL, 0);
    if (wide_len == 0) {
        return 0;
    }
    
    if (!dst || size == 0) {
        return (DWORD)wide_len;
    }
    
    if (size < (DWORD)wide_len) {
        return (DWORD)wide_len;
    }
    
    lsw_MultiByteToWideChar(CP_UTF8, 0, expanded_ansi, -1, dst, size);
    LSW_LOG_INFO("ExpandEnvironmentStringsW: successfully expanded");
    return (DWORD)wide_len;
}

// ============================================================================
// END Path/Environment APIs
// ============================================================================

// ============================================================================
// COMDLG32 APIs (Common Dialogs)
// ============================================================================

// COMDLG32.dll!PrintDlgW - Display Print dialog
int __attribute__((ms_abi)) lsw_PrintDlgW(void* lppd) {
    LSW_LOG_INFO("PrintDlgW called: lppd=%p", lppd);
    LSW_LOG_WARN("PrintDlgW: stub implementation - returning FALSE (user cancelled)");
    
    // TODO: Implement print dialog
    // For now, return FALSE to indicate user cancelled
    return 0;
}

// COMDLG32.dll!ChooseColorW - Display Color picker dialog
int __attribute__((ms_abi)) lsw_ChooseColorW(void* lpcc) {
    LSW_LOG_INFO("ChooseColorW called: lpcc=%p", lpcc);
    LSW_LOG_WARN("ChooseColorW: stub implementation - returning FALSE (user cancelled)");
    
    // TODO: Implement color picker dialog
    // For now, return FALSE to indicate user cancelled
    return 0;
}

// ============================================================================
// END COMDLG32 APIs
// ============================================================================

// ============================================================================
// File Enumeration APIs (KERNEL32)
// ============================================================================

// Internal structure for directory search handle
typedef struct {
    DIR* dir;
    char pattern[LSW_MAX_PATH];
    char dir_path[LSW_MAX_PATH];
    struct dirent* current_entry;
    int first_call;
} lsw_find_data_t;

// Helper: Convert Linux dirent to WIN32_FIND_DATAW
static void dirent_to_find_data(struct dirent* entry, const char* dir_path, WIN32_FIND_DATAW* find_data) {
    memset(find_data, 0, sizeof(WIN32_FIND_DATAW));
    
    // Convert filename to wide-char
    lsw_MultiByteToWideChar(CP_UTF8, 0, entry->d_name, -1, 
                            find_data->cFileName, sizeof(find_data->cFileName)/sizeof(wchar_t));
    
    // Get file stats
    char full_path[LSW_MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
    
    struct stat st;
    if (stat(full_path, &st) == 0) {
        // Set attributes
        find_data->dwFileAttributes = 0;
        if (S_ISDIR(st.st_mode)) {
            find_data->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
        }
        if (entry->d_name[0] == '.') {
            find_data->dwFileAttributes |= FILE_ATTRIBUTE_HIDDEN;
        }
        if (!(st.st_mode & S_IWUSR)) {
            find_data->dwFileAttributes |= FILE_ATTRIBUTE_READONLY;
        }
        if (find_data->dwFileAttributes == 0) {
            find_data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
        
        // Set file size
        find_data->nFileSizeLow = (uint32_t)(st.st_size & 0xFFFFFFFF);
        find_data->nFileSizeHigh = (uint32_t)(st.st_size >> 32);
        
        // TODO: Convert timestamps properly
    } else {
        find_data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
}

// Helper: Simple wildcard matching (* and ? supported)
static int match_pattern(const char* str, const char* pattern) {
    if (*pattern == '\0') return (*str == '\0');
    if (*pattern == '*') {
        if (match_pattern(str, pattern + 1)) return 1;
        if (*str && match_pattern(str + 1, pattern)) return 1;
        return 0;
    }
    if (*pattern == '?' || *pattern == *str) {
        return match_pattern(str + 1, pattern + 1);
    }
    return 0;
}

// KERNEL32.dll!FindFirstFileW - Start file search
void* __attribute__((ms_abi)) lsw_FindFirstFileW(const wchar_t* filename, WIN32_FIND_DATAW* find_data) {
    LSW_LOG_INFO("FindFirstFileW called");
    
    if (!filename || !find_data) {
        LSW_LOG_ERROR("FindFirstFileW: null parameters");
        return (void*)-1; // INVALID_HANDLE_VALUE
    }
    
    // Convert filename to multi-byte
    char filename_mb[LSW_MAX_PATH];
    int result = lsw_WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_mb, sizeof(filename_mb), NULL, NULL);
    if (result == 0) {
        LSW_LOG_ERROR("FindFirstFileW: filename conversion failed");
        return (void*)-1;
    }
    
    LSW_LOG_INFO("FindFirstFileW: searching for '%s' (len=%d)", filename_mb, result);
    
    // Debug: show first few bytes as hex
    LSW_LOG_INFO("FindFirstFileW: hex dump: %02x %02x %02x %02x", 
                 (unsigned char)filename_mb[0], (unsigned char)filename_mb[1], 
                 (unsigned char)filename_mb[2], (unsigned char)filename_mb[3]);
    
    // Translate Windows path to Linux
    char linux_path[LSW_MAX_PATH];
    if (lsw_fs_win_to_linux(filename_mb, linux_path, sizeof(linux_path)) != LSW_SUCCESS) {
        LSW_LOG_ERROR("FindFirstFileW: path translation failed");
        return (void*)-1;
    }
    
    // Extract directory and pattern
    char dir_path[LSW_MAX_PATH];
    char pattern[LSW_MAX_PATH];
    char* last_slash = strrchr(linux_path, '/');
    
    if (last_slash) {
        size_t dir_len = last_slash - linux_path;
        strncpy(dir_path, linux_path, dir_len);
        dir_path[dir_len] = '\0';
        strcpy(pattern, last_slash + 1);
    } else {
        strcpy(dir_path, ".");
        strcpy(pattern, linux_path);
    }
    
    LSW_LOG_INFO("FindFirstFileW: dir='%s', pattern='%s'", dir_path, pattern);
    
    // Open directory
    DIR* dir = opendir(dir_path);
    if (!dir) {
        LSW_LOG_ERROR("FindFirstFileW: opendir failed: %s", strerror(errno));
        return (void*)-1;
    }
    
    // Allocate find handle
    lsw_find_data_t* find_handle = malloc(sizeof(lsw_find_data_t));
    if (!find_handle) {
        closedir(dir);
        return (void*)-1;
    }
    
    find_handle->dir = dir;
    strcpy(find_handle->pattern, pattern);
    strcpy(find_handle->dir_path, dir_path);
    find_handle->first_call = 1;
    
    // Find first matching entry
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (match_pattern(entry->d_name, pattern)) {
            dirent_to_find_data(entry, dir_path, find_data);
            LSW_LOG_INFO("FindFirstFileW: found '%s'", entry->d_name);
            return (void*)find_handle;
        }
    }
    
    // No match found
    LSW_LOG_INFO("FindFirstFileW: no matches found");
    closedir(dir);
    free(find_handle);
    return (void*)-1;
}

// KERNEL32.dll!FindNextFileW - Get next file in search
int __attribute__((ms_abi)) lsw_FindNextFileW(void* find_handle, WIN32_FIND_DATAW* find_data) {
    LSW_LOG_INFO("FindNextFileW called: handle=%p", find_handle);
    
    if (!find_handle || find_handle == (void*)-1 || !find_data) {
        LSW_LOG_ERROR("FindNextFileW: invalid parameters");
        return 0; // FALSE
    }
    
    lsw_find_data_t* handle = (lsw_find_data_t*)find_handle;
    
    // Continue searching
    struct dirent* entry;
    while ((entry = readdir(handle->dir)) != NULL) {
        if (match_pattern(entry->d_name, handle->pattern)) {
            dirent_to_find_data(entry, handle->dir_path, find_data);
            LSW_LOG_INFO("FindNextFileW: found '%s'", entry->d_name);
            return 1; // TRUE
        }
    }
    
    LSW_LOG_INFO("FindNextFileW: no more files");
    return 0; // FALSE - no more files
}

// KERNEL32.dll!FindClose - Close search handle
int __attribute__((ms_abi)) lsw_FindClose(void* find_handle) {
    LSW_LOG_INFO("FindClose called: handle=%p", find_handle);
    
    if (!find_handle || find_handle == (void*)-1) {
        LSW_LOG_ERROR("FindClose: invalid handle");
        return 0; // FALSE
    }
    
    lsw_find_data_t* handle = (lsw_find_data_t*)find_handle;
    
    if (handle->dir) {
        closedir(handle->dir);
    }
    
    free(handle);
    LSW_LOG_INFO("FindClose: handle closed successfully");
    return 1; // TRUE
}

// KERNEL32.dll!FindFirstFileExW - Advanced file search
void* __attribute__((ms_abi)) lsw_FindFirstFileExW(
    const wchar_t* filename,
    int info_level,
    void* find_data,
    int search_op,
    void* search_filter,
    uint32_t flags)
{
    (void)info_level;
    (void)search_op;
    (void)search_filter;
    (void)flags;
    
    LSW_LOG_INFO("FindFirstFileExW called (using standard FindFirstFileW)");
    
    // For now, just delegate to FindFirstFileW
    return lsw_FindFirstFileW(filename, (WIN32_FIND_DATAW*)find_data);
}

// ============================================================================
// END File Enumeration APIs
// ============================================================================

// ============================================================================
// Memory Management APIs (KERNEL32)
// ============================================================================

// KERNEL32.dll!GetProcessHeap - Get default process heap
void* __attribute__((ms_abi)) lsw_GetProcessHeap(void) {
    LSW_LOG_INFO("GetProcessHeap called - returning dummy heap handle");
    // Return a dummy heap handle (we'll use malloc/free underneath)
    return (void*)0x1; // Non-null heap handle
}

// KERNEL32.dll!HeapAlloc - Allocate memory from heap
void* __attribute__((ms_abi)) lsw_HeapAlloc(void* heap, uint32_t flags, size_t size) {
    (void)heap; // Ignore heap parameter, use malloc
    
    LSW_LOG_INFO("HeapAlloc called: size=%zu, flags=0x%x", size, flags);
    
    void* ptr = malloc(size);
    
    // HEAP_ZERO_MEMORY flag
    if (ptr && (flags & 0x00000008)) {
        memset(ptr, 0, size);
    }
    
    LSW_LOG_INFO("HeapAlloc: allocated %p", ptr);
    return ptr;
}

// KERNEL32.dll!HeapFree - Free heap memory
int __attribute__((ms_abi)) lsw_HeapFree(void* heap, uint32_t flags, void* mem) {
    (void)heap;
    (void)flags;
    
    LSW_LOG_INFO("HeapFree called: mem=%p", mem);
    
    if (mem) {
        free(mem);
        return 1; // TRUE
    }
    
    return 0; // FALSE
}

// KERNEL32.dll!HeapReAlloc - Reallocate heap memory
void* __attribute__((ms_abi)) lsw_HeapReAlloc(void* heap, uint32_t flags, void* mem, size_t size) {
    (void)heap;
    (void)flags;
    
    LSW_LOG_INFO("HeapReAlloc called: mem=%p, new_size=%zu", mem, size);
    
    void* new_ptr = realloc(mem, size);
    LSW_LOG_INFO("HeapReAlloc: reallocated to %p", new_ptr);
    return new_ptr;
}

// KERNEL32.dll!HeapSize - Get size of heap block
size_t __attribute__((ms_abi)) lsw_HeapSize(void* heap, uint32_t flags, void* mem) {
    (void)heap;
    (void)flags;
    (void)mem;
    
    LSW_LOG_WARN("HeapSize called: not fully implemented, returning 0");
    // TODO: Track allocation sizes
    return 0;
}

// KERNEL32.dll!LocalAlloc - Allocate local memory
void* __attribute__((ms_abi)) lsw_LocalAlloc(uint32_t flags, size_t size) {
    LSW_LOG_INFO("LocalAlloc called: size=%zu, flags=0x%x", size, flags);
    
    void* ptr = malloc(size);
    
    // LMEM_ZEROINIT flag
    if (ptr && (flags & 0x0040)) {
        memset(ptr, 0, size);
    }
    
    LSW_LOG_INFO("LocalAlloc: allocated %p", ptr);
    return ptr;
}

// KERNEL32.dll!LocalFree - Free local memory
void* __attribute__((ms_abi)) lsw_LocalFree(void* mem) {
    LSW_LOG_INFO("LocalFree called: mem=%p", mem);
    
    if (mem) {
        free(mem);
    }
    
    return NULL; // Success returns NULL
}

// KERNEL32.dll!GlobalAlloc - Allocate global memory
void* __attribute__((ms_abi)) lsw_GlobalAlloc(uint32_t flags, size_t size) {
    LSW_LOG_INFO("GlobalAlloc called: size=%zu, flags=0x%x", size, flags);
    
    void* ptr = malloc(size);
    
    // GMEM_ZEROINIT flag
    if (ptr && (flags & 0x0040)) {
        memset(ptr, 0, size);
    }
    
    LSW_LOG_INFO("GlobalAlloc: allocated %p", ptr);
    return ptr;
}

// KERNEL32.dll!GlobalFree - Free global memory
void* __attribute__((ms_abi)) lsw_GlobalFree(void* mem) {
    LSW_LOG_INFO("GlobalFree called: mem=%p", mem);
    
    if (mem) {
        free(mem);
    }
    
    return NULL; // Success returns NULL
}

// KERNEL32.dll!GlobalLock - Lock global memory
void* __attribute__((ms_abi)) lsw_GlobalLock(void* mem) {
    LSW_LOG_INFO("GlobalLock called: mem=%p", mem);
    // In our implementation, memory is already accessible
    return mem;
}

// KERNEL32.dll!GlobalUnlock - Unlock global memory
int __attribute__((ms_abi)) lsw_GlobalUnlock(void* mem) {
    LSW_LOG_INFO("GlobalUnlock called: mem=%p", mem);
    // In our implementation, no-op
    (void)mem;
    return 1; // TRUE
}

// KERNEL32.dll!GlobalSize - Get size of global memory block
size_t __attribute__((ms_abi)) lsw_GlobalSize(void* mem) {
    LSW_LOG_WARN("GlobalSize called: mem=%p, not fully implemented", mem);
    (void)mem;
    // TODO: Track allocation sizes
    return 0;
}

// ============================================================================
// END Memory Management APIs
// ============================================================================

void* __attribute__((ms_abi)) lsw_CreateThread(
    void* thread_attributes,
    uint32_t stack_size,
    void* start_address,
    void* parameter,
    uint32_t creation_flags,
    uint32_t* thread_id)
{
    (void)thread_attributes; // Not used yet
    
    LSW_LOG_INFO("CreateThread called: start=0x%p, param=0x%p, flags=0x%x",
                 start_address, parameter, creation_flags);
    
    if (!start_address) {
        LSW_LOG_ERROR("CreateThread: null start address");
        return NULL; // INVALID_HANDLE_VALUE
    }
    
    // Route through kernel NtCreateThreadEx
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing CreateThread through kernel NtCreateThreadEx!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtCreateThreadEx;
        req.arg_count = 4;
        req.args[0] = (uint64_t)(uintptr_t)start_address;  // Thread start function
        req.args[1] = (uint64_t)(uintptr_t)parameter;      // Thread parameter
        req.args[2] = stack_size ? stack_size : 0x100000;  // Default 1MB stack
        req.args[3] = creation_flags;                       // Creation flags
        
        LSW_LOG_INFO("  Request: syscall=0x%x, args=[0x%lx, 0x%lx, %lu, 0x%x]",
                     req.syscall_number, req.args[0], req.args[1], req.args[2], (uint32_t)req.args[3]);
        
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0) {
            void* thread_handle = (void*)(uintptr_t)req.return_value;
            
            // Return thread ID if requested
            if (thread_id) {
                *thread_id = (uint32_t)(req.return_value & 0xFFFFFFFF);
            }
            
            LSW_LOG_INFO("CreateThread: handle=%p, tid=%u", 
                        thread_handle, thread_id ? *thread_id : 0);
            return thread_handle;
        } else {
            LSW_LOG_ERROR("Kernel ioctl failed for CreateThread: %s", strerror(errno));
        }
    }
    
    // Fallback: create pthread
    LSW_LOG_WARN("Using pthread fallback for CreateThread");
    
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, (void*(*)(void*))start_address, parameter);
    
    if (ret != 0) {
        LSW_LOG_ERROR("pthread_create failed: %s", strerror(ret));
        return NULL;
    }
    
    if (thread_id) {
        *thread_id = (uint32_t)(uintptr_t)thread;
    }
    
    LSW_LOG_INFO("CreateThread fallback: pthread=%lu", (unsigned long)thread);
    
    // Return pthread handle as Win32 handle
    return (void*)(uintptr_t)thread;
}

void __attribute__((ms_abi)) lsw_ExitThread(uint32_t exit_code)
{
    LSW_LOG_INFO("ExitThread called: exit_code=%u", exit_code);
    
    // Route through kernel NtTerminateThread
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing ExitThread through kernel NtTerminateThread!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtTerminateThread;
        req.arg_count = 2;
        req.args[0] = 0;  // NULL = current thread
        req.args[1] = exit_code;
        
        ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req);
        // If we get here, syscall failed, fall through to pthread_exit
    }
    
    // Fallback: use pthread_exit
    LSW_LOG_INFO("ExitThread: using pthread_exit fallback");
    pthread_exit((void*)(uintptr_t)exit_code);
}

uint32_t __attribute__((ms_abi)) lsw_WaitForSingleObject(void* handle, uint32_t milliseconds)
{
    LSW_LOG_INFO("WaitForSingleObject called: handle=%p, timeout=%u", handle, milliseconds);
    
    if (!handle) {
        LSW_LOG_ERROR("WaitForSingleObject: null handle");
        return 0xFFFFFFFF; // WAIT_FAILED
    }
    
    // Route through kernel
    if (g_kernel_fd >= 0) {
        LSW_LOG_INFO("Routing WaitForSingleObject through kernel!");
        
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtWaitForSingleObject;
        req.arg_count = 3;
        req.args[0] = (uint64_t)(uintptr_t)handle;
        req.args[1] = 0;  // Alertable = FALSE
        req.args[2] = milliseconds;
        
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0) {
            uint32_t result = (uint32_t)req.return_value;
            LSW_LOG_INFO("WaitForSingleObject: result=%u (0=WAIT_OBJECT_0)", result);
            return result;
        } else {
            LSW_LOG_ERROR("Kernel ioctl failed for WaitForSingleObject: %s", strerror(errno));
        }
    }
    
    // Fallback: basic sleep (not ideal but works for testing)
    LSW_LOG_WARN("WaitForSingleObject: using sleep fallback");
    if (milliseconds != 0xFFFFFFFF) {  // Not INFINITE
        usleep(milliseconds * 1000);
    }
    return 0; // WAIT_OBJECT_0
}

void* __attribute__((ms_abi)) lsw_LoadLibraryA(const char* filename)
{
    LSW_LOG_INFO("LoadLibraryA called: %s", filename ? filename : "(null)");
    
    if (!filename) {
        LSW_LOG_ERROR("LoadLibraryA: null filename");
        return NULL;
    }
    
    // Convert Windows DLL name to Linux SO name
    char linux_path[512];
    
    // Check if it's a system DLL we're providing
    if (strcasecmp(filename, "kernel32.dll") == 0 ||
        strcasecmp(filename, "user32.dll") == 0 ||
        strcasecmp(filename, "gdi32.dll") == 0) {
        // These are provided by LSW itself - return a fake handle
        // The PE loader will map their functions
        LSW_LOG_INFO("LoadLibraryA: System DLL %s (returning fake handle)", filename);
        return (void*)0xDEADBEEF;  // Fake handle for system DLLs
    }
    
    // Try to load as Linux shared library
    const char* so_name = filename;
    if (strstr(filename, ".dll") || strstr(filename, ".DLL")) {
        // Convert foo.dll -> libfoo.so
        char dll_name[256];
        strncpy(dll_name, filename, sizeof(dll_name) - 1);
        char* dot = strrchr(dll_name, '.');
        if (dot) *dot = '\0';
        
        snprintf(linux_path, sizeof(linux_path), "lib%s.so", dll_name);
        so_name = linux_path;
    }
    
    LSW_LOG_INFO("LoadLibraryA: Attempting to load %s as %s", filename, so_name);
    
    void* handle = dlopen(so_name, RTLD_NOW | RTLD_LOCAL);
    
    if (!handle) {
        LSW_LOG_ERROR("LoadLibraryA: dlopen failed: %s", dlerror());
        return NULL;
    }
    
    LSW_LOG_INFO("LoadLibraryA: Successfully loaded %s at %p", so_name, handle);
    return handle;
}

void* __attribute__((ms_abi)) lsw_GetProcAddress(void* module, const char* proc_name)
{
    LSW_LOG_INFO("GetProcAddress called: module=%p, proc=%s", module, proc_name ? proc_name : "(null)");
    
    if (!module) {
        LSW_LOG_ERROR("GetProcAddress: null module");
        return NULL;
    }
    
    if (!proc_name) {
        LSW_LOG_ERROR("GetProcAddress: null proc_name");
        return NULL;
    }
    
    // Check if it's a system DLL fake handle
    if (module == (void*)0xDEADBEEF) {
        // System DLL - return NULL, let PE loader handle it
        LSW_LOG_INFO("GetProcAddress: System DLL function %s (letting PE loader resolve)", proc_name);
        return NULL;
    }
    
    // Real dlopen handle - use dlsym
    void* addr = dlsym(module, proc_name);
    
    if (!addr) {
        LSW_LOG_WARN("GetProcAddress: dlsym failed: %s", dlerror());
        return NULL;
    }
    
    LSW_LOG_INFO("GetProcAddress: Found %s at %p", proc_name, addr);
    return addr;
}

int __attribute__((ms_abi)) lsw_lstrlenA(const char* str) {
    if (!str) return 0;
    return (int)strlen(str);
}

// kernel32.dll!GetCommandLineA - Get command line string
LPSTR __attribute__((ms_abi)) lsw_GetCommandLineA(void) {
    const char* cmdline = win32_get_command_line();
    LSW_LOG_DEBUG("GetCommandLineA() -> '%s'", cmdline);
    return (LPSTR)cmdline;
}

// kernel32.dll!ExitProcess - Terminate process
void __attribute__((ms_abi)) lsw_ExitProcess(DWORD exit_code) {
    LSW_LOG_INFO("ExitProcess(%u)", exit_code);
    exit(exit_code);
}

// ============================================================================
// SECTION: Winsock (Networking) APIs
// ============================================================================

// Winsock constants
#define SOCKET_ERROR            (-1)
#define INVALID_SOCKET          ((SOCKET)(~0))
#define SOCK_STREAM_WIN         1
#define SOCK_DGRAM_WIN          2
#define AF_INET_WIN             2
#define IPPROTO_TCP_WIN         6
#define IPPROTO_UDP_WIN         17

// Winsock error codes
#define WSAEINTR                10004
#define WSAEBADF                10009
#define WSAEACCES               10013
#define WSAEFAULT               10014
#define WSAEINVAL               10022
#define WSAEWOULDBLOCK          10035
#define WSAEINPROGRESS          10036
#define WSAECONNREFUSED         10061
#define WSAEHOSTUNREACH         10065

// Winsock version
#define MAKEWORD(a,b)           ((WORD)(((BYTE)(a))|(((WORD)((BYTE)(b)))<<8)))
#define WINSOCK_VERSION         MAKEWORD(2,2)

typedef uintptr_t SOCKET;

// WSADATA structure
typedef struct {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char* lpVendorInfo;
} WSADATA;

// sockaddr_in structure (matches Windows layout)
struct sockaddr_in_win {
    short sin_family;
    unsigned short sin_port;
    struct {
        unsigned long s_addr;
    } sin_addr;
    char sin_zero[8];
};

// Last Winsock error (thread-local would be better, but keeping it simple)
static int g_last_wsa_error = 0;

// Map errno to WSA error code
static int errno_to_wsa_error(int err) {
    switch (err) {
        case EINTR: return WSAEINTR;
        case EBADF: return WSAEBADF;
        case EACCES: return WSAEACCES;
        case EFAULT: return WSAEFAULT;
        case EINVAL: return WSAEINVAL;
        case EWOULDBLOCK: return WSAEWOULDBLOCK;
        case EINPROGRESS: return WSAEINPROGRESS;
        case ECONNREFUSED: return WSAECONNREFUSED;
        case EHOSTUNREACH: return WSAEHOSTUNREACH;
        default: return err + 10000; // Generic mapping
    }
}

// ws2_32.dll!WSAStartup - Initialize Winsock
int __attribute__((ms_abi)) lsw_WSAStartup(WORD version_requested, WSADATA* wsa_data) {
    LSW_LOG_INFO("WSAStartup: version=0x%04x", version_requested);
    
    if (!wsa_data) {
        return WSAEFAULT;
    }
    
    // Fill in WSADATA
    memset(wsa_data, 0, sizeof(WSADATA));
    wsa_data->wVersion = WINSOCK_VERSION;
    wsa_data->wHighVersion = WINSOCK_VERSION;
    strncpy(wsa_data->szDescription, "LSW Winsock 2.2", sizeof(wsa_data->szDescription));
    strncpy(wsa_data->szSystemStatus, "Running", sizeof(wsa_data->szSystemStatus));
    wsa_data->iMaxSockets = 0; // No limit in modern Winsock
    wsa_data->iMaxUdpDg = 65467;
    
    LSW_LOG_INFO("WSAStartup: success");
    return 0;
}

// ws2_32.dll!WSACleanup - Cleanup Winsock
int __attribute__((ms_abi)) lsw_WSACleanup(void) {
    LSW_LOG_INFO("WSACleanup");
    return 0; // Nothing to clean up
}

// ws2_32.dll!WSAGetLastError - Get last error
int __attribute__((ms_abi)) lsw_WSAGetLastError(void) {
    return g_last_wsa_error;
}

// ws2_32.dll!WSASetLastError - Set last error
void __attribute__((ms_abi)) lsw_WSASetLastError(int error) {
    g_last_wsa_error = error;
}

// ws2_32.dll!socket - Create socket
SOCKET __attribute__((ms_abi)) lsw_socket(int af, int type, int protocol) {
    LSW_LOG_INFO("socket: af=%d, type=%d, protocol=%d", af, type, protocol);
    
    // Map Windows constants to POSIX
    int posix_af = (af == AF_INET_WIN) ? AF_INET : af;
    int posix_type = (type == SOCK_STREAM_WIN) ? SOCK_STREAM : 
                     (type == SOCK_DGRAM_WIN) ? SOCK_DGRAM : type;
    int posix_protocol = (protocol == IPPROTO_TCP_WIN) ? IPPROTO_TCP :
                         (protocol == IPPROTO_UDP_WIN) ? IPPROTO_UDP : protocol;
    
    int sock = socket(posix_af, posix_type, posix_protocol);
    
    if (sock < 0) {
        g_last_wsa_error = errno_to_wsa_error(errno);
        LSW_LOG_ERROR("socket failed: %s", strerror(errno));
        return INVALID_SOCKET;
    }
    
    LSW_LOG_INFO("socket: created fd=%d", sock);
    return (SOCKET)sock;
}

// ws2_32.dll!connect - Connect socket
int __attribute__((ms_abi)) lsw_connect(SOCKET s, const struct sockaddr_in_win* name, int namelen) {
    (void)namelen;
    
    LSW_LOG_INFO("connect: socket=%lu", (unsigned long)s);
    
    if (!name) {
        g_last_wsa_error = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    // Convert Windows sockaddr_in to POSIX
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = name->sin_port;
    addr.sin_addr.s_addr = name->sin_addr.s_addr;
    
    LSW_LOG_INFO("connect: %s:%d", 
                 inet_ntoa(addr.sin_addr), 
                 ntohs(addr.sin_port));
    
    int result = connect((int)s, (struct sockaddr*)&addr, sizeof(addr));
    
    if (result < 0) {
        g_last_wsa_error = errno_to_wsa_error(errno);
        LSW_LOG_ERROR("connect failed: %s", strerror(errno));
        return SOCKET_ERROR;
    }
    
    LSW_LOG_INFO("connect: success");
    return 0;
}

// ws2_32.dll!send - Send data
int __attribute__((ms_abi)) lsw_send(SOCKET s, const char* buf, int len, int flags) {
    LSW_LOG_INFO("send: socket=%lu, len=%d", (unsigned long)s, len);
    
    int result = send((int)s, buf, len, flags);
    
    if (result < 0) {
        g_last_wsa_error = errno_to_wsa_error(errno);
        LSW_LOG_ERROR("send failed: %s", strerror(errno));
        return SOCKET_ERROR;
    }
    
    LSW_LOG_INFO("send: sent %d bytes", result);
    return result;
}

// ws2_32.dll!recv - Receive data
int __attribute__((ms_abi)) lsw_recv(SOCKET s, char* buf, int len, int flags) {
    LSW_LOG_INFO("recv: socket=%lu, len=%d", (unsigned long)s, len);
    
    int result = recv((int)s, buf, len, flags);
    
    if (result < 0) {
        g_last_wsa_error = errno_to_wsa_error(errno);
        LSW_LOG_ERROR("recv failed: %s", strerror(errno));
        return SOCKET_ERROR;
    }
    
    LSW_LOG_INFO("recv: received %d bytes", result);
    return result;
}

// ws2_32.dll!closesocket - Close socket
int __attribute__((ms_abi)) lsw_closesocket(SOCKET s) {
    LSW_LOG_INFO("closesocket: socket=%lu", (unsigned long)s);
    
    int result = close((int)s);
    
    if (result < 0) {
        g_last_wsa_error = errno_to_wsa_error(errno);
        LSW_LOG_ERROR("closesocket failed: %s", strerror(errno));
        return SOCKET_ERROR;
    }
    
    return 0;
}

// ws2_32.dll!htons - Host to network short
unsigned short __attribute__((ms_abi)) lsw_htons(unsigned short hostshort) {
    return htons(hostshort);
}

// ws2_32.dll!htonl - Host to network long
unsigned long __attribute__((ms_abi)) lsw_htonl(unsigned long hostlong) {
    return htonl(hostlong);
}

// ws2_32.dll!ntohs - Network to host short
unsigned short __attribute__((ms_abi)) lsw_ntohs(unsigned short netshort) {
    return ntohs(netshort);
}

// ws2_32.dll!ntohl - Network to host long
unsigned long __attribute__((ms_abi)) lsw_ntohl(unsigned long netlong) {
    return ntohl(netlong);
}

// ws2_32.dll!inet_addr - Convert IP string to address
unsigned long __attribute__((ms_abi)) lsw_inet_addr(const char* cp) {
    if (!cp) return INADDR_NONE;
    return inet_addr(cp);
}

// ============================================================================
// END Winsock APIs
// ============================================================================

// ============================================================================
// SECTION: Registry APIs
// ============================================================================

// Windows error codes
#define ERROR_SUCCESS               0
#define ERROR_FILE_NOT_FOUND        2
#define ERROR_ACCESS_DENIED         5
#define ERROR_INVALID_HANDLE        6
#define ERROR_INVALID_PARAMETER     87

// Windows registry key handles - predefined keys
#define HKEY_CLASSES_ROOT       ((HANDLE)(uintptr_t)0x80000000)
#define HKEY_CURRENT_USER       ((HANDLE)(uintptr_t)0x80000001)
#define HKEY_LOCAL_MACHINE      ((HANDLE)(uintptr_t)0x80000002)
#define HKEY_USERS              ((HANDLE)(uintptr_t)0x80000003)
#define HKEY_CURRENT_CONFIG     ((HANDLE)(uintptr_t)0x80000005)

// Registry value types
#define REG_NONE                0
#define REG_SZ                  1
#define REG_EXPAND_SZ           2
#define REG_BINARY              3
#define REG_DWORD               4
#define REG_DWORD_BIG_ENDIAN    5
#define REG_QWORD               11

// Registry access rights
#define KEY_QUERY_VALUE         0x0001
#define KEY_SET_VALUE           0x0002
#define KEY_CREATE_SUB_KEY      0x0004
#define KEY_READ                0x20019
#define KEY_WRITE               0x20006
#define KEY_ALL_ACCESS          0xF003F

// Convert Windows HKEY to LSW hkey enum
static lsw_hkey_t win_hkey_to_lsw(HANDLE hkey) {
    uintptr_t val = (uintptr_t)hkey;
    // Handle both signed and unsigned representations
    if (val == 0x80000000 || val == 0xffffffff80000000UL) return LSW_HKEY_CLASSES_ROOT;
    if (val == 0x80000001 || val == 0xffffffff80000001UL) return LSW_HKEY_CURRENT_USER;
    if (val == 0x80000002 || val == 0xffffffff80000002UL) return LSW_HKEY_LOCAL_MACHINE;
    if (val == 0x80000003 || val == 0xffffffff80000003UL) return LSW_HKEY_USERS;
    if (val == 0x80000005 || val == 0xffffffff80000005UL) return LSW_HKEY_CURRENT_CONFIG;
    return (lsw_hkey_t)0;
}

// Convert LSW reg type to Windows reg type
static DWORD lsw_regtype_to_win(lsw_reg_type_t type) {
    switch (type) {
        case LSW_REG_NONE: return REG_NONE;
        case LSW_REG_SZ: return REG_SZ;
        case LSW_REG_BINARY: return REG_BINARY;
        case LSW_REG_DWORD: return REG_DWORD;
        case LSW_REG_QWORD: return REG_QWORD;
        default: return REG_NONE;
    }
}

// Convert Windows reg type to LSW reg type
static lsw_reg_type_t win_regtype_to_lsw(DWORD type) {
    switch (type) {
        case REG_NONE: return LSW_REG_NONE;
        case REG_SZ: return LSW_REG_SZ;
        case REG_EXPAND_SZ: return LSW_REG_SZ;  // Treat as regular string
        case REG_BINARY: return LSW_REG_BINARY;
        case REG_DWORD: return LSW_REG_DWORD;
        case REG_DWORD_BIG_ENDIAN: return LSW_REG_DWORD;
        case REG_QWORD: return LSW_REG_QWORD;
        default: return LSW_REG_NONE;
    }
}

// advapi32.dll!RegOpenKeyExA - Open registry key
LONG __attribute__((ms_abi)) lsw_RegOpenKeyExA(
    HANDLE hkey,
    const char* subkey,
    DWORD options,
    DWORD samDesired,
    HANDLE* phkResult
) {
    (void)options;
    (void)samDesired;
    
    LSW_LOG_INFO("RegOpenKeyExA: hkey=0x%p, subkey='%s'", hkey, subkey ? subkey : "(null)");
    
    if (!phkResult) {
        return ERROR_INVALID_PARAMETER;
    }
    
    // Convert Windows HKEY to LSW hkey
    lsw_hkey_t lsw_hkey = win_hkey_to_lsw(hkey);
    if (lsw_hkey == 0 && (uintptr_t)hkey >= 0x80000000) {
        LSW_LOG_ERROR("Unknown predefined key: 0x%p", hkey);
        return ERROR_INVALID_HANDLE;
    }
    
    // Open the key
    HANDLE result_handle;
    lsw_status_t status = lsw_reg_open_key(lsw_hkey, subkey, &result_handle);
    
    if (status == LSW_SUCCESS) {
        *phkResult = result_handle;
        LSW_LOG_INFO("RegOpenKeyExA: success, handle=0x%p", result_handle);
        return ERROR_SUCCESS;
    } else if (status == LSW_ERROR_FILE_NOT_FOUND) {
        LSW_LOG_DEBUG("RegOpenKeyExA: key not found");
        return ERROR_FILE_NOT_FOUND;
    } else {
        LSW_LOG_ERROR("RegOpenKeyExA: failed with status %d", status);
        return ERROR_ACCESS_DENIED;
    }
}

// advapi32.dll!RegCreateKeyExA - Create or open registry key
LONG __attribute__((ms_abi)) lsw_RegCreateKeyExA(
    HANDLE hkey,
    const char* subkey,
    DWORD reserved,
    char* class_name,
    DWORD options,
    DWORD samDesired,
    void* security_attributes,
    HANDLE* phkResult,
    DWORD* disposition
) {
    (void)reserved;
    (void)class_name;
    (void)options;
    (void)samDesired;
    (void)security_attributes;
    
    LSW_LOG_INFO("RegCreateKeyExA: hkey=0x%p, subkey='%s'", hkey, subkey ? subkey : "(null)");
    
    if (!phkResult) {
        return ERROR_INVALID_PARAMETER;
    }
    
    lsw_hkey_t lsw_hkey = win_hkey_to_lsw(hkey);
    if (lsw_hkey == 0 && (uintptr_t)hkey >= 0x80000000) {
        return ERROR_INVALID_HANDLE;
    }
    
    HANDLE result_handle;
    lsw_status_t status = lsw_reg_create_key(lsw_hkey, subkey, &result_handle);
    
    if (status == LSW_SUCCESS) {
        *phkResult = result_handle;
        if (disposition) *disposition = 1; // REG_CREATED_NEW_KEY
        LSW_LOG_INFO("RegCreateKeyExA: success, handle=0x%p", result_handle);
        return ERROR_SUCCESS;
    } else {
        LSW_LOG_ERROR("RegCreateKeyExA: failed with status %d", status);
        return ERROR_ACCESS_DENIED;
    }
}

// advapi32.dll!RegQueryValueExA - Read registry value
LONG __attribute__((ms_abi)) lsw_RegQueryValueExA(
    HANDLE hkey,
    const char* value_name,
    DWORD* reserved,
    DWORD* type,
    BYTE* data,
    DWORD* data_size
) {
    (void)reserved;
    
    LSW_LOG_INFO("RegQueryValueExA: hkey=0x%p, value='%s'", hkey, value_name ? value_name : "(null)");
    
    if (!data_size) {
        return ERROR_INVALID_PARAMETER;
    }
    
    lsw_reg_type_t lsw_type;
    size_t size = *data_size;
    
    lsw_status_t status = lsw_reg_query_value(hkey, value_name, &lsw_type, data, &size);
    
    if (status == LSW_SUCCESS) {
        *data_size = (DWORD)size;
        if (type) *type = lsw_regtype_to_win(lsw_type);
        LSW_LOG_INFO("RegQueryValueExA: success, type=%u, size=%u", *type, *data_size);
        return ERROR_SUCCESS;
    } else if (status == LSW_ERROR_FILE_NOT_FOUND) {
        LSW_LOG_DEBUG("RegQueryValueExA: value not found");
        return ERROR_FILE_NOT_FOUND;
    } else {
        LSW_LOG_ERROR("RegQueryValueExA: failed with status %d", status);
        return ERROR_ACCESS_DENIED;
    }
}

// advapi32.dll!RegSetValueExA - Write registry value
LONG __attribute__((ms_abi)) lsw_RegSetValueExA(
    HANDLE hkey,
    const char* value_name,
    DWORD reserved,
    DWORD type,
    const BYTE* data,
    DWORD data_size
) {
    (void)reserved;
    
    LSW_LOG_INFO("RegSetValueExA: hkey=0x%p, value='%s', type=%u, size=%u", 
                 hkey, value_name ? value_name : "(null)", type, data_size);
    
    if (!data) {
        return ERROR_INVALID_PARAMETER;
    }
    
    lsw_reg_type_t lsw_type = win_regtype_to_lsw(type);
    
    lsw_status_t status = lsw_reg_set_value(hkey, value_name, lsw_type, data, data_size);
    
    if (status == LSW_SUCCESS) {
        LSW_LOG_INFO("RegSetValueExA: success");
        return ERROR_SUCCESS;
    } else {
        LSW_LOG_ERROR("RegSetValueExA: failed with status %d", status);
        return ERROR_ACCESS_DENIED;
    }
}

// advapi32.dll!RegCloseKey - Close registry key
LONG __attribute__((ms_abi)) lsw_RegCloseKey(HANDLE hkey) {
    LSW_LOG_INFO("RegCloseKey: hkey=0x%p", hkey);
    
    // Don't close predefined keys
    uintptr_t val = (uintptr_t)hkey;
    if (val >= 0x80000000 && val <= 0x80000005) {
        return ERROR_SUCCESS;
    }
    
    lsw_status_t status = lsw_reg_close_key(hkey);
    
    if (status == LSW_SUCCESS) {
        return ERROR_SUCCESS;
    } else {
        return ERROR_INVALID_HANDLE;
    }
}

// ============================================================================
// END Registry APIs
// ============================================================================

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
    {"msvcrt.dll", "strcmp", (void*)lsw_strcmp},
    {"msvcrt.dll", "strncmp", (void*)lsw_strncmp},
    {"msvcrt.dll", "strstr", (void*)lsw_strstr},
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
    {"KERNEL32.dll", "WriteConsoleA", (void*)lsw_WriteConsoleA},
    {"KERNEL32.dll", "GetCommandLineA", (void*)lsw_GetCommandLineA},
    {"KERNEL32.dll", "ExitProcess", (void*)lsw_ExitProcess},
    
    // advapi32.dll - Registry APIs
    {"advapi32.dll", "RegOpenKeyExA", (void*)lsw_RegOpenKeyExA},
    {"advapi32.dll", "RegCreateKeyExA", (void*)lsw_RegCreateKeyExA},
    {"advapi32.dll", "RegQueryValueExA", (void*)lsw_RegQueryValueExA},
    {"advapi32.dll", "RegSetValueExA", (void*)lsw_RegSetValueExA},
    {"advapi32.dll", "RegCloseKey", (void*)lsw_RegCloseKey},
    
    // COMDLG32.dll - Common Dialogs
    {"COMDLG32.dll", "PrintDlgW", (void*)lsw_PrintDlgW},
    {"COMDLG32.dll", "ChooseColorW", (void*)lsw_ChooseColorW},
    
    // ws2_32.dll - Winsock APIs
    {"ws2_32.dll", "WSAStartup", (void*)lsw_WSAStartup},
    {"ws2_32.dll", "WSACleanup", (void*)lsw_WSACleanup},
    {"ws2_32.dll", "WSAGetLastError", (void*)lsw_WSAGetLastError},
    {"ws2_32.dll", "WSASetLastError", (void*)lsw_WSASetLastError},
    {"ws2_32.dll", "socket", (void*)lsw_socket},
    {"ws2_32.dll", "connect", (void*)lsw_connect},
    {"ws2_32.dll", "send", (void*)lsw_send},
    {"ws2_32.dll", "recv", (void*)lsw_recv},
    {"ws2_32.dll", "closesocket", (void*)lsw_closesocket},
    {"ws2_32.dll", "htons", (void*)lsw_htons},
    {"ws2_32.dll", "htonl", (void*)lsw_htonl},
    {"ws2_32.dll", "ntohs", (void*)lsw_ntohs},
    {"ws2_32.dll", "ntohl", (void*)lsw_ntohl},
    {"ws2_32.dll", "inet_addr", (void*)lsw_inet_addr},
    
    // KERNEL32.dll - continued
    {"KERNEL32.dll", "CreateThread", (void*)lsw_CreateThread},
    {"KERNEL32.dll", "ExitThread", (void*)lsw_ExitThread},
    {"KERNEL32.dll", "WaitForSingleObject", (void*)lsw_WaitForSingleObject},
    {"KERNEL32.dll", "WriteFile", (void*)lsw_WriteFile},
    {"KERNEL32.dll", "ReadFile", (void*)lsw_ReadFile},
    {"KERNEL32.dll", "GetFileSize", (void*)lsw_GetFileSize},
    {"KERNEL32.dll", "SetFilePointer", (void*)lsw_SetFilePointer},
    {"KERNEL32.dll", "DeleteFileA", (void*)lsw_DeleteFileA},
    {"KERNEL32.dll", "CreateFileW", (void*)lsw_CreateFileW},
    {"KERNEL32.dll", "DeleteFileW", (void*)lsw_DeleteFileW},
    {"KERNEL32.dll", "CopyFileW", (void*)lsw_CopyFileW},
    {"KERNEL32.dll", "CreateDirectoryW", (void*)lsw_CreateDirectoryW},
    {"KERNEL32.dll", "RemoveDirectoryW", (void*)lsw_RemoveDirectoryW},
    {"KERNEL32.dll", "GetFileAttributesW", (void*)lsw_GetFileAttributesW},
    {"KERNEL32.dll", "SetFileAttributesW", (void*)lsw_SetFileAttributesW},
    {"KERNEL32.dll", "GetWindowsDirectoryA", (void*)lsw_GetWindowsDirectoryA},
    {"KERNEL32.dll", "GetWindowsDirectoryW", (void*)lsw_GetWindowsDirectoryW},
    {"KERNEL32.dll", "GetSystemDirectoryA", (void*)lsw_GetSystemDirectoryA},
    {"KERNEL32.dll", "GetSystemDirectoryW", (void*)lsw_GetSystemDirectoryW},
    {"KERNEL32.dll", "GetTempPathA", (void*)lsw_GetTempPathA},
    {"KERNEL32.dll", "GetTempPathW", (void*)lsw_GetTempPathW},
    {"KERNEL32.dll", "GetEnvironmentVariableA", (void*)lsw_GetEnvironmentVariableA},
    {"KERNEL32.dll", "GetEnvironmentVariableW", (void*)lsw_GetEnvironmentVariableW},
    {"KERNEL32.dll", "SetEnvironmentVariableA", (void*)lsw_SetEnvironmentVariableA},
    {"KERNEL32.dll", "SetEnvironmentVariableW", (void*)lsw_SetEnvironmentVariableW},
    {"KERNEL32.dll", "ExpandEnvironmentStringsA", (void*)lsw_ExpandEnvironmentStringsA},
    {"KERNEL32.dll", "ExpandEnvironmentStringsW", (void*)lsw_ExpandEnvironmentStringsW},
    {"KERNEL32.dll", "FindFirstFileW", (void*)lsw_FindFirstFileW},
    {"KERNEL32.dll", "FindNextFileW", (void*)lsw_FindNextFileW},
    {"KERNEL32.dll", "FindClose", (void*)lsw_FindClose},
    {"KERNEL32.dll", "FindFirstFileExW", (void*)lsw_FindFirstFileExW},
    {"KERNEL32.dll", "GetProcessHeap", (void*)lsw_GetProcessHeap},
    {"KERNEL32.dll", "HeapAlloc", (void*)lsw_HeapAlloc},
    {"KERNEL32.dll", "HeapFree", (void*)lsw_HeapFree},
    {"KERNEL32.dll", "HeapReAlloc", (void*)lsw_HeapReAlloc},
    {"KERNEL32.dll", "HeapSize", (void*)lsw_HeapSize},
    {"KERNEL32.dll", "LocalAlloc", (void*)lsw_LocalAlloc},
    {"KERNEL32.dll", "LocalFree", (void*)lsw_LocalFree},
    {"KERNEL32.dll", "GlobalAlloc", (void*)lsw_GlobalAlloc},
    {"KERNEL32.dll", "GlobalFree", (void*)lsw_GlobalFree},
    {"KERNEL32.dll", "GlobalLock", (void*)lsw_GlobalLock},
    {"KERNEL32.dll", "GlobalUnlock", (void*)lsw_GlobalUnlock},
    {"KERNEL32.dll", "GlobalSize", (void*)lsw_GlobalSize},
    {"KERNEL32.dll", "LoadLibraryA", (void*)lsw_LoadLibraryA},
    {"KERNEL32.dll", "GetProcAddress", (void*)lsw_GetProcAddress},
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
