/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * Win32 API - Function mapping implementation
 */

#define _GNU_SOURCE  /* strdup, wcsdup, readlink, symlink, ftruncate */

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
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sched.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/un.h>      /* Unix domain sockets for named pipes */
#include <malloc.h>      /* malloc_usable_size */
#include <semaphore.h>   /* sem_t — for CreateSemaphore */
#include <sys/timerfd.h> /* timerfd_create — for waitable timers */
#include <poll.h>        /* poll — for IOCP wait */
#include <setjmp.h>      /* longjmp — for C++ exception delivery */

// ioctl command  
#define LSW_IOCTL_MAGIC 'L'
#define LSW_IOCTL_SYSCALL _IOWR(LSW_IOCTL_MAGIC, 5, struct lsw_syscall_request)

/* Forward declarations */
static void createprocess_win_to_linux(const char* wpath, char* out, size_t outsz);

/* ---- PE module handle ---- */
#define LSW_PE_HMODULE_MAGIC 0x5045484DU  /* "PEHM" */
struct lsw_pe_hmodule_s {
    uint32_t magic;
    char dll_name[128];
    void*  image_base;
    size_t image_size;
    void*  export_dir;
    uint32_t export_dir_size;
};
typedef struct lsw_pe_hmodule_s lsw_pe_hmodule_t;

/* ---- Named pipe handle ---- */
#define LSW_PIPE_MAGIC 0x50495045U  /* "PIPE" */
struct lsw_pipe_s {
    uint32_t magic;
    int listen_fd;
    int client_fd;
    char path[128];
};
typedef struct lsw_pipe_s lsw_pipe_t;

/* ---- Synchronization handle types ---- */
#define LSW_EVENT_MAGIC   0x45564E54U  /* "EVNT" */
#define LSW_MUTEX_MAGIC   0x4D555458U  /* "MUTX" */
#define LSW_SEMA_MAGIC    0x53454D41U  /* "SEMA" */
#define LSW_TIMER_MAGIC   0x54494D52U  /* "TIMR" */
#define LSW_IOCP_MAGIC    0x494F4350U  /* "IOCP" */
#define LSW_TPWORK_MAGIC  0x54505744U  /* "TPWD" */

typedef struct {
    uint32_t magic;       /* LSW_EVENT_MAGIC */
    int manual_reset;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    volatile int signaled;
} lsw_event_t;

typedef struct {
    uint32_t magic;       /* LSW_MUTEX_MAGIC */
    pthread_mutex_t mutex;
    volatile pthread_t owner;
    volatile int owned;
} lsw_mutex_t;

typedef struct {
    uint32_t magic;       /* LSW_SEMA_MAGIC */
    sem_t    sem;
    long     max_count;
} lsw_semaphore_t;

typedef struct {
    uint32_t magic;       /* LSW_TIMER_MAGIC */
    int      timerfd;
    int32_t  period_ms;
    int      manual_reset;
} lsw_timer_t;

typedef struct lsw_completion_s {
    uint32_t   error;
    uint32_t   bytes;
    uintptr_t  key;
    void      *overlapped;
    struct lsw_completion_s *next;
} lsw_completion_t;

typedef struct {
    uint32_t          magic;      /* LSW_IOCP_MAGIC */
    int               wakefd[2];  /* pipe: [0]=read [1]=write */
    pthread_mutex_t   lock;
    lsw_completion_t *head;
    lsw_completion_t *tail;
} lsw_iocp_t;

typedef void (__attribute__((ms_abi)) *lsw_tp_callback_fn)(void*,void*,void*);
typedef struct {
    uint32_t          magic;      /* LSW_TPWORK_MAGIC */
    lsw_tp_callback_fn callback;
    void             *context;
} lsw_tp_work_t;

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

// WIN32_FIND_DATAW structure — must match Windows memory layout exactly.
// On Windows: wchar_t = 2 bytes, FILETIME = two DWORDs at 4-byte alignment.
// On Linux:   wchar_t = 4 bytes, uint64_t has 8-byte alignment padding.
// We use uint32_t pairs for FILETIME and uint16_t for WCHAR arrays so the
// struct is 592 bytes on both platforms, matching what a Windows-compiled PE
// expects on its stack.
typedef struct {
    uint32_t dwFileAttributes;      // offset   0
    uint32_t ftCreationTimeLow;     // offset   4
    uint32_t ftCreationTimeHigh;    // offset   8
    uint32_t ftLastAccessTimeLow;   // offset  12
    uint32_t ftLastAccessTimeHigh;  // offset  16
    uint32_t ftLastWriteTimeLow;    // offset  20
    uint32_t ftLastWriteTimeHigh;   // offset  24
    uint32_t nFileSizeHigh;         // offset  28
    uint32_t nFileSizeLow;          // offset  32
    uint32_t dwReserved0;           // offset  36
    uint32_t dwReserved1;           // offset  40
    uint16_t cFileName[260];        // offset  44 (520 bytes)
    uint16_t cAlternateFileName[14];// offset 564 (28 bytes)
} WIN32_FIND_DATAW;                 // total: 592 bytes
_Static_assert(sizeof(WIN32_FIND_DATAW) == 592,
               "WIN32_FIND_DATAW must be exactly 592 bytes — layout mismatch!");

// Global kernel fd for syscalls
static int g_kernel_fd = -1;

// Thread-local last Win32 error code (set by SetLastError, read by GetLastError)
static __thread DWORD g_last_error = 0;

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

void* __attribute__((ms_abi)) lsw_realloc(void* ptr, size_t size) {
    return realloc(ptr, size);
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

// Wide-char versions (stubs - convert to narrow and use regular fprintf)
int __attribute__((ms_abi)) lsw_fwprintf(FILE* stream, const wchar_t* format, ...) {
    // Stub: For now, just return success
    // TODO: Properly convert wide-char format string and args
    (void)stream;
    (void)format;
    return 0;
}

int __attribute__((ms_abi)) lsw_fputwc(wchar_t wc, FILE* stream) {
    // Stub: Convert wide char to multibyte and output
    char mb[4];
    if (wc < 0x80) {
        mb[0] = (char)wc;
        mb[1] = '\0';
        return fputc(mb[0], stream);
    }
    // For non-ASCII, just output '?'
    return fputc('?', stream);
}

int __attribute__((ms_abi)) lsw_fflush(FILE* stream) {
    // Handle NULL (flush all streams)
    if (!stream) {
        return fflush(NULL);
    }
    
    // Define the fake FILE structure (same as in vfprintf)
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
    
    // Check if it's one of our fake stdio FILE structures
    if (fake && fake->_file >= 0 && fake->_file <= 2) {
        // For stdout/stderr/stdin fake structures, just return success
        // Don't call real fflush as it will crash with fake FILE*
        return 0;
    }
    
    // Otherwise call real fflush
    return fflush(stream);
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
    LSW_LOG_DEBUG("GetLastError() -> %u", g_last_error);
    return g_last_error;
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
    if (handle == INVALID_HANDLE_VALUE || !handle) return 0;

    uint32_t magic = *(const uint32_t*)handle;

    /* Named pipe handle */
    if (magic == LSW_PIPE_MAGIC) {
        lsw_pipe_t* pp = (lsw_pipe_t*)handle;
        if (pp->client_fd >= 0) { close(pp->client_fd); pp->client_fd = -1; }
        if (pp->listen_fd >= 0) { close(pp->listen_fd); unlink(pp->path); pp->listen_fd = -1; }
        pp->magic = 0;
        free(pp);
        return 1;
    }

    /* PE module handle */
    if (magic == LSW_PE_HMODULE_MAGIC) {
        lsw_pe_hmodule_t* pem = (lsw_pe_hmodule_t*)handle;
        if (pem->image_base) munmap(pem->image_base, pem->image_size);
        pem->magic = 0;
        return 1;
    }

    /* Event handle */
    if (magic == LSW_EVENT_MAGIC) {
        lsw_event_t* ev = (lsw_event_t*)handle;
        pthread_mutex_destroy(&ev->lock);
        pthread_cond_destroy(&ev->cond);
        ev->magic = 0;
        free(ev);
        return 1;
    }

    /* Mutex handle */
    if (magic == LSW_MUTEX_MAGIC) {
        lsw_mutex_t* m = (lsw_mutex_t*)handle;
        pthread_mutex_destroy(&m->mutex);
        m->magic = 0;
        free(m);
        return 1;
    }

    /* Semaphore handle */
    if (magic == LSW_SEMA_MAGIC) {
        lsw_semaphore_t* s = (lsw_semaphore_t*)handle;
        sem_destroy(&s->sem);
        s->magic = 0;
        free(s);
        return 1;
    }

    /* Waitable timer handle */
    if (magic == LSW_TIMER_MAGIC) {
        lsw_timer_t* t = (lsw_timer_t*)handle;
        if (t->timerfd >= 0) close(t->timerfd);
        t->magic = 0;
        free(t);
        return 1;
    }

    /* IOCP handle */
    if (magic == LSW_IOCP_MAGIC) {
        lsw_iocp_t* io = (lsw_iocp_t*)handle;
        close(io->wakefd[0]); close(io->wakefd[1]);
        pthread_mutex_destroy(&io->lock);
        lsw_completion_t* c = io->head;
        while (c) { lsw_completion_t* n = c->next; free(c); c = n; }
        io->magic = 0;
        free(io);
        return 1;
    }

    /* Raw file descriptor */
    intptr_t fd = (intptr_t)handle;
    if (fd >= 0 && fd < 1024) {
        close((int)fd);
        return 1;
    }

    LSW_LOG_INFO("CloseHandle: handle=%p (non-fd)", handle);
    return 1;
}

// Synchronization functions
void* __attribute__((ms_abi)) lsw_CreateEventA(void* security, int manual_reset, int initial_state, const char* name) {
    (void)security; (void)name;
    lsw_event_t* ev = calloc(1, sizeof(lsw_event_t));
    ev->magic = LSW_EVENT_MAGIC;
    ev->manual_reset = manual_reset;
    pthread_mutex_init(&ev->lock, NULL);
    pthread_cond_init(&ev->cond, NULL);
    ev->signaled = initial_state ? 1 : 0;
    LSW_LOG_INFO("CreateEventA: name=%s -> %p", name ? name : "(null)", ev);
    return ev;
}

int __attribute__((ms_abi)) lsw_SetEvent(void* handle) {
    lsw_event_t* ev = handle;
    if (!ev) return 0;
    if (ev->magic == LSW_EVENT_MAGIC) {
        pthread_mutex_lock(&ev->lock);
        ev->signaled = 1;
        if (ev->manual_reset) pthread_cond_broadcast(&ev->cond);
        else                  pthread_cond_signal(&ev->cond);
        pthread_mutex_unlock(&ev->lock);
        return 1;
    }
    LSW_LOG_INFO("SetEvent: handle=%p (unknown type)", handle);
    return 1; /* best effort */
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
    (void)overlapped;
    
    if (!handle || !buffer) { if (bytes_written) *bytes_written = 0; return 0; }

    /* Named pipe handle — write to Unix domain socket fd */
    {
        lsw_pipe_t* pp = (lsw_pipe_t*)handle;
        if (pp->magic == LSW_PIPE_MAGIC) {
            int pfd = pp->client_fd >= 0 ? pp->client_fd : -1;
            if (pfd < 0) { if (bytes_written) *bytes_written = 0; return 0; }
            ssize_t r = write(pfd, buffer, bytes_to_write);
            if (bytes_written) *bytes_written = r < 0 ? 0 : (uint32_t)r;
            return r >= 0 ? 1 : 0;
        }
    }

    LSW_LOG_INFO("WriteFile called: handle=%p, buffer=%p, bytes=%u", handle, buffer, bytes_to_write);
    LSW_LOG_INFO("  Buffer content (first 32 bytes): %.32s", buffer ? (const char*)buffer : "(null)");
    LSW_LOG_INFO("  bytes_written ptr: %p", bytes_written);
    
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
    (void)overlapped;
    
    if (!handle || !buffer) { if (bytes_read) *bytes_read = 0; return 0; }

    /* Named pipe handle — read from Unix domain socket fd */
    {
        lsw_pipe_t* pp = (lsw_pipe_t*)handle;
        if (pp->magic == LSW_PIPE_MAGIC) {
            int pfd = pp->client_fd >= 0 ? pp->client_fd : -1;
            if (pfd < 0) { if (bytes_read) *bytes_read = 0; return 0; }
            ssize_t r = read(pfd, buffer, bytes_to_read);
            if (bytes_read) *bytes_read = r < 0 ? 0 : (uint32_t)r;
            return r >= 0 ? 1 : 0;
        }
    }

    LSW_LOG_INFO("ReadFile called: handle=%p, buffer=%p, bytes=%u", handle, buffer, bytes_to_read);
    
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

// Helper: convert UTF-8 string to UTF-16LE into a uint16_t buffer.
// Handles BMP characters (U+0000..U+FFFF) including basic multi-byte UTF-8.
// Returns the number of uint16_t code units written (excluding null terminator).
static int utf8_to_utf16le(const char* src, uint16_t* dst, int dst_capacity) {
    int out = 0;
    unsigned char* s = (unsigned char*)src;
    while (*s && out < dst_capacity - 1) {
        uint32_t cp;
        if (*s < 0x80) {
            cp = *s++;
        } else if ((*s & 0xE0) == 0xC0) {
            cp = (*s++ & 0x1F) << 6;
            cp |= (*s++ & 0x3F);
        } else if ((*s & 0xF0) == 0xE0) {
            cp = (*s++ & 0x0F) << 12;
            cp |= (*s++ & 0x3F) << 6;
            cp |= (*s++ & 0x3F);
        } else {
            // Skip 4-byte (surrogate pair needed) — emit replacement char
            s += 4;
            cp = 0xFFFD;
        }
        dst[out++] = (uint16_t)cp;
    }
    dst[out] = 0;
    return out;
}

// Helper: Convert Linux dirent to WIN32_FIND_DATAW
static void dirent_to_find_data(struct dirent* entry, const char* dir_path, WIN32_FIND_DATAW* find_data) {
    memset(find_data, 0, sizeof(WIN32_FIND_DATAW));
    
    // Convert filename to UTF-16LE (uint16_t, matching Windows WCHAR)
    utf8_to_utf16le(entry->d_name, find_data->cFileName,
                    (int)(sizeof(find_data->cFileName) / sizeof(find_data->cFileName[0])));
    
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
    if (!handle) return 0xFFFFFFFF; /* WAIT_FAILED */

    /* ---- Typed handle dispatch ---- */
    uint32_t magic = *(const uint32_t*)handle;

    if (magic == LSW_EVENT_MAGIC) {
        lsw_event_t* ev = handle;
        pthread_mutex_lock(&ev->lock);
        if (milliseconds == 0xFFFFFFFF) {
            while (!ev->signaled)
                pthread_cond_wait(&ev->cond, &ev->lock);
        } else if (milliseconds == 0) {
            if (!ev->signaled) {
                pthread_mutex_unlock(&ev->lock);
                return 0x00000102; /* WAIT_TIMEOUT */
            }
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += milliseconds / 1000;
            ts.tv_nsec += (milliseconds % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            while (!ev->signaled) {
                if (pthread_cond_timedwait(&ev->cond, &ev->lock, &ts) != 0)
                    break;
            }
            if (!ev->signaled) {
                pthread_mutex_unlock(&ev->lock);
                return 0x00000102;
            }
        }
        if (!ev->manual_reset) ev->signaled = 0; /* auto-reset */
        pthread_mutex_unlock(&ev->lock);
        return 0; /* WAIT_OBJECT_0 */
    }

    if (magic == LSW_MUTEX_MAGIC) {
        lsw_mutex_t* m = handle;
        int r;
        if (milliseconds == 0xFFFFFFFF) {
            r = pthread_mutex_lock(&m->mutex);
        } else if (milliseconds == 0) {
            r = pthread_mutex_trylock(&m->mutex);
            if (r != 0) return 0x00000102;
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += milliseconds / 1000;
            ts.tv_nsec += (milliseconds % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            r = pthread_mutex_timedlock(&m->mutex, &ts);
            if (r != 0) return 0x00000102;
        }
        if (r == 0) { m->owner = pthread_self(); m->owned = 1; }
        return (r == 0) ? 0 : 0xFFFFFFFF;
    }

    if (magic == LSW_SEMA_MAGIC) {
        lsw_semaphore_t* s = handle;
        if (milliseconds == 0xFFFFFFFF) {
            return (sem_wait(&s->sem) == 0) ? 0 : 0xFFFFFFFF;
        } else if (milliseconds == 0) {
            return (sem_trywait(&s->sem) == 0) ? 0 : 0x00000102;
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += milliseconds / 1000;
            ts.tv_nsec += (milliseconds % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            return (sem_timedwait(&s->sem, &ts) == 0) ? 0 : 0x00000102;
        }
    }

    if (magic == LSW_TIMER_MAGIC) {
        lsw_timer_t* t = handle;
        if (t->timerfd < 0) return 0xFFFFFFFF;
        struct pollfd pfd = { .fd = t->timerfd, .events = POLLIN };
        int r = poll(&pfd, 1, (milliseconds == 0xFFFFFFFF) ? -1 : (int)milliseconds);
        if (r > 0) {
            uint64_t expirations;
            read(t->timerfd, &expirations, sizeof(expirations));
            return 0;
        }
        return (r == 0) ? 0x00000102 : 0xFFFFFFFF;
    }

    /* ---- Process handle (PID) ---- */
    pid_t pid = (pid_t)(uintptr_t)handle;
    if (pid > 1 && pid < 65536) {
        int wstatus = 0;
        if (milliseconds == 0xFFFFFFFF) {
            pid_t r = waitpid(pid, &wstatus, 0);
            if (r == pid) return 0;
        } else if (milliseconds == 0) {
            pid_t r = waitpid(pid, &wstatus, WNOHANG);
            if (r == pid) return 0;
            return 0x00000102;
        } else {
            uint32_t waited = 0, step = 5;
            while (waited < milliseconds) {
                pid_t r = waitpid(pid, &wstatus, WNOHANG);
                if (r == pid) return 0;
                usleep(step * 1000);
                waited += step;
                if (step < 100) step *= 2;
            }
            return 0x00000102;
        }
    }

    /* ---- Kernel path ---- */
    if (g_kernel_fd >= 0) {
        struct lsw_syscall_request req;
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtWaitForSingleObject;
        req.arg_count = 3;
        req.args[0] = (uint64_t)(uintptr_t)handle;
        req.args[1] = 0;
        req.args[2] = milliseconds;
        if (ioctl(g_kernel_fd, LSW_IOCTL_SYSCALL, &req) == 0)
            return (uint32_t)req.return_value;
    }

    /* Fallback sleep */
    LSW_LOG_WARN("WaitForSingleObject(%p, %u): unknown handle type, fallback sleep", handle, milliseconds);
    if (milliseconds != 0xFFFFFFFF)
        usleep(milliseconds * 1000UL);
    return 0;
}

/*
 * PE DLL handle table — maps "fake" HMODULE handles to PE images loaded via
 * the DLL chain loader.  Allows GetProcAddress to look up exported symbols.
 */
/* LSW_PE_HMODULE_MAGIC and lsw_pe_hmodule_t defined at top of file */

static lsw_pe_hmodule_t  g_pe_modules[64];
static int               g_pe_module_count = 0;
static pthread_mutex_t   g_pe_module_lock = PTHREAD_MUTEX_INITIALIZER;

/* Return symbol address from a PE export directory */
static void* pe_hmodule_get_proc(lsw_pe_hmodule_t* mod, const char* name) {
    if (!mod->export_dir || !name) return NULL;
    uint8_t* base = (uint8_t*)mod->image_base;
    /* IMAGE_EXPORT_DIRECTORY offsets */
    uint32_t* expdir = (uint32_t*)mod->export_dir;
    uint32_t num_names = expdir[6];     /* NumberOfNames */
    uint32_t names_rva = expdir[8];     /* AddressOfNames */
    uint32_t ords_rva  = expdir[9];     /* AddressOfNameOrdinals */
    uint32_t funcs_rva = expdir[7];     /* AddressOfFunctions */
    uint32_t* names = (uint32_t*)(base + names_rva);
    uint16_t* ords  = (uint16_t*)(base + ords_rva);
    uint32_t* funcs = (uint32_t*)(base + funcs_rva);
    for (uint32_t i = 0; i < num_names; i++) {
        const char* ename = (const char*)(base + names[i]);
        if (strcmp(ename, name) == 0) {
            uint32_t fn_rva = funcs[ords[i]];
            return (void*)(base + fn_rva);
        }
    }
    return NULL;
}

/* Known Win32 system DLL names — return fake handle, GetProcAddress routes to stubs */
static int is_system_dll(const char* name) {
    static const char* system_dlls[] = {
        "kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll",
        "ntdll.dll","advapi32.dll","shell32.dll","shlwapi.dll",
        "ole32.dll","oleaut32.dll","comctl32.dll","msvcrt.dll",
        "ucrtbase.dll","ws2_32.dll","ws2_32","msvcp140.dll",
        "vcruntime140.dll","vcruntime140_1.dll","msvcp_win.dll",
        NULL
    };
    char lower[128]; size_t n = strlen(name);
    if (n >= sizeof(lower)) n = sizeof(lower)-1;
    for (size_t i = 0; i < n; i++) lower[i] = (char)tolower((unsigned char)name[i]);
    lower[n] = '\0';
    for (int i = 0; system_dlls[i]; i++)
        if (strcmp(lower, system_dlls[i]) == 0) return 1;
    return 0;
}

#define LSW_SYSTEM_HMODULE ((void*)0xDEADBEEF)

void* __attribute__((ms_abi)) lsw_LoadLibraryA(const char* filename)
{
    LSW_LOG_INFO("LoadLibraryA called: %s", filename ? filename : "(null)");
    
    if (!filename) {
        LSW_LOG_ERROR("LoadLibraryA: null filename");
        return NULL;
    }
    
    /* Get just the basename for system-DLL check */
    const char* base = strrchr(filename, '\\');
    if (!base) base = strrchr(filename, '/');
    base = base ? base + 1 : filename;

    /* System DLLs provided by LSW itself */
    if (is_system_dll(base)) {
        LSW_LOG_INFO("LoadLibraryA: system DLL %s -> fake handle", base);
        return LSW_SYSTEM_HMODULE;
    }
    
    /* If it's a .dll file, try to load it as a PE via the DLL chain loader */
    const char* ext = strrchr(base, '.');
    if (ext && strcasecmp(ext, ".dll") == 0) {
        /* Search for the file on disk using the chain loader search paths */
        static const char* search_dirs[] = {
            NULL, /* filled from LSW_SYSTEM32 */
            "~/.lsw/system32",
            "~/.wine/drive_c/windows/system32",
            "/opt/lsw/system32",
            "/usr/share/lsw/system32",
            NULL
        };
        const char* env_s32 = getenv("LSW_SYSTEM32");
        search_dirs[0] = env_s32; /* may be NULL — skip */

        char found[512] = {0};
        /* First check if it's an absolute/relative path that exists directly */
        {
            char try[512];
            createprocess_win_to_linux(filename, try, sizeof(try));
            if (access(try, R_OK) == 0) strncpy(found, try, sizeof(found)-1);
        }
        if (!found[0]) {
            char lower_base[128];
            strncpy(lower_base, base, sizeof(lower_base)-1); lower_base[sizeof(lower_base)-1]='\0';
            for (char* p = lower_base; *p; p++) *p = (char)tolower((unsigned char)*p);

            for (int di = 0; search_dirs[di] && !found[0]; di++) {
                const char* dir = search_dirs[di];
                if (!dir) continue;
                /* Expand ~ */
                char full_dir[512];
                if (dir[0] == '~') {
                    const char* home = getenv("HOME"); if (!home) home = "/root";
                    snprintf(full_dir, sizeof(full_dir), "%s%s", home, dir + 1);
                    dir = full_dir;
                }
                char try1[512], try2[512];
                snprintf(try1, sizeof(try1), "%s/%s", dir, base);
                snprintf(try2, sizeof(try2), "%s/%s", dir, lower_base);
                if (access(try1, R_OK) == 0) strncpy(found, try1, sizeof(found)-1);
                else if (access(try2, R_OK) == 0) strncpy(found, try2, sizeof(found)-1);
            }
        }

        if (found[0]) {
            LSW_LOG_INFO("LoadLibraryA: loading PE DLL %s from %s", base, found);
            /* mmap + parse PE export directory */
            int fd = open(found, O_RDONLY);
            if (fd >= 0) {
                struct stat st; fstat(fd, &st);
                void* file_data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                close(fd);
                if (file_data != MAP_FAILED) {
                    /* Quick PE validity check */
                    uint8_t* fd8 = (uint8_t*)file_data;
                    if (fd8[0] == 'M' && fd8[1] == 'Z') {
                        uint32_t pe_off = *(uint32_t*)(fd8 + 0x3C);
                        if (pe_off + 4 < (uint32_t)st.st_size &&
                            fd8[pe_off]=='P' && fd8[pe_off+1]=='E') {
                            /* Allocate executable copy */
                            void* image = mmap(NULL, (size_t)st.st_size,
                                PROT_READ|PROT_WRITE|PROT_EXEC,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                            if (image != MAP_FAILED) {
                                memcpy(image, file_data, (size_t)st.st_size);
                                munmap(file_data, (size_t)st.st_size);
                                /* Locate export directory */
                                uint8_t* b = (uint8_t*)image;
                                uint32_t pe_off2 = *(uint32_t*)(b + 0x3C);
                                uint32_t export_rva = *(uint32_t*)(b + pe_off2 + 24 + 112); /* OptHdr+DataDir[0].VirtualAddress */
                                uint32_t export_sz  = *(uint32_t*)(b + pe_off2 + 24 + 116);
                                pthread_mutex_lock(&g_pe_module_lock);
                                int slot = g_pe_module_count < 64 ? g_pe_module_count++ : -1;
                                pthread_mutex_unlock(&g_pe_module_lock);
                                if (slot >= 0) {
                                    lsw_pe_hmodule_t* mod = &g_pe_modules[slot];
                                    mod->magic = LSW_PE_HMODULE_MAGIC;
                                    strncpy(mod->dll_name, base, sizeof(mod->dll_name)-1);
                                    mod->image_base = image;
                                    mod->image_size = (size_t)st.st_size;
                                    mod->export_dir = export_rva ? (b + export_rva) : NULL;
                                    mod->export_dir_size = export_sz;
                                    LSW_LOG_INFO("LoadLibraryA: PE DLL loaded -> slot %d, base %p", slot, image);
                                    return (void*)mod;
                                }
                            } else {
                                munmap(file_data, (size_t)st.st_size);
                            }
                        }
                    }
                    munmap(file_data, (size_t)st.st_size);
                }
            }
        }
        /* Fall through: no .dll found on disk, warn and return fake handle */
        LSW_LOG_WARN("LoadLibraryA: %s not found on disk — returning system handle", base);
        return LSW_SYSTEM_HMODULE;
    }

    /* Non-DLL: try dlopen as a Linux shared library */
    LSW_LOG_INFO("LoadLibraryA: attempting dlopen for %s", filename);
    void* handle = dlopen(filename, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        /* Try libfoo.so conversion */
        char so_name[512];
        char dll_name[256]; strncpy(dll_name, base, sizeof(dll_name)-1);
        char* dot = strrchr(dll_name, '.'); if (dot) *dot = '\0';
        snprintf(so_name, sizeof(so_name), "lib%s.so", dll_name);
        handle = dlopen(so_name, RTLD_NOW | RTLD_LOCAL);
    }
    if (!handle) {
        LSW_LOG_ERROR("LoadLibraryA: dlopen failed: %s", dlerror());
        return NULL;
    }
    LSW_LOG_INFO("LoadLibraryA: dlopen succeeded -> %p", handle);
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

    /* PE module handle? */
    lsw_pe_hmodule_t* pem = (lsw_pe_hmodule_t*)module;
    if (pem->magic == LSW_PE_HMODULE_MAGIC) {
        /* First check our Win32 stub tables (highest priority) */
        void* addr = win32_api_resolve(pem->dll_name, proc_name);
        if (!addr) addr = pe_hmodule_get_proc(pem, proc_name);
        if (addr) { LSW_LOG_INFO("GetProcAddress: PE %s!%s -> %p", pem->dll_name, proc_name, addr); }
        else { LSW_LOG_WARN("GetProcAddress: PE %s!%s not found", pem->dll_name, proc_name); }
        return addr;
    }

    /* System fake handle — resolve from our Win32 stubs */
    if (module == LSW_SYSTEM_HMODULE) {
        void* addr = win32_api_resolve_any(proc_name);
        if (addr) { LSW_LOG_INFO("GetProcAddress: system stub %s -> %p", proc_name, addr); return addr; }
        LSW_LOG_WARN("GetProcAddress: system stub %s not found", proc_name);
        return NULL;
    }
    
    /* Real dlopen handle */
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
LONG __attribute__((ms_abi)) lsw_legacy_RegOpenKeyExA(
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
LONG __attribute__((ms_abi)) lsw_legacy_RegCreateKeyExA(
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
LONG __attribute__((ms_abi)) lsw_legacy_RegQueryValueExA(
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
LONG __attribute__((ms_abi)) lsw_legacy_RegSetValueExA(
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
LONG __attribute__((ms_abi)) lsw_legacy_RegCloseKey(HANDLE hkey) {
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

// ============================================================================
// SECTION: Missing high-priority KERNEL32 APIs
// ============================================================================

// KERNEL32.dll!SetLastError
void __attribute__((ms_abi)) lsw_SetLastError(DWORD code) {
    g_last_error = code;
    LSW_LOG_DEBUG("SetLastError(%u)", code);
}

// KERNEL32.dll!GetTickCount - milliseconds since boot (wraps at ~49.7 days)
uint32_t __attribute__((ms_abi)) lsw_GetTickCount(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t ms = (uint32_t)(tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL);
    LSW_LOG_DEBUG("GetTickCount() -> %u", ms);
    return ms;
}

// KERNEL32.dll!GetTickCount64
uint64_t __attribute__((ms_abi)) lsw_GetTickCount64(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
    LSW_LOG_DEBUG("GetTickCount64() -> %llu", (unsigned long long)ms);
    return ms;
}

// SYSTEM_INFO structure (Windows layout)
typedef struct {
    union {
        uint32_t dwOemId;
        struct {
            uint16_t wProcessorArchitecture;
            uint16_t wReserved;
        };
    };
    uint32_t dwPageSize;
    void*    lpMinimumApplicationAddress;
    void*    lpMaximumApplicationAddress;
    uintptr_t dwActiveProcessorMask;
    uint32_t dwNumberOfProcessors;
    uint32_t dwProcessorType;
    uint32_t dwAllocationGranularity;
    uint16_t wProcessorLevel;
    uint16_t wProcessorRevision;
} SYSTEM_INFO_WIN;

// KERNEL32.dll!GetSystemInfo
void __attribute__((ms_abi)) lsw_GetSystemInfo(SYSTEM_INFO_WIN* info) {
    LSW_LOG_INFO("GetSystemInfo called");
    if (!info) return;
    memset(info, 0, sizeof(*info));
    info->wProcessorArchitecture = 9;  // PROCESSOR_ARCHITECTURE_AMD64
    info->dwPageSize = (uint32_t)sysconf(_SC_PAGESIZE);
    info->lpMinimumApplicationAddress = (void*)0x10000;
    info->lpMaximumApplicationAddress = (void*)0x7FFFFFFEFFFF;
    info->dwNumberOfProcessors = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
    info->dwProcessorType = 8664;      // PROCESSOR_AMD_X8664
    info->dwAllocationGranularity = 65536;
}

// OSVERSIONINFOEXW structure (Windows layout, Unicode)
typedef struct {
    uint32_t dwOSVersionInfoSize;
    uint32_t dwMajorVersion;
    uint32_t dwMinorVersion;
    uint32_t dwBuildNumber;
    uint32_t dwPlatformId;
    uint16_t szCSDVersion[128];
    uint16_t wServicePackMajor;
    uint16_t wServicePackMinor;
    uint16_t wSuiteMask;
    uint8_t  wProductType;
    uint8_t  wReserved;
} OSVERSIONINFOEXW_WIN;

// KERNEL32.dll!GetVersionExW
int __attribute__((ms_abi)) lsw_GetVersionExW(OSVERSIONINFOEXW_WIN* info) {
    LSW_LOG_INFO("GetVersionExW called");
    if (!info || info->dwOSVersionInfoSize < 148) return 0;  // FALSE
    info->dwMajorVersion = 10;
    info->dwMinorVersion = 0;
    info->dwBuildNumber  = 19041;    // Windows 10 2004
    info->dwPlatformId   = 2;        // VER_PLATFORM_WIN32_NT
    return 1;  // TRUE
}

// KERNEL32.dll!IsDebuggerPresent
int __attribute__((ms_abi)) lsw_IsDebuggerPresent(void) {
    LSW_LOG_DEBUG("IsDebuggerPresent() -> FALSE");
    return 0;  // FALSE
}

// KERNEL32.dll!DecodePointer — no-op on non-encoded pointers
void* __attribute__((ms_abi)) lsw_DecodePointer(void* ptr) {
    return ptr;
}

// KERNEL32.dll!EncodePointer — no-op
void* __attribute__((ms_abi)) lsw_EncodePointer(void* ptr) {
    return ptr;
}

// KERNEL32.dll!FormatMessageA — minimal stub returning empty string
// KERNEL32.dll!FormatMessageA — translate system error codes via strerror
uint32_t __attribute__((ms_abi)) lsw_FormatMessageA(
    uint32_t flags, const void* source, uint32_t message_id,
    uint32_t language_id, char* buffer, uint32_t size, void* args)
{
    (void)source; (void)language_id; (void)args;
    if (!buffer || size == 0) return 0;
    if (flags & 0x1000) { /* FORMAT_MESSAGE_FROM_SYSTEM */
        const char* msg = strerror((int)message_id);
        if (!msg) snprintf(buffer, size, "Error %u (0x%x)", message_id, message_id);
        else       snprintf(buffer, size, "%s", msg);
    } else {
        snprintf(buffer, size, "Error 0x%x", message_id);
    }
    return (uint32_t)strlen(buffer);
}

// KERNEL32.dll!FormatMessageW
uint32_t __attribute__((ms_abi)) lsw_FormatMessageW(
    uint32_t flags, const void* source, uint32_t message_id,
    uint32_t language_id, uint16_t* buffer, uint32_t size, void* args)
{
    (void)source; (void)language_id; (void)args;
    if (!buffer || size == 0) return 0;
    char tmp[512];
    if (flags & 0x1000) {
        const char* msg = strerror((int)message_id);
        if (!msg) snprintf(tmp, sizeof(tmp), "Error %u", message_id);
        else       snprintf(tmp, sizeof(tmp), "%s", msg);
    } else {
        snprintf(tmp, sizeof(tmp), "Error 0x%x", message_id);
    }
    uint32_t len = (uint32_t)strlen(tmp);
    if (len >= size) len = size - 1;
    for (uint32_t i = 0; i <= len; i++) buffer[i] = (uint16_t)tmp[i];
    return len;
}

// ---- SRW Locks (use pthread_mutex_t as a simple approximation) ----
// Windows SRW locks have separate shared/exclusive modes; we approximate both
// modes with a single mutex since most LSW workloads don't need true read parallelism.
void __attribute__((ms_abi)) lsw_InitializeSRWLock(void** lock) {
    if (!lock) return;
    *lock = malloc(sizeof(pthread_mutex_t));
    if (*lock) pthread_mutex_init((pthread_mutex_t*)*lock, NULL);
}
void __attribute__((ms_abi)) lsw_AcquireSRWLockExclusive(void** lock) {
    if (lock && *lock) pthread_mutex_lock((pthread_mutex_t*)*lock);
}
void __attribute__((ms_abi)) lsw_ReleaseSRWLockExclusive(void** lock) {
    if (lock && *lock) pthread_mutex_unlock((pthread_mutex_t*)*lock);
}
void __attribute__((ms_abi)) lsw_AcquireSRWLockShared(void** lock) {
    if (lock && *lock) pthread_mutex_lock((pthread_mutex_t*)*lock);
}
void __attribute__((ms_abi)) lsw_ReleaseSRWLockShared(void** lock) {
    if (lock && *lock) pthread_mutex_unlock((pthread_mutex_t*)*lock);
}

// KERNEL32.dll!TryEnterCriticalSection
int __attribute__((ms_abi)) lsw_TryEnterCriticalSection(pthread_mutex_t** cs) {
    if (!cs || !*cs) return 0;
    return (pthread_mutex_trylock(*cs) == 0) ? 1 : 0;
}

// ---- FLS (Fiber-Local Storage, backed by TLS on Linux) ----
#define FLS_SLOTS_MAX 128
static pthread_key_t g_fls_keys[FLS_SLOTS_MAX];
static int           g_fls_used[FLS_SLOTS_MAX];
static void        (*g_fls_callbacks[FLS_SLOTS_MAX])(void*);

uint32_t __attribute__((ms_abi)) lsw_FlsAlloc(void* callback) {
    for (int i = 0; i < FLS_SLOTS_MAX; i++) {
        if (!g_fls_used[i]) {
            g_fls_used[i] = 1;
            g_fls_callbacks[i] = (void(*)(void*))callback;
            pthread_key_create(&g_fls_keys[i], (void(*)(void*))callback);
            LSW_LOG_DEBUG("FlsAlloc -> slot %d", i);
            return (uint32_t)i;
        }
    }
    LSW_LOG_ERROR("FlsAlloc: no free FLS slots");
    return 0xFFFFFFFF;  // FLS_OUT_OF_INDEXES
}
int __attribute__((ms_abi)) lsw_FlsFree(uint32_t index) {
    if (index >= FLS_SLOTS_MAX || !g_fls_used[index]) return 0;
    pthread_key_delete(g_fls_keys[index]);
    g_fls_used[index] = 0;
    return 1;
}
void* __attribute__((ms_abi)) lsw_FlsGetValue(uint32_t index) {
    if (index >= FLS_SLOTS_MAX || !g_fls_used[index]) return NULL;
    return pthread_getspecific(g_fls_keys[index]);
}
int __attribute__((ms_abi)) lsw_FlsSetValue(uint32_t index, void* value) {
    if (index >= FLS_SLOTS_MAX || !g_fls_used[index]) return 0;
    return (pthread_setspecific(g_fls_keys[index], value) == 0) ? 1 : 0;
}

// ---- CreateMutexW ----
void* __attribute__((ms_abi)) lsw_CreateMutexW(void* attrs, int initial_owner, const uint16_t* name) {
    (void)attrs; (void)name;
    lsw_mutex_t* m = calloc(1, sizeof(lsw_mutex_t));
    if (!m) return NULL;
    m->magic = LSW_MUTEX_MAGIC;
    pthread_mutex_init(&m->mutex, NULL);
    if (initial_owner) {
        pthread_mutex_lock(&m->mutex);
        m->owner = pthread_self();
        m->owned = 1;
    }
    LSW_LOG_INFO("CreateMutexW -> %p", (void*)m);
    return (void*)m;
}

// ---- CreateEventW ----
void* __attribute__((ms_abi)) lsw_CreateEventW(void* attrs, int manual_reset, int initial_state, const uint16_t* name) {
    (void)attrs; (void)name;
    lsw_event_t* ev = calloc(1, sizeof(lsw_event_t));
    if (!ev) return NULL;
    ev->magic = LSW_EVENT_MAGIC;
    pthread_mutex_init(&ev->lock, NULL);
    pthread_cond_init(&ev->cond, NULL);
    ev->signaled = initial_state;
    ev->manual_reset = manual_reset;
    LSW_LOG_INFO("CreateEventW(manual=%d, init=%d) -> %p", manual_reset, initial_state, (void*)ev);
    return (void*)ev;
}

// ---- File Mapping (backed by anonymous mmap) ----
typedef struct {
    void*  base;
    size_t size;
} lsw_file_mapping_t;

void* __attribute__((ms_abi)) lsw_CreateFileMappingW(
    void* hfile, void* attrs, uint32_t protect,
    uint32_t size_high, uint32_t size_low, const uint16_t* name)
{
    (void)hfile; (void)attrs; (void)protect; (void)name;
    size_t size = ((size_t)size_high << 32) | (size_t)size_low;
    if (size == 0) {
        LSW_LOG_WARN("CreateFileMappingW: size 0 not supported");
        return NULL;
    }
    lsw_file_mapping_t* fm = malloc(sizeof(lsw_file_mapping_t));
    if (!fm) return NULL;
    fm->base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (fm->base == MAP_FAILED) {
        LSW_LOG_ERROR("CreateFileMappingW: mmap failed: %s", strerror(errno));
        free(fm);
        return NULL;
    }
    fm->size = size;
    LSW_LOG_INFO("CreateFileMappingW: size=%zu -> %p", size, fm->base);
    return (void*)fm;
}

void* __attribute__((ms_abi)) lsw_MapViewOfFile(
    void* hmap, uint32_t access, uint32_t offset_high, uint32_t offset_low, size_t bytes)
{
    (void)access;
    lsw_file_mapping_t* fm = (lsw_file_mapping_t*)hmap;
    if (!fm) return NULL;
    size_t offset = ((size_t)offset_high << 32) | (size_t)offset_low;
    void* view = (uint8_t*)fm->base + offset;
    LSW_LOG_INFO("MapViewOfFile: map=%p offset=%zu bytes=%zu -> %p", fm->base, offset, bytes, view);
    return view;
}

int __attribute__((ms_abi)) lsw_UnmapViewOfFile(void* base) {
    LSW_LOG_INFO("UnmapViewOfFile: base=%p (no-op — unmapped on CloseHandle)", base);
    return 1;  // TRUE
}

// ---- LoadLibraryW / GetModuleHandleW / GetModuleFileNameW ----
void* __attribute__((ms_abi)) lsw_LoadLibraryW(const uint16_t* filename) {
    if (!filename) return NULL;
    // Convert UTF-16 to UTF-8 for LoadLibraryA
    char buf[512];
    int i = 0;
    while (filename[i] && i < 510) {
        buf[i] = (char)(filename[i] & 0xFF);  // ASCII range only for DLL names
        i++;
    }
    buf[i] = '\0';
    return lsw_LoadLibraryA(buf);
}

void* __attribute__((ms_abi)) lsw_GetModuleHandleW(const uint16_t* name) {
    if (!name) {
        // NULL = handle of calling module (main PE)
        LSW_LOG_INFO("GetModuleHandleW(NULL) -> returning NULL (no self handle)");
        return NULL;
    }
    char buf[256];
    int i = 0;
    while (name[i] && i < 254) { buf[i] = (char)(name[i] & 0xFF); i++; }
    buf[i] = '\0';
    LSW_LOG_INFO("GetModuleHandleW(%s) -> using GetModuleHandleA", buf);
    return lsw_GetModuleHandleA(buf);
}

uint32_t __attribute__((ms_abi)) lsw_GetModuleFileNameW(void* module, uint16_t* buf, uint32_t size) {
    (void)module;
    LSW_LOG_WARN("GetModuleFileNameW stub");
    if (buf && size > 0) buf[0] = 0;
    return 0;
}

uint32_t __attribute__((ms_abi)) lsw_GetModuleFileNameA(void* module, char* buf, uint32_t size) {
    (void)module;
    LSW_LOG_WARN("GetModuleFileNameA stub");
    if (buf && size > 0) buf[0] = 0;
    return 0;
}

// ============================================================================
// END Missing high-priority KERNEL32 APIs
// ============================================================================

// ============================================================================
// SECTION: Additional msvcrt.dll stubs (sprintf, string, math, ctype, I/O)
// ============================================================================

int __attribute__((ms_abi)) lsw_sprintf(char* buf, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf, 65536, fmt, ap);
    va_end(ap);
    return r;
}
int __attribute__((ms_abi)) lsw_snprintf(char* buf, size_t n, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}
// _snprintf (Windows, not null-terminated if truncated)
int __attribute__((ms_abi)) lsw__snprintf(char* buf, size_t n, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}
int __attribute__((ms_abi)) lsw_vsprintf(char* buf, const char* fmt, va_list ap) {
    return vsprintf(buf, fmt, ap);
}
int __attribute__((ms_abi)) lsw_vsnprintf(char* buf, size_t n, const char* fmt, va_list ap) {
    return vsnprintf(buf, n, fmt, ap);
}
int __attribute__((ms_abi)) lsw_sscanf(const char* s, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsscanf(s, fmt, ap);
    va_end(ap);
    return r;
}
int __attribute__((ms_abi)) lsw_vsscanf(const char* s, const char* fmt, va_list ap) {
    return vsscanf(s, fmt, ap);
}

// String functions
char* __attribute__((ms_abi)) lsw_strcpy(char* dst, const char* src)   { return strcpy(dst, src); }
char* __attribute__((ms_abi)) lsw_strncpy(char* dst, const char* src, size_t n) { return strncpy(dst, src, n); }
char* __attribute__((ms_abi)) lsw_strcat(char* dst, const char* src)   { return strcat(dst, src); }
char* __attribute__((ms_abi)) lsw_strncat(char* dst, const char* src, size_t n) { return strncat(dst, src, n); }
char* __attribute__((ms_abi)) lsw_strchr(const char* s, int c)         { return strchr(s, c); }
char* __attribute__((ms_abi)) lsw_strrchr(const char* s, int c)        { return strrchr(s, c); }
char* __attribute__((ms_abi)) lsw_strtok(char* s, const char* delim)   { return strtok(s, delim); }
char* __attribute__((ms_abi)) lsw_strdup(const char* s)                { return strdup(s); }
char* __attribute__((ms_abi)) lsw__strdup(const char* s)               { return strdup(s); }
int   __attribute__((ms_abi)) lsw_strcasecmp(const char* a, const char* b) { return strcasecmp(a, b); }
int   __attribute__((ms_abi)) lsw__stricmp(const char* a, const char* b)   { return strcasecmp(a, b); }
int   __attribute__((ms_abi)) lsw__strnicmp(const char* a, const char* b, size_t n) {
    return strncasecmp(a, b, n);
}

// Wide string helpers
wchar_t* __attribute__((ms_abi)) lsw_wcscpy(wchar_t* d, const wchar_t* s)            { return wcscpy(d, s); }
wchar_t* __attribute__((ms_abi)) lsw_wcsncpy(wchar_t* d, const wchar_t* s, size_t n) { return wcsncpy(d, s, n); }
wchar_t* __attribute__((ms_abi)) lsw_wcscat(wchar_t* d, const wchar_t* s)            { return wcscat(d, s); }
wchar_t* __attribute__((ms_abi)) lsw_wcsncat(wchar_t* d, const wchar_t* s, size_t n) { return wcsncat(d, s, n); }
int      __attribute__((ms_abi)) lsw_wcscmp(const wchar_t* a, const wchar_t* b)      { return wcscmp(a, b); }
int      __attribute__((ms_abi)) lsw_wcsncmp(const wchar_t* a, const wchar_t* b, size_t n) { return wcsncmp(a, b, n); }
wchar_t* __attribute__((ms_abi)) lsw_wcschr(const wchar_t* s, wchar_t c)             { return wcschr(s, c); }
wchar_t* __attribute__((ms_abi)) lsw_wcsrchr(const wchar_t* s, wchar_t c)            { return wcsrchr(s, c); }
wchar_t* __attribute__((ms_abi)) lsw_wcsstr(const wchar_t* h, const wchar_t* n)      { return wcsstr(h, n); }
wchar_t* __attribute__((ms_abi)) lsw__wcsdup(const wchar_t* s)                       { return wcsdup(s); }

// Numeric conversion
int       __attribute__((ms_abi)) lsw_atoi(const char* s)               { return atoi(s); }
long      __attribute__((ms_abi)) lsw_atol(const char* s)               { return atol(s); }
double    __attribute__((ms_abi)) lsw_atof(const char* s)               { return atof(s); }
long      __attribute__((ms_abi)) lsw_strtol(const char* s, char** e, int b)  { return strtol(s, e, b); }
unsigned long __attribute__((ms_abi)) lsw_strtoul(const char* s, char** e, int b) { return strtoul(s, e, b); }
double    __attribute__((ms_abi)) lsw_strtod(const char* s, char** e)   { return strtod(s, e); }
long long __attribute__((ms_abi)) lsw__atoi64(const char* s)            { return atoll(s); }
long long __attribute__((ms_abi)) lsw_strtoll(const char* s, char** e, int b) { return strtoll(s, e, b); }

// Memory
void* __attribute__((ms_abi)) lsw_memmove(void* d, const void* s, size_t n)     { return memmove(d, s, n); }
void* __attribute__((ms_abi)) lsw_memchr(const void* s, int c, size_t n)        { return memchr(s, c, n); }
int   __attribute__((ms_abi)) lsw_memcmp(const void* a, const void* b, size_t n){ return memcmp(a, b, n); }

// ctype
int __attribute__((ms_abi)) lsw_toupper(int c)   { return toupper(c); }
int __attribute__((ms_abi)) lsw_tolower(int c)   { return tolower(c); }
int __attribute__((ms_abi)) lsw_isalpha(int c)   { return isalpha(c); }
int __attribute__((ms_abi)) lsw_isdigit(int c)   { return isdigit(c); }
int __attribute__((ms_abi)) lsw_isspace(int c)   { return isspace(c); }
int __attribute__((ms_abi)) lsw_isalnum(int c)   { return isalnum(c); }
int __attribute__((ms_abi)) lsw_isupper(int c)   { return isupper(c); }
int __attribute__((ms_abi)) lsw_islower(int c)   { return islower(c); }
int __attribute__((ms_abi)) lsw_isprint(int c)   { return isprint(c); }
int __attribute__((ms_abi)) lsw_ispunct(int c)   { return ispunct(c); }

// stdlib sorting
void __attribute__((ms_abi)) lsw_qsort(void* base, size_t n, size_t size,
    int (*cmp)(const void*, const void*)) {
    qsort(base, n, size, cmp);
}
void* __attribute__((ms_abi)) lsw_bsearch(const void* key, const void* base, size_t n, size_t size,
    int (*cmp)(const void*, const void*)) {
    return bsearch(key, base, n, size, cmp);
}

// Time
#include <time.h>
typedef long lsw_time_t;
lsw_time_t __attribute__((ms_abi)) lsw_time(lsw_time_t* t) {
    time_t v = time(NULL);
    if (t) *t = (lsw_time_t)v;
    return (lsw_time_t)v;
}
double __attribute__((ms_abi)) lsw_difftime(lsw_time_t t1, lsw_time_t t0) {
    return difftime((time_t)t1, (time_t)t0);
}
uint64_t __attribute__((ms_abi)) lsw_clock(void) { return (uint64_t)clock(); }

// Random
int __attribute__((ms_abi)) lsw_rand(void)     { return rand(); }
void __attribute__((ms_abi)) lsw_srand(unsigned int seed) { srand(seed); }

// I/O
#include <ctype.h>
void* __attribute__((ms_abi)) lsw_fopen(const char* path, const char* mode) {
    return fopen(path, mode);
}
int   __attribute__((ms_abi)) lsw_fclose(void* f)  { return fclose((FILE*)f); }
int   __attribute__((ms_abi)) lsw_feof(void* f)    { return feof((FILE*)f); }
int   __attribute__((ms_abi)) lsw_ferror(void* f)  { return ferror((FILE*)f); }
int   __attribute__((ms_abi)) lsw_fgetc(void* f)   { return fgetc((FILE*)f); }
int   __attribute__((ms_abi)) lsw_ungetc(int c, void* f) { return ungetc(c, (FILE*)f); }
char* __attribute__((ms_abi)) lsw_fgets(char* s, int n, void* f) { return fgets(s, n, (FILE*)f); }
size_t __attribute__((ms_abi)) lsw_fread(void* buf, size_t sz, size_t cnt, void* f) {
    return fread(buf, sz, cnt, (FILE*)f);
}
long  __attribute__((ms_abi)) lsw_ftell(void* f)  { return ftell((FILE*)f); }
int   __attribute__((ms_abi)) lsw_fseek(void* f, long off, int whence) { return fseek((FILE*)f, off, whence); }
void  __attribute__((ms_abi)) lsw_rewind(void* f) { rewind((FILE*)f); }
int   __attribute__((ms_abi)) lsw_puts(const char* s)    { return puts(s); }
int   __attribute__((ms_abi)) lsw_putchar(int c)          { return putchar(c); }
int   __attribute__((ms_abi)) lsw_getchar(void)           { return getchar(); }
int   __attribute__((ms_abi)) lsw_fscanf(void* f, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vfscanf((FILE*)f, fmt, ap);
    va_end(ap);
    return r;
}
int   __attribute__((ms_abi)) lsw_vprintf(const char* fmt, va_list ap) {
    return vprintf(fmt, ap);
}
int   __attribute__((ms_abi)) lsw_swprintf(wchar_t* buf, const wchar_t* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vswprintf(buf, 65536, fmt, ap);
    va_end(ap);
    return r;
}

// Math
#include <math.h>
double __attribute__((ms_abi)) lsw_floor(double x)  { return floor(x); }
double __attribute__((ms_abi)) lsw_ceil(double x)   { return ceil(x); }
double __attribute__((ms_abi)) lsw_fabs(double x)   { return fabs(x); }
double __attribute__((ms_abi)) lsw_sqrt(double x)   { return sqrt(x); }
double __attribute__((ms_abi)) lsw_pow(double x, double y) { return pow(x, y); }
double __attribute__((ms_abi)) lsw_math_log(double x)    { return log(x); }
double __attribute__((ms_abi)) lsw_math_log10(double x)  { return log10(x); }
double __attribute__((ms_abi)) lsw_exp(double x)    { return exp(x); }
double __attribute__((ms_abi)) lsw_sin(double x)    { return sin(x); }
double __attribute__((ms_abi)) lsw_cos(double x)    { return cos(x); }
double __attribute__((ms_abi)) lsw_tan(double x)    { return tan(x); }
double __attribute__((ms_abi)) lsw_atan2(double y, double x) { return atan2(y, x); }
double __attribute__((ms_abi)) lsw_atan(double x)  { return atan(x); }
double __attribute__((ms_abi)) lsw_asin(double x)  { return asin(x); }
double __attribute__((ms_abi)) lsw_acos(double x)  { return acos(x); }
double __attribute__((ms_abi)) lsw_log2(double x)  { return log2(x); }
double __attribute__((ms_abi)) lsw_fmod(double x, double y) { return fmod(x, y); }
double __attribute__((ms_abi)) lsw_hypot(double x, double y){ return hypot(x, y); }
double __attribute__((ms_abi)) lsw_ldexp(double x, int exp) { return ldexp(x, exp); }
double __attribute__((ms_abi)) lsw_frexp(double x, int* e) { return frexp(x, e); }
double __attribute__((ms_abi)) lsw_modf(double x, double* iptr){ return modf(x, iptr); }
float  __attribute__((ms_abi)) lsw_sqrtf(float x)  { return sqrtf(x); }
float  __attribute__((ms_abi)) lsw_sinf(float x)   { return sinf(x); }
float  __attribute__((ms_abi)) lsw_cosf(float x)   { return cosf(x); }
float  __attribute__((ms_abi)) lsw_powf(float x, float y) { return powf(x, y); }
float  __attribute__((ms_abi)) lsw_fabsf(float x)  { return fabsf(x); }
float  __attribute__((ms_abi)) lsw_floorf(float x) { return floorf(x); }
float  __attribute__((ms_abi)) lsw_ceilf(float x)  { return ceilf(x); }
float  __attribute__((ms_abi)) lsw_expf(float x)   { return expf(x); }
float  __attribute__((ms_abi)) lsw_logf(float x)   { return logf(x); }
float  __attribute__((ms_abi)) lsw_fmodf(float x, float y) { return fmodf(x, y); }

// Time - localtime/gmtime/mktime
struct tm* __attribute__((ms_abi)) lsw_localtime(const lsw_time_t* t)
    { return localtime((const time_t*)t); }
struct tm* __attribute__((ms_abi)) lsw_gmtime(const lsw_time_t* t)
    { return gmtime((const time_t*)t); }
lsw_time_t __attribute__((ms_abi)) lsw_mktime(struct tm* tm_)
    { return (lsw_time_t)mktime(tm_); }
char* __attribute__((ms_abi)) lsw_asctime(const struct tm* t) { return asctime(t); }
char* __attribute__((ms_abi)) lsw_ctime(const lsw_time_t* t) { return ctime((const time_t*)t); }
size_t __attribute__((ms_abi)) lsw_strftime(char* s, size_t max, const char* fmt, const struct tm* tm_)
    { return strftime(s, max, fmt, tm_); }

// Environment
char* __attribute__((ms_abi)) lsw_getenv(const char* n) { return getenv(n); }
int   __attribute__((ms_abi)) lsw__putenv(const char* s) { return putenv((char*)s); }

// Security/safe string variants (CRT secure versions)
int __attribute__((ms_abi)) lsw_strcpy_s(char* dst, size_t sz, const char* src) {
    if (!dst || !sz) return 22; /* EINVAL */
    strncpy(dst, src, sz); dst[sz-1] = 0; return 0;
}
int __attribute__((ms_abi)) lsw_strncpy_s(char* dst, size_t dsz, const char* src, size_t cnt) {
    if (!dst || !dsz) return 22;
    size_t n = cnt < dsz-1 ? cnt : dsz-1;
    memcpy(dst, src, n); dst[n] = 0; return 0;
}
int __attribute__((ms_abi)) lsw_strcat_s(char* dst, size_t sz, const char* src) {
    if (!dst || !sz) return 22;
    size_t used = strlen(dst);
    if (used >= sz) return 22;
    strncat(dst, src, sz - used - 1); return 0;
}
int __attribute__((ms_abi)) lsw_sprintf_s(char* dst, size_t sz, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); int r = vsnprintf(dst, sz, fmt, ap); va_end(ap); return r;
}
int __attribute__((ms_abi)) lsw_memcpy_s(void* dst, size_t dsz, const void* src, size_t cnt) {
    if (cnt > dsz) return 22;
    memcpy(dst, src, cnt); return 0;
}
int __attribute__((ms_abi)) lsw_memmove_s(void* dst, size_t dsz, const void* src, size_t cnt) {
    if (cnt > dsz) return 22;
    memmove(dst, src, cnt); return 0;
}
int __attribute__((ms_abi)) lsw_wcscpy_s(wchar_t* dst, size_t sz, const wchar_t* src) {
    if (!dst || !sz) return 22;
    wcsncpy(dst, src, sz); dst[sz-1] = 0; return 0;
}
int __attribute__((ms_abi)) lsw_wcscat_s(wchar_t* dst, size_t sz, const wchar_t* src) {
    if (!dst || !sz) return 22;
    size_t used = wcslen(dst);
    if (used >= sz) return 22;
    wcsncat(dst, src, sz - used - 1); return 0;
}
int __attribute__((ms_abi)) lsw_swprintf_s(wchar_t* dst, size_t sz, const wchar_t* fmt, ...) {
    va_list ap; va_start(ap, fmt); int r = vswprintf(dst, sz, fmt, ap); va_end(ap); return r;
}

// Wide I/O
void* __attribute__((ms_abi)) lsw__wfopen(const wchar_t* path, const wchar_t* mode) {
    char p[512], m[32];
    wcstombs(p, path, sizeof(p)); wcstombs(m, mode, sizeof(m));
    return fopen(p, m);
}
int __attribute__((ms_abi)) lsw__waccess(const wchar_t* path, int mode) {
    char p[512]; wcstombs(p, path, sizeof(p)); return access(p, mode);
}
int __attribute__((ms_abi)) lsw__wrename(const wchar_t* o, const wchar_t* n_) {
    char o2[512], n2[512]; wcstombs(o2, o, sizeof(o2)); wcstombs(n2, n_, sizeof(n2));
    return rename(o2, n2);
}
int __attribute__((ms_abi)) lsw__wremove(const wchar_t* path) {
    char p[512]; wcstombs(p, path, sizeof(p)); return remove(p);
}

// Aligned allocation
void* __attribute__((ms_abi)) lsw__aligned_malloc(size_t sz, size_t align) {
    void* p = NULL; if (posix_memalign(&p, align < sizeof(void*) ? sizeof(void*) : align, sz)) return NULL; return p;
}
void  __attribute__((ms_abi)) lsw__aligned_free(void* p) { free(p); }
void* __attribute__((ms_abi)) lsw__aligned_realloc(void* p, size_t sz, size_t align) {
    void* n = NULL; if (posix_memalign(&n, align < sizeof(void*) ? sizeof(void*) : align, sz)) return NULL;
    if (p) { memcpy(n, p, sz); free(p); } return n;
}
size_t __attribute__((ms_abi)) lsw__msize(void* p) { return p ? malloc_usable_size(p) : 0; }

// CRT init helpers
int __attribute__((ms_abi)) lsw__initterm_e(int (**start)(void), int (**end)(void)) {
    for (int (**fn)(void) = start; fn < end; fn++) if (*fn) { int r = (*fn)(); if (r) return r; }
    return 0;
}
void __attribute__((ms_abi)) lsw___security_init_cookie(void) {}
void __attribute__((ms_abi)) lsw___security_check_cookie(uintptr_t c) { (void)c; }

// Additional wide string helpers
size_t __attribute__((ms_abi)) lsw_wcsnlen(const wchar_t* s, size_t max) {
    size_t n = 0; while (n < max && s[n]) n++; return n;
}
int __attribute__((ms_abi)) lsw__wcsicmp(const wchar_t* a, const wchar_t* b) { return wcscasecmp(a, b); }
int __attribute__((ms_abi)) lsw__wcsnicmp(const wchar_t* a, const wchar_t* b, size_t n) { return wcsncasecmp(a, b, n); }
/* lsw__stricmp, lsw__strnicmp, lsw__strdup, lsw__wcsdup, lsw__atoi64 defined earlier */
long long __attribute__((ms_abi)) lsw__strtoi64(const char* s, char** e, int b) { return strtoll(s, e, b); }
unsigned long long __attribute__((ms_abi)) lsw__strtoui64(const char* s, char** e, int b) { return strtoull(s, e, b); }
float __attribute__((ms_abi)) lsw_strtof(const char* s, char** e) { return strtof(s, e); }
/* lsw_strerror defined earlier */
void  __attribute__((ms_abi)) lsw_perror(const char* s) { perror(s); }

// errno accessor
int* __attribute__((ms_abi)) lsw__errno(void) { return &errno; }
int __attribute__((ms_abi)) lsw__get_errno(int* e) { if (e) *e = errno; return 0; }
int __attribute__((ms_abi)) lsw__set_errno(int v) { errno = v; return 0; }

// ============================================================================
// SECTION: vcruntime140.dll / api-ms-win-crt-* stubs
// Modern MSVC apps (VS2015+) import from vcruntime140.dll and the
// api-ms-win-crt-*.dll Universal CRT forwarder DLLs instead of msvcrt.dll.
// These are mostly identical to their msvcrt counterparts.
// ============================================================================

// __acrt_iob_func(index) returns FILE* for stdin(0)/stdout(1)/stderr(2)
void* __attribute__((ms_abi)) lsw___acrt_iob_func(unsigned int index) {
    switch (index) {
        case 0: return stdin;
        case 1: return stdout;
        case 2: return stderr;
        default: return NULL;
    }
}

// __stdio_common_vfprintf / __stdio_common_vsprintf: used by all printf family
// Signature: int __stdio_common_vfprintf(uint64_t options, FILE* f, const char* fmt, ..., va_list ap)
int __attribute__((ms_abi)) lsw___stdio_common_vfprintf(
    uint64_t opts, void* f, const char* fmt, void* locale, va_list ap)
{
    (void)opts; (void)locale;
    return vfprintf((FILE*)f, fmt, ap);
}
int __attribute__((ms_abi)) lsw___stdio_common_vsprintf(
    uint64_t opts, char* buf, size_t bufsz, const char* fmt, void* locale, va_list ap)
{
    (void)opts; (void)locale;
    return vsnprintf(buf, bufsz, fmt, ap);
}
int __attribute__((ms_abi)) lsw___stdio_common_vsscanf(
    uint64_t opts, const char* buf, size_t bufsz, const char* fmt, void* locale, va_list ap)
{
    (void)opts; (void)locale; (void)bufsz;
    return vsscanf(buf, fmt, ap);
}
int __attribute__((ms_abi)) lsw___stdio_common_vswprintf(
    uint64_t opts, wchar_t* buf, size_t n, const wchar_t* fmt, void* locale, va_list ap)
{
    (void)opts; (void)locale;
    return vswprintf(buf, n, fmt, ap);
}
int __attribute__((ms_abi)) lsw___stdio_common_vfwprintf(
    uint64_t opts, void* f, const wchar_t* fmt, void* locale, va_list ap)
{
    (void)opts; (void)locale;
    return vfwprintf((FILE*)f, fmt, ap);
}

// _configure_narrow_argv / _configure_wide_argv — CRT startup config, no-op
void __attribute__((ms_abi)) lsw__configure_narrow_argv(int mode) { (void)mode; }
void __attribute__((ms_abi)) lsw__configure_wide_argv(int mode)   { (void)mode; }

// _initialize_narrow_environment / _initialize_wide_environment — no-op
void __attribute__((ms_abi)) lsw__initialize_narrow_environment(void) {}
void __attribute__((ms_abi)) lsw__initialize_wide_environment(void)   {}
void __attribute__((ms_abi)) lsw__initialize_onexit_table(void* t) { (void)t; }
void __attribute__((ms_abi)) lsw__register_onexit_function(void* t, void* fn) { (void)t; (void)fn; }
void __attribute__((ms_abi)) lsw__execute_onexit_table(void* t) { (void)t; }
void __attribute__((ms_abi)) lsw___p___argc(void)   {}   // Returns pointer to __argc — stubbed
void __attribute__((ms_abi)) lsw___p___argv(void)   {}
void __attribute__((ms_abi)) lsw___p__commode(void) {}

// terminate / unexpected
void __attribute__((ms_abi)) lsw__crt_atexit(void* fn) { (void)fn; }
void __attribute__((ms_abi)) lsw___crt_at_quick_exit(void* fn) { (void)fn; }

// vcruntime: memory functions
void* __attribute__((ms_abi)) lsw___std_type_info_destroy_list(void* p) { (void)p; return NULL; }

// C++ exception helpers (vcruntime)
// Thread-local storage for the last thrown C++ exception
static __thread void* tls_cxx_exception_obj  = NULL;
static __thread void* tls_cxx_exception_type = NULL;

void __attribute__((ms_abi)) lsw__CxxThrowException(void* obj, void* type) {
    tls_cxx_exception_obj  = obj;
    tls_cxx_exception_type = type;
    LSW_LOG_ERROR("_CxxThrowException: obj=%p type=%p — calling exit(1)", obj, type);
    exit(1);
}

// __CxxFrameHandler3 — called by MSVC exception filter logic; always continue search
int __attribute__((ms_abi)) lsw___CxxFrameHandler3(void* a, void* b, void* c, void* d) {
    (void)a; (void)b; (void)c; (void)d;
    return 0; /* ExceptionContinueSearch */
}

// __C_specific_handler — SEH handler for functions compiled with /EHa
int __attribute__((ms_abi)) lsw___C_specific_handler(void* a, void* b, void* c, void* d) {
    (void)a; (void)b; (void)c; (void)d;
    return 0; /* ExceptionContinueSearch */
}

// ============================================================================
// END vcruntime140 / api-ms-win-crt-* stubs
// ============================================================================

// ============================================================================
// SECTION: Additional KERNEL32 APIs (process, console, misc)
// ============================================================================

// GetCurrentThread / GetCurrentProcess
void* __attribute__((ms_abi)) lsw_GetCurrentThread(void) {
    return (void*)(uintptr_t)0xFFFFFFFFFFFFFFFEULL; // pseudohandle
}
void* __attribute__((ms_abi)) lsw_GetCurrentProcess(void) {
    return (void*)(uintptr_t)0xFFFFFFFFFFFFFFFFULL; // pseudohandle
}
uint32_t __attribute__((ms_abi)) lsw_GetCurrentThreadId(void) {
    return (uint32_t)(uintptr_t)pthread_self();
}

// GetSystemTimeAsFileTime — fills FILETIME (100-ns intervals since 1601-01-01)
void __attribute__((ms_abi)) lsw_GetSystemTimeAsFileTime(uint64_t* ft) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    // Unix epoch (1970-01-01) in Windows FILETIME ticks (100 ns since 1601-01-01):
    // Difference = 116444736000000000 ticks
    uint64_t ticks = (uint64_t)tv.tv_sec * 10000000ULL
                   + (uint64_t)tv.tv_usec * 10ULL
                   + 116444736000000000ULL;
    if (ft) *ft = ticks;
}
void __attribute__((ms_abi)) lsw_GetSystemTime(void* lpSystemTime) {
    // SYSTEMTIME: Year, Month, DayOfWeek, Day, Hour, Minute, Second, Ms (each 2 bytes)
    uint16_t* st = (uint16_t*)lpSystemTime;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    (void)st; // TODO: fill from tm struct
}
void __attribute__((ms_abi)) lsw_GetLocalTime(void* lpSystemTime) {
    lsw_GetSystemTime(lpSystemTime); // stub — same as SystemTime
}
int __attribute__((ms_abi)) lsw_FileTimeToSystemTime(const uint64_t* ft, void* st) {
    (void)ft; (void)st; return 1; // stub
}
int __attribute__((ms_abi)) lsw_SystemTimeToFileTime(const void* st, uint64_t* ft) {
    (void)st; if (ft) *ft = 0; return 1; // stub
}

// QueryPerformanceCounter/Frequency
int __attribute__((ms_abi)) lsw_QueryPerformanceCounter(uint64_t* out) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (out) *out = (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
    return 1;
}
int __attribute__((ms_abi)) lsw_QueryPerformanceFrequency(uint64_t* out) {
    if (out) *out = 1000000ULL; // 1 MHz (matches gettimeofday resolution)
    return 1;
}

// Console functions
int __attribute__((ms_abi)) lsw_AllocConsole(void) { return 1; }
int __attribute__((ms_abi)) lsw_FreeConsole(void)  { return 1; }
int __attribute__((ms_abi)) lsw_AttachConsole(uint32_t pid) { (void)pid; return 1; }
void* __attribute__((ms_abi)) lsw_GetConsoleWindow(void) { return NULL; }
int __attribute__((ms_abi)) lsw_SetConsoleTitle(const char* t) { (void)t; return 1; }
int __attribute__((ms_abi)) lsw_SetConsoleTitleA(const char* t) {
    if (t) LSW_LOG_DEBUG("SetConsoleTitleA: \"%s\"", t);
    return 1;
}
int __attribute__((ms_abi)) lsw_SetConsoleTitleW(const uint16_t* t) { (void)t; return 1; }
int __attribute__((ms_abi)) lsw_GetConsoleMode(void* h, uint32_t* mode) {
    (void)h; if (mode) *mode = 0x3; return 1;
}
int __attribute__((ms_abi)) lsw_SetConsoleMode(void* h, uint32_t mode) {
    (void)h; (void)mode; return 1;
}
uint32_t __attribute__((ms_abi)) lsw_WriteConsoleW(
    void* h, const uint16_t* buf, uint32_t nchars, uint32_t* written, void* reserved) {
    (void)h; (void)reserved;
    // Simple Latin-1 downcast for console output
    for (uint32_t i = 0; i < nchars; i++) {
        uint16_t c = buf[i];
        if (c < 128) putchar((char)c);
        else putchar('?');
    }
    if (written) *written = nchars;
    return 1;
}
uint32_t __attribute__((ms_abi)) lsw_ReadConsoleA(
    void* h, char* buf, uint32_t toread, uint32_t* nread, void* reserved) {
    (void)h; (void)reserved;
    char* r = fgets(buf, (int)toread, stdin);
    uint32_t n = r ? (uint32_t)strlen(buf) : 0;
    if (nread) *nread = n;
    return r ? 1 : 0;
}
uint32_t __attribute__((ms_abi)) lsw_ReadConsoleW(
    void* h, uint16_t* buf, uint32_t toread, uint32_t* nread, void* reserved) {
    (void)h; (void)reserved;
    char tmp[4096] = {0};
    uint32_t limit = toread < 4095 ? toread : 4095;
    char* r = fgets(tmp, (int)limit, stdin);
    uint32_t n = 0;
    if (r) {
        while (tmp[n] && n < toread) { buf[n] = (uint16_t)tmp[n]; n++; }
    }
    if (nread) *nread = n;
    return r ? 1 : 0;
}

// Misc KERNEL32
uint32_t __attribute__((ms_abi)) lsw_GetFileType(void* h) {
    (void)h;
    return 2; // FILE_TYPE_CHAR (console)
}
int __attribute__((ms_abi)) lsw_DuplicateHandle(
    void* hsrcproc, void* hsrc, void* hdstproc, void** hdst,
    uint32_t access, int inherit, uint32_t opts) {
    (void)hsrcproc; (void)hdstproc; (void)access; (void)inherit;
#define DUPLICATE_CLOSE_SOURCE 0x1
    if (!hdst) {
        if ((opts & DUPLICATE_CLOSE_SOURCE) && hsrc)
            lsw_CloseHandle(hsrc);
        return 1;
    }
    /* Try fd dup for file descriptor handles */
    intptr_t fd = (intptr_t)hsrc;
    if (fd >= 0 && fd < 65536) {
        int nfd = dup((int)fd);
        if (nfd >= 0) {
            *hdst = (void*)(intptr_t)nfd;
            if (opts & DUPLICATE_CLOSE_SOURCE) close((int)fd);
            return 1;
        }
    }
    /* For typed handles just alias; caller must not double-free */
    *hdst = hsrc;
    if (opts & DUPLICATE_CLOSE_SOURCE) lsw_CloseHandle(hsrc);
    return 1;
}
void __attribute__((ms_abi)) lsw_OutputDebugStringA(const char* s) {
    if (s) LSW_LOG_DEBUG("[ODS] %s", s);
}
void __attribute__((ms_abi)) lsw_OutputDebugStringW(const uint16_t* s) { (void)s; }
int __attribute__((ms_abi)) lsw_CreateDirectoryA(const char* path, void* attrs) {
    (void)attrs;
    if (!path) return 0;
    return (mkdir(path, 0755) == 0) ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_GetFileAttributesA(const char* path) {
    if (!path) return (int)0xFFFFFFFF;
    struct stat st;
    if (stat(path, &st) != 0) return (int)0xFFFFFFFF;
    int attr = 0x20; // FILE_ATTRIBUTE_ARCHIVE
    if (S_ISDIR(st.st_mode)) attr = 0x10; // FILE_ATTRIBUTE_DIRECTORY
    return attr;
}
uint32_t __attribute__((ms_abi)) lsw_GetFullPathNameA(const char* path, uint32_t buf_len, char* buf, char** fname) {
    if (!path || !buf || buf_len == 0) return 0;
    char* r = realpath(path, buf);
    if (!r) { snprintf(buf, buf_len, "%s", path); }
    if (fname) {
        char* slash = strrchr(buf, '/');
        *fname = slash ? slash + 1 : buf;
    }
    return (uint32_t)strlen(buf);
}
uint32_t __attribute__((ms_abi)) lsw_GetFullPathNameW(const uint16_t* path, uint32_t buf_len, uint16_t* buf, uint16_t** fname) {
    (void)path; (void)buf_len; (void)buf; (void)fname; return 0;
}
int __attribute__((ms_abi)) lsw_SetCurrentDirectoryA(const char* path) {
    if (!path) return 0;
    return (chdir(path) == 0) ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_SetCurrentDirectoryW(const uint16_t* path) { (void)path; return 1; }
uint32_t __attribute__((ms_abi)) lsw_GetCurrentDirectoryA(uint32_t n, char* buf) {
    if (!buf || n == 0) return 0;
    if (!getcwd(buf, n)) return 0;
    return (uint32_t)strlen(buf);
}
uint32_t __attribute__((ms_abi)) lsw_GetCurrentDirectoryW(uint32_t n, uint16_t* buf) {
    (void)n; (void)buf; return 0;
}
int __attribute__((ms_abi)) lsw_MoveFileA(const char* src, const char* dst) {
    if (!src || !dst) return 0;
    return (rename(src, dst) == 0) ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_MoveFileW(const uint16_t* src, const uint16_t* dst) { (void)src; (void)dst; return 0; }
int __attribute__((ms_abi)) lsw_CopyFileA(const char* src, const char* dst, int fail_if_exists) {
    (void)fail_if_exists;
    if (!src || !dst) return 0;
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) return 0;
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) { close(sfd); return 0; }
    char buf[4096];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        if (write(dfd, buf, (size_t)n) != n) { close(sfd); close(dfd); return 0; }
    }
    close(sfd); close(dfd);
    return 1;
}
void* __attribute__((ms_abi)) lsw_FindFirstFileA(const char* pattern, void* data) {
    (void)pattern; (void)data;
    LSW_LOG_WARN("FindFirstFileA: stub");
    return (void*)(uintptr_t)0xFFFFFFFFFFFFFFFFULL; // INVALID_HANDLE_VALUE
}
int __attribute__((ms_abi)) lsw_FindNextFileA(void* h, void* data) { (void)h; (void)data; return 0; }

// Heap size tracking — trivially returns 0; real implementation needs an alloc map
size_t __attribute__((ms_abi)) lsw_HeapSize_impl(void* heap, uint32_t flags, const void* mem) {
    (void)heap; (void)flags; (void)mem;
    return 0;
}

// WaitForMultipleObjects (basic: loop WaitForSingleObject)
uint32_t __attribute__((ms_abi)) lsw_WaitForMultipleObjects(
    uint32_t count, void** handles, int wait_all, uint32_t timeout_ms)
{
    (void)wait_all;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t r = lsw_WaitForSingleObject(handles[i], timeout_ms);
        if (r == 0) return i; // WAIT_OBJECT_0 + i
    }
    return 0xFFFFFFFF; // WAIT_FAILED
}

// CreateMutexA — same as CreateMutexW but accepts ASCII name
void* __attribute__((ms_abi)) lsw_CreateMutexA(void* attrs, int initial_owner, const char* name) {
    (void)attrs; (void)name;
    lsw_mutex_t* m = calloc(1, sizeof(lsw_mutex_t));
    if (!m) return NULL;
    m->magic = LSW_MUTEX_MAGIC;
    pthread_mutex_init(&m->mutex, NULL);
    if (initial_owner) {
        pthread_mutex_lock(&m->mutex);
        m->owner = pthread_self();
        m->owned = 1;
    }
    return (void*)m;
}
// OpenMutex stubs
void* __attribute__((ms_abi)) lsw_OpenMutexA(uint32_t access, int inherit, const char* name) {
    (void)access; (void)inherit; (void)name; return NULL;
}
int __attribute__((ms_abi)) lsw_ReleaseMutex(void* h) {
    if (!h) return 0;
    lsw_mutex_t* m = (lsw_mutex_t*)h;
    if (m->magic == LSW_MUTEX_MAGIC) {
        m->owned = 0;
        m->owner = (pthread_t)0;
        pthread_mutex_unlock(&m->mutex);
        return 1;
    }
    /* Legacy: raw pthread_mutex_t* */
    return (pthread_mutex_unlock((pthread_mutex_t*)h) == 0) ? 1 : 0;
}

// CreateSemaphoreA/W, OpenSemaphoreA, ReleaseSemaphore (backed by lsw_semaphore_t)
void* __attribute__((ms_abi)) lsw_CreateSemaphoreA(void* attrs, long init, long max, const char* name) {
    (void)attrs; (void)name;
    lsw_semaphore_t* s = calloc(1, sizeof(lsw_semaphore_t));
    if (!s) return NULL;
    s->magic = LSW_SEMA_MAGIC;
    s->max_count = max;
    sem_init(&s->sem, 0, (unsigned int)init);
    return (void*)s;
}
void* __attribute__((ms_abi)) lsw_CreateSemaphoreW(void* attrs, long init, long max, const uint16_t* name) {
    (void)attrs; (void)name;
    lsw_semaphore_t* s = calloc(1, sizeof(lsw_semaphore_t));
    if (!s) return NULL;
    s->magic = LSW_SEMA_MAGIC;
    s->max_count = max;
    sem_init(&s->sem, 0, (unsigned int)init);
    return (void*)s;
}
int __attribute__((ms_abi)) lsw_ReleaseSemaphore(void* h, long count, long* prev) {
    if (!h) return 0;
    lsw_semaphore_t* s = (lsw_semaphore_t*)h;
    if (s->magic == LSW_SEMA_MAGIC) {
        if (prev) { int v = 0; sem_getvalue(&s->sem, &v); *prev = (long)v; }
        for (long i = 0; i < count; i++) sem_post(&s->sem);
        return 1;
    }
    /* Legacy raw sem_t* */
    sem_t* raw = (sem_t*)h;
    if (prev) { int v = 0; sem_getvalue(raw, &v); *prev = (long)v; }
    for (long i = 0; i < count; i++) sem_post(raw);
    return 1;
}

// KERNEL32.dll!ResetEvent
int __attribute__((ms_abi)) lsw_ResetEvent(void* h) {
    if (!h) return 0;
    lsw_event_t* ev = (lsw_event_t*)h;
    if (ev->magic != LSW_EVENT_MAGIC) return 0;
    pthread_mutex_lock(&ev->lock);
    ev->signaled = 0;
    pthread_mutex_unlock(&ev->lock);
    return 1;
}

// ---------------------------------------------------------------------------
// Condition Variables
// ---------------------------------------------------------------------------
void __attribute__((ms_abi)) lsw_InitializeConditionVariable(void** cv) {
    if (!cv) return;
    pthread_cond_t* c = calloc(1, sizeof(pthread_cond_t));
    pthread_cond_init(c, NULL);
    *cv = c;
}

void __attribute__((ms_abi)) lsw_WakeConditionVariable(void** cv) {
    if (!cv || !*cv) return;
    pthread_cond_signal((pthread_cond_t*)*cv);
}

void __attribute__((ms_abi)) lsw_WakeAllConditionVariable(void** cv) {
    if (!cv || !*cv) return;
    pthread_cond_broadcast((pthread_cond_t*)*cv);
}

int __attribute__((ms_abi)) lsw_SleepConditionVariableCS(void** cv, void* cs, uint32_t ms) {
    if (!cv || !*cv || !cs) return 0;
    pthread_cond_t* c = (pthread_cond_t*)*cv;
    pthread_mutex_t* m = (pthread_mutex_t*)cs;
    if (ms == 0xFFFFFFFF) {
        return (pthread_cond_wait(c, m) == 0) ? 1 : 0;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    int r = pthread_cond_timedwait(c, m, &ts);
    if (r == ETIMEDOUT) { /* SetLastError(ERROR_TIMEOUT) */ return 0; }
    return (r == 0) ? 1 : 0;
}

int __attribute__((ms_abi)) lsw_SleepConditionVariableSRW(void** cv, void** srw, uint32_t ms, uint32_t flags) {
    /* SRW in shared mode (CONDITION_VARIABLE_LOCKMODE_SHARED=1) needs read unlock/lock
       but we store them as plain mutexes, so just treat same as CS */
    (void)flags;
    return lsw_SleepConditionVariableCS(cv, srw ? *srw : NULL, ms);
}

// ---------------------------------------------------------------------------
// Waitable Timers
// ---------------------------------------------------------------------------
void* __attribute__((ms_abi)) lsw_CreateWaitableTimerW(void* sec, int manual, const uint16_t* name) {
    (void)sec; (void)manual; (void)name;
    lsw_timer_t* t = calloc(1, sizeof(lsw_timer_t));
    t->magic = LSW_TIMER_MAGIC;
    t->manual_reset = manual;
    t->timerfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK);
    return t;
}
void* __attribute__((ms_abi)) lsw_CreateWaitableTimerA(void* sec, int manual, const char* name) {
    (void)name; return lsw_CreateWaitableTimerW(sec, manual, NULL);
}
void* __attribute__((ms_abi)) lsw_CreateWaitableTimerExW(void* sec, const uint16_t* name, uint32_t flags, uint32_t access) {
    (void)access;
    int manual = (flags & 1) ? 1 : 0; /* CREATE_WAITABLE_TIMER_MANUAL_RESET=1 */
    return lsw_CreateWaitableTimerW(sec, manual, name);
}
void* __attribute__((ms_abi)) lsw_OpenWaitableTimerW(uint32_t access, int inherit, const uint16_t* name) {
    (void)access; (void)inherit; (void)name; return NULL; /* named timers not supported */
}

int __attribute__((ms_abi)) lsw_SetWaitableTimer(void* h, const int64_t* due, int period_ms,
                                                   void* apc, void* apc_arg, int resume) {
    (void)apc; (void)apc_arg; (void)resume;
    if (!h) return 0;
    lsw_timer_t* t = (lsw_timer_t*)h;
    if (t->magic != LSW_TIMER_MAGIC || t->timerfd < 0) return 0;
    struct itimerspec its = {0};
    int64_t d = due ? *due : 0;
    if (d < 0) {
        /* Relative time in 100ns units */
        int64_t ns = (-d) * 100;
        its.it_value.tv_sec  = ns / 1000000000LL;
        its.it_value.tv_nsec = ns % 1000000000LL;
    } else if (d > 0) {
        /* Absolute FILETIME: 100ns since 1601-01-01 */
        /* Convert to Unix epoch: subtract 116444736000000000 (100ns units) */
        int64_t unix_ns = (d - 116444736000000000LL) * 100;
        its.it_value.tv_sec  = unix_ns / 1000000000LL;
        its.it_value.tv_nsec = unix_ns % 1000000000LL;
    } else {
        /* due==NULL or 0: fire immediately */
        its.it_value.tv_nsec = 1;
    }
    if (period_ms > 0) {
        its.it_interval.tv_sec  = period_ms / 1000;
        its.it_interval.tv_nsec = (period_ms % 1000) * 1000000L;
    }
    return (timerfd_settime(t->timerfd, (d > 0) ? TFD_TIMER_ABSTIME : 0, &its, NULL) == 0) ? 1 : 0;
}

int __attribute__((ms_abi)) lsw_CancelWaitableTimer(void* h) {
    if (!h) return 0;
    lsw_timer_t* t = (lsw_timer_t*)h;
    if (t->magic != LSW_TIMER_MAGIC || t->timerfd < 0) return 0;
    struct itimerspec its = {0};
    return (timerfd_settime(t->timerfd, 0, &its, NULL) == 0) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// IOCP — I/O Completion Ports
// ---------------------------------------------------------------------------
void* __attribute__((ms_abi)) lsw_CreateIoCompletionPort(void* file_handle, void* existing_port,
                                                           uintptr_t completion_key, uint32_t threads) {
    (void)file_handle; (void)completion_key; (void)threads;
    if (existing_port) return existing_port; /* associate file — we ignore it */
    lsw_iocp_t* io = calloc(1, sizeof(lsw_iocp_t));
    io->magic = LSW_IOCP_MAGIC;
    pthread_mutex_init(&io->lock, NULL);
    pipe(io->wakefd);
    return io;
}

int __attribute__((ms_abi)) lsw_PostQueuedCompletionStatus(void* port, uint32_t bytes,
                                                             uintptr_t key, void* overlapped) {
    if (!port) return 0;
    lsw_iocp_t* io = (lsw_iocp_t*)port;
    if (io->magic != LSW_IOCP_MAGIC) return 0;
    lsw_completion_t* c = calloc(1, sizeof(lsw_completion_t));
    c->bytes = bytes; c->key = key; c->overlapped = overlapped;
    pthread_mutex_lock(&io->lock);
    c->next = NULL;
    if (io->tail) io->tail->next = c; else io->head = c;
    io->tail = c;
    pthread_mutex_unlock(&io->lock);
    uint8_t wake = 1;
    write(io->wakefd[1], &wake, 1);
    return 1;
}

int __attribute__((ms_abi)) lsw_GetQueuedCompletionStatus(void* port, uint32_t* bytes,
                                                            uintptr_t* key, void** overlapped,
                                                            uint32_t ms) {
    if (!port) return 0;
    lsw_iocp_t* io = (lsw_iocp_t*)port;
    if (io->magic != LSW_IOCP_MAGIC) return 0;
    struct pollfd pfd = { .fd = io->wakefd[0], .events = POLLIN };
    int r = poll(&pfd, 1, (ms == 0xFFFFFFFF) ? -1 : (int)ms);
    if (r <= 0) return 0; /* timeout or error */
    uint8_t dummy;
    read(io->wakefd[0], &dummy, 1);
    pthread_mutex_lock(&io->lock);
    lsw_completion_t* c = io->head;
    if (c) {
        io->head = c->next;
        if (!io->head) io->tail = NULL;
    }
    pthread_mutex_unlock(&io->lock);
    if (!c) return 0;
    if (bytes)      *bytes      = c->bytes;
    if (key)        *key        = c->key;
    if (overlapped) *overlapped = c->overlapped;
    free(c);
    return 1;
}

int __attribute__((ms_abi)) lsw_GetQueuedCompletionStatusEx(void* port, void* entries,
                                                              uint32_t count, uint32_t* removed,
                                                              uint32_t ms, int alertable) {
    (void)alertable;
    /* Simple single-entry version */
    typedef struct { uintptr_t key; void* overlapped; uintptr_t internal; uint32_t bytes; } OVERLAPPED_ENTRY;
    OVERLAPPED_ENTRY* ents = (OVERLAPPED_ENTRY*)entries;
    uint32_t got = 0;
    for (uint32_t i = 0; i < count; i++) {
        int r = lsw_GetQueuedCompletionStatus(port, &ents[i].bytes, &ents[i].key, &ents[i].overlapped,
                                               (i == 0) ? ms : 0);
        if (!r) break;
        got++;
    }
    if (removed) *removed = got;
    return got > 0 ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Thread Pool API
// ---------------------------------------------------------------------------
typedef struct lsw_tp_work_s {
    uint32_t magic;           /* LSW_TPWORK_MAGIC */
    void* callback;           /* PTP_WORK_CALLBACK  (ms_abi) */
    void* callback_param;
    pthread_t thread;
    int submitted;
} lsw_tp_work_impl_t;

static void* _tp_work_thread(void* arg) {
    lsw_tp_work_impl_t* w = (lsw_tp_work_impl_t*)arg;
    typedef void (__attribute__((ms_abi)) *cb_t)(void*, void*, void*);
    cb_t cb = (cb_t)(uintptr_t)w->callback;
    if (cb) cb(NULL, w->callback_param, w);
    return NULL;
}

void* __attribute__((ms_abi)) lsw_CreateThreadpoolWork(void* callback, void* param, void* env) {
    (void)env;
    lsw_tp_work_impl_t* w = calloc(1, sizeof(lsw_tp_work_impl_t));
    w->magic = LSW_TPWORK_MAGIC;
    w->callback = callback;
    w->callback_param = param;
    return w;
}

void __attribute__((ms_abi)) lsw_SubmitThreadpoolWork(void* work) {
    lsw_tp_work_impl_t* w = (lsw_tp_work_impl_t*)work;
    if (!w || w->magic != LSW_TPWORK_MAGIC) return;
    w->submitted = 1;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&w->thread, &attr, _tp_work_thread, w);
    pthread_attr_destroy(&attr);
}

void __attribute__((ms_abi)) lsw_WaitForThreadpoolWorkCallbacks(void* work, int cancel) {
    (void)cancel;
    /* For detached threads we can't join — just yield briefly */
    usleep(10000);
}

void __attribute__((ms_abi)) lsw_CloseThreadpoolWork(void* work) {
    lsw_tp_work_impl_t* w = (lsw_tp_work_impl_t*)work;
    if (!w || w->magic != LSW_TPWORK_MAGIC) return;
    w->magic = 0;
    free(w);
}

void* __attribute__((ms_abi)) lsw_CreateThreadpool(void* env) {
    (void)env; return (void*)(uintptr_t)0x1; /* dummy pool */
}
void __attribute__((ms_abi)) lsw_CloseThreadpool(void* pool) { (void)pool; }
void __attribute__((ms_abi)) lsw_SetThreadpoolThreadMaximum(void* pool, uint32_t max) { (void)pool; (void)max; }
void __attribute__((ms_abi)) lsw_SetThreadpoolThreadMinimum(void* pool, uint32_t min) { (void)pool; (void)min; }

// Thread pool timer (simple timerfd-backed)
void* __attribute__((ms_abi)) lsw_CreateThreadpoolTimer(void* callback, void* param, void* env) {
    (void)env;
    lsw_tp_work_impl_t* w = calloc(1, sizeof(lsw_tp_work_impl_t));
    w->magic = LSW_TPWORK_MAGIC;
    w->callback = callback;
    w->callback_param = param;
    return w;
}
void __attribute__((ms_abi)) lsw_SetThreadpoolTimer(void* timer, const void* ft, uint32_t ms_period, uint32_t ms_window) {
    (void)ft; (void)ms_period; (void)ms_window;
    /* Fire immediately via SubmitThreadpoolWork */
    lsw_SubmitThreadpoolWork(timer);
}
void __attribute__((ms_abi)) lsw_WaitForThreadpoolTimerCallbacks(void* timer, int cancel) { lsw_WaitForThreadpoolWorkCallbacks(timer, cancel); }
void __attribute__((ms_abi)) lsw_CloseThreadpoolTimer(void* timer)  { lsw_CloseThreadpoolWork(timer); }
int  __attribute__((ms_abi)) lsw_IsThreadpoolTimerSet(void* timer)  { lsw_tp_work_impl_t* w = timer; return w && w->submitted; }

void* __attribute__((ms_abi)) lsw_CreateThreadpoolIo(void* file, void* callback, void* param, void* env) {
    (void)file; (void)env;
    lsw_tp_work_impl_t* w = calloc(1, sizeof(lsw_tp_work_impl_t));
    w->magic = LSW_TPWORK_MAGIC; w->callback = callback; w->callback_param = param;
    return w;
}
void __attribute__((ms_abi)) lsw_StartThreadpoolIo(void* io)           { (void)io; }
void __attribute__((ms_abi)) lsw_CancelThreadpoolIo(void* io)          { (void)io; }
void __attribute__((ms_abi)) lsw_WaitForThreadpoolIoCallbacks(void* io, int cancel) { lsw_WaitForThreadpoolWorkCallbacks(io, cancel); }
void __attribute__((ms_abi)) lsw_CloseThreadpoolIo(void* io)           { lsw_CloseThreadpoolWork(io); }
int __attribute__((ms_abi)) lsw_InitOnceExecuteOnce(
    void* once, void* initfn, void* param, void** ctx) {
    // Call initfn unconditionally (no real once guarantee, but correct for most uses)
    typedef int (__attribute__((ms_abi)) *initonce_fn_t)(void*, void*, void**);
    initonce_fn_t fn = (initonce_fn_t)(uintptr_t)initfn;
    if (fn) return fn(once, param, ctx);
    return 0;
}

// SetHandleInformation / GetHandleInformation (stubs)
int __attribute__((ms_abi)) lsw_SetHandleInformation(void* h, uint32_t mask, uint32_t flags) {
    (void)h; (void)mask; (void)flags; return 1;
}
int __attribute__((ms_abi)) lsw_GetHandleInformation(void* h, uint32_t* flags) {
    (void)h; if (flags) *flags = 0; return 1;
}

// Process environment block helpers
void* __attribute__((ms_abi)) lsw_GetCommandLineW(void) {
    // Return a static empty wide string
    static uint16_t empty[2] = {0, 0};
    return (void*)empty;
}

// RtlMoveMemory / RtlFillMemory / RtlZeroMemory (KERNEL32 re-exports of ntdll)
void __attribute__((ms_abi)) lsw_RtlMoveMemory(void* d, const void* s, size_t n) { memmove(d, s, n); }
void __attribute__((ms_abi)) lsw_RtlFillMemory(void* d, size_t n, int c)         { memset(d, c, n); }
void __attribute__((ms_abi)) lsw_RtlZeroMemory(void* d, size_t n)                { memset(d, 0, n); }
void __attribute__((ms_abi)) lsw_ZeroMemory(void* d, size_t n)                   { memset(d, 0, n); }
void __attribute__((ms_abi)) lsw_FillMemory(void* d, size_t n, int c)            { memset(d, c, n); }
void __attribute__((ms_abi)) lsw_CopyMemory(void* d, const void* s, size_t n)    { memcpy(d, s, n); }
void __attribute__((ms_abi)) lsw_MoveMemory(void* d, const void* s, size_t n)    { memmove(d, s, n); }

// MultiByteToWideChar / WideCharToMultiByte already exist; add stubs for
// common CharToOem / OemToChar / CharNext
int __attribute__((ms_abi)) lsw_CharToOemA(const char* src, char* dst) {
    if (src && dst) strcpy(dst, src);
    return 1;
}
int __attribute__((ms_abi)) lsw_OemToCharA(const char* src, char* dst) {
    if (src && dst) strcpy(dst, src);
    return 1;
}

// ============================================================================
// SECTION: Additional KERNEL32 APIs — batch 2
// ============================================================================

// ---- IsWow64Process ----
int __attribute__((ms_abi)) lsw_IsWow64Process(void* hProcess, int* Wow64Process) {
    (void)hProcess;
    if (Wow64Process) *Wow64Process = 0; // We are native 64-bit
    return 1;
}

// ---- FreeLibrary ----
int __attribute__((ms_abi)) lsw_FreeLibrary(void* hLibModule) {
    if (!hLibModule || hLibModule == LSW_SYSTEM_HMODULE) return 1;
    lsw_pe_hmodule_t* pem = (lsw_pe_hmodule_t*)hLibModule;
    if (pem->magic == LSW_PE_HMODULE_MAGIC) {
        if (pem->image_base) munmap(pem->image_base, pem->image_size);
        pem->magic = 0;
        return 1;
    }
    dlclose(hLibModule);
    return 1;
}
void __attribute__((ms_abi)) lsw_FreeLibraryAndExitThread(void* hLibModule, uint32_t dwExitCode) {
    lsw_FreeLibrary(hLibModule);
    pthread_exit((void*)(uintptr_t)dwExitCode);
}
void* __attribute__((ms_abi)) lsw_LoadLibraryExW(const uint16_t* lpLibFileName, void* hFile, uint32_t dwFlags) {
    (void)hFile; (void)dwFlags;
    if (!lpLibFileName) return NULL;
    char narrow[512]; size_t i = 0;
    while (lpLibFileName[i] && i < 511) { narrow[i] = (char)lpLibFileName[i]; i++; }
    narrow[i] = 0;
    return lsw_LoadLibraryA(narrow);
}
int __attribute__((ms_abi)) lsw_GetModuleHandleExW(uint32_t dwFlags, const uint16_t* lpModuleName, void** phModule) {
    (void)dwFlags;
    if (phModule) *phModule = lsw_LoadLibraryExW(lpModuleName, NULL, 0);
    return phModule && *phModule ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_GetModuleHandleExA(uint32_t dwFlags, const char* lpModuleName, void** phModule) {
    (void)dwFlags;
    if (phModule) *phModule = lsw_LoadLibraryA(lpModuleName);
    return phModule && *phModule ? 1 : 0;
}

// ---- Heap management ----
void* __attribute__((ms_abi)) lsw_HeapCreate(uint32_t flOptions, size_t dwInitialSize, size_t dwMaximumSize) {
    (void)flOptions; (void)dwInitialSize; (void)dwMaximumSize;
    return (void*)0xDEADFACE; // fake heap handle
}
int __attribute__((ms_abi)) lsw_HeapDestroy(void* hHeap) {
    (void)hHeap; return 1;
}
int __attribute__((ms_abi)) lsw_HeapValidate(void* hHeap, uint32_t dwFlags, const void* lpMem) {
    (void)hHeap; (void)dwFlags; (void)lpMem; return 1;
}
size_t __attribute__((ms_abi)) lsw_HeapCompact(void* hHeap, uint32_t dwFlags) {
    (void)hHeap; (void)dwFlags; return 0;
}
int __attribute__((ms_abi)) lsw_HeapLock(void* hHeap) { (void)hHeap; return 1; }
int __attribute__((ms_abi)) lsw_HeapUnlock(void* hHeap) { (void)hHeap; return 1; }
int __attribute__((ms_abi)) lsw_HeapWalk(void* hHeap, void* lpEntry) { (void)hHeap; (void)lpEntry; return 0; }
int __attribute__((ms_abi)) lsw_HeapSetInformation(void* hHeap, int HeapInformationClass, void* HeapInformation, size_t HeapInformationLength) {
    (void)hHeap; (void)HeapInformationClass; (void)HeapInformation; (void)HeapInformationLength;
    return 1;
}
int __attribute__((ms_abi)) lsw_HeapQueryInformation(void* hHeap, int HeapInformationClass, void* HeapInformation, size_t HeapInformationLength, size_t* ReturnLength) {
    (void)hHeap; (void)HeapInformationClass; (void)HeapInformation; (void)HeapInformationLength;
    if (ReturnLength) *ReturnLength = 0;
    return 1;
}

// ---- TLS (Thread Local Storage) ----
// Slot 0 reserved; real TLS via pthread keys
#define LSW_TLS_MAX 128
static pthread_key_t lsw_tls_keys[LSW_TLS_MAX];
static int           lsw_tls_used[LSW_TLS_MAX];
static int           lsw_tls_once_done = 0;
static pthread_mutex_t lsw_tls_lock = PTHREAD_MUTEX_INITIALIZER;

static void lsw_tls_init(void) {
    for (int i = 0; i < LSW_TLS_MAX; i++) lsw_tls_used[i] = 0;
    lsw_tls_once_done = 1;
}

uint32_t __attribute__((ms_abi)) lsw_TlsAlloc(void) {
    pthread_mutex_lock(&lsw_tls_lock);
    if (!lsw_tls_once_done) lsw_tls_init();
    for (int i = 0; i < LSW_TLS_MAX; i++) {
        if (!lsw_tls_used[i]) {
            if (pthread_key_create(&lsw_tls_keys[i], NULL) == 0) {
                lsw_tls_used[i] = 1;
                pthread_mutex_unlock(&lsw_tls_lock);
                LSW_LOG_DEBUG("TlsAlloc -> slot %d", i);
                return (uint32_t)i;
            }
        }
    }
    pthread_mutex_unlock(&lsw_tls_lock);
    return 0xFFFFFFFF; // TLS_OUT_OF_INDEXES
}
int __attribute__((ms_abi)) lsw_TlsFree(uint32_t dwTlsIndex) {
    if (dwTlsIndex >= LSW_TLS_MAX) return 0;
    pthread_mutex_lock(&lsw_tls_lock);
    if (lsw_tls_used[dwTlsIndex]) {
        pthread_key_delete(lsw_tls_keys[dwTlsIndex]);
        lsw_tls_used[dwTlsIndex] = 0;
    }
    pthread_mutex_unlock(&lsw_tls_lock);
    return 1;
}
int __attribute__((ms_abi)) lsw_TlsSetValue(uint32_t dwTlsIndex, void* lpTlsValue) {
    if (dwTlsIndex >= LSW_TLS_MAX || !lsw_tls_used[dwTlsIndex]) return 0;
    return pthread_setspecific(lsw_tls_keys[dwTlsIndex], lpTlsValue) == 0 ? 1 : 0;
}
void* __attribute__((ms_abi)) lsw_TlsGetValueEx(uint32_t dwTlsIndex) {
    if (dwTlsIndex >= LSW_TLS_MAX || !lsw_tls_used[dwTlsIndex]) return NULL;
    return pthread_getspecific(lsw_tls_keys[dwTlsIndex]);
}

// ---- CompareString ----
int __attribute__((ms_abi)) lsw_CompareStringW(uint32_t Locale, uint32_t dwCmpFlags, const uint16_t* lpString1, int cchCount1, const uint16_t* lpString2, int cchCount2) {
    (void)Locale; (void)dwCmpFlags;
    if (!lpString1 || !lpString2) return 0; // CSTR_ERROR
    // Convert to narrow and compare
    char s1[1024], s2[1024];
    int i = 0;
    while (lpString1[i] && (cchCount1 < 0 || i < cchCount1) && i < 1023) { s1[i]=(char)lpString1[i]; i++; } s1[i]=0;
    i = 0;
    while (lpString2[i] && (cchCount2 < 0 || i < cchCount2) && i < 1023) { s2[i]=(char)lpString2[i]; i++; } s2[i]=0;
    int r;
    if (dwCmpFlags & 0x1) // NORM_IGNORECASE
        r = strcasecmp(s1, s2);
    else
        r = strcmp(s1, s2);
    return (r < 0) ? 1 : (r == 0) ? 2 : 3; // CSTR_LESS_THAN=1, CSTR_EQUAL=2, CSTR_GREATER_THAN=3
}
int __attribute__((ms_abi)) lsw_CompareStringA(uint32_t Locale, uint32_t dwCmpFlags, const char* lpString1, int cchCount1, const char* lpString2, int cchCount2) {
    (void)Locale;
    if (!lpString1 || !lpString2) return 0;
    int r;
    if (dwCmpFlags & 0x1)
        r = strncasecmp(lpString1, lpString2, (cchCount1 < 0 || cchCount2 < 0) ? (size_t)-1 : (size_t)(cchCount1 < cchCount2 ? cchCount2 : cchCount1));
    else
        r = strncmp(lpString1, lpString2, (cchCount1 < 0 || cchCount2 < 0) ? (size_t)-1 : (size_t)(cchCount1 < cchCount2 ? cchCount2 : cchCount1));
    return (r < 0) ? 1 : (r == 0) ? 2 : 3;
}
int __attribute__((ms_abi)) lsw_CompareStringEx(void* lpLocaleName, uint32_t dwCmpFlags, const uint16_t* lpString1, int cchCount1, const uint16_t* lpString2, int cchCount2, void* lpVersionInformation, void* lpReserved, int32_t lParam) {
    (void)lpLocaleName; (void)lpVersionInformation; (void)lpReserved; (void)lParam;
    return lsw_CompareStringW(0x0409, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
}
int __attribute__((ms_abi)) lsw_CompareStringOrdinal(const uint16_t* lpString1, int cchCount1, const uint16_t* lpString2, int cchCount2, int bIgnoreCase) {
    uint32_t flags = bIgnoreCase ? 0x1 : 0x0;
    return lsw_CompareStringW(0, flags, lpString1, cchCount1, lpString2, cchCount2);
}
int __attribute__((ms_abi)) lsw_lstrcmpA(const char* lpString1, const char* lpString2) {
    if (!lpString1 || !lpString2) return 0;
    return strcmp(lpString1, lpString2);
}
int __attribute__((ms_abi)) lsw_lstrcmpiA(const char* lpString1, const char* lpString2) {
    if (!lpString1 || !lpString2) return 0;
    return strcasecmp(lpString1, lpString2);
}
int __attribute__((ms_abi)) lsw_lstrcmpW(const uint16_t* lpString1, const uint16_t* lpString2) {
    return lsw_CompareStringW(0, 0, lpString1, -1, lpString2, -1) - 2;
}
int __attribute__((ms_abi)) lsw_lstrcmpiW(const uint16_t* lpString1, const uint16_t* lpString2) {
    return lsw_CompareStringW(0, 1, lpString1, -1, lpString2, -1) - 2;
}
int __attribute__((ms_abi)) lsw_lstrcpyA(char* lpString1, const char* lpString2) {
    if (lpString1 && lpString2) strcpy(lpString1, lpString2);
    return 1;
}
int __attribute__((ms_abi)) lsw_lstrcpynA(char* lpString1, const char* lpString2, int iMaxLength) {
    if (lpString1 && lpString2 && iMaxLength > 0) { strncpy(lpString1, lpString2, (size_t)iMaxLength-1); lpString1[iMaxLength-1]=0; }
    return 1;
}
/* lsw_lstrlenA already defined earlier — skip duplicate */
int __attribute__((ms_abi)) lsw_lstrlenW(const uint16_t* lpString) {
    if (!lpString) return 0;
    int n = 0; while (lpString[n]) n++; return n;
}

// ---- SystemParametersInfo ----
int __attribute__((ms_abi)) lsw_SystemParametersInfoW(uint32_t uiAction, uint32_t uiParam, void* pvParam, uint32_t fWinIni) {
    (void)uiParam; (void)fWinIni;
    // SPI_GETWORKAREA=48: fill RECT with (0,0,1920,1080)
    if (uiAction == 48 && pvParam) {
        int32_t* r = (int32_t*)pvParam;
        r[0]=0; r[1]=0; r[2]=1920; r[3]=1080;
        return 1;
    }
    // SPI_GETNONCLIENTMETRICS=41: partially fill
    if (uiAction == 41 && pvParam) {
        memset(pvParam, 0, uiParam > 0 ? uiParam : 500);
        return 1;
    }
    // SPI_GETICONTITLELOGFONT=31: fill with default font info
    if (uiAction == 31 && pvParam) {
        memset(pvParam, 0, 92); // sizeof LOGFONTW
        return 1;
    }
    return 1;
}
int __attribute__((ms_abi)) lsw_SystemParametersInfoA(uint32_t uiAction, uint32_t uiParam, void* pvParam, uint32_t fWinIni) {
    return lsw_SystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
}

// ---- TryAcquireSRWLock ----
int __attribute__((ms_abi)) lsw_TryAcquireSRWLockExclusive(void** lock) {
    if (!lock || !*lock) return 0;
    return pthread_mutex_trylock((pthread_mutex_t*)*lock) == 0 ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_TryAcquireSRWLockShared(void** lock) {
    if (!lock || !*lock) return 0;
    return pthread_mutex_trylock((pthread_mutex_t*)*lock) == 0 ? 1 : 0;
}

// ---- More file mapping ----
void* __attribute__((ms_abi)) lsw_OpenFileMappingW(uint32_t dwDesiredAccess, int bInheritHandle, const uint16_t* lpName) {
    (void)dwDesiredAccess; (void)bInheritHandle; (void)lpName;
    return NULL; // Named mappings not supported
}
void* __attribute__((ms_abi)) lsw_OpenFileMappingA(uint32_t dwDesiredAccess, int bInheritHandle, const char* lpName) {
    (void)dwDesiredAccess; (void)bInheritHandle; (void)lpName;
    return NULL;
}
void* __attribute__((ms_abi)) lsw_CreateFileMappingA(void* hFile, void* lpFileMappingAttributes, uint32_t flProtect, uint32_t dwMaximumSizeHigh, uint32_t dwMaximumSizeLow, const char* lpName) {
    (void)lpName; (void)hFile; (void)lpFileMappingAttributes; (void)flProtect;
    // Convert and delegate to W version
    size_t size = ((size_t)dwMaximumSizeHigh << 32) | dwMaximumSizeLow;
    if (size == 0) size = 4096;
    typedef struct { void* base; size_t size; } lsw_file_mapping_t;
    lsw_file_mapping_t* fm = (lsw_file_mapping_t*)malloc(sizeof(*fm));
    if (!fm) return NULL;
    fm->base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (fm->base == MAP_FAILED) { free(fm); return NULL; }
    fm->size = size;
    return fm;
}
void* __attribute__((ms_abi)) lsw_MapViewOfFileEx(void* hFileMappingObject, uint32_t dwDesiredAccess, uint32_t dwFileOffsetHigh, uint32_t dwFileOffsetLow, size_t dwNumberOfBytesToMap, void* lpBaseAddress) {
    (void)dwDesiredAccess; (void)lpBaseAddress;
    typedef struct { void* base; size_t size; } lsw_file_mapping_t;
    lsw_file_mapping_t* fm = (lsw_file_mapping_t*)hFileMappingObject;
    if (!fm) return NULL;
    size_t offset = ((size_t)dwFileOffsetHigh << 32) | dwFileOffsetLow;
    size_t bytes = dwNumberOfBytesToMap ? dwNumberOfBytesToMap : fm->size;
    (void)offset;
    return fm->base;
}
int __attribute__((ms_abi)) lsw_FlushViewOfFile(const void* lpBaseAddress, size_t dwNumberOfBytesToFlush) {
    (void)lpBaseAddress; (void)dwNumberOfBytesToFlush; return 1;
}
int __attribute__((ms_abi)) lsw_FlushFileBuffers(void* hFile) { (void)hFile; return 1; }

// ---- GetFileSizeEx / SetEndOfFile / LockFile ----
int __attribute__((ms_abi)) lsw_GetFileSizeEx(void* hFile, void* lpFileSize) {
    if (!hFile || !lpFileSize) return 0;
    int fd = (int)(uintptr_t)hFile - 1;
    struct stat st;
    if (fstat(fd, &st) != 0) { *(int64_t*)lpFileSize = 0; return 0; }
    *(int64_t*)lpFileSize = (int64_t)st.st_size;
    return 1;
}
int __attribute__((ms_abi)) lsw_SetEndOfFile(void* hFile) {
    if (!hFile) return 0;
    int fd = (int)(uintptr_t)hFile - 1;
    off_t pos = lseek(fd, 0, SEEK_CUR);
    return ftruncate(fd, pos) == 0 ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_LockFile(void* hFile, uint32_t dwFileOffsetLow, uint32_t dwFileOffsetHigh, uint32_t nNumberOfBytesToLockLow, uint32_t nNumberOfBytesToLockHigh) {
    (void)hFile; (void)dwFileOffsetLow; (void)dwFileOffsetHigh; (void)nNumberOfBytesToLockLow; (void)nNumberOfBytesToLockHigh;
    return 1; // Stub: no-op
}
int __attribute__((ms_abi)) lsw_UnlockFile(void* hFile, uint32_t dwFileOffsetLow, uint32_t dwFileOffsetHigh, uint32_t nNumberOfBytesToUnlockLow, uint32_t nNumberOfBytesToUnlockHigh) {
    (void)hFile; (void)dwFileOffsetLow; (void)dwFileOffsetHigh; (void)nNumberOfBytesToUnlockLow; (void)nNumberOfBytesToUnlockHigh;
    return 1;
}
int __attribute__((ms_abi)) lsw_LockFileEx(void* hFile, uint32_t dwFlags, uint32_t dwReserved, uint32_t nNumberOfBytesToLockLow, uint32_t nNumberOfBytesToLockHigh, void* lpOverlapped) {
    (void)hFile; (void)dwFlags; (void)dwReserved; (void)nNumberOfBytesToLockLow; (void)nNumberOfBytesToLockHigh; (void)lpOverlapped;
    return 1;
}
int __attribute__((ms_abi)) lsw_UnlockFileEx(void* hFile, uint32_t dwReserved, uint32_t nNumberOfBytesToUnlockLow, uint32_t nNumberOfBytesToUnlockHigh, void* lpOverlapped) {
    (void)hFile; (void)dwReserved; (void)nNumberOfBytesToUnlockLow; (void)nNumberOfBytesToUnlockHigh; (void)lpOverlapped;
    return 1;
}
int __attribute__((ms_abi)) lsw_SetFilePointerEx(void* hFile, int64_t liDistanceToMove, int64_t* lpNewFilePointer, uint32_t dwMoveMethod) {
    if (!hFile) return 0;
    int fd = (int)(uintptr_t)hFile - 1;
    int whence = (dwMoveMethod == 0) ? SEEK_SET : (dwMoveMethod == 1) ? SEEK_CUR : SEEK_END;
    off_t result = lseek(fd, (off_t)liDistanceToMove, whence);
    if (result == (off_t)-1) return 0;
    if (lpNewFilePointer) *lpNewFilePointer = (int64_t)result;
    return 1;
}

// ---- GetFileTime / SetFileTime / GetFileInformationByHandle ----
int __attribute__((ms_abi)) lsw_GetFileTime(void* hFile, void* lpCreationTime, void* lpLastAccessTime, void* lpLastWriteTime) {
    if (!hFile) return 0;
    int fd = (int)(uintptr_t)hFile - 1;
    struct stat st;
    if (fstat(fd, &st) != 0) return 0;
    // Convert Unix time to FILETIME (100ns intervals since 1601-01-01)
    uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t mtime = (uint64_t)st.st_mtime * 10000000ULL + epoch_offset;
    if (lpCreationTime)  *(uint64_t*)lpCreationTime  = mtime;
    if (lpLastAccessTime) *(uint64_t*)lpLastAccessTime = mtime;
    if (lpLastWriteTime)  *(uint64_t*)lpLastWriteTime  = mtime;
    return 1;
}
int __attribute__((ms_abi)) lsw_SetFileTime(void* hFile, const void* lpCreationTime, const void* lpLastAccessTime, const void* lpLastWriteTime) {
    (void)hFile; (void)lpCreationTime; (void)lpLastAccessTime; (void)lpLastWriteTime;
    return 1; // Stub
}
int __attribute__((ms_abi)) lsw_GetFileInformationByHandle(void* hFile, void* lpFileInformation) {
    if (!hFile || !lpFileInformation) return 0;
    int fd = (int)(uintptr_t)hFile - 1;
    struct stat st;
    if (fstat(fd, &st) != 0) return 0;
    // BY_HANDLE_FILE_INFORMATION layout (80 bytes):
    uint32_t* p = (uint32_t*)lpFileInformation;
    uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t mtime = (uint64_t)st.st_mtime * 10000000ULL + epoch_offset;
    p[0] = S_ISDIR(st.st_mode) ? 0x10 : 0x80; // dwFileAttributes
    *(uint64_t*)(p+1) = mtime;   // ftCreationTime
    *(uint64_t*)(p+3) = mtime;   // ftLastAccessTime
    *(uint64_t*)(p+5) = mtime;   // ftLastWriteTime
    p[7] = (uint32_t)st.st_dev;  // dwVolumeSerialNumber
    p[8] = (uint32_t)(st.st_size & 0xFFFFFFFF);  // nFileSizeLow
    p[9] = (uint32_t)(st.st_size >> 32);         // nFileSizeHigh
    p[10] = 1; // nNumberOfLinks
    p[11] = (uint32_t)(st.st_ino & 0xFFFFFFFF);
    p[12] = (uint32_t)(st.st_ino >> 32);
    return 1;
}
int __attribute__((ms_abi)) lsw_GetFileInformationByHandleEx(void* hFile, int FileInformationClass, void* lpFileInformation, uint32_t dwBufferSize) {
    (void)hFile; (void)FileInformationClass; (void)dwBufferSize;
    if (lpFileInformation) memset(lpFileInformation, 0, dwBufferSize > 0 ? dwBufferSize : 16);
    return 0;
}

// ---- GetFileAttributesExW/A ----
int __attribute__((ms_abi)) lsw_GetFileAttributesExW(const uint16_t* lpFileName, int fInfoLevelId, void* lpFileInformation) {
    (void)fInfoLevelId;
    if (!lpFileName || !lpFileInformation) return 0;
    char path[4096]; int i=0;
    while (lpFileName[i] && i<4095) { path[i]=(char)lpFileName[i]; i++; } path[i]=0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    uint32_t* p = (uint32_t*)lpFileInformation;
    p[0] = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
    uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t mtime = (uint64_t)st.st_mtime * 10000000ULL + epoch_offset;
    *(uint64_t*)(p+1) = mtime; *(uint64_t*)(p+3) = mtime; *(uint64_t*)(p+5) = mtime;
    p[7] = (uint32_t)(st.st_size & 0xFFFFFFFF);
    p[8] = (uint32_t)(st.st_size >> 32);
    return 1;
}
int __attribute__((ms_abi)) lsw_GetFileAttributesExA(const char* lpFileName, int fInfoLevelId, void* lpFileInformation) {
    (void)fInfoLevelId;
    if (!lpFileName || !lpFileInformation) return 0;
    struct stat st;
    if (stat(lpFileName, &st) != 0) return 0;
    uint32_t* p = (uint32_t*)lpFileInformation;
    p[0] = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
    uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t mtime = (uint64_t)st.st_mtime * 10000000ULL + epoch_offset;
    *(uint64_t*)(p+1) = mtime; *(uint64_t*)(p+3) = mtime; *(uint64_t*)(p+5) = mtime;
    p[7] = (uint32_t)(st.st_size & 0xFFFFFFFF);
    p[8] = (uint32_t)(st.st_size >> 32);
    return 1;
}

// ---- Volume/Drive info ----
int __attribute__((ms_abi)) lsw_GetVolumeInformationW(const uint16_t* lpRootPathName, uint16_t* lpVolumeNameBuffer, uint32_t nVolumeNameSize, uint32_t* lpVolumeSerialNumber, uint32_t* lpMaximumComponentLength, uint32_t* lpFileSystemFlags, uint16_t* lpFileSystemNameBuffer, uint32_t nFileSystemNameSize) {
    (void)lpRootPathName;
    if (lpVolumeNameBuffer && nVolumeNameSize > 3) { lpVolumeNameBuffer[0]='L'; lpVolumeNameBuffer[1]='S'; lpVolumeNameBuffer[2]='W'; lpVolumeNameBuffer[3]=0; }
    if (lpVolumeSerialNumber)       *lpVolumeSerialNumber = 0xDEADBEEF;
    if (lpMaximumComponentLength)   *lpMaximumComponentLength = 255;
    if (lpFileSystemFlags)          *lpFileSystemFlags = 0x00000003; // case-sensitive + preserves case
    if (lpFileSystemNameBuffer && nFileSystemNameSize > 5) { lpFileSystemNameBuffer[0]='e'; lpFileSystemNameBuffer[1]='x'; lpFileSystemNameBuffer[2]='t'; lpFileSystemNameBuffer[3]='4'; lpFileSystemNameBuffer[4]=0; }
    return 1;
}
int __attribute__((ms_abi)) lsw_GetVolumeInformationA(const char* lpRootPathName, char* lpVolumeNameBuffer, uint32_t nVolumeNameSize, uint32_t* lpVolumeSerialNumber, uint32_t* lpMaximumComponentLength, uint32_t* lpFileSystemFlags, char* lpFileSystemNameBuffer, uint32_t nFileSystemNameSize) {
    (void)lpRootPathName;
    if (lpVolumeNameBuffer && nVolumeNameSize > 3) strcpy(lpVolumeNameBuffer, "LSW");
    if (lpVolumeSerialNumber)       *lpVolumeSerialNumber = 0xDEADBEEF;
    if (lpMaximumComponentLength)   *lpMaximumComponentLength = 255;
    if (lpFileSystemFlags)          *lpFileSystemFlags = 3;
    if (lpFileSystemNameBuffer && nFileSystemNameSize > 4) strcpy(lpFileSystemNameBuffer, "ext4");
    return 1;
}
uint32_t __attribute__((ms_abi)) lsw_GetDriveTypeW(const uint16_t* lpRootPathName) {
    (void)lpRootPathName; return 3; // DRIVE_FIXED
}
uint32_t __attribute__((ms_abi)) lsw_GetDriveTypeA(const char* lpRootPathName) {
    (void)lpRootPathName; return 3;
}
uint32_t __attribute__((ms_abi)) lsw_GetLogicalDrives(void) { return 0x4; } // 'C' drive bit
uint32_t __attribute__((ms_abi)) lsw_GetLogicalDriveStringsW(uint32_t nBufferLength, uint16_t* lpBuffer) {
    if (lpBuffer && nBufferLength >= 6) {
        lpBuffer[0]='C'; lpBuffer[1]=':'; lpBuffer[2]='\\'; lpBuffer[3]=0;
        lpBuffer[4]=0;
    }
    return 4; // "C:\0\0" = 4 wide chars
}
uint32_t __attribute__((ms_abi)) lsw_GetLogicalDriveStringsA(uint32_t nBufferLength, char* lpBuffer) {
    if (lpBuffer && nBufferLength >= 5) { memcpy(lpBuffer, "C:\\\0\0", 5); }
    return 4;
}
int __attribute__((ms_abi)) lsw_GetDiskFreeSpaceExW(const uint16_t* lpDirectoryName, void* lpFreeBytesAvailableToCaller, void* lpTotalNumberOfBytes, void* lpTotalNumberOfFreeBytes) {
    (void)lpDirectoryName;
    struct statvfs sv;
    statvfs("/", &sv);
    uint64_t free_b = (uint64_t)sv.f_bavail * sv.f_bsize;
    uint64_t total_b = (uint64_t)sv.f_blocks * sv.f_bsize;
    if (lpFreeBytesAvailableToCaller) *(uint64_t*)lpFreeBytesAvailableToCaller = free_b;
    if (lpTotalNumberOfBytes)         *(uint64_t*)lpTotalNumberOfBytes = total_b;
    if (lpTotalNumberOfFreeBytes)     *(uint64_t*)lpTotalNumberOfFreeBytes = free_b;
    return 1;
}
int __attribute__((ms_abi)) lsw_GetDiskFreeSpaceExA(const char* lpDirectoryName, void* lpFreeBytesAvailableToCaller, void* lpTotalNumberOfBytes, void* lpTotalNumberOfFreeBytes) {
    (void)lpDirectoryName;
    return lsw_GetDiskFreeSpaceExW(NULL, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
}
int __attribute__((ms_abi)) lsw_GetDiskFreeSpaceW(const uint16_t* lpRootPathName, uint32_t* lpSectorsPerCluster, uint32_t* lpBytesPerSector, uint32_t* lpNumberOfFreeClusters, uint32_t* lpTotalNumberOfClusters) {
    (void)lpRootPathName;
    if (lpSectorsPerCluster)     *lpSectorsPerCluster = 8;
    if (lpBytesPerSector)        *lpBytesPerSector = 512;
    if (lpNumberOfFreeClusters)  *lpNumberOfFreeClusters = 1024*1024;
    if (lpTotalNumberOfClusters) *lpTotalNumberOfClusters = 4*1024*1024;
    return 1;
}

// ---- CriticalSection extras ----
int __attribute__((ms_abi)) lsw_InitializeCriticalSectionAndSpinCount(void* lpCriticalSection, uint32_t dwSpinCount) {
    (void)dwSpinCount;
    lsw_InitializeCriticalSection(lpCriticalSection);
    return 1;
}
int __attribute__((ms_abi)) lsw_InitializeCriticalSectionEx(void* lpCriticalSection, uint32_t dwSpinCount, uint32_t Flags) {
    (void)dwSpinCount; (void)Flags;
    lsw_InitializeCriticalSection(lpCriticalSection);
    return 1;
}
/* lsw_TryEnterCriticalSection already defined earlier — skip duplicate */
int __attribute__((ms_abi)) lsw_SetCriticalSectionSpinCount(void* lpCriticalSection, uint32_t dwSpinCount) {
    (void)lpCriticalSection; (void)dwSpinCount; return 0;
}

// ---- Thread extras ----
int __attribute__((ms_abi)) lsw_SuspendThread(void* hThread) { (void)hThread; return 0xFFFFFFFF; }
int __attribute__((ms_abi)) lsw_ResumeThread(void* hThread) { (void)hThread; return 1; }
int __attribute__((ms_abi)) lsw_TerminateThread(void* hThread, uint32_t dwExitCode) { (void)hThread; (void)dwExitCode; return 1; }
int __attribute__((ms_abi)) lsw_TerminateProcess(void* hProcess, uint32_t uExitCode) {
    pid_t pid = (pid_t)(uintptr_t)hProcess;
    /* If handle looks like a PID (1..65535) send SIGKILL to it */
    if (pid > 1 && pid < 65536 && pid != getpid()) {
        kill(pid, SIGKILL);
        return 1;
    }
    exit((int)uExitCode);
    return 1;
}
int __attribute__((ms_abi)) lsw_GetExitCodeThread(void* hThread, uint32_t* lpExitCode) { (void)hThread; if (lpExitCode) *lpExitCode = 0; return 1; }
int __attribute__((ms_abi)) lsw_GetExitCodeProcess(void* hProcess, uint32_t* lpExitCode) {
    pid_t pid = (pid_t)(uintptr_t)hProcess;
    if (lpExitCode) *lpExitCode = 259; /* STILL_ACTIVE */
    if (pid > 1 && pid < 65536) {
        int wstatus = 0;
        pid_t r = waitpid(pid, &wstatus, WNOHANG);
        if (r == pid && lpExitCode) {
            *lpExitCode = WIFEXITED(wstatus) ? (uint32_t)WEXITSTATUS(wstatus) : 1;
        }
    }
    return 1;
}
void* __attribute__((ms_abi)) lsw_OpenThread(uint32_t dwDesiredAccess, int bInheritHandle, uint32_t dwThreadId) { (void)dwDesiredAccess; (void)bInheritHandle; (void)dwThreadId; return (void*)0xF001; }
void* __attribute__((ms_abi)) lsw_OpenProcess(uint32_t dwDesiredAccess, int bInheritHandle, uint32_t dwProcessId) {
    (void)dwDesiredAccess; (void)bInheritHandle;
    /* Return PID as handle so WaitForSingleObject / TerminateProcess work */
    return (void*)(uintptr_t)(uint64_t)dwProcessId;
}
uint32_t __attribute__((ms_abi)) lsw_GetProcessId(void* Process) { (void)Process; return (uint32_t)getpid(); }
uint32_t __attribute__((ms_abi)) lsw_GetThreadId(void* Thread) { (void)Thread; return (uint32_t)(uintptr_t)pthread_self(); }
int __attribute__((ms_abi)) lsw_SetThreadPriority(void* hThread, int nPriority) { (void)hThread; (void)nPriority; return 1; }
int __attribute__((ms_abi)) lsw_GetThreadPriority(void* hThread) { (void)hThread; return 0; } // THREAD_PRIORITY_NORMAL
int __attribute__((ms_abi)) lsw_SetThreadPriorityBoost(void* hThread, int DisablePriorityBoost) { (void)hThread; (void)DisablePriorityBoost; return 1; }
uint64_t __attribute__((ms_abi)) lsw_SetThreadAffinityMask(void* hThread, uint64_t dwThreadAffinityMask) { (void)hThread; return dwThreadAffinityMask; }
int __attribute__((ms_abi)) lsw_SleepEx(uint32_t dwMilliseconds, int bAlertable) { (void)bAlertable; usleep(dwMilliseconds * 1000); return 0; }
int __attribute__((ms_abi)) lsw_SwitchToThread(void) { sched_yield(); return 1; }
int __attribute__((ms_abi)) lsw_Beep(uint32_t dwFreq, uint32_t dwDuration) { (void)dwFreq; (void)dwDuration; return 1; }

// ---- CreatePipe ----
int __attribute__((ms_abi)) lsw_CreatePipe(void** hReadPipe, void** hWritePipe, void* lpPipeAttributes, uint32_t nSize) {
    (void)lpPipeAttributes; (void)nSize;
    int pfd[2];
    if (pipe(pfd) != 0) return 0;
    if (hReadPipe)  *hReadPipe  = (void*)(uintptr_t)(pfd[0] + 1);
    if (hWritePipe) *hWritePipe = (void*)(uintptr_t)(pfd[1] + 1);
    return 1;
}
/*
 * Named pipe implementation via Unix domain sockets.
 * \\.\pipe\foo  →  /tmp/lsw-pipes/foo
 * Pipe handles: server side returns a listening socket fd;
 * on ConnectNamedPipe we accept() one client.
 * Client side (OpenFile/CreateFile on \\.\pipe\foo) connects to the socket.
 */
/* LSW_PIPE_DIR/MAGIC + lsw_pipe_t defined at top of file */
#define LSW_PIPE_DIR "/tmp/lsw-pipes"

static lsw_pipe_t g_pipes[64];
static int        g_pipe_count = 0;
static pthread_mutex_t g_pipe_lock = PTHREAD_MUTEX_INITIALIZER;

/* Translate \\.\pipe\foo -> /tmp/lsw-pipes/foo */
static void pipe_win_to_unix(const char* wname, char* out, size_t outsz) {
    /* Skip \\.\pipe\ prefix */
    const char* p = wname;
    if (p[0]=='\\' && p[1]=='\\') {
        p = strchr(p+2, '\\'); /* skip server part */
        if (p) p++;
        if (p && strncasecmp(p, "pipe\\", 5) == 0) p += 5;
        else if (p && strncasecmp(p, "pipe/", 5) == 0) p += 5;
    } else if (strncasecmp(p, "\\\\.\\pipe\\", 9) == 0) {
        p += 9;
    }
    if (!p || !*p) p = wname;
    /* Sanitize: replace backslashes with underscores */
    char name[64]; snprintf(name, sizeof(name), "%s", p);
    for (char* c = name; *c; c++) if (*c == '\\' || *c == '/') *c = '_';
    mkdir(LSW_PIPE_DIR, 0700);
    snprintf(out, outsz, "%s/%s", LSW_PIPE_DIR, name);
}

static lsw_pipe_t* alloc_pipe(void) {
    pthread_mutex_lock(&g_pipe_lock);
    lsw_pipe_t* h = NULL;
    for (int i = 0; i < 64; i++) {
        if (g_pipes[i].magic != LSW_PIPE_MAGIC) { h = &g_pipes[i]; break; }
    }
    if (h) { memset(h, 0, sizeof(*h)); h->magic = LSW_PIPE_MAGIC; h->listen_fd = -1; h->client_fd = -1; }
    pthread_mutex_unlock(&g_pipe_lock);
    return h;
}

void* __attribute__((ms_abi)) lsw_CreateNamedPipeA(const char* lpName,
    uint32_t dwOpenMode, uint32_t dwPipeMode, uint32_t nMaxInstances,
    uint32_t nOutBufferSize, uint32_t nInBufferSize, uint32_t nDefaultTimeOut,
    void* lpSecurityAttributes)
{
    (void)dwOpenMode; (void)dwPipeMode; (void)nMaxInstances;
    (void)nOutBufferSize; (void)nInBufferSize; (void)nDefaultTimeOut; (void)lpSecurityAttributes;
    if (!lpName) return (void*)-1;

    lsw_pipe_t* p = alloc_pipe();
    if (!p) return (void*)-1;

    pipe_win_to_unix(lpName, p->path, sizeof(p->path));
    unlink(p->path); /* remove stale socket */

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) { p->magic = 0; return (void*)-1; }

    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, p->path, sizeof(addr.sun_path)-1);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(sfd, 4) < 0) {
        close(sfd); p->magic = 0; return (void*)-1;
    }
    p->listen_fd = sfd;
    LSW_LOG_INFO("CreateNamedPipeA: %s -> %s (fd=%d)", lpName, p->path, sfd);
    return (void*)p;
}

void* __attribute__((ms_abi)) lsw_CreateNamedPipeW(const uint16_t* lpName,
    uint32_t dwOpenMode, uint32_t dwPipeMode, uint32_t nMaxInstances,
    uint32_t nOutBufferSize, uint32_t nInBufferSize, uint32_t nDefaultTimeOut,
    void* lpSecurityAttributes)
{
    char name[256]; wcstombs(name, (const wchar_t*)lpName, sizeof(name));
    return lsw_CreateNamedPipeA(name, dwOpenMode, dwPipeMode, nMaxInstances,
        nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
}

int __attribute__((ms_abi)) lsw_ConnectNamedPipe(void* hNamedPipe, void* lpOverlapped) {
    (void)lpOverlapped;
    lsw_pipe_t* p = (lsw_pipe_t*)hNamedPipe;
    if (!p || p->magic != LSW_PIPE_MAGIC || p->listen_fd < 0) return 0;
    int cfd = accept(p->listen_fd, NULL, NULL);
    if (cfd < 0) return 0;
    p->client_fd = cfd;
    LSW_LOG_INFO("ConnectNamedPipe: accepted client fd=%d on %s", cfd, p->path);
    return 1;
}

int __attribute__((ms_abi)) lsw_DisconnectNamedPipe(void* hNamedPipe) {
    lsw_pipe_t* p = (lsw_pipe_t*)hNamedPipe;
    if (!p || p->magic != LSW_PIPE_MAGIC) return 1;
    if (p->client_fd >= 0) { close(p->client_fd); p->client_fd = -1; }
    return 1;
}

void* __attribute__((ms_abi)) lsw_OpenNamedPipeA(const char* lpName, uint32_t dwDesiredAccess) {
    (void)dwDesiredAccess;
    if (!lpName) return (void*)-1;
    lsw_pipe_t* p = alloc_pipe();
    if (!p) return (void*)-1;
    pipe_win_to_unix(lpName, p->path, sizeof(p->path));
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) { p->magic = 0; return (void*)-1; }
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, p->path, sizeof(addr.sun_path)-1);
    if (connect(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sfd); p->magic = 0; return (void*)-1;
    }
    p->client_fd = sfd; /* client uses client_fd for I/O */
    LSW_LOG_INFO("OpenNamedPipe(client): %s fd=%d", p->path, sfd);
    return (void*)p;
}

int __attribute__((ms_abi)) lsw_WaitNamedPipeA(const char* lpNamedPipeName, uint32_t nTimeOut) {
    (void)nTimeOut;
    char path[256]; pipe_win_to_unix(lpNamedPipeName, path, sizeof(path));
    /* Poll until socket file exists, up to nTimeOut ms */
    uint32_t waited = 0;
    uint32_t step = 50;
    while (access(path, F_OK) != 0) {
        if (nTimeOut != 0xFFFFFFFF && waited >= nTimeOut) return 0;
        usleep(step * 1000);
        waited += step;
    }
    return 1;
}

int __attribute__((ms_abi)) lsw_WaitNamedPipeW(const uint16_t* n, uint32_t t) {
    char name[256]; wcstombs(name, (const wchar_t*)n, sizeof(name));
    return lsw_WaitNamedPipeA(name, t);
}

/* Read/Write on named pipe handles route through the client_fd */
static int pipe_handle_fd(void* handle) {
    lsw_pipe_t* p = (lsw_pipe_t*)handle;
    if (p && p->magic == LSW_PIPE_MAGIC) {
        return p->client_fd >= 0 ? p->client_fd : -1;
    }
    return -1;
}

int __attribute__((ms_abi)) lsw_CallNamedPipeW(const uint16_t* lpName,
    void* lpInBuffer, uint32_t nInBufferSize,
    void* lpOutBuffer, uint32_t nOutBufferSize,
    uint32_t* lpBytesRead, uint32_t nTimeOut)
{
    char name[256]; wcstombs(name, (const wchar_t*)lpName, sizeof(name));
    if (!lsw_WaitNamedPipeA(name, nTimeOut)) return 0;
    void* h = lsw_OpenNamedPipeA(name, 0);
    if (!h || h == (void*)-1) return 0;
    uint32_t written = 0;
    lsw_WriteFile(h, lpInBuffer, nInBufferSize, &written, NULL);
    uint32_t nread = 0;
    int r = lsw_ReadFile(h, lpOutBuffer, nOutBufferSize, &nread, NULL);
    if (lpBytesRead) *lpBytesRead = nread;
    /* Close the transient handle */
    lsw_pipe_t* p = (lsw_pipe_t*)h;
    if (p->client_fd >= 0) close(p->client_fd);
    p->magic = 0;
    return r;
}


// ---- Console extra APIs ----
uint32_t __attribute__((ms_abi)) lsw_GetConsoleCP(void) { return 65001; } // UTF-8
uint32_t __attribute__((ms_abi)) lsw_GetConsoleOutputCP(void) { return 65001; }
int __attribute__((ms_abi)) lsw_SetConsoleCP(uint32_t wCodePageID) { (void)wCodePageID; return 1; }
int __attribute__((ms_abi)) lsw_SetConsoleOutputCP(uint32_t wCodePageID) { (void)wCodePageID; return 1; }
int __attribute__((ms_abi)) lsw_GetConsoleCursorInfo(void* hConsoleOutput, void* lpConsoleCursorInfo) {
    (void)hConsoleOutput;
    if (lpConsoleCursorInfo) { *(uint32_t*)lpConsoleCursorInfo = 25; *((int32_t*)lpConsoleCursorInfo+1) = 1; }
    return 1;
}
int __attribute__((ms_abi)) lsw_SetConsoleCursorInfo(void* hConsoleOutput, const void* lpConsoleCursorInfo) { (void)hConsoleOutput; (void)lpConsoleCursorInfo; return 1; }
int __attribute__((ms_abi)) lsw_SetConsoleCursorPosition(void* hConsoleOutput, uint32_t dwCursorPosition) { (void)hConsoleOutput; (void)dwCursorPosition; return 1; }
int __attribute__((ms_abi)) lsw_GetConsoleScreenBufferInfo(void* hConsoleOutput, void* lpConsoleScreenBufferInfo) {
    (void)hConsoleOutput;
    if (lpConsoleScreenBufferInfo) {
        memset(lpConsoleScreenBufferInfo, 0, 22);
        uint16_t* p = (uint16_t*)lpConsoleScreenBufferInfo;
        p[0]=1920; p[1]=1080; // dwSize
        p[4]=1920-1; p[5]=1080-1; // srWindow Right/Bottom
    }
    return 1;
}
int __attribute__((ms_abi)) lsw_SetConsoleTextAttribute(void* hConsoleOutput, uint16_t wAttributes) { (void)hConsoleOutput; (void)wAttributes; return 1; }
int __attribute__((ms_abi)) lsw_SetConsoleScreenBufferSize(void* hConsoleOutput, uint32_t dwSize) { (void)hConsoleOutput; (void)dwSize; return 1; }
int __attribute__((ms_abi)) lsw_FillConsoleOutputCharacterW(void* hConsoleOutput, uint16_t cCharacter, uint32_t nLength, uint32_t dwWriteCoord, uint32_t* lpNumberOfCharsWritten) {
    (void)hConsoleOutput; (void)cCharacter;
    if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nLength;
    return 1;
}
int __attribute__((ms_abi)) lsw_FillConsoleOutputAttribute(void* hConsoleOutput, uint16_t wAttribute, uint32_t nLength, uint32_t dwWriteCoord, uint32_t* lpNumberOfAttrsWritten) {
    (void)hConsoleOutput; (void)wAttribute;
    if (lpNumberOfAttrsWritten) *lpNumberOfAttrsWritten = nLength;
    return 1;
}
int __attribute__((ms_abi)) lsw_WriteConsoleOutputCharacterW(void* hConsoleOutput, const uint16_t* lpCharacter, uint32_t nLength, uint32_t dwWriteCoord, uint32_t* lpNumberOfCharsWritten) {
    (void)hConsoleOutput; (void)lpCharacter; (void)dwWriteCoord;
    if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nLength;
    return 1;
}
int __attribute__((ms_abi)) lsw_WriteConsoleOutputW(void* hConsoleOutput, const void* lpBuffer, uint32_t dwBufferSize, uint32_t dwBufferCoord, void* lpWriteRegion) {
    (void)hConsoleOutput; (void)lpBuffer; (void)dwBufferSize; (void)dwBufferCoord; (void)lpWriteRegion; return 1;
}
int __attribute__((ms_abi)) lsw_ReadConsoleInputW(void* hConsoleInput, void* lpBuffer, uint32_t nLength, uint32_t* lpNumberOfEventsRead) {
    (void)hConsoleInput; (void)lpBuffer; (void)nLength;
    if (lpNumberOfEventsRead) *lpNumberOfEventsRead = 0;
    return 1;
}
int __attribute__((ms_abi)) lsw_GetNumberOfConsoleInputEvents(void* hConsoleInput, uint32_t* lpcNumberOfEvents) {
    (void)hConsoleInput; if (lpcNumberOfEvents) *lpcNumberOfEvents = 0; return 1;
}
int __attribute__((ms_abi)) lsw_SetConsoleWindowInfo(void* hConsoleOutput, int bAbsolute, const void* lpConsoleWindow) { (void)hConsoleOutput; (void)bAbsolute; (void)lpConsoleWindow; return 1; }
int __attribute__((ms_abi)) lsw_SetConsoleActiveScreenBuffer(void* hConsoleOutput) { (void)hConsoleOutput; return 1; }
void* __attribute__((ms_abi)) lsw_CreateConsoleScreenBuffer(uint32_t dwDesiredAccess, uint32_t dwShareMode, const void* lpSecurityAttributes, uint32_t dwFlags, void* lpScreenBufferData) {
    (void)dwDesiredAccess; (void)dwShareMode; (void)lpSecurityAttributes; (void)dwFlags; (void)lpScreenBufferData;
    return (void*)2; // fake handle
}

// ---- GetStartupInfo ----
void __attribute__((ms_abi)) lsw_GetStartupInfoW(void* lpStartupInfo) {
    if (!lpStartupInfo) return;
    memset(lpStartupInfo, 0, 104); // sizeof STARTUPINFOW
    *(uint32_t*)lpStartupInfo = 104; // cb
}
void __attribute__((ms_abi)) lsw_GetStartupInfoA(void* lpStartupInfo) {
    if (!lpStartupInfo) return;
    memset(lpStartupInfo, 0, 68); // sizeof STARTUPINFOA
    *(uint32_t*)lpStartupInfo = 68;
}

// ---- CreateProcess ----

/*
 * Helper: translate a Windows app path to a Linux path for execve.
 * C:\foo\bar.exe -> $LSW_PREFIX/c/foo/bar.exe  (or as-is if already Linux path)
 */
static void createprocess_win_to_linux(const char* wpath, char* out, size_t outsz) {
    if (!wpath || !*wpath) { out[0] = '\0'; return; }
    /* Already a Linux absolute path? */
    if (wpath[0] == '/') { strncpy(out, wpath, outsz-1); out[outsz-1]='\0'; return; }
    /* Windows drive-letter path: C:\... */
    if (wpath[1] == ':' && (wpath[2] == '\\' || wpath[2] == '/')) {
        char drive = (char)tolower((unsigned char)wpath[0]);
        const char* prefix = getenv("LSW_PREFIX");
        if (!prefix) prefix = "/root/.lsw/drives";
        char rest[512]; strncpy(rest, wpath + 3, sizeof(rest)-1); rest[sizeof(rest)-1]='\0';
        /* replace backslashes */
        for (char* p = rest; *p; p++) if (*p == '\\') *p = '/';
        snprintf(out, outsz, "%s/%c/%s", prefix, drive, rest);
        return;
    }
    /* Relative path — use as-is */
    strncpy(out, wpath, outsz-1); out[outsz-1]='\0';
    for (char* p = out; *p; p++) if (*p == '\\') *p = '/';
}

/* Find the lsw-pe-loader binary (same directory as this process, or $PATH) */
static int find_pe_loader(char* out, size_t outsz) {
    /* Try argv[0] directory first */
    char self[512]; ssize_t n = readlink("/proc/self/exe", self, sizeof(self)-1);
    if (n > 0) {
        self[n] = '\0';
        char* slash = strrchr(self, '/');
        if (slash) {
            *slash = '\0';
            snprintf(out, outsz, "%s/lsw-pe-loader", self);
            if (access(out, X_OK) == 0) return 1;
        }
    }
    /* Installed locations */
    const char* candidates[] = {
        "/usr/local/bin/lsw-pe-loader",
        "/usr/bin/lsw-pe-loader",
        "/opt/lsw/bin/lsw-pe-loader",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) {
            strncpy(out, candidates[i], outsz-1); out[outsz-1]='\0';
            return 1;
        }
    }
    /* Try build/bin relative to CWD */
    snprintf(out, outsz, "build/bin/lsw-pe-loader");
    if (access(out, X_OK) == 0) return 1;
    return 0;
}

/* Parse command line string into argv array.
 * Handles quoted tokens.  Caller must free argv[0..n-1] and argv itself. */
static char** parse_cmdline(const char* cmdline, int* argc_out) {
    int cap = 16, cnt = 0;
    char** argv = malloc(cap * sizeof(char*));
    if (!argv) { *argc_out = 0; return NULL; }
    const char* p = cmdline;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        char tok[4096]; int ti = 0;
        if (*p == '"') {
            p++;
            while (*p && *p != '"') tok[ti++] = *p++;
            if (*p == '"') p++;
        } else {
            while (*p && *p != ' ' && *p != '\t') tok[ti++] = *p++;
        }
        tok[ti] = '\0';
        if (cnt >= cap-1) { cap *= 2; argv = realloc(argv, cap * sizeof(char*)); }
        argv[cnt++] = strdup(tok);
    }
    argv[cnt] = NULL;
    *argc_out = cnt;
    return argv;
}

/* PROCESS_INFORMATION layout (must match Windows ABI exactly) */
typedef struct {
    void*    hProcess;
    void*    hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} PROCESS_INFORMATION_t;

int __attribute__((ms_abi)) lsw_CreateProcessA(
    const char* lpApplicationName, char* lpCommandLine,
    void* lpProcessAttributes, void* lpThreadAttributes,
    int bInheritHandles, uint32_t dwCreationFlags,
    void* lpEnvironment, const char* lpCurrentDirectory,
    void* lpStartupInfo, void* lpProcessInformation)
{
    (void)lpProcessAttributes; (void)lpThreadAttributes;
    (void)bInheritHandles; (void)dwCreationFlags;
    (void)lpEnvironment; (void)lpStartupInfo;

    if (lpProcessInformation) memset(lpProcessInformation, 0, sizeof(PROCESS_INFORMATION_t));

    /* Determine EXE path */
    char exe_win[1024] = {0};
    if (lpApplicationName && *lpApplicationName) {
        strncpy(exe_win, lpApplicationName, sizeof(exe_win)-1);
    } else if (lpCommandLine && *lpCommandLine) {
        /* Extract first token */
        int argc = 0;
        char** av = parse_cmdline(lpCommandLine, &argc);
        if (argc > 0) { strncpy(exe_win, av[0], sizeof(exe_win)-1); free(av[0]); }
        for (int i = 1; i < argc; i++) free(av[i]);
        free(av);
    }
    if (!exe_win[0]) {
        LSW_LOG_ERROR("CreateProcessA: no executable specified");
        return 0;
    }

    char exe_linux[1024];
    createprocess_win_to_linux(exe_win, exe_linux, sizeof(exe_linux));
    LSW_LOG_INFO("CreateProcessA: launching %s (linux: %s)", exe_win, exe_linux);

    /* Find pe-loader */
    char loader[512];
    if (!find_pe_loader(loader, sizeof(loader))) {
        LSW_LOG_ERROR("CreateProcessA: lsw-pe-loader not found");
        return 0;
    }

    /* Build argv for pe-loader */
    char* child_argv[64];
    int ci = 0;
    child_argv[ci++] = loader;
    child_argv[ci++] = exe_linux;
    /* Pass remaining args from lpCommandLine if application name was separate */
    char** extra = NULL; int extra_cnt = 0;
    if (lpApplicationName && lpCommandLine) {
        extra = parse_cmdline(lpCommandLine, &extra_cnt);
        /* skip first token if it matches application name */
        int start = 0;
        if (extra_cnt > 0 && strcasecmp(extra[0], lpApplicationName) == 0) start = 1;
        for (int i = start; i < extra_cnt && ci < 62; i++)
            child_argv[ci++] = extra[i];
    }
    child_argv[ci] = NULL;

    /* Change working directory in child if requested */
    char cwd_linux[1024] = {0};
    if (lpCurrentDirectory)
        createprocess_win_to_linux(lpCurrentDirectory, cwd_linux, sizeof(cwd_linux));

    pid_t pid = fork();
    if (pid < 0) {
        LSW_LOG_ERROR("CreateProcessA: fork failed: %s", strerror(errno));
        if (extra) { for (int i = 0; i < extra_cnt; i++) free(extra[i]); free(extra); }
        return 0;
    }
    if (pid == 0) {
        /* Child */
        if (cwd_linux[0]) chdir(cwd_linux);
        execv(loader, child_argv);
        _exit(127); /* exec failed */
    }
    /* Parent */
    if (extra) { for (int i = 0; i < extra_cnt; i++) free(extra[i]); free(extra); }
    LSW_LOG_INFO("CreateProcessA: child PID=%d", (int)pid);
    if (lpProcessInformation) {
        PROCESS_INFORMATION_t* pi = (PROCESS_INFORMATION_t*)lpProcessInformation;
        pi->hProcess   = (void*)(uintptr_t)(uint64_t)pid;
        pi->hThread    = (void*)(uintptr_t)1;
        pi->dwProcessId = (uint32_t)pid;
        pi->dwThreadId  = 1;
    }
    return 1;
}

int __attribute__((ms_abi)) lsw_CreateProcessW(
    const uint16_t* lpApplicationName, uint16_t* lpCommandLine,
    void* lpProcessAttributes, void* lpThreadAttributes,
    int bInheritHandles, uint32_t dwCreationFlags,
    void* lpEnvironment, const uint16_t* lpCurrentDirectory,
    void* lpStartupInfo, void* lpProcessInformation)
{
    /* Convert wide strings to narrow, then delegate */
    char appA[1024] = {0}, cmdA[4096] = {0}, cwdA[1024] = {0};
    if (lpApplicationName)
        for (int i = 0; lpApplicationName[i] && i < 1023; i++) appA[i] = (char)lpApplicationName[i];
    if (lpCommandLine)
        for (int i = 0; lpCommandLine[i] && i < 4095; i++) cmdA[i] = (char)lpCommandLine[i];
    if (lpCurrentDirectory)
        for (int i = 0; lpCurrentDirectory[i] && i < 1023; i++) cwdA[i] = (char)lpCurrentDirectory[i];
    return lsw_CreateProcessA(
        appA[0] ? appA : NULL,
        cmdA[0] ? cmdA : NULL,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags,
        lpEnvironment,
        cwdA[0] ? cwdA : NULL,
        lpStartupInfo, lpProcessInformation);
}

// ---- Symbolic/Hard links ----
int __attribute__((ms_abi)) lsw_CreateSymbolicLinkW(const uint16_t* lpSymlinkFileName, const uint16_t* lpTargetFileName, uint32_t dwFlags) {
    (void)dwFlags;
    if (!lpSymlinkFileName || !lpTargetFileName) return 0;
    char link[512], target[512]; int i=0;
    while (lpSymlinkFileName[i] && i<511) { link[i]=(char)lpSymlinkFileName[i]; i++; } link[i]=0;
    i=0;
    while (lpTargetFileName[i] && i<511) { target[i]=(char)lpTargetFileName[i]; i++; } target[i]=0;
    return symlink(target, link) == 0 ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_CreateSymbolicLinkA(const char* lpSymlinkFileName, const char* lpTargetFileName, uint32_t dwFlags) {
    (void)dwFlags;
    return (lpSymlinkFileName && lpTargetFileName && symlink(lpTargetFileName, lpSymlinkFileName) == 0) ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_CreateHardLinkW(const uint16_t* lpFileName, const uint16_t* lpExistingFileName, void* lpSecurityAttributes) {
    (void)lpSecurityAttributes;
    if (!lpFileName || !lpExistingFileName) return 0;
    char newf[512], existing[512]; int i=0;
    while (lpFileName[i] && i<511) { newf[i]=(char)lpFileName[i]; i++; } newf[i]=0;
    i=0;
    while (lpExistingFileName[i] && i<511) { existing[i]=(char)lpExistingFileName[i]; i++; } existing[i]=0;
    return link(existing, newf) == 0 ? 1 : 0;
}
int __attribute__((ms_abi)) lsw_CreateHardLinkA(const char* lpFileName, const char* lpExistingFileName, void* lpSecurityAttributes) {
    (void)lpSecurityAttributes;
    return (lpFileName && lpExistingFileName && link(lpExistingFileName, lpFileName) == 0) ? 1 : 0;
}

// ---- LocalAlloc extras / GlobalAlloc extras ----
void* __attribute__((ms_abi)) lsw_LocalLock(void* hMem) { return hMem; }
void* __attribute__((ms_abi)) lsw_LocalUnlock(void* hMem) { (void)hMem; return 0; }
size_t __attribute__((ms_abi)) lsw_LocalSize(void* hMem) { (void)hMem; return 0; }
void* __attribute__((ms_abi)) lsw_LocalReAlloc(void* hMem, size_t uBytes, uint32_t uFlags) { (void)uFlags; return realloc(hMem, uBytes); }
uint32_t __attribute__((ms_abi)) lsw_LocalFlags(void* hMem) { (void)hMem; return 0; }
/* lsw_GlobalUnlock / lsw_GlobalSize already defined earlier — skip duplicates */
void* __attribute__((ms_abi)) lsw_GlobalReAlloc(void* hMem, size_t dwBytes, uint32_t uFlags) { (void)uFlags; return realloc(hMem, dwBytes); }
void* __attribute__((ms_abi)) lsw_GlobalHandle(void* pMem) { return pMem; }
uint32_t __attribute__((ms_abi)) lsw_GlobalFlags(void* hMem) { (void)hMem; return 0; }
uint32_t __attribute__((ms_abi)) lsw_GlobalGetAtomNameW(uint16_t nAtom, uint16_t* lpBuffer, int nSize) { (void)nAtom; (void)lpBuffer; (void)nSize; return 0; }
uint16_t __attribute__((ms_abi)) lsw_GlobalAddAtomW(const uint16_t* lpString) { (void)lpString; return 0; }
uint16_t __attribute__((ms_abi)) lsw_GlobalDeleteAtom(uint16_t nAtom) { (void)nAtom; return nAtom; }
uint16_t __attribute__((ms_abi)) lsw_GlobalFindAtomW(const uint16_t* lpString) { (void)lpString; return 0; }
uint16_t __attribute__((ms_abi)) lsw_AddAtomW(const uint16_t* lpString) { (void)lpString; return 0xC000; }
uint16_t __attribute__((ms_abi)) lsw_DeleteAtom(uint16_t nAtom) { (void)nAtom; return nAtom; }
uint16_t __attribute__((ms_abi)) lsw_FindAtomW(const uint16_t* lpString) { (void)lpString; return 0; }
uint32_t __attribute__((ms_abi)) lsw_GetAtomNameW(uint16_t nAtom, uint16_t* lpBuffer, int nSize) { (void)nAtom; (void)lpBuffer; (void)nSize; return 0; }

// ---- DeviceIoControl ----
int __attribute__((ms_abi)) lsw_DeviceIoControl(void* hDevice, uint32_t dwIoControlCode, void* lpInBuffer, uint32_t nInBufferSize, void* lpOutBuffer, uint32_t nOutBufferSize, uint32_t* lpBytesReturned, void* lpOverlapped) {
    (void)hDevice; (void)dwIoControlCode; (void)lpInBuffer; (void)nInBufferSize; (void)lpOutBuffer; (void)nOutBufferSize; (void)lpOverlapped;
    if (lpBytesReturned) *lpBytesReturned = 0;
    return 0; // Not supported
}

// ---- GetNativeSystemInfo ----
void __attribute__((ms_abi)) lsw_GetNativeSystemInfo(void* lpSystemInfo) {
    lsw_GetSystemInfo(lpSystemInfo);
}

// ---- GetSystemTimes / GetProcessTimes ----
int __attribute__((ms_abi)) lsw_GetSystemTimes(void* lpIdleTime, void* lpKernelTime, void* lpUserTime) {
    if (lpIdleTime)  *(uint64_t*)lpIdleTime  = 0;
    if (lpKernelTime) *(uint64_t*)lpKernelTime = 0;
    if (lpUserTime)  *(uint64_t*)lpUserTime  = 0;
    return 1;
}
int __attribute__((ms_abi)) lsw_GetProcessTimes(void* hProcess, void* lpCreationTime, void* lpExitTime, void* lpKernelTime, void* lpUserTime) {
    (void)hProcess;
    uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t now = (uint64_t)time(NULL) * 10000000ULL + epoch_offset;
    if (lpCreationTime) *(uint64_t*)lpCreationTime = now;
    if (lpExitTime)     *(uint64_t*)lpExitTime     = 0;
    if (lpKernelTime)   *(uint64_t*)lpKernelTime   = 0;
    if (lpUserTime)     *(uint64_t*)lpUserTime     = 0;
    return 1;
}
int __attribute__((ms_abi)) lsw_GetThreadTimes(void* hThread, void* lpCreationTime, void* lpExitTime, void* lpKernelTime, void* lpUserTime) {
    return lsw_GetProcessTimes(hThread, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);
}

// ---- GetTimeZoneInformation ----
uint32_t __attribute__((ms_abi)) lsw_GetTimeZoneInformation(void* lpTimeZoneInformation) {
    if (lpTimeZoneInformation) memset(lpTimeZoneInformation, 0, 172);
    return 0; // TIME_ZONE_ID_UNKNOWN
}

// ---- Overlapped I/O ----
int __attribute__((ms_abi)) lsw_GetOverlappedResult(void* hFile, void* lpOverlapped, uint32_t* lpNumberOfBytesTransferred, int bWait) {
    (void)hFile; (void)lpOverlapped; (void)bWait;
    if (lpNumberOfBytesTransferred) *lpNumberOfBytesTransferred = 0;
    return 0;
}
int __attribute__((ms_abi)) lsw_ReadFileEx(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, void* lpOverlapped, void* lpCompletionRoutine) {
    (void)lpOverlapped; (void)lpCompletionRoutine;
    return lsw_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, NULL, NULL);
}
int __attribute__((ms_abi)) lsw_WriteFileEx(void* hFile, const void* lpBuffer, uint32_t nNumberOfBytesToWrite, void* lpOverlapped, void* lpCompletionRoutine) {
    (void)lpOverlapped; (void)lpCompletionRoutine;
    return lsw_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, NULL, NULL);
}
int __attribute__((ms_abi)) lsw_CancelIo(void* hFile) { (void)hFile; return 1; }
int __attribute__((ms_abi)) lsw_CancelIoEx(void* hFile, void* lpOverlapped) { (void)hFile; (void)lpOverlapped; return 1; }
int __attribute__((ms_abi)) lsw_CancelSynchronousIo(void* hThread) { (void)hThread; return 1; }

// ---- Memory extras ----
void* __attribute__((ms_abi)) lsw_MapViewOfFile3(void* FileMappingObject, void* Process, void* BaseAddress, uint64_t Offset, size_t ViewSize, uint32_t AllocationType, uint32_t PageProtection, void* ExtendedParameters, uint32_t ParameterCount) {
    (void)Process; (void)BaseAddress; (void)Offset; (void)ViewSize; (void)AllocationType; (void)PageProtection; (void)ExtendedParameters; (void)ParameterCount;
    typedef struct { void* base; size_t size; } lsw_file_mapping_t;
    lsw_file_mapping_t* fm = (lsw_file_mapping_t*)FileMappingObject;
    return fm ? fm->base : NULL;
}
void* __attribute__((ms_abi)) lsw_VirtualAllocEx(void* hProcess, void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect) {
    (void)hProcess;
    return lsw_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}
int __attribute__((ms_abi)) lsw_VirtualFreeEx(void* hProcess, void* lpAddress, size_t dwSize, uint32_t dwFreeType) {
    (void)hProcess;
    return lsw_VirtualFree(lpAddress, dwSize, dwFreeType);
}
int __attribute__((ms_abi)) lsw_VirtualProtectEx(void* hProcess, void* lpAddress, size_t dwSize, uint32_t flNewProtect, uint32_t* lpflOldProtect) {
    (void)hProcess;
    return lsw_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// ---- Misc remaining ----
int __attribute__((ms_abi)) lsw_GetBinaryTypeW(const uint16_t* lpApplicationName, uint32_t* lpBinaryType) {
    (void)lpApplicationName;
    if (lpBinaryType) *lpBinaryType = 6; // SCS_64BIT_BINARY
    return 1;
}
int __attribute__((ms_abi)) lsw_GetBinaryTypeA(const char* lpApplicationName, uint32_t* lpBinaryType) {
    (void)lpApplicationName;
    if (lpBinaryType) *lpBinaryType = 6;
    return 1;
}
int __attribute__((ms_abi)) lsw_SetErrorMode(uint32_t uMode) { (void)uMode; return 0; }
uint32_t __attribute__((ms_abi)) lsw_GetErrorMode(void) { return 0; }
int __attribute__((ms_abi)) lsw_SetThreadErrorMode(uint32_t dwNewMode, uint32_t* lpOldMode) { if (lpOldMode) *lpOldMode = 0; (void)dwNewMode; return 1; }
uint32_t __attribute__((ms_abi)) lsw_GetThreadErrorMode(void) { return 0; }
uint32_t __attribute__((ms_abi)) lsw_GetProcessVersion(uint32_t ProcessId) { (void)ProcessId; return (6<<16)|1; } // 6.1 = Win7
uint32_t __attribute__((ms_abi)) lsw_GetCurrentPackageId(uint32_t* bufferLength, uint8_t* buffer) { (void)buffer; if (bufferLength) *bufferLength=0; return 15700L; } // APPMODEL_ERROR_NO_PACKAGE
uint64_t __attribute__((ms_abi)) lsw_GetActiveProcessorCount(uint16_t GroupNumber) { (void)GroupNumber; return (uint64_t)sysconf(_SC_NPROCESSORS_ONLN); }
uint16_t __attribute__((ms_abi)) lsw_GetActiveProcessorGroupCount(void) { return 1; }
int __attribute__((ms_abi)) lsw_QueryFullProcessImageNameW(void* hProcess, uint32_t dwFlags, uint16_t* lpExeName, uint32_t* lpdwSize) {
    (void)hProcess; (void)dwFlags;
    if (lpExeName && lpdwSize && *lpdwSize > 4) { lpExeName[0]='l'; lpExeName[1]='s'; lpExeName[2]='w'; lpExeName[3]=0; *lpdwSize=3; }
    return 1;
}
void __attribute__((ms_abi)) lsw_RaiseException(uint32_t dwExceptionCode, uint32_t dwExceptionFlags, uint32_t nNumberOfArguments, const uint64_t* lpArguments) {
    (void)dwExceptionFlags; (void)nNumberOfArguments; (void)lpArguments;
    LSW_LOG_ERROR("RaiseException: code=0x%08x", dwExceptionCode);
    // Don't actually raise — log and return
}
int __attribute__((ms_abi)) lsw_SetConsoleCtrlHandler(void* HandlerRoutine, int Add) { (void)HandlerRoutine; (void)Add; return 1; }
int __attribute__((ms_abi)) lsw_GenerateConsoleCtrlEvent(uint32_t dwCtrlEvent, uint32_t dwProcessGroupId) { (void)dwCtrlEvent; (void)dwProcessGroupId; return 1; }
int __attribute__((ms_abi)) lsw_GetConsoleTitle(uint16_t* lpConsoleTitle, uint32_t nSize) { if (lpConsoleTitle && nSize > 3) { lpConsoleTitle[0]='L'; lpConsoleTitle[1]='S'; lpConsoleTitle[2]='W'; lpConsoleTitle[3]=0; } return 3; }
/* lsw_FindClose already defined earlier — skip duplicate */
// RemoveDirectoryA
int __attribute__((ms_abi)) lsw_RemoveDirectoryA(const char* lpPathName) {
    if (!lpPathName) return 0;
    return rmdir(lpPathName) == 0 ? 1 : 0;
}

// ============================================================================
// END Additional KERNEL32 APIs
// ============================================================================


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

// Global API mapping table
static const win32_api_mapping_t api_mappings[] = {
    // msvcrt.dll - CRT functions
    {"msvcrt.dll", "malloc", (void*)lsw_malloc},
    {"msvcrt.dll", "free", (void*)lsw_free},
    {"msvcrt.dll", "calloc", (void*)lsw_calloc},
    {"msvcrt.dll", "realloc", (void*)lsw_realloc},
    {"msvcrt.dll", "memcpy", (void*)lsw_memcpy},
    {"msvcrt.dll", "memset", (void*)lsw_memset},
    {"msvcrt.dll", "strlen", (void*)lsw_strlen},
    {"msvcrt.dll", "exit", (void*)lsw_exit},
    {"msvcrt.dll", "abort", (void*)lsw_abort},
    {"msvcrt.dll", "printf", (void*)lsw_printf},
    {"msvcrt.dll", "fprintf", (void*)lsw_fprintf},
    {"msvcrt.dll", "fwprintf", (void*)lsw_fwprintf},
    {"msvcrt.dll", "fputwc", (void*)lsw_fputwc},
    {"msvcrt.dll", "fflush", (void*)lsw_fflush},
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

    // KERNEL32.dll - newly added APIs
    {"KERNEL32.dll", "SetLastError", (void*)lsw_SetLastError},
    {"KERNEL32.dll", "GetTickCount", (void*)lsw_GetTickCount},
    {"KERNEL32.dll", "GetTickCount64", (void*)lsw_GetTickCount64},
    {"KERNEL32.dll", "GetSystemInfo", (void*)lsw_GetSystemInfo},
    {"KERNEL32.dll", "GetVersionExW", (void*)lsw_GetVersionExW},
    {"KERNEL32.dll", "IsDebuggerPresent", (void*)lsw_IsDebuggerPresent},
    {"KERNEL32.dll", "DecodePointer", (void*)lsw_DecodePointer},
    {"KERNEL32.dll", "EncodePointer", (void*)lsw_EncodePointer},
    {"KERNEL32.dll", "FormatMessageA", (void*)lsw_FormatMessageA},
    {"KERNEL32.dll", "FormatMessageW", (void*)lsw_FormatMessageW},
    {"KERNEL32.dll", "InitializeSRWLock", (void*)lsw_InitializeSRWLock},
    {"KERNEL32.dll", "AcquireSRWLockExclusive", (void*)lsw_AcquireSRWLockExclusive},
    {"KERNEL32.dll", "ReleaseSRWLockExclusive", (void*)lsw_ReleaseSRWLockExclusive},
    {"KERNEL32.dll", "AcquireSRWLockShared", (void*)lsw_AcquireSRWLockShared},
    {"KERNEL32.dll", "ReleaseSRWLockShared", (void*)lsw_ReleaseSRWLockShared},
    {"KERNEL32.dll", "TryEnterCriticalSection", (void*)lsw_TryEnterCriticalSection},
    {"KERNEL32.dll", "FlsAlloc", (void*)lsw_FlsAlloc},
    {"KERNEL32.dll", "FlsFree", (void*)lsw_FlsFree},
    {"KERNEL32.dll", "FlsGetValue", (void*)lsw_FlsGetValue},
    {"KERNEL32.dll", "FlsSetValue", (void*)lsw_FlsSetValue},
    {"KERNEL32.dll", "CreateMutexW", (void*)lsw_CreateMutexW},
    {"KERNEL32.dll", "CreateEventW", (void*)lsw_CreateEventW},
    {"KERNEL32.dll", "CreateFileMappingW", (void*)lsw_CreateFileMappingW},
    {"KERNEL32.dll", "MapViewOfFile", (void*)lsw_MapViewOfFile},
    {"KERNEL32.dll", "UnmapViewOfFile", (void*)lsw_UnmapViewOfFile},
    {"KERNEL32.dll", "LoadLibraryW", (void*)lsw_LoadLibraryW},
    {"KERNEL32.dll", "GetModuleHandleW", (void*)lsw_GetModuleHandleW},
    {"KERNEL32.dll", "GetModuleFileNameW", (void*)lsw_GetModuleFileNameW},
    {"KERNEL32.dll", "GetModuleFileNameA", (void*)lsw_GetModuleFileNameA},

    /* ----------------------------------------------------------------
     * msvcrt.dll / ucrtbase.dll — sprintf/string/math/IO/ctype
     * ---------------------------------------------------------------- */
    {"msvcrt.dll",   "sprintf",      (void*)lsw_sprintf},
    {"msvcrt.dll",   "snprintf",     (void*)lsw_snprintf},
    {"msvcrt.dll",   "_snprintf",    (void*)lsw__snprintf},
    {"msvcrt.dll",   "vsprintf",     (void*)lsw_vsprintf},
    {"msvcrt.dll",   "vsnprintf",    (void*)lsw_vsnprintf},
    {"msvcrt.dll",   "sscanf",       (void*)lsw_sscanf},
    {"msvcrt.dll",   "vsscanf",      (void*)lsw_vsscanf},
    {"msvcrt.dll",   "strcpy",       (void*)lsw_strcpy},
    {"msvcrt.dll",   "strncpy",      (void*)lsw_strncpy},
    {"msvcrt.dll",   "strcat",       (void*)lsw_strcat},
    {"msvcrt.dll",   "strncat",      (void*)lsw_strncat},
    {"msvcrt.dll",   "strchr",       (void*)lsw_strchr},
    {"msvcrt.dll",   "strrchr",      (void*)lsw_strrchr},
    {"msvcrt.dll",   "strtok",       (void*)lsw_strtok},
    {"msvcrt.dll",   "strdup",       (void*)lsw_strdup},
    {"msvcrt.dll",   "_strdup",      (void*)lsw__strdup},
    {"msvcrt.dll",   "_stricmp",     (void*)lsw__stricmp},
    {"msvcrt.dll",   "_strnicmp",    (void*)lsw__strnicmp},
    {"msvcrt.dll",   "wcscpy",       (void*)lsw_wcscpy},
    {"msvcrt.dll",   "wcsncpy",      (void*)lsw_wcsncpy},
    {"msvcrt.dll",   "wcscat",       (void*)lsw_wcscat},
    {"msvcrt.dll",   "wcsncat",      (void*)lsw_wcsncat},
    {"msvcrt.dll",   "wcscmp",       (void*)lsw_wcscmp},
    {"msvcrt.dll",   "wcsncmp",      (void*)lsw_wcsncmp},
    {"msvcrt.dll",   "wcschr",       (void*)lsw_wcschr},
    {"msvcrt.dll",   "wcsrchr",      (void*)lsw_wcsrchr},
    {"msvcrt.dll",   "wcsstr",       (void*)lsw_wcsstr},
    {"msvcrt.dll",   "_wcsdup",      (void*)lsw__wcsdup},
    {"msvcrt.dll",   "atoi",         (void*)lsw_atoi},
    {"msvcrt.dll",   "atol",         (void*)lsw_atol},
    {"msvcrt.dll",   "atof",         (void*)lsw_atof},
    {"msvcrt.dll",   "strtol",       (void*)lsw_strtol},
    {"msvcrt.dll",   "strtoul",      (void*)lsw_strtoul},
    {"msvcrt.dll",   "strtod",       (void*)lsw_strtod},
    {"msvcrt.dll",   "_atoi64",      (void*)lsw__atoi64},
    {"msvcrt.dll",   "strtoll",      (void*)lsw_strtoll},
    {"msvcrt.dll",   "memmove",      (void*)lsw_memmove},
    {"msvcrt.dll",   "memchr",       (void*)lsw_memchr},
    {"msvcrt.dll",   "memcmp",       (void*)lsw_memcmp},
    {"msvcrt.dll",   "toupper",      (void*)lsw_toupper},
    {"msvcrt.dll",   "tolower",      (void*)lsw_tolower},
    {"msvcrt.dll",   "isalpha",      (void*)lsw_isalpha},
    {"msvcrt.dll",   "isdigit",      (void*)lsw_isdigit},
    {"msvcrt.dll",   "isspace",      (void*)lsw_isspace},
    {"msvcrt.dll",   "isalnum",      (void*)lsw_isalnum},
    {"msvcrt.dll",   "isupper",      (void*)lsw_isupper},
    {"msvcrt.dll",   "islower",      (void*)lsw_islower},
    {"msvcrt.dll",   "isprint",      (void*)lsw_isprint},
    {"msvcrt.dll",   "ispunct",      (void*)lsw_ispunct},
    {"msvcrt.dll",   "qsort",        (void*)lsw_qsort},
    {"msvcrt.dll",   "bsearch",      (void*)lsw_bsearch},
    {"msvcrt.dll",   "time",         (void*)lsw_time},
    {"msvcrt.dll",   "difftime",     (void*)lsw_difftime},
    {"msvcrt.dll",   "clock",        (void*)lsw_clock},
    {"msvcrt.dll",   "rand",         (void*)lsw_rand},
    {"msvcrt.dll",   "srand",        (void*)lsw_srand},
    {"msvcrt.dll",   "fopen",        (void*)lsw_fopen},
    {"msvcrt.dll",   "fclose",       (void*)lsw_fclose},
    {"msvcrt.dll",   "feof",         (void*)lsw_feof},
    {"msvcrt.dll",   "ferror",       (void*)lsw_ferror},
    {"msvcrt.dll",   "fgetc",        (void*)lsw_fgetc},
    {"msvcrt.dll",   "ungetc",       (void*)lsw_ungetc},
    {"msvcrt.dll",   "fgets",        (void*)lsw_fgets},
    {"msvcrt.dll",   "fread",        (void*)lsw_fread},
    {"msvcrt.dll",   "ftell",        (void*)lsw_ftell},
    {"msvcrt.dll",   "fseek",        (void*)lsw_fseek},
    {"msvcrt.dll",   "rewind",       (void*)lsw_rewind},
    {"msvcrt.dll",   "puts",         (void*)lsw_puts},
    {"msvcrt.dll",   "putchar",      (void*)lsw_putchar},
    {"msvcrt.dll",   "getchar",      (void*)lsw_getchar},
    {"msvcrt.dll",   "fscanf",       (void*)lsw_fscanf},
    {"msvcrt.dll",   "vprintf",      (void*)lsw_vprintf},
    {"msvcrt.dll",   "swprintf",     (void*)lsw_swprintf},
    {"msvcrt.dll",   "floor",        (void*)lsw_floor},
    {"msvcrt.dll",   "ceil",         (void*)lsw_ceil},
    {"msvcrt.dll",   "fabs",         (void*)lsw_fabs},
    {"msvcrt.dll",   "sqrt",         (void*)lsw_sqrt},
    {"msvcrt.dll",   "pow",          (void*)lsw_pow},
    {"msvcrt.dll",   "log",          (void*)lsw_math_log},
    {"msvcrt.dll",   "log10",        (void*)lsw_math_log10},
    {"msvcrt.dll",   "exp",          (void*)lsw_exp},
    {"msvcrt.dll",   "sin",          (void*)lsw_sin},
    {"msvcrt.dll",   "cos",          (void*)lsw_cos},
    {"msvcrt.dll",   "tan",          (void*)lsw_tan},
    {"msvcrt.dll",   "atan2",        (void*)lsw_atan2},
    /* ucrtbase.dll aliases (same functions, different DLL name) */
    {"ucrtbase.dll", "sprintf",      (void*)lsw_sprintf},
    {"ucrtbase.dll", "snprintf",     (void*)lsw_snprintf},
    {"ucrtbase.dll", "_snprintf",    (void*)lsw__snprintf},
    {"ucrtbase.dll", "vsprintf",     (void*)lsw_vsprintf},
    {"ucrtbase.dll", "sscanf",       (void*)lsw_sscanf},
    {"ucrtbase.dll", "strcpy",       (void*)lsw_strcpy},
    {"ucrtbase.dll", "strncpy",      (void*)lsw_strncpy},
    {"ucrtbase.dll", "strcat",       (void*)lsw_strcat},
    {"ucrtbase.dll", "atoi",         (void*)lsw_atoi},
    {"ucrtbase.dll", "atof",         (void*)lsw_atof},
    {"ucrtbase.dll", "strtol",       (void*)lsw_strtol},
    {"ucrtbase.dll", "strtod",       (void*)lsw_strtod},
    {"ucrtbase.dll", "memmove",      (void*)lsw_memmove},
    {"ucrtbase.dll", "fopen",        (void*)lsw_fopen},
    {"ucrtbase.dll", "fclose",       (void*)lsw_fclose},
    {"ucrtbase.dll", "fread",        (void*)lsw_fread},
    {"ucrtbase.dll", "fseek",        (void*)lsw_fseek},
    {"ucrtbase.dll", "ftell",        (void*)lsw_ftell},
    {"ucrtbase.dll", "qsort",        (void*)lsw_qsort},
    {"ucrtbase.dll", "rand",         (void*)lsw_rand},
    {"ucrtbase.dll", "srand",        (void*)lsw_srand},
    {"ucrtbase.dll", "floor",        (void*)lsw_floor},
    {"ucrtbase.dll", "ceil",         (void*)lsw_ceil},
    {"ucrtbase.dll", "sqrt",         (void*)lsw_sqrt},
    {"ucrtbase.dll", "pow",          (void*)lsw_pow},
    {"ucrtbase.dll", "sin",          (void*)lsw_sin},
    {"ucrtbase.dll", "cos",          (void*)lsw_cos},
    {"ucrtbase.dll", "exp",          (void*)lsw_exp},
    /* ucrtbase.dll — extended coverage */
    {"ucrtbase.dll", "tan",          (void*)lsw_tan},
    {"ucrtbase.dll", "atan2",        (void*)lsw_atan2},
    {"ucrtbase.dll", "atan",         (void*)lsw_atan},
    {"ucrtbase.dll", "asin",         (void*)lsw_asin},
    {"ucrtbase.dll", "acos",         (void*)lsw_acos},
    {"ucrtbase.dll", "log",          (void*)lsw_math_log},
    {"ucrtbase.dll", "log2",         (void*)lsw_log2},
    {"ucrtbase.dll", "log10",        (void*)lsw_math_log10},
    {"ucrtbase.dll", "fabs",         (void*)lsw_fabs},
    {"ucrtbase.dll", "fmod",         (void*)lsw_fmod},
    {"ucrtbase.dll", "hypot",        (void*)lsw_hypot},
    {"ucrtbase.dll", "modf",         (void*)lsw_modf},
    {"ucrtbase.dll", "ldexp",        (void*)lsw_ldexp},
    {"ucrtbase.dll", "frexp",        (void*)lsw_frexp},
    {"ucrtbase.dll", "sqrtf",        (void*)lsw_sqrtf},
    {"ucrtbase.dll", "sinf",         (void*)lsw_sinf},
    {"ucrtbase.dll", "cosf",         (void*)lsw_cosf},
    {"ucrtbase.dll", "powf",         (void*)lsw_powf},
    {"ucrtbase.dll", "fabsf",        (void*)lsw_fabsf},
    {"ucrtbase.dll", "floorf",       (void*)lsw_floorf},
    {"ucrtbase.dll", "ceilf",        (void*)lsw_ceilf},
    {"ucrtbase.dll", "expf",         (void*)lsw_expf},
    {"ucrtbase.dll", "logf",         (void*)lsw_logf},
    {"ucrtbase.dll", "fmodf",        (void*)lsw_fmodf},
    /* ucrtbase.dll — CRT internal functions */
    {"ucrtbase.dll", "__acrt_iob_func",             (void*)lsw___acrt_iob_func},
    {"ucrtbase.dll", "__stdio_common_vfprintf",     (void*)lsw___stdio_common_vfprintf},
    {"ucrtbase.dll", "__stdio_common_vsprintf",     (void*)lsw___stdio_common_vsprintf},
    {"ucrtbase.dll", "__stdio_common_vsscanf",      (void*)lsw___stdio_common_vsscanf},
    {"ucrtbase.dll", "__stdio_common_vswprintf",    (void*)lsw___stdio_common_vswprintf},
    {"ucrtbase.dll", "__stdio_common_vfwprintf",    (void*)lsw___stdio_common_vfwprintf},
    {"ucrtbase.dll", "_configure_narrow_argv",      (void*)lsw__configure_narrow_argv},
    {"ucrtbase.dll", "_configure_wide_argv",        (void*)lsw__configure_wide_argv},
    {"ucrtbase.dll", "_initialize_narrow_environment",(void*)lsw__initialize_narrow_environment},
    {"ucrtbase.dll", "_initialize_wide_environment",(void*)lsw__initialize_wide_environment},
    {"ucrtbase.dll", "_initialize_onexit_table",    (void*)lsw__initialize_onexit_table},
    {"ucrtbase.dll", "_register_onexit_function",   (void*)lsw__register_onexit_function},
    {"ucrtbase.dll", "_execute_onexit_table",       (void*)lsw__execute_onexit_table},
    {"ucrtbase.dll", "_crt_atexit",                 (void*)lsw__crt_atexit},
    {"ucrtbase.dll", "__crt_at_quick_exit",         (void*)lsw___crt_at_quick_exit},
    {"ucrtbase.dll", "_initterm",                   (void*)lsw__initterm},
    {"ucrtbase.dll", "_initterm_e",                 (void*)lsw__initterm_e},
    {"ucrtbase.dll", "__security_init_cookie",      (void*)lsw___security_init_cookie},
    {"ucrtbase.dll", "__security_check_cookie",     (void*)lsw___security_check_cookie},
    {"ucrtbase.dll", "__p___argc",                  (void*)lsw___p___argc},
    {"ucrtbase.dll", "__p___argv",                  (void*)lsw___p___argv},
    {"ucrtbase.dll", "__p__commode",                (void*)lsw___p__commode},
    /* ucrtbase.dll — memory/string/time/IO */
    {"ucrtbase.dll", "malloc",       (void*)lsw_malloc},
    {"ucrtbase.dll", "free",         (void*)lsw_free},
    {"ucrtbase.dll", "calloc",       (void*)lsw_calloc},
    {"ucrtbase.dll", "realloc",      (void*)lsw_realloc},
    {"ucrtbase.dll", "memcpy",       (void*)lsw_memcpy},
    {"ucrtbase.dll", "memset",       (void*)lsw_memset},
    {"ucrtbase.dll", "memmove",      (void*)lsw_memmove},
    {"ucrtbase.dll", "memcmp",       (void*)lsw_memcmp},
    {"ucrtbase.dll", "memcpy_s",     (void*)lsw_memcpy_s},
    {"ucrtbase.dll", "memmove_s",    (void*)lsw_memmove_s},
    {"ucrtbase.dll", "_msize",       (void*)lsw__msize},
    {"ucrtbase.dll", "_aligned_malloc",  (void*)lsw__aligned_malloc},
    {"ucrtbase.dll", "_aligned_free",    (void*)lsw__aligned_free},
    {"ucrtbase.dll", "_aligned_realloc", (void*)lsw__aligned_realloc},
    {"ucrtbase.dll", "strlen",       (void*)lsw_strlen},
    {"ucrtbase.dll", "strcmp",       (void*)lsw_strcmp},
    {"ucrtbase.dll", "strncmp",      (void*)lsw_strncmp},
    {"ucrtbase.dll", "strncpy",      (void*)lsw_strncpy},
    {"ucrtbase.dll", "strncat",      (void*)lsw_strncat},
    {"ucrtbase.dll", "strchr",       (void*)lsw_strchr},
    {"ucrtbase.dll", "strrchr",      (void*)lsw_strrchr},
    {"ucrtbase.dll", "strstr",       (void*)lsw_strstr},
    {"ucrtbase.dll", "strtoul",      (void*)lsw_strtoul},
    {"ucrtbase.dll", "strtoll",      (void*)lsw_strtoll},
    {"ucrtbase.dll", "strtof",       (void*)lsw_strtof},
    {"ucrtbase.dll", "_strtoi64",    (void*)lsw__strtoi64},
    {"ucrtbase.dll", "_strtoui64",   (void*)lsw__strtoui64},
    {"ucrtbase.dll", "_atoi64",      (void*)lsw__atoi64},
    {"ucrtbase.dll", "_stricmp",     (void*)lsw__stricmp},
    {"ucrtbase.dll", "_strnicmp",    (void*)lsw__strnicmp},
    {"ucrtbase.dll", "_strdup",      (void*)lsw__strdup},
    {"ucrtbase.dll", "strerror",     (void*)lsw_strerror},
    {"ucrtbase.dll", "perror",       (void*)lsw_perror},
    {"ucrtbase.dll", "strcpy_s",     (void*)lsw_strcpy_s},
    {"ucrtbase.dll", "strncpy_s",    (void*)lsw_strncpy_s},
    {"ucrtbase.dll", "strcat_s",     (void*)lsw_strcat_s},
    {"ucrtbase.dll", "sprintf_s",    (void*)lsw_sprintf_s},
    {"ucrtbase.dll", "wcslen",       (void*)lsw_wcslen},
    {"ucrtbase.dll", "wcscpy",       (void*)lsw_wcscpy},
    {"ucrtbase.dll", "wcscat",       (void*)lsw_wcscat},
    {"ucrtbase.dll", "wcscmp",       (void*)lsw_wcscmp},
    {"ucrtbase.dll", "wcsncmp",      (void*)lsw_wcsncmp},
    {"ucrtbase.dll", "wcsncpy",      (void*)lsw_wcsncpy},
    {"ucrtbase.dll", "wcschr",       (void*)lsw_wcschr},
    {"ucrtbase.dll", "wcsrchr",      (void*)lsw_wcsrchr},
    {"ucrtbase.dll", "wcsstr",       (void*)lsw_wcsstr},
    {"ucrtbase.dll", "wcsnlen",      (void*)lsw_wcsnlen},
    {"ucrtbase.dll", "_wcsicmp",     (void*)lsw__wcsicmp},
    {"ucrtbase.dll", "_wcsnicmp",    (void*)lsw__wcsnicmp},
    {"ucrtbase.dll", "_wcsdup",      (void*)lsw__wcsdup},
    {"ucrtbase.dll", "wcscpy_s",     (void*)lsw_wcscpy_s},
    {"ucrtbase.dll", "wcscat_s",     (void*)lsw_wcscat_s},
    {"ucrtbase.dll", "swprintf_s",   (void*)lsw_swprintf_s},
    {"ucrtbase.dll", "printf",       (void*)lsw_printf},
    {"ucrtbase.dll", "fprintf",      (void*)lsw_fprintf},
    {"ucrtbase.dll", "vprintf",      (void*)lsw_vprintf},
    {"ucrtbase.dll", "vfprintf",     (void*)lsw_vfprintf},
    {"ucrtbase.dll", "fwrite",       (void*)lsw_fwrite},
    {"ucrtbase.dll", "fputc",        (void*)lsw_fputc},
    {"ucrtbase.dll", "fgetc",        (void*)lsw_fgetc},
    {"ucrtbase.dll", "fgets",        (void*)lsw_fgets},
    {"ucrtbase.dll", "feof",         (void*)lsw_feof},
    {"ucrtbase.dll", "ferror",       (void*)lsw_ferror},
    {"ucrtbase.dll", "fflush",       (void*)lsw_fflush},
    {"ucrtbase.dll", "rewind",       (void*)lsw_rewind},
    {"ucrtbase.dll", "puts",         (void*)lsw_puts},
    {"ucrtbase.dll", "putchar",      (void*)lsw_putchar},
    {"ucrtbase.dll", "getchar",      (void*)lsw_getchar},
    {"ucrtbase.dll", "fscanf",       (void*)lsw_fscanf},
    {"ucrtbase.dll", "_wfopen",      (void*)lsw__wfopen},
    {"ucrtbase.dll", "_waccess",     (void*)lsw__waccess},
    {"ucrtbase.dll", "_wrename",     (void*)lsw__wrename},
    {"ucrtbase.dll", "_wremove",     (void*)lsw__wremove},
    {"ucrtbase.dll", "time",         (void*)lsw_time},
    {"ucrtbase.dll", "difftime",     (void*)lsw_difftime},
    {"ucrtbase.dll", "clock",        (void*)lsw_clock},
    {"ucrtbase.dll", "localtime",    (void*)lsw_localtime},
    {"ucrtbase.dll", "gmtime",       (void*)lsw_gmtime},
    {"ucrtbase.dll", "mktime",       (void*)lsw_mktime},
    {"ucrtbase.dll", "asctime",      (void*)lsw_asctime},
    {"ucrtbase.dll", "ctime",        (void*)lsw_ctime},
    {"ucrtbase.dll", "strftime",     (void*)lsw_strftime},
    {"ucrtbase.dll", "getenv",       (void*)lsw_getenv},
    {"ucrtbase.dll", "_putenv",      (void*)lsw__putenv},
    {"ucrtbase.dll", "exit",         (void*)lsw_exit},
    {"ucrtbase.dll", "_exit",        (void*)lsw_exit},
    {"ucrtbase.dll", "abort",        (void*)lsw_abort},
    {"ucrtbase.dll", "qsort",        (void*)lsw_qsort},
    {"ucrtbase.dll", "bsearch",      (void*)lsw_bsearch},
    {"ucrtbase.dll", "_errno",       (void*)lsw__errno},
    {"ucrtbase.dll", "_get_errno",   (void*)lsw__get_errno},
    {"ucrtbase.dll", "_set_errno",   (void*)lsw__set_errno},
    /* msvcr140.dll / msvcp140.dll — VS2015 runtime DLLs */
    {"msvcr140.dll", "malloc",       (void*)lsw_malloc},
    {"msvcr140.dll", "free",         (void*)lsw_free},
    {"msvcr140.dll", "calloc",       (void*)lsw_calloc},
    {"msvcr140.dll", "realloc",      (void*)lsw_realloc},
    {"msvcr140.dll", "memcpy",       (void*)lsw_memcpy},
    {"msvcr140.dll", "memset",       (void*)lsw_memset},
    {"msvcr140.dll", "strlen",       (void*)lsw_strlen},
    {"msvcr140.dll", "strcmp",       (void*)lsw_strcmp},
    {"msvcr140.dll", "printf",       (void*)lsw_printf},
    {"msvcr140.dll", "fprintf",      (void*)lsw_fprintf},
    {"msvcr140.dll", "sprintf",      (void*)lsw_sprintf},
    {"msvcr140.dll", "snprintf",     (void*)lsw_snprintf},
    {"msvcr140.dll", "exit",         (void*)lsw_exit},
    {"msvcr140.dll", "abort",        (void*)lsw_abort},
    {"msvcr140.dll", "fopen",        (void*)lsw_fopen},
    {"msvcr140.dll", "fclose",       (void*)lsw_fclose},
    {"msvcr140.dll", "fread",        (void*)lsw_fread},
    {"msvcr140.dll", "fwrite",       (void*)lsw_fwrite},
    {"msvcr140.dll", "time",         (void*)lsw_time},
    {"msvcr140.dll", "localtime",    (void*)lsw_localtime},
    {"msvcr140.dll", "__acrt_iob_func", (void*)lsw___acrt_iob_func},
    {"msvcr140.dll", "__stdio_common_vfprintf",(void*)lsw___stdio_common_vfprintf},
    {"msvcr140.dll", "__stdio_common_vsprintf",(void*)lsw___stdio_common_vsprintf},
    {"msvcr140.dll", "_initterm",    (void*)lsw__initterm},
    {"msvcr140.dll", "_initterm_e",  (void*)lsw__initterm_e},
    {"msvcp140.dll", "malloc",       (void*)lsw_malloc},
    {"msvcp140.dll", "free",         (void*)lsw_free},
    {"msvcp_win.dll","malloc",       (void*)lsw_malloc},
    {"msvcp_win.dll","free",         (void*)lsw_free},
    /* ----------------------------------------------------------------
     * vcruntime140.dll / api-ms-win-crt-* stubs
     * ---------------------------------------------------------------- */
    {"vcruntime140.dll", "__acrt_iob_func",              (void*)lsw___acrt_iob_func},
    {"vcruntime140.dll", "__stdio_common_vfprintf",      (void*)lsw___stdio_common_vfprintf},
    {"vcruntime140.dll", "__stdio_common_vsprintf",      (void*)lsw___stdio_common_vsprintf},
    {"vcruntime140.dll", "__stdio_common_vsscanf",       (void*)lsw___stdio_common_vsscanf},
    {"vcruntime140.dll", "__stdio_common_vswprintf",     (void*)lsw___stdio_common_vswprintf},
    {"vcruntime140.dll", "__stdio_common_vfwprintf",     (void*)lsw___stdio_common_vfwprintf},
    {"vcruntime140.dll", "_configure_narrow_argv",       (void*)lsw__configure_narrow_argv},
    {"vcruntime140.dll", "_configure_wide_argv",         (void*)lsw__configure_wide_argv},
    {"vcruntime140.dll", "_initialize_narrow_environment",(void*)lsw__initialize_narrow_environment},
    {"vcruntime140.dll", "_initialize_wide_environment", (void*)lsw__initialize_wide_environment},
    {"vcruntime140.dll", "_initialize_onexit_table",     (void*)lsw__initialize_onexit_table},
    {"vcruntime140.dll", "_register_onexit_function",    (void*)lsw__register_onexit_function},
    {"vcruntime140.dll", "_execute_onexit_table",        (void*)lsw__execute_onexit_table},
    {"vcruntime140.dll", "__p___argc",                   (void*)lsw___p___argc},
    {"vcruntime140.dll", "__p___argv",                   (void*)lsw___p___argv},
    {"vcruntime140.dll", "__p__commode",                 (void*)lsw___p__commode},
    {"vcruntime140.dll", "_crt_atexit",                  (void*)lsw__crt_atexit},
    {"vcruntime140.dll", "__crt_at_quick_exit",          (void*)lsw___crt_at_quick_exit},
    {"vcruntime140.dll", "__std_type_info_destroy_list", (void*)lsw___std_type_info_destroy_list},
    {"vcruntime140.dll", "_CxxThrowException",           (void*)lsw__CxxThrowException},
    {"vcruntime140.dll", "__CxxFrameHandler3",           (void*)lsw___CxxFrameHandler3},
    {"vcruntime140.dll", "__C_specific_handler",         (void*)lsw___C_specific_handler},
    {"ntdll.dll",        "__C_specific_handler",         (void*)lsw___C_specific_handler},
    {"ntdll.dll",        "__CxxFrameHandler3",           (void*)lsw___CxxFrameHandler3},
    {"api-ms-win-crt-stdio-l1-1-0.dll",   "__acrt_iob_func",          (void*)lsw___acrt_iob_func},
    {"api-ms-win-crt-stdio-l1-1-0.dll",   "__stdio_common_vfprintf",  (void*)lsw___stdio_common_vfprintf},
    {"api-ms-win-crt-stdio-l1-1-0.dll",   "__stdio_common_vsprintf",  (void*)lsw___stdio_common_vsprintf},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_configure_narrow_argv",   (void*)lsw__configure_narrow_argv},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_narrow_environment", (void*)lsw__initialize_narrow_environment},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_onexit_table", (void*)lsw__initialize_onexit_table},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_register_onexit_function",(void*)lsw__register_onexit_function},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_execute_onexit_table",    (void*)lsw__execute_onexit_table},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_crt_atexit",              (void*)lsw__crt_atexit},
    {"api-ms-win-crt-math-l1-1-0.dll",    "floor",    (void*)lsw_floor},
    {"api-ms-win-crt-math-l1-1-0.dll",    "ceil",     (void*)lsw_ceil},
    {"api-ms-win-crt-math-l1-1-0.dll",    "sqrt",     (void*)lsw_sqrt},
    {"api-ms-win-crt-math-l1-1-0.dll",    "pow",      (void*)lsw_pow},
    {"api-ms-win-crt-math-l1-1-0.dll",    "sin",      (void*)lsw_sin},
    {"api-ms-win-crt-math-l1-1-0.dll",    "cos",      (void*)lsw_cos},
    {"api-ms-win-crt-math-l1-1-0.dll",    "exp",      (void*)lsw_exp},
    {"api-ms-win-crt-math-l1-1-0.dll",    "fabs",     (void*)lsw_fabs},
    {"api-ms-win-crt-string-l1-1-0.dll",  "strcpy",   (void*)lsw_strcpy},
    {"api-ms-win-crt-string-l1-1-0.dll",  "strlen",   (void*)lsw_strlen},
    {"api-ms-win-crt-string-l1-1-0.dll",  "strcmp",   (void*)lsw_strcmp},
    {"api-ms-win-crt-string-l1-1-0.dll",  "strncmp",  (void*)lsw_strncmp},
    {"api-ms-win-crt-string-l1-1-0.dll",  "strstr",   (void*)lsw_strstr},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atoi",     (void*)lsw_atoi},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atof",     (void*)lsw_atof},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtol",   (void*)lsw_strtol},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtod",   (void*)lsw_strtod},
    {"api-ms-win-crt-heap-l1-1-0.dll",    "malloc",   (void*)lsw_malloc},
    {"api-ms-win-crt-heap-l1-1-0.dll",    "free",     (void*)lsw_free},
    {"api-ms-win-crt-heap-l1-1-0.dll",    "calloc",   (void*)lsw_calloc},
    {"api-ms-win-crt-heap-l1-1-0.dll",    "realloc",  (void*)lsw_realloc},
    /* ----------------------------------------------------------------
     * KERNEL32.dll — new APIs added in this session
     * ---------------------------------------------------------------- */
    {"KERNEL32.dll", "GetCurrentThread",         (void*)lsw_GetCurrentThread},
    {"KERNEL32.dll", "GetCurrentProcess",        (void*)lsw_GetCurrentProcess},
    {"KERNEL32.dll", "GetCurrentThreadId",       (void*)lsw_GetCurrentThreadId},
    {"KERNEL32.dll", "GetSystemTimeAsFileTime",  (void*)lsw_GetSystemTimeAsFileTime},
    {"KERNEL32.dll", "GetSystemTime",            (void*)lsw_GetSystemTime},
    {"KERNEL32.dll", "GetLocalTime",             (void*)lsw_GetLocalTime},
    {"KERNEL32.dll", "FileTimeToSystemTime",     (void*)lsw_FileTimeToSystemTime},
    {"KERNEL32.dll", "SystemTimeToFileTime",     (void*)lsw_SystemTimeToFileTime},
    {"KERNEL32.dll", "QueryPerformanceCounter",  (void*)lsw_QueryPerformanceCounter},
    {"KERNEL32.dll", "QueryPerformanceFrequency",(void*)lsw_QueryPerformanceFrequency},
    {"KERNEL32.dll", "AllocConsole",             (void*)lsw_AllocConsole},
    {"KERNEL32.dll", "FreeConsole",              (void*)lsw_FreeConsole},
    {"KERNEL32.dll", "AttachConsole",            (void*)lsw_AttachConsole},
    {"KERNEL32.dll", "GetConsoleWindow",         (void*)lsw_GetConsoleWindow},
    {"KERNEL32.dll", "SetConsoleTitleA",         (void*)lsw_SetConsoleTitleA},
    {"KERNEL32.dll", "SetConsoleTitleW",         (void*)lsw_SetConsoleTitleW},
    {"KERNEL32.dll", "GetConsoleMode",           (void*)lsw_GetConsoleMode},
    {"KERNEL32.dll", "SetConsoleMode",           (void*)lsw_SetConsoleMode},
    {"KERNEL32.dll", "WriteConsoleW",            (void*)lsw_WriteConsoleW},
    {"KERNEL32.dll", "ReadConsoleA",             (void*)lsw_ReadConsoleA},
    {"KERNEL32.dll", "ReadConsoleW",             (void*)lsw_ReadConsoleW},
    {"KERNEL32.dll", "GetFileType",              (void*)lsw_GetFileType},
    {"KERNEL32.dll", "DuplicateHandle",          (void*)lsw_DuplicateHandle},
    {"KERNEL32.dll", "OutputDebugStringA",       (void*)lsw_OutputDebugStringA},
    {"KERNEL32.dll", "OutputDebugStringW",       (void*)lsw_OutputDebugStringW},
    {"KERNEL32.dll", "CreateDirectoryA",         (void*)lsw_CreateDirectoryA},
    {"KERNEL32.dll", "GetFileAttributesA",       (void*)lsw_GetFileAttributesA},
    {"KERNEL32.dll", "GetFullPathNameA",         (void*)lsw_GetFullPathNameA},
    {"KERNEL32.dll", "GetFullPathNameW",         (void*)lsw_GetFullPathNameW},
    {"KERNEL32.dll", "SetCurrentDirectoryA",     (void*)lsw_SetCurrentDirectoryA},
    {"KERNEL32.dll", "SetCurrentDirectoryW",     (void*)lsw_SetCurrentDirectoryW},
    {"KERNEL32.dll", "GetCurrentDirectoryA",     (void*)lsw_GetCurrentDirectoryA},
    {"KERNEL32.dll", "GetCurrentDirectoryW",     (void*)lsw_GetCurrentDirectoryW},
    {"KERNEL32.dll", "MoveFileA",                (void*)lsw_MoveFileA},
    {"KERNEL32.dll", "MoveFileW",                (void*)lsw_MoveFileW},
    {"KERNEL32.dll", "CopyFileA",                (void*)lsw_CopyFileA},
    {"KERNEL32.dll", "FindFirstFileA",           (void*)lsw_FindFirstFileA},
    {"KERNEL32.dll", "FindNextFileA",            (void*)lsw_FindNextFileA},
    {"KERNEL32.dll", "WaitForMultipleObjects",   (void*)lsw_WaitForMultipleObjects},
    {"KERNEL32.dll", "CreateMutexA",             (void*)lsw_CreateMutexA},
    {"KERNEL32.dll", "OpenMutexA",               (void*)lsw_OpenMutexA},
    {"KERNEL32.dll", "ReleaseMutex",             (void*)lsw_ReleaseMutex},
    {"KERNEL32.dll", "CreateSemaphoreA",         (void*)lsw_CreateSemaphoreA},
    {"KERNEL32.dll", "CreateSemaphoreW",         (void*)lsw_CreateSemaphoreW},
    {"KERNEL32.dll", "ReleaseSemaphore",         (void*)lsw_ReleaseSemaphore},
    {"KERNEL32.dll", "ResetEvent",               (void*)lsw_ResetEvent},
    /* Condition variables */
    {"KERNEL32.dll", "InitializeConditionVariable",   (void*)lsw_InitializeConditionVariable},
    {"KERNEL32.dll", "WakeConditionVariable",          (void*)lsw_WakeConditionVariable},
    {"KERNEL32.dll", "WakeAllConditionVariable",       (void*)lsw_WakeAllConditionVariable},
    {"KERNEL32.dll", "SleepConditionVariableCS",       (void*)lsw_SleepConditionVariableCS},
    {"KERNEL32.dll", "SleepConditionVariableSRW",      (void*)lsw_SleepConditionVariableSRW},
    /* Waitable timers */
    {"KERNEL32.dll", "CreateWaitableTimerA",     (void*)lsw_CreateWaitableTimerA},
    {"KERNEL32.dll", "CreateWaitableTimerW",     (void*)lsw_CreateWaitableTimerW},
    {"KERNEL32.dll", "CreateWaitableTimerExW",   (void*)lsw_CreateWaitableTimerExW},
    {"KERNEL32.dll", "OpenWaitableTimerW",       (void*)lsw_OpenWaitableTimerW},
    {"KERNEL32.dll", "SetWaitableTimer",         (void*)lsw_SetWaitableTimer},
    {"KERNEL32.dll", "CancelWaitableTimer",      (void*)lsw_CancelWaitableTimer},
    /* IOCP */
    {"KERNEL32.dll", "CreateIoCompletionPort",        (void*)lsw_CreateIoCompletionPort},
    {"KERNEL32.dll", "PostQueuedCompletionStatus",     (void*)lsw_PostQueuedCompletionStatus},
    {"KERNEL32.dll", "GetQueuedCompletionStatus",      (void*)lsw_GetQueuedCompletionStatus},
    {"KERNEL32.dll", "GetQueuedCompletionStatusEx",    (void*)lsw_GetQueuedCompletionStatusEx},
    /* Thread pool */
    {"KERNEL32.dll", "CreateThreadpoolWork",           (void*)lsw_CreateThreadpoolWork},
    {"KERNEL32.dll", "SubmitThreadpoolWork",            (void*)lsw_SubmitThreadpoolWork},
    {"KERNEL32.dll", "WaitForThreadpoolWorkCallbacks",  (void*)lsw_WaitForThreadpoolWorkCallbacks},
    {"KERNEL32.dll", "CloseThreadpoolWork",             (void*)lsw_CloseThreadpoolWork},
    {"KERNEL32.dll", "CreateThreadpool",                (void*)lsw_CreateThreadpool},
    {"KERNEL32.dll", "CloseThreadpool",                 (void*)lsw_CloseThreadpool},
    {"KERNEL32.dll", "SetThreadpoolThreadMaximum",      (void*)lsw_SetThreadpoolThreadMaximum},
    {"KERNEL32.dll", "SetThreadpoolThreadMinimum",      (void*)lsw_SetThreadpoolThreadMinimum},
    {"KERNEL32.dll", "CreateThreadpoolTimer",           (void*)lsw_CreateThreadpoolTimer},
    {"KERNEL32.dll", "SetThreadpoolTimer",              (void*)lsw_SetThreadpoolTimer},
    {"KERNEL32.dll", "WaitForThreadpoolTimerCallbacks", (void*)lsw_WaitForThreadpoolTimerCallbacks},
    {"KERNEL32.dll", "CloseThreadpoolTimer",            (void*)lsw_CloseThreadpoolTimer},
    {"KERNEL32.dll", "IsThreadpoolTimerSet",            (void*)lsw_IsThreadpoolTimerSet},
    {"KERNEL32.dll", "CreateThreadpoolIo",              (void*)lsw_CreateThreadpoolIo},
    {"KERNEL32.dll", "StartThreadpoolIo",               (void*)lsw_StartThreadpoolIo},
    {"KERNEL32.dll", "CancelThreadpoolIo",              (void*)lsw_CancelThreadpoolIo},
    {"KERNEL32.dll", "WaitForThreadpoolIoCallbacks",    (void*)lsw_WaitForThreadpoolIoCallbacks},
    {"KERNEL32.dll", "CloseThreadpoolIo",               (void*)lsw_CloseThreadpoolIo},
    {"KERNEL32.dll", "InitOnceExecuteOnce",      (void*)lsw_InitOnceExecuteOnce},
    {"KERNEL32.dll", "SetHandleInformation",     (void*)lsw_SetHandleInformation},
    {"KERNEL32.dll", "GetHandleInformation",     (void*)lsw_GetHandleInformation},
    {"KERNEL32.dll", "GetCommandLineW",          (void*)lsw_GetCommandLineW},
    {"KERNEL32.dll", "RtlMoveMemory",            (void*)lsw_RtlMoveMemory},
    {"KERNEL32.dll", "RtlFillMemory",            (void*)lsw_RtlFillMemory},
    {"KERNEL32.dll", "RtlZeroMemory",            (void*)lsw_RtlZeroMemory},
    {"KERNEL32.dll", "ZeroMemory",               (void*)lsw_ZeroMemory},
    {"KERNEL32.dll", "FillMemory",               (void*)lsw_FillMemory},
    {"KERNEL32.dll", "CopyMemory",               (void*)lsw_CopyMemory},
    {"KERNEL32.dll", "MoveMemory",               (void*)lsw_MoveMemory},
    {"KERNEL32.dll", "CharToOemA",               (void*)lsw_CharToOemA},
    {"KERNEL32.dll", "OemToCharA",               (void*)lsw_OemToCharA},
    // KERNEL32 batch 2
    {"KERNEL32.dll", "IsWow64Process",           (void*)lsw_IsWow64Process},
    {"KERNEL32.dll", "FreeLibrary",              (void*)lsw_FreeLibrary},
    {"KERNEL32.dll", "FreeLibraryAndExitThread", (void*)lsw_FreeLibraryAndExitThread},
    {"KERNEL32.dll", "LoadLibraryExW",           (void*)lsw_LoadLibraryExW},
    {"KERNEL32.dll", "GetModuleHandleExW",       (void*)lsw_GetModuleHandleExW},
    {"KERNEL32.dll", "GetModuleHandleExA",       (void*)lsw_GetModuleHandleExA},
    {"KERNEL32.dll", "HeapCreate",               (void*)lsw_HeapCreate},
    {"KERNEL32.dll", "HeapDestroy",              (void*)lsw_HeapDestroy},
    {"KERNEL32.dll", "HeapValidate",             (void*)lsw_HeapValidate},
    {"KERNEL32.dll", "HeapCompact",              (void*)lsw_HeapCompact},
    {"KERNEL32.dll", "HeapLock",                 (void*)lsw_HeapLock},
    {"KERNEL32.dll", "HeapUnlock",               (void*)lsw_HeapUnlock},
    {"KERNEL32.dll", "HeapWalk",                 (void*)lsw_HeapWalk},
    {"KERNEL32.dll", "HeapSetInformation",       (void*)lsw_HeapSetInformation},
    {"KERNEL32.dll", "HeapQueryInformation",     (void*)lsw_HeapQueryInformation},
    {"KERNEL32.dll", "TlsAlloc",                 (void*)lsw_TlsAlloc},
    {"KERNEL32.dll", "TlsFree",                  (void*)lsw_TlsFree},
    {"KERNEL32.dll", "TlsSetValue",              (void*)lsw_TlsSetValue},
    {"KERNEL32.dll", "TlsGetValue",              (void*)lsw_TlsGetValueEx},
    {"KERNEL32.dll", "CompareStringW",           (void*)lsw_CompareStringW},
    {"KERNEL32.dll", "CompareStringA",           (void*)lsw_CompareStringA},
    {"KERNEL32.dll", "CompareStringEx",          (void*)lsw_CompareStringEx},
    {"KERNEL32.dll", "CompareStringOrdinal",     (void*)lsw_CompareStringOrdinal},
    {"KERNEL32.dll", "lstrcmpA",                 (void*)lsw_lstrcmpA},
    {"KERNEL32.dll", "lstrcmpiA",                (void*)lsw_lstrcmpiA},
    {"KERNEL32.dll", "lstrcmpW",                 (void*)lsw_lstrcmpW},
    {"KERNEL32.dll", "lstrcmpiW",                (void*)lsw_lstrcmpiW},
    {"KERNEL32.dll", "lstrcpyA",                 (void*)lsw_lstrcpyA},
    {"KERNEL32.dll", "lstrcpynA",                (void*)lsw_lstrcpynA},
    {"KERNEL32.dll", "lstrlenA",                 (void*)lsw_lstrlenA},
    {"KERNEL32.dll", "lstrlenW",                 (void*)lsw_lstrlenW},
    {"KERNEL32.dll", "SystemParametersInfoW",    (void*)lsw_SystemParametersInfoW},
    {"KERNEL32.dll", "SystemParametersInfoA",    (void*)lsw_SystemParametersInfoA},
    {"KERNEL32.dll", "TryAcquireSRWLockExclusive",(void*)lsw_TryAcquireSRWLockExclusive},
    {"KERNEL32.dll", "TryAcquireSRWLockShared",  (void*)lsw_TryAcquireSRWLockShared},
    {"KERNEL32.dll", "OpenFileMappingW",         (void*)lsw_OpenFileMappingW},
    {"KERNEL32.dll", "OpenFileMappingA",         (void*)lsw_OpenFileMappingA},
    {"KERNEL32.dll", "CreateFileMappingA",       (void*)lsw_CreateFileMappingA},
    {"KERNEL32.dll", "MapViewOfFileEx",          (void*)lsw_MapViewOfFileEx},
    {"KERNEL32.dll", "FlushViewOfFile",          (void*)lsw_FlushViewOfFile},
    {"KERNEL32.dll", "FlushFileBuffers",         (void*)lsw_FlushFileBuffers},
    {"KERNEL32.dll", "GetFileSizeEx",            (void*)lsw_GetFileSizeEx},
    {"KERNEL32.dll", "SetEndOfFile",             (void*)lsw_SetEndOfFile},
    {"KERNEL32.dll", "LockFile",                 (void*)lsw_LockFile},
    {"KERNEL32.dll", "UnlockFile",               (void*)lsw_UnlockFile},
    {"KERNEL32.dll", "LockFileEx",               (void*)lsw_LockFileEx},
    {"KERNEL32.dll", "UnlockFileEx",             (void*)lsw_UnlockFileEx},
    {"KERNEL32.dll", "SetFilePointerEx",         (void*)lsw_SetFilePointerEx},
    {"KERNEL32.dll", "GetFileTime",              (void*)lsw_GetFileTime},
    {"KERNEL32.dll", "SetFileTime",              (void*)lsw_SetFileTime},
    {"KERNEL32.dll", "GetFileInformationByHandle",(void*)lsw_GetFileInformationByHandle},
    {"KERNEL32.dll", "GetFileInformationByHandleEx",(void*)lsw_GetFileInformationByHandleEx},
    {"KERNEL32.dll", "GetFileAttributesExW",     (void*)lsw_GetFileAttributesExW},
    {"KERNEL32.dll", "GetFileAttributesExA",     (void*)lsw_GetFileAttributesExA},
    {"KERNEL32.dll", "FindFirstFileW",           (void*)lsw_FindFirstFileW},
    {"KERNEL32.dll", "FindNextFileW",            (void*)lsw_FindNextFileW},
    {"KERNEL32.dll", "FindFirstFileExW",         (void*)lsw_FindFirstFileExW},
    {"KERNEL32.dll", "FindClose",                (void*)lsw_FindClose},
    {"KERNEL32.dll", "RemoveDirectoryA",         (void*)lsw_RemoveDirectoryA},
    {"KERNEL32.dll", "GetVolumeInformationW",    (void*)lsw_GetVolumeInformationW},
    {"KERNEL32.dll", "GetVolumeInformationA",    (void*)lsw_GetVolumeInformationA},
    {"KERNEL32.dll", "GetDriveTypeW",            (void*)lsw_GetDriveTypeW},
    {"KERNEL32.dll", "GetDriveTypeA",            (void*)lsw_GetDriveTypeA},
    {"KERNEL32.dll", "GetLogicalDrives",         (void*)lsw_GetLogicalDrives},
    {"KERNEL32.dll", "GetLogicalDriveStringsW",  (void*)lsw_GetLogicalDriveStringsW},
    {"KERNEL32.dll", "GetLogicalDriveStringsA",  (void*)lsw_GetLogicalDriveStringsA},
    {"KERNEL32.dll", "GetDiskFreeSpaceExW",      (void*)lsw_GetDiskFreeSpaceExW},
    {"KERNEL32.dll", "GetDiskFreeSpaceExA",      (void*)lsw_GetDiskFreeSpaceExA},
    {"KERNEL32.dll", "GetDiskFreeSpaceW",        (void*)lsw_GetDiskFreeSpaceW},
    {"KERNEL32.dll", "InitializeCriticalSectionAndSpinCount",(void*)lsw_InitializeCriticalSectionAndSpinCount},
    {"KERNEL32.dll", "InitializeCriticalSectionEx",(void*)lsw_InitializeCriticalSectionEx},
    {"KERNEL32.dll", "TryEnterCriticalSection",  (void*)lsw_TryEnterCriticalSection},
    {"KERNEL32.dll", "SetCriticalSectionSpinCount",(void*)lsw_SetCriticalSectionSpinCount},
    {"KERNEL32.dll", "SuspendThread",            (void*)lsw_SuspendThread},
    {"KERNEL32.dll", "ResumeThread",             (void*)lsw_ResumeThread},
    {"KERNEL32.dll", "TerminateThread",          (void*)lsw_TerminateThread},
    {"KERNEL32.dll", "TerminateProcess",         (void*)lsw_TerminateProcess},
    {"KERNEL32.dll", "GetExitCodeThread",        (void*)lsw_GetExitCodeThread},
    {"KERNEL32.dll", "GetExitCodeProcess",       (void*)lsw_GetExitCodeProcess},
    {"KERNEL32.dll", "OpenThread",               (void*)lsw_OpenThread},
    {"KERNEL32.dll", "OpenProcess",              (void*)lsw_OpenProcess},
    {"KERNEL32.dll", "GetProcessId",             (void*)lsw_GetProcessId},
    {"KERNEL32.dll", "GetThreadId",              (void*)lsw_GetThreadId},
    {"KERNEL32.dll", "SetThreadPriority",        (void*)lsw_SetThreadPriority},
    {"KERNEL32.dll", "GetThreadPriority",        (void*)lsw_GetThreadPriority},
    {"KERNEL32.dll", "SetThreadPriorityBoost",   (void*)lsw_SetThreadPriorityBoost},
    {"KERNEL32.dll", "SetThreadAffinityMask",    (void*)lsw_SetThreadAffinityMask},
    {"KERNEL32.dll", "SleepEx",                  (void*)lsw_SleepEx},
    {"KERNEL32.dll", "SwitchToThread",           (void*)lsw_SwitchToThread},
    {"KERNEL32.dll", "Beep",                     (void*)lsw_Beep},
    {"KERNEL32.dll", "CreatePipe",               (void*)lsw_CreatePipe},
    {"KERNEL32.dll", "CreateNamedPipeA",         (void*)lsw_CreateNamedPipeA},
    {"KERNEL32.dll", "CreateNamedPipeW",         (void*)lsw_CreateNamedPipeW},
    {"KERNEL32.dll", "ConnectNamedPipe",         (void*)lsw_ConnectNamedPipe},
    {"KERNEL32.dll", "DisconnectNamedPipe",      (void*)lsw_DisconnectNamedPipe},
    {"KERNEL32.dll", "CallNamedPipeW",           (void*)lsw_CallNamedPipeW},
    {"KERNEL32.dll", "CallNamedPipeA",           (void*)lsw_CallNamedPipeW},
    {"KERNEL32.dll", "WaitNamedPipeA",           (void*)lsw_WaitNamedPipeA},
    {"KERNEL32.dll", "WaitNamedPipeW",           (void*)lsw_WaitNamedPipeW},
    {"KERNEL32.dll", "GetConsoleCP",             (void*)lsw_GetConsoleCP},
    {"KERNEL32.dll", "GetConsoleOutputCP",       (void*)lsw_GetConsoleOutputCP},
    {"KERNEL32.dll", "SetConsoleCP",             (void*)lsw_SetConsoleCP},
    {"KERNEL32.dll", "SetConsoleOutputCP",       (void*)lsw_SetConsoleOutputCP},
    {"KERNEL32.dll", "GetConsoleCursorInfo",     (void*)lsw_GetConsoleCursorInfo},
    {"KERNEL32.dll", "SetConsoleCursorInfo",     (void*)lsw_SetConsoleCursorInfo},
    {"KERNEL32.dll", "SetConsoleCursorPosition", (void*)lsw_SetConsoleCursorPosition},
    {"KERNEL32.dll", "GetConsoleScreenBufferInfo",(void*)lsw_GetConsoleScreenBufferInfo},
    {"KERNEL32.dll", "SetConsoleTextAttribute",  (void*)lsw_SetConsoleTextAttribute},
    {"KERNEL32.dll", "SetConsoleScreenBufferSize",(void*)lsw_SetConsoleScreenBufferSize},
    {"KERNEL32.dll", "FillConsoleOutputCharacterW",(void*)lsw_FillConsoleOutputCharacterW},
    {"KERNEL32.dll", "FillConsoleOutputAttribute",(void*)lsw_FillConsoleOutputAttribute},
    {"KERNEL32.dll", "WriteConsoleOutputCharacterW",(void*)lsw_WriteConsoleOutputCharacterW},
    {"KERNEL32.dll", "WriteConsoleOutputW",      (void*)lsw_WriteConsoleOutputW},
    {"KERNEL32.dll", "ReadConsoleInputW",        (void*)lsw_ReadConsoleInputW},
    {"KERNEL32.dll", "GetNumberOfConsoleInputEvents",(void*)lsw_GetNumberOfConsoleInputEvents},
    {"KERNEL32.dll", "SetConsoleWindowInfo",     (void*)lsw_SetConsoleWindowInfo},
    {"KERNEL32.dll", "SetConsoleActiveScreenBuffer",(void*)lsw_SetConsoleActiveScreenBuffer},
    {"KERNEL32.dll", "CreateConsoleScreenBuffer",(void*)lsw_CreateConsoleScreenBuffer},
    {"KERNEL32.dll", "GetStartupInfoW",          (void*)lsw_GetStartupInfoW},
    {"KERNEL32.dll", "GetStartupInfoA",          (void*)lsw_GetStartupInfoA},
    {"KERNEL32.dll", "CreateProcessW",           (void*)lsw_CreateProcessW},
    {"KERNEL32.dll", "CreateProcessA",           (void*)lsw_CreateProcessA},
    {"KERNEL32.dll", "CreateSymbolicLinkW",      (void*)lsw_CreateSymbolicLinkW},
    {"KERNEL32.dll", "CreateSymbolicLinkA",      (void*)lsw_CreateSymbolicLinkA},
    {"KERNEL32.dll", "CreateHardLinkW",          (void*)lsw_CreateHardLinkW},
    {"KERNEL32.dll", "CreateHardLinkA",          (void*)lsw_CreateHardLinkA},
    {"KERNEL32.dll", "LocalLock",                (void*)lsw_LocalLock},
    {"KERNEL32.dll", "LocalUnlock",              (void*)lsw_LocalUnlock},
    {"KERNEL32.dll", "LocalSize",                (void*)lsw_LocalSize},
    {"KERNEL32.dll", "LocalReAlloc",             (void*)lsw_LocalReAlloc},
    {"KERNEL32.dll", "LocalFlags",               (void*)lsw_LocalFlags},
    {"KERNEL32.dll", "GlobalUnlock",             (void*)lsw_GlobalUnlock},
    {"KERNEL32.dll", "GlobalSize",               (void*)lsw_GlobalSize},
    {"KERNEL32.dll", "GlobalReAlloc",            (void*)lsw_GlobalReAlloc},
    {"KERNEL32.dll", "GlobalHandle",             (void*)lsw_GlobalHandle},
    {"KERNEL32.dll", "GlobalFlags",              (void*)lsw_GlobalFlags},
    {"KERNEL32.dll", "GlobalAddAtomW",           (void*)lsw_GlobalAddAtomW},
    {"KERNEL32.dll", "GlobalDeleteAtom",         (void*)lsw_GlobalDeleteAtom},
    {"KERNEL32.dll", "GlobalFindAtomW",          (void*)lsw_GlobalFindAtomW},
    {"KERNEL32.dll", "GlobalGetAtomNameW",       (void*)lsw_GlobalGetAtomNameW},
    {"KERNEL32.dll", "AddAtomW",                 (void*)lsw_AddAtomW},
    {"KERNEL32.dll", "DeleteAtom",               (void*)lsw_DeleteAtom},
    {"KERNEL32.dll", "FindAtomW",                (void*)lsw_FindAtomW},
    {"KERNEL32.dll", "GetAtomNameW",             (void*)lsw_GetAtomNameW},
    {"KERNEL32.dll", "DeviceIoControl",          (void*)lsw_DeviceIoControl},
    {"KERNEL32.dll", "GetNativeSystemInfo",      (void*)lsw_GetNativeSystemInfo},
    {"KERNEL32.dll", "GetSystemTimes",           (void*)lsw_GetSystemTimes},
    {"KERNEL32.dll", "GetProcessTimes",          (void*)lsw_GetProcessTimes},
    {"KERNEL32.dll", "GetThreadTimes",           (void*)lsw_GetThreadTimes},
    {"KERNEL32.dll", "GetTimeZoneInformation",   (void*)lsw_GetTimeZoneInformation},
    {"KERNEL32.dll", "GetOverlappedResult",      (void*)lsw_GetOverlappedResult},
    {"KERNEL32.dll", "ReadFileEx",               (void*)lsw_ReadFileEx},
    {"KERNEL32.dll", "WriteFileEx",              (void*)lsw_WriteFileEx},
    {"KERNEL32.dll", "CancelIo",                 (void*)lsw_CancelIo},
    {"KERNEL32.dll", "CancelIoEx",               (void*)lsw_CancelIoEx},
    {"KERNEL32.dll", "CancelSynchronousIo",      (void*)lsw_CancelSynchronousIo},
    {"KERNEL32.dll", "VirtualAllocEx",           (void*)lsw_VirtualAllocEx},
    {"KERNEL32.dll", "VirtualFreeEx",            (void*)lsw_VirtualFreeEx},
    {"KERNEL32.dll", "VirtualProtectEx",         (void*)lsw_VirtualProtectEx},
    {"KERNEL32.dll", "GetBinaryTypeW",           (void*)lsw_GetBinaryTypeW},
    {"KERNEL32.dll", "GetBinaryTypeA",           (void*)lsw_GetBinaryTypeA},
    {"KERNEL32.dll", "SetErrorMode",             (void*)lsw_SetErrorMode},
    {"KERNEL32.dll", "GetErrorMode",             (void*)lsw_GetErrorMode},
    {"KERNEL32.dll", "SetThreadErrorMode",       (void*)lsw_SetThreadErrorMode},
    {"KERNEL32.dll", "GetThreadErrorMode",       (void*)lsw_GetThreadErrorMode},
    {"KERNEL32.dll", "GetProcessVersion",        (void*)lsw_GetProcessVersion},
    {"KERNEL32.dll", "GetCurrentPackageId",      (void*)lsw_GetCurrentPackageId},
    {"KERNEL32.dll", "GetActiveProcessorCount",  (void*)lsw_GetActiveProcessorCount},
    {"KERNEL32.dll", "GetActiveProcessorGroupCount",(void*)lsw_GetActiveProcessorGroupCount},
    {"KERNEL32.dll", "QueryFullProcessImageNameW",(void*)lsw_QueryFullProcessImageNameW},
    {"KERNEL32.dll", "RaiseException",           (void*)lsw_RaiseException},
    {"KERNEL32.dll", "SetConsoleCtrlHandler",    (void*)lsw_SetConsoleCtrlHandler},
    {"KERNEL32.dll", "GenerateConsoleCtrlEvent", (void*)lsw_GenerateConsoleCtrlEvent},
    {"KERNEL32.dll", "GetConsoleTitle",          (void*)lsw_GetConsoleTitle},
    // USER32 SystemParametersInfo (also lives under user32.dll)
    {"user32.dll",   "SystemParametersInfoW",    (void*)lsw_SystemParametersInfoW},
    {"user32.dll",   "SystemParametersInfoA",    (void*)lsw_SystemParametersInfoA},
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

void* win32_api_get_generic_stub(void) {
    return (void*)(uintptr_t)generic_stub;
}

/*
 * Ordinal-to-name tables for the most common DLLs.
 * Only well-known, frequently-encountered ordinals are listed.
 * For any DLL/ordinal pair not found here the generic stub is returned
 * so that IAT patching still succeeds (the app won't crash on import,
 * and will only fail if it actually calls the unresolved function).
 */
typedef struct {
    const char* dll_name;
    uint16_t    ordinal;
    const char* function_name;
} lsw_ordinal_entry_t;

static const lsw_ordinal_entry_t ordinal_table[] = {
    /* ws2_32.dll — documented ordinals (Windows SDK) */
    {"ws2_32.dll",  1, "bind"},
    {"ws2_32.dll",  2, "closesocket"},
    {"ws2_32.dll",  3, "connect"},
    {"ws2_32.dll",  4, "getpeername"},
    {"ws2_32.dll",  5, "getsockname"},
    {"ws2_32.dll",  6, "getsockopt"},
    {"ws2_32.dll",  7, "htonl"},
    {"ws2_32.dll",  8, "htons"},
    {"ws2_32.dll",  9, "ioctlsocket"},
    {"ws2_32.dll", 10, "inet_addr"},
    {"ws2_32.dll", 11, "inet_ntoa"},
    {"ws2_32.dll", 12, "listen"},
    {"ws2_32.dll", 13, "ntohl"},
    {"ws2_32.dll", 14, "ntohs"},
    {"ws2_32.dll", 15, "recv"},
    {"ws2_32.dll", 16, "recvfrom"},
    {"ws2_32.dll", 17, "select"},
    {"ws2_32.dll", 18, "send"},
    {"ws2_32.dll", 19, "sendto"},
    {"ws2_32.dll", 20, "setsockopt"},
    {"ws2_32.dll", 21, "shutdown"},
    {"ws2_32.dll", 22, "socket"},
    {"ws2_32.dll", 23, "GetAddrInfoW"},
    {"ws2_32.dll", 24, "GetNameInfoW"},
    {"ws2_32.dll", 51, "gethostbyaddr"},
    {"ws2_32.dll", 52, "gethostbyname"},
    {"ws2_32.dll", 53, "getprotobyname"},
    {"ws2_32.dll", 54, "getprotobynumber"},
    {"ws2_32.dll", 55, "getservbyname"},
    {"ws2_32.dll", 56, "getservbyport"},
    {"ws2_32.dll", 57, "gethostname"},
    {"ws2_32.dll",111, "WSAAsyncGetHostByAddr"},
    {"ws2_32.dll",112, "WSAAsyncGetHostByName"},
    {"ws2_32.dll",113, "WSAAsyncGetProtoByName"},
    {"ws2_32.dll",114, "WSAAsyncGetProtoByNumber"},
    {"ws2_32.dll",115, "WSAStartup"},
    {"ws2_32.dll",116, "WSACleanup"},
    {"ws2_32.dll",117, "WSASetLastError"},
    {"ws2_32.dll",118, "WSAGetLastError"},
    /* ntdll.dll — ordinals used by some apps */
    {"ntdll.dll",   0, "RtlAllocateHeap"},
    {"ntdll.dll",   2, "RtlFreeHeap"},
    /* {sentinel} */
    {NULL, 0, NULL}
};

void* win32_api_resolve_ordinal(const char* dll_name, uint16_t ordinal) {
    /* First: walk the ordinal_table to map ordinal → function name */
    for (int i = 0; ordinal_table[i].dll_name != NULL; i++) {
        if (strcasecmp(ordinal_table[i].dll_name, dll_name) == 0 &&
            ordinal_table[i].ordinal == ordinal) {
            /* Found a name — resolve through the normal table */
            const char* fn = ordinal_table[i].function_name;
            void* addr = win32_api_resolve(dll_name, fn);
            if (addr) {
                LSW_LOG_DEBUG("Ordinal %s!#%u -> %s -> %p", dll_name, ordinal, fn, addr);
                return addr;
            }
        }
    }
    /* Unknown ordinal — caller will use generic_stub */
    LSW_LOG_WARN("Unknown ordinal %s!#%u — caller will use generic stub", dll_name, ordinal);
    return NULL;
}


/* Secondary mapping tables from split Win32 API stub files */
extern const win32_api_mapping_t win32_api_ntdll_mappings[];
extern const size_t               win32_api_ntdll_mappings_count;
extern const win32_api_mapping_t win32_api_user32_mappings[];
extern const size_t               win32_api_user32_mappings_count;
extern const win32_api_mapping_t win32_api_shlwapi_mappings[];
extern const size_t               win32_api_shlwapi_mappings_count;
extern const win32_api_mapping_t win32_api_shell32_mappings[];
extern const size_t               win32_api_shell32_mappings_count;
extern const win32_api_mapping_t win32_api_ole32_mappings[];
extern const size_t               win32_api_ole32_mappings_count;
extern const win32_api_mapping_t win32_api_oleaut32_mappings[];
extern const size_t               win32_api_oleaut32_mappings_count;
extern const win32_api_mapping_t win32_api_comctl32_mappings[];
extern const size_t               win32_api_comctl32_mappings_count;
extern const win32_api_mapping_t win32_api_misc_mappings[];
extern const size_t               win32_api_misc_mappings_count;
extern win32_api_mapping_t        win32_api_advapi32_mappings[];
extern size_t                     win32_api_advapi32_mappings_count;
extern const win32_api_mapping_t  win32_api_game_mappings[];
extern const size_t               win32_api_game_mappings_count;

void* win32_api_resolve(const char* dll_name, const char* function_name) {
    /* Primary table */
    for (size_t i = 0; i < api_mappings_count; i++) {
        if (strcasecmp(api_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(api_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved %s!%s -> %p", dll_name, function_name, api_mappings[i].implementation);
            return api_mappings[i].implementation;
        }
    }
    /* ntdll secondary table */
    for (size_t i = 0; i < win32_api_ntdll_mappings_count; i++) {
        if (strcasecmp(win32_api_ntdll_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_ntdll_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(ntdll) %s!%s -> %p", dll_name, function_name, win32_api_ntdll_mappings[i].implementation);
            return win32_api_ntdll_mappings[i].implementation;
        }
    }
    /* user32/gdi32 secondary table */
    for (size_t i = 0; i < win32_api_user32_mappings_count; i++) {
        if (strcasecmp(win32_api_user32_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_user32_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(user32) %s!%s -> %p", dll_name, function_name, win32_api_user32_mappings[i].implementation);
            return win32_api_user32_mappings[i].implementation;
        }
    }
    /* shlwapi secondary table */
    for (size_t i = 0; i < win32_api_shlwapi_mappings_count; i++) {
        if (strcasecmp(win32_api_shlwapi_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_shlwapi_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(shlwapi) %s!%s -> %p", dll_name, function_name, win32_api_shlwapi_mappings[i].implementation);
            return win32_api_shlwapi_mappings[i].implementation;
        }
    }
    /* shell32 secondary table */
    for (size_t i = 0; i < win32_api_shell32_mappings_count; i++) {
        if (strcasecmp(win32_api_shell32_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_shell32_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(shell32) %s!%s -> %p", dll_name, function_name, win32_api_shell32_mappings[i].implementation);
            return win32_api_shell32_mappings[i].implementation;
        }
    }
    /* ole32 secondary table */
    for (size_t i = 0; i < win32_api_ole32_mappings_count; i++) {
        if (strcasecmp(win32_api_ole32_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_ole32_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(ole32) %s!%s -> %p", dll_name, function_name, win32_api_ole32_mappings[i].implementation);
            return win32_api_ole32_mappings[i].implementation;
        }
    }
    /* oleaut32 secondary table */
    for (size_t i = 0; i < win32_api_oleaut32_mappings_count; i++) {
        if (strcasecmp(win32_api_oleaut32_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_oleaut32_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(oleaut32) %s!%s -> %p", dll_name, function_name, win32_api_oleaut32_mappings[i].implementation);
            return win32_api_oleaut32_mappings[i].implementation;
        }
    }
    /* comctl32 secondary table */
    for (size_t i = 0; i < win32_api_comctl32_mappings_count; i++) {
        if (strcasecmp(win32_api_comctl32_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_comctl32_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(comctl32) %s!%s -> %p", dll_name, function_name, win32_api_comctl32_mappings[i].implementation);
            return win32_api_comctl32_mappings[i].implementation;
        }
    }
    /* misc DLL secondary table */
    for (size_t i = 0; i < win32_api_misc_mappings_count; i++) {
        if (strcasecmp(win32_api_misc_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_misc_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(misc) %s!%s -> %p", dll_name, function_name, win32_api_misc_mappings[i].implementation);
            return win32_api_misc_mappings[i].implementation;
        }
    }
    /* advapi32 secondary table */
    for (size_t i = 0; i < win32_api_advapi32_mappings_count; i++) {
        if (strcasecmp(win32_api_advapi32_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_advapi32_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(advapi32) %s!%s -> %p", dll_name, function_name, win32_api_advapi32_mappings[i].implementation);
            return win32_api_advapi32_mappings[i].implementation;
        }
    }
    /* game API table */
    for (size_t i = 0; i < win32_api_game_mappings_count; i++) {
        if (strcasecmp(win32_api_game_mappings[i].dll_name, dll_name) == 0 &&
            strcmp(win32_api_game_mappings[i].function_name, function_name) == 0) {
            LSW_LOG_DEBUG("Resolved(game) %s!%s -> %p", dll_name, function_name, win32_api_game_mappings[i].implementation);
            return win32_api_game_mappings[i].implementation;
        }
    }

    LSW_LOG_WARN("Could not resolve %s!%s - returning stub", dll_name, function_name);
    return (void*)(uintptr_t)generic_stub;
}

/* Search all tables by function name only — used by GetProcAddress on system handles */
void* win32_api_resolve_any(const char* function_name) {
    if (!function_name) return NULL;
    /* Try with each known system DLL name */
    static const char* dllnames[] = {
        "KERNEL32.dll","kernel32.dll","USER32.dll","user32.dll",
        "GDI32.dll","gdi32.dll","ADVAPI32.dll","advapi32.dll",
        "ntdll.dll","NTDLL.dll","ws2_32.dll","WS2_32.dll",
        "shell32.dll","SHELL32.dll","shlwapi.dll","ole32.dll",
        "oleaut32.dll","comctl32.dll","MSVCRT.dll","msvcrt.dll",
        "ucrtbase.dll","vcruntime140.dll",
        NULL
    };
    for (int di = 0; dllnames[di]; di++) {
        /* Only call resolve for non-stub result */
        for (size_t i = 0; i < api_mappings_count; i++) {
            if (strcasecmp(api_mappings[i].dll_name, dllnames[di]) == 0 &&
                strcmp(api_mappings[i].function_name, function_name) == 0)
                return api_mappings[i].implementation;
        }
    }
    /* Linear search across all secondary tables without DLL filter */
    #define SEARCH_TABLE(tbl, cnt) \
        for (size_t i = 0; i < cnt; i++) \
            if (strcmp(tbl[i].function_name, function_name) == 0) return tbl[i].implementation;
    SEARCH_TABLE(win32_api_ntdll_mappings,   win32_api_ntdll_mappings_count)
    SEARCH_TABLE(win32_api_user32_mappings,  win32_api_user32_mappings_count)
    SEARCH_TABLE(win32_api_shlwapi_mappings, win32_api_shlwapi_mappings_count)
    SEARCH_TABLE(win32_api_shell32_mappings, win32_api_shell32_mappings_count)
    SEARCH_TABLE(win32_api_ole32_mappings,   win32_api_ole32_mappings_count)
    SEARCH_TABLE(win32_api_oleaut32_mappings,win32_api_oleaut32_mappings_count)
    SEARCH_TABLE(win32_api_comctl32_mappings,win32_api_comctl32_mappings_count)
    SEARCH_TABLE(win32_api_misc_mappings,    win32_api_misc_mappings_count)
    SEARCH_TABLE(win32_api_advapi32_mappings,win32_api_advapi32_mappings_count)
    SEARCH_TABLE(win32_api_game_mappings,    win32_api_game_mappings_count)
    #undef SEARCH_TABLE
    return NULL;
}

const win32_api_mapping_t* win32_api_get_mappings(size_t* count) {
    if (count) {
        *count = api_mappings_count;
    }
    return api_mappings;
}
