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
#include <inttypes.h>   /* PRId64, PRIu64, PRIx64, PRIX64 */
#include <uchar.h>      /* char16_t (for (const uint16_t*)u"" literals) */
#include <semaphore.h>   /* sem_t — for CreateSemaphore */
#include <sys/timerfd.h> /* timerfd_create — for waitable timers */
#include <poll.h>        /* poll — for IOCP wait */
#include <execinfo.h>   /* backtrace, backtrace_symbols_fd */
#include <setjmp.h>      /* longjmp — for C++ exception delivery */
#include <pwd.h>         /* getpwuid — for username lookup */

/* ---- ms_abi va_list → sysv va_list conversion ----
 * GCC generates broken sysv va_list when va_start is used inside __attribute__((ms_abi))
 * variadic functions. Fix: use __builtin_ms_va_start to get a proper ms_abi va_list (just a
 * stack pointer), then manually build a sysv va_list struct with:
 *   gp_offset=48 (all 6 GP regs "used") and overflow_arg_area = the ms stack pointer.
 * This correctly maps ms_abi variadic args (stored linearly on the stack) to sysv's
 * "overflow" arg area which vsnprintf/etc. reads from when gp_offset >= 48.
 *
 * x86-64 sysv va_list layout: { uint gp_off(4), fp_off(4), void* oa(8), void* rs(8) }[1]
 */
#define LSW_MS_TO_SYSV_VA(sysv_ap_, ms_ap_) do { \
    ((unsigned int*)(sysv_ap_))[0] = 48;          \
    ((unsigned int*)(sysv_ap_))[1] = 304;         \
    ((void**)((char*)(sysv_ap_)+8))[0] = (ms_ap_);\
    ((void**)((char*)(sysv_ap_)+16))[0] = NULL;   \
} while(0)


#define LSW_IOCTL_SYSCALL _IOWR(LSW_IOCTL_MAGIC, 5, struct lsw_syscall_request)

/* Forward declarations */
static void createprocess_win_to_linux(const char* wpath, char* out, size_t outsz);
int __attribute__((ms_abi)) lsw_GetDiskFreeSpaceW(const uint16_t* lpRootPathName, uint32_t* lpSectorsPerCluster, uint32_t* lpBytesPerSector, uint32_t* lpNumberOfFreeClusters, uint32_t* lpTotalNumberOfClusters);
int __attribute__((ms_abi)) lsw_WideCharToMultiByte(unsigned int codepage, unsigned long flags, const wchar_t* src, int srclen, char* dst, int dstlen, const char* defchar, int* used_default);
int __attribute__((ms_abi)) lsw_MultiByteToWideChar(unsigned int codepage, unsigned long flags, const char* src, int srclen, uint16_t* dst, int dstlen);

/* Windows pseudo-handle constants: STD_INPUT=-10, STD_OUTPUT=-11, STD_ERROR=-12 */
#define LSW_IS_PSEUDO_HANDLE(h) ((intptr_t)(uintptr_t)(h) >= -12 && (intptr_t)(uintptr_t)(h) <= -10)
static inline int lsw_pseudo_handle_to_fd(void* handle) {
    intptr_t h = (intptr_t)(uintptr_t)handle;
    if (h == -10) return STDIN_FILENO;
    if (h == -11) return STDOUT_FILENO;
    if (h == -12) return STDERR_FILENO;
    return -1;
}

/* ---- Global exe path (set by PE loader at startup) ---- */
static char g_lsw_exe_path[4096] = {0};

/* ---- PE image info for x64 C++ exception dispatch ---- */
static uint64_t g_lsw_image_base  = 0;
static uint32_t g_lsw_image_size  = 0;   /* SizeOfImage from PE header */
static void*    g_lsw_pdata_va    = NULL;
static uint32_t g_lsw_pdata_size  = 0;

/* Forward declaration (struct defined below) */
struct lsw_pe_hmodule_s;
typedef struct lsw_pe_hmodule_s lsw_pe_hmodule_t;

/* ---- PE module handle ---- */
#define LSW_PE_HMODULE_MAGIC 0x5045484DU  /* "PEHM" */
struct lsw_pe_hmodule_s {
    uint32_t magic;
    char dll_name[128];
    void*  image_base;
    size_t image_size;
    void*  export_dir;
    uint32_t export_dir_size;
    /* resource section: NULL if the DLL has no .rsrc section */
    void*    rsrc_raw;   /* pointer into image_base at VirtualAddress of .rsrc */
    uint32_t rsrc_rva;   /* VirtualAddress of .rsrc section */
    /* MUI satellite image (for message-only DLLs on Vista+) */
    void*    mui_image;
    size_t   mui_image_size;
    /* 1 if sections are already mapped at VAs (in-memory PE, e.g. main exe);
     * 0 if flat file layout where RVA must be translated via section raw offsets. */
    int      mapped_va;
};

/* ---- Typed handle for the main executable (returned by GetModuleHandle(NULL)) ---- */
/* Defined as a static so it lives forever and can be safely returned as an HMODULE */
static lsw_pe_hmodule_t g_main_exe_hmodule;
static int               g_main_exe_hmodule_ready = 0;

void win32_api_set_pe_image_info(uint64_t image_base,
                                  void*    pdata_va,
                                  uint32_t pdata_size,
                                  uint32_t image_size)
{
    g_lsw_image_base = image_base;
    g_lsw_image_size = image_size;
    g_lsw_pdata_va   = pdata_va;
    g_lsw_pdata_size = pdata_size;
    LSW_LOG_INFO("[exception] PE image info: base=0x%lx pdata=%p size=%u",
                 (unsigned long)image_base, pdata_va, pdata_size);

    /* Build typed HMODULE for the main executable so that
     * GetModuleHandleA(NULL) returns a handle that FormatMessageW(FROM_HMODULE)
     * can use to find RT_MESSAGETABLE resources (e.g. ping.exe, ipconfig.exe). */
    if (image_base && !g_main_exe_hmodule_ready) {
        /* defined as 0x5045484DU below — replicate literal to avoid forward-ref */
        g_main_exe_hmodule.magic      = 0x5045484DU; /* LSW_PE_HMODULE_MAGIC */
        strncpy(g_main_exe_hmodule.dll_name, "<main>", sizeof(g_main_exe_hmodule.dll_name)-1);
        g_main_exe_hmodule.image_base = (void*)(uintptr_t)image_base;
        g_main_exe_hmodule.image_size = image_size;
        g_main_exe_hmodule.export_dir = NULL;
        g_main_exe_hmodule.export_dir_size = 0;
        g_main_exe_hmodule.rsrc_raw   = NULL;
        g_main_exe_hmodule.rsrc_rva   = 0;
        g_main_exe_hmodule.mui_image  = NULL;
        g_main_exe_hmodule.mui_image_size = 0;
        g_main_exe_hmodule.mapped_va  = 1; /* sections mapped at VAs, not raw offsets */
        /* Walk PE section headers to find .rsrc */
        uint8_t* b = (uint8_t*)(uintptr_t)image_base;
        uint32_t pe_off = *(uint32_t*)(b + 0x3C);
        if (pe_off + 4 < image_size && b[pe_off] == 'P' && b[pe_off+1] == 'E') {
            uint16_t opt_size  = *(uint16_t*)(b + pe_off + 4 + 16);
            uint16_t num_sec   = *(uint16_t*)(b + pe_off + 4 + 2);
            uint32_t sec_off   = pe_off + 4 + 20 + opt_size;
            for (uint16_t si = 0; si < num_sec; si++) {
                uint8_t* sh = b + sec_off + (uint32_t)si * 40;
                if (memcmp(sh, ".rsrc\0\0\0", 8) == 0) {
                    g_main_exe_hmodule.rsrc_rva = *(uint32_t*)(sh + 12);
                    g_main_exe_hmodule.rsrc_raw = b + g_main_exe_hmodule.rsrc_rva;
                    break;
                }
            }
        }
        g_main_exe_hmodule_ready = 1;
        LSW_LOG_INFO("[exception] main exe HMODULE ready: rsrc_raw=%p rsrc_rva=0x%x",
                     g_main_exe_hmodule.rsrc_raw, g_main_exe_hmodule.rsrc_rva);

        /* If the main exe has no RT_MESSAGETABLE (Vista+ MUI pattern),
         * look for en-US/<basename>.mui in the same directory as the exe. */
        if (g_lsw_exe_path[0]) {
            char dir_part[4096]; strncpy(dir_part, g_lsw_exe_path, sizeof(dir_part)-1);
            char* sl = strrchr(dir_part, '/');
            if (!sl) sl = strrchr(dir_part, '\\');
            char lower_base[128] = {0};
            const char* base = g_lsw_exe_path;
            if (sl) {
                *sl = '\0';
                base = sl + 1;
            } else {
                dir_part[0] = '\0';
            }
            strncpy(lower_base, base, sizeof(lower_base)-1);
            for (char* p = lower_base; *p; p++) *p = (char)tolower((unsigned char)*p);

            char mui_path[4352];
            if (dir_part[0])
                snprintf(mui_path, sizeof(mui_path), "%s/en-US/%s.mui", dir_part, lower_base);
            else
                snprintf(mui_path, sizeof(mui_path), "en-US/%s.mui", lower_base);

            /* Also try mixed-case basename */
            char mui_path2[4352];
            if (dir_part[0])
                snprintf(mui_path2, sizeof(mui_path2), "%s/en-US/%s.mui", dir_part, base);
            else
                snprintf(mui_path2, sizeof(mui_path2), "en-US/%s.mui", base);

            const char* mui_try = (access(mui_path, R_OK) == 0) ? mui_path :
                                  (access(mui_path2, R_OK) == 0) ? mui_path2 : NULL;
            if (mui_try) {
                int mfd = open(mui_try, O_RDONLY);
                if (mfd >= 0) {
                    struct stat st2;
                    if (fstat(mfd, &st2) == 0 && st2.st_size > 0) {
                        void* mmap_img = mmap(NULL, (size_t)st2.st_size, PROT_READ,
                                              MAP_PRIVATE, mfd, 0);
                        if (mmap_img != MAP_FAILED) {
                            g_main_exe_hmodule.mui_image      = mmap_img;
                            g_main_exe_hmodule.mui_image_size = (size_t)st2.st_size;
                            LSW_LOG_INFO("[exception] MUI loaded: %s (%zu bytes)",
                                         mui_try, (size_t)st2.st_size);
                        }
                    }
                    close(mfd);
                }
            } else {
                LSW_LOG_INFO("[exception] no MUI found at %s", mui_path);
            }
        }
    }
}

void lsw_set_exe_path(const char* path) {
    if (path) strncpy(g_lsw_exe_path, path, sizeof(g_lsw_exe_path) - 1);
}

/* ---- Named pipe handle ---- */
#define LSW_PIPE_MAGIC 0x50495045U  /* "PIPE" */

/*
 * IS_TYPED_HANDLE(h) — true only if 'h' could be a heap-allocated typed handle.
 * Raw file descriptors are small integers (0–1023 typically); malloc pointers on
 * Linux x86-64 are always ≥ 0x10000 (mmap/heap live above page zero).
 * Checking this before dereferencing magic prevents SIGSEGV on raw fd handles.
 */
#define IS_TYPED_HANDLE(h) ((uintptr_t)(h) >= 0x10000u)
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

// ============================================================================
// CRT data-symbol stubs
// msvcrt.dll exports these as DATA (global variables), not functions.
// When the PE IAT has an entry for e.g. "__initenv", the loader must write the
// *address* of a valid char** here, not a code stub.  win32_api_resolve_data()
// below returns &<static> for each known CRT data symbol.
// ============================================================================
static char**          lsw_crt_initenv    = NULL;  /* __initenv   */
static char**          lsw_crt_environ    = NULL;  /* _environ    */
static wchar_t**       lsw_crt_wenviron   = NULL;  /* _wenviron   */
static char*           lsw_crt_acmdln     = NULL;  /* _acmdln     */
static wchar_t*        lsw_crt_wcmdln     = NULL;  /* _wcmdln     */
static int             lsw_crt_argc       = 0;     /* __argc      */
static char**          lsw_crt_argv       = NULL;  /* __argv      */
static wchar_t**       lsw_crt_wargv      = NULL;  /* __wargv     */
static wchar_t**       lsw_crt_wenvp      = NULL;  /* __wenvp     */
static int             lsw_crt_fmode      = 0;     /* _fmode      */
static int             lsw_crt_commode    = 0;     /* _commode    */
static unsigned int    lsw_crt_osver      = 0x0A00;/* _osver      */
static unsigned int    lsw_crt_winver     = 0x0A00;/* _winver     */
static unsigned int    lsw_crt_winmajor   = 10;    /* _winmajor   */
static unsigned int    lsw_crt_winminor   = 0;     /* _winminor   */

/* Character classification table stub — 257 entries (index 0 = EOF sentinel) */
static unsigned short  lsw_crt_pctype[257];
static unsigned short* lsw_crt_pctype_ptr = lsw_crt_pctype + 1; /* _pctype */

/*
 * win32_api_resolve_data() — return the *address* of a static variable for
 * known CRT data-import symbols, or NULL if not a known data symbol.
 *
 * The PE loader writes this address directly into the IAT slot so that
 * Windows CRT startup code that dereferences __imp___initenv etc. works.
 */
void* win32_api_resolve_data(const char* dll_name, const char* sym) {
    (void)dll_name; /* any DLL — most are msvcrt / ucrtbase / api-ms-win-crt-* */
    if (!sym) return NULL;
    /* Strip leading underscore variants */
    const char* s = sym;
    if (s[0] == '_' && s[1] == '_') s += 2;      /* "__initenv" -> "initenv" */
    else if (s[0] == '_')           s += 1;       /* "_environ"  -> "environ" */

    if (!strcmp(sym,"__initenv")  || !strcmp(s,"initenv"))  return &lsw_crt_initenv;
    if (!strcmp(sym,"_environ")   || !strcmp(s,"environ"))  return &lsw_crt_environ;
    if (!strcmp(sym,"_wenviron")  || !strcmp(s,"wenviron")) return &lsw_crt_wenviron;
    if (!strcmp(sym,"_acmdln")    || !strcmp(s,"acmdln"))   return &lsw_crt_acmdln;
    if (!strcmp(sym,"_wcmdln")    || !strcmp(s,"wcmdln"))   return &lsw_crt_wcmdln;
    if (!strcmp(sym,"__argc")     || !strcmp(s,"argc"))     return &lsw_crt_argc;
    if (!strcmp(sym,"__argv")     || !strcmp(s,"argv"))     return &lsw_crt_argv;
    if (!strcmp(sym,"__wargv")    || !strcmp(s,"wargv"))    return &lsw_crt_wargv;
    if (!strcmp(sym,"__wenvp")    || !strcmp(s,"wenvp"))    return &lsw_crt_wenvp;
    if (!strcmp(sym,"_fmode")     || !strcmp(s,"fmode"))    return &lsw_crt_fmode;
    if (!strcmp(sym,"_commode")   || !strcmp(s,"commode"))  return &lsw_crt_commode;
    if (!strcmp(sym,"_osver")     || !strcmp(s,"osver"))    return &lsw_crt_osver;
    if (!strcmp(sym,"_winver")    || !strcmp(s,"winver"))   return &lsw_crt_winver;
    if (!strcmp(sym,"_winmajor")  || !strcmp(s,"winmajor")) return &lsw_crt_winmajor;
    if (!strcmp(sym,"_winminor")  || !strcmp(s,"winminor")) return &lsw_crt_winminor;
    if (!strcmp(sym,"_pctype"))                             return &lsw_crt_pctype_ptr;
    if (!strcmp(sym,"_pwctype"))                            return &lsw_crt_pctype_ptr;
    return NULL;
}

/*
 * win32_crt_data_init() — populate the CRT data stubs from real argc/argv/envp.
 * Called by win32_set_command_line() after the PE is loaded.
 */
void win32_crt_data_init(int argc, char** argv) {
    lsw_crt_argc = argc;
    lsw_crt_argv = argv;
    lsw_crt_initenv = environ;  /* libc's global environ */
    lsw_crt_environ = environ;

    /* Build command-line string from argv.
     * Quote arguments that contain spaces so GetCommandLineW() returns a
     * properly parseable Windows-style command line. */
    static char cmdln_buf[4096];
    cmdln_buf[0] = '\0';
    for (int i = 0; i < argc; i++) {
        if (i) strncat(cmdln_buf, " ", sizeof(cmdln_buf) - strlen(cmdln_buf) - 1);
        int has_space = argv[i] && strchr(argv[i], ' ') != NULL;
        if (has_space) strncat(cmdln_buf, "\"", sizeof(cmdln_buf) - strlen(cmdln_buf) - 1);
        if (argv[i])   strncat(cmdln_buf, argv[i], sizeof(cmdln_buf) - strlen(cmdln_buf) - 1);
        if (has_space) strncat(cmdln_buf, "\"", sizeof(cmdln_buf) - strlen(cmdln_buf) - 1);
    }
    lsw_crt_acmdln = cmdln_buf;

    /* Initialise _pctype with basic ASCII character classification */
    memset(lsw_crt_pctype, 0, sizeof(lsw_crt_pctype));
    for (int c = 0; c < 256; c++) {
        unsigned short v = 0;
        if (isupper(c))  v |= 0x0001;
        if (islower(c))  v |= 0x0002;
        if (isdigit(c))  v |= 0x0004;
        if (isspace(c))  v |= 0x0008;
        if (ispunct(c))  v |= 0x0010;
        if (isblank(c))  v |= 0x0040;
        if (isalpha(c))  v |= 0x0103;
        lsw_crt_pctype[c + 1] = v;
    }
}

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

/*
 * ms_abi va_list → SysV va_list conversion helper
 *
 * In ms_abi, variadic args are all passed on the stack (shadow home space).
 * va_start() sets ap to point to the first variadic arg on the stack.
 * In SysV, va_list is a struct { gp_offset, fp_offset, overflow_arg_area, reg_save_area }.
 * Setting gp_offset=48 fp_offset=176 means "all registers exhausted, read from stack".
 * Then overflow_arg_area=ap reads directly from the ms_abi stack layout.
 * This correctly bridges the two ABIs for integer/pointer variadic args.
 */
typedef struct { unsigned int gp_offset; unsigned int fp_offset;
                 void* overflow_arg_area; void* reg_save_area; } lsw_sysv_va_list_t;

/* Format a string from ms_abi va_list to a heap buffer. Caller must free result. */
static char* lsw_format_ms_va(const char* format, va_list ap) {
    lsw_sysv_va_list_t sysv_ap_s = { 48, 176, ap, NULL };
    /* va_list is an array type; pass via pointer-to-first-element trick */
    __builtin_va_list sysv_vl;
    memcpy(&sysv_vl, &sysv_ap_s, sizeof(sysv_ap_s));
    char* buf = NULL;
    int n = vasprintf(&buf, format, sysv_vl);
    (void)n;
    return buf;
}

int __attribute__((ms_abi)) lsw_printf(const char* format, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, format);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    char* buf = NULL; vasprintf(&buf, format, ap);
    __builtin_ms_va_end(ms_ap);
    if (!buf) return -1;
    int n = (int)write(1, buf, strlen(buf));
    free(buf);
    return n;
}

// vfprintf / fprintf
int __attribute__((ms_abi)) lsw_vfprintf(FILE* stream, const char* format, va_list ap) {
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

    if (!format) return 0;

    /* ap here is an ms_abi va_list (just a pointer); convert to sysv */
    va_list sysv_ap; LSW_MS_TO_SYSV_VA(sysv_ap, ap);
    char* buf = NULL; vasprintf(&buf, format, sysv_ap);
    if (!buf) return -1;

    int fd = -1;
    fake_FILE* fake = (fake_FILE*)stream;
    if (fake && fake->_file >= 0 && fake->_file <= 2)
        fd = fake->_file;
    else if (stream == (FILE*)stdout) fd = 1;
    else if (stream == (FILE*)stderr) fd = 2;
    else if (stream == (FILE*)stdin)  fd = 0;

    int result;
    if (fd >= 0)
        result = (int)write(fd, buf, strlen(buf));
    else
        result = (int)fwrite(buf, 1, strlen(buf), stream ? stream : stderr);

    free(buf);
    return result;
}

int __attribute__((ms_abi)) lsw_fprintf(FILE* stream, const char* format, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, format);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    char* buf = NULL; vasprintf(&buf, format, ap);
    __builtin_ms_va_end(ms_ap);
    if (!buf) return -1;
    int fd = -1;
    if (stream == stdout) fd = 1; else if (stream == stderr) fd = 2;
    int result = (fd >= 0) ? (int)write(fd, buf, strlen(buf))
                           : (int)fwrite(buf, 1, strlen(buf), stream ? stream : stderr);
    free(buf);
    return result;
}

/* Convert a single UTF-16LE code unit to UTF-8. Returns bytes written. */
static int lsw_u16cp_to_utf8(uint16_t c, char* out) {
    if (c < 0x80) { out[0] = (char)c; return 1; }
    if (c < 0x800) { out[0] = 0xC0|(c>>6); out[1] = 0x80|(c&0x3F); return 2; }
    out[0] = 0xE0|(c>>12); out[1] = 0x80|((c>>6)&0x3F); out[2] = 0x80|(c&0x3F); return 3;
}

/* Convert a Windows UTF-16LE string to UTF-8 in dst (dstlen includes null). Returns bytes written. */
static int lsw_u16str_to_utf8(const uint16_t* src, char* dst, int dstlen) {
    int j = 0;
    if (!src || dstlen <= 0) { if (dst && dstlen>0) dst[0]='\0'; return 0; }
    for (int i = 0; src[i] && j < dstlen - 4; i++)
        j += lsw_u16cp_to_utf8(src[i], dst + j);
    dst[j] = '\0';
    return j;
}

/*
 * lsw_wide_vprintf_to_fd — Windows-semantics wide printf to a Linux fd.
 *
 * 'format' is a pointer to a Windows UTF-16LE string (2 bytes per code unit).
 * On Linux wchar_t is 4 bytes, so we MUST treat the format as uint16_t*.
 *
 * 'ap' is a raw Windows x64 ms_abi vararg pointer (char*).  Each argument
 * slot is exactly 8 bytes; integers are zero-extended to 8 bytes.
 *   #define W64_VA(ap, T) (ap += 8, *(T*)((ap)-8))
 *
 * Windows wide printf specifier semantics (differ from Linux):
 *   %s / %ls / %ws  → wide string (uint16_t* / UTF-16LE)
 *   %S / %hs        → narrow string (char*)
 *   %c / %lc / %wc  → wide char (uint16_t, promoted to int)
 *   %C / %hc        → narrow char (int)
 *   %I64d / %I64u / %I64x → Windows 64-bit integer
 *   %d %i %u %x %X %o %p → standard (same as Linux)
 *   %l* modifiers   → 'long' (same as Linux)
 */
/* Read one Windows x64 ms_abi vararg slot (always 8 bytes) */
#define W64_VA(ap, T) (ap += 8, *(T*)((ap)-8))

static int lsw_wide_vprintf_to_fd(int fd, const wchar_t* format_wc, char* ap) {
    if (!format_wc) return 0;
    const uint16_t* fmt = (const uint16_t*)format_wc; /* treat as UTF-16LE */

    char out[16384];
    int olen = 0;

    for (int fi = 0; fmt[fi] && olen < (int)sizeof(out) - 128; ) {
        uint16_t ch = fmt[fi++];
        if (ch != '%') {
            olen += lsw_u16cp_to_utf8(ch, out + olen);
            continue;
        }
        /* Start of format specifier: %[flags][width][.prec][length]conv */
        if (!fmt[fi]) { out[olen++] = '%'; break; }

        /* Collect into a narrow spec buffer for snprintf fallback */
        char spec[32];
        int sp = 0;
        spec[sp++] = '%';

        /* Flags */
        while (fmt[fi] && (fmt[fi]=='-'||fmt[fi]=='+'||fmt[fi]==' '||
                           fmt[fi]=='0'||fmt[fi]=='#'||fmt[fi]=='\''||fmt[fi]=='F')) /* F = Windows flag */
            spec[sp++] = (char)fmt[fi++];

        /* Width */
        if (fmt[fi] == '*') {
            int w = W64_VA(ap, int);
            sp += snprintf(spec+sp, sizeof(spec)-sp, "%d", w);
            fi++;
        } else {
            while (fmt[fi] >= '0' && fmt[fi] <= '9') spec[sp++] = (char)fmt[fi++];
        }

        /* Precision */
        if (fmt[fi] == '.') {
            spec[sp++] = '.'; fi++;
            if (fmt[fi] == '*') {
                int p = W64_VA(ap, int);
                sp += snprintf(spec+sp, sizeof(spec)-sp, "%d", p);
                fi++;
            } else {
                while (fmt[fi] >= '0' && fmt[fi] <= '9') spec[sp++] = (char)fmt[fi++];
            }
        }

        /* Length modifier + conversion */
        uint16_t lm = fmt[fi]; /* potential length modifier */
        uint16_t conv;

        /* Windows %I64d / %I64u / %I64x */
        if (lm=='I' && fmt[fi+1]=='6' && fmt[fi+2]=='4') {
            fi += 3;
            conv = fmt[fi++];
            int64_t  sv; uint64_t uv;
            char tmp[64];
            if (conv=='d'||conv=='i') { sv=W64_VA(ap,int64_t); snprintf(tmp,sizeof(tmp),"%"PRId64,sv); }
            else if (conv=='u')       { uv=W64_VA(ap,uint64_t); snprintf(tmp,sizeof(tmp),"%"PRIu64,uv); }
            else if (conv=='x')       { uv=W64_VA(ap,uint64_t); snprintf(tmp,sizeof(tmp),"%"PRIx64,uv); }
            else if (conv=='X')       { uv=W64_VA(ap,uint64_t); snprintf(tmp,sizeof(tmp),"%"PRIX64,uv); }
            else { tmp[0]='?'; tmp[1]='\0'; }
            int tl=(int)strlen(tmp); if(olen+tl<(int)sizeof(out)) { memcpy(out+olen,tmp,tl); olen+=tl; }
            continue;
        }

        /* %% */
        if (lm=='%') { fi++; out[olen++]='%'; continue; }

        /* Detect 'h' / 'l' / 'w' / 'F' length modifiers */
        int lmod_h=0, lmod_l=0;
        if (lm=='h') { lmod_h=1; fi++; lm=fmt[fi]; }
        else if (lm=='l') { lmod_l=1; fi++; lm=fmt[fi]; }
        else if (lm=='w' || lm=='F') { /* Windows 'w'/'F' = wide, same as 'l' for strings */
            lmod_l=1; fi++; lm=fmt[fi];
        }

        conv = fmt[fi++];

        if (conv=='s' || conv=='S') {
            /* Windows wide printf: %s/%ls/%ws = wide string; %S/%hs = narrow string */
            int want_wide = (conv=='s' && !lmod_h) || (conv=='s' && lmod_l) || (conv=='S' && lmod_l);
            int want_narrow = (conv=='s' && lmod_h) || (conv=='S' && !lmod_l);
            (void)want_narrow; /* narrow handled by else */
            if (want_wide || (!lmod_h && conv=='s')) {
                const uint16_t* wstr = W64_VA(ap, const uint16_t*);
                if (!wstr) wstr = (const uint16_t*)u"(null)";
                olen += lsw_u16str_to_utf8(wstr, out+olen, (int)sizeof(out)-olen);
            } else {
                /* narrow string */
                const char* nstr = W64_VA(ap, const char*);
                if (!nstr) nstr = "(null)";
                int nl=(int)strlen(nstr); if(olen+nl<(int)sizeof(out)) { memcpy(out+olen,nstr,nl); olen+=nl; }
            }
        } else if (conv=='c' || conv=='C') {
            /* %c/%lc/%wc = wide char; %C/%hc = narrow char */
            if ((conv=='c' && !lmod_h) || (conv=='C' && lmod_l)) {
                uint16_t wc = (uint16_t)W64_VA(ap, int);
                olen += lsw_u16cp_to_utf8(wc, out+olen);
            } else {
                out[olen++] = (char)W64_VA(ap, int);
            }
        } else if (conv=='d' || conv=='i') {
            spec[sp++] = lmod_l ? 'l' : (lmod_h ? 'h' : 0); if(!lmod_h&&!lmod_l) sp--;
            spec[sp++] = 'd'; spec[sp]='\0';
            long long v = lmod_l ? (long long)W64_VA(ap,long) : (long long)W64_VA(ap,int);
            char tmp[64]; snprintf(tmp,sizeof(tmp),spec,v);
            int tl=(int)strlen(tmp); if(olen+tl<(int)sizeof(out)) { memcpy(out+olen,tmp,tl); olen+=tl; }
        } else if (conv=='u') {
            spec[sp++] = lmod_l ? 'l' : (lmod_h ? 'h' : 0); if(!lmod_h&&!lmod_l) sp--;
            spec[sp++] = 'u'; spec[sp]='\0';
            unsigned long long v = lmod_l ? (unsigned long long)W64_VA(ap,unsigned long) : (unsigned long long)W64_VA(ap,unsigned int);
            char tmp[64]; snprintf(tmp,sizeof(tmp),spec,v);
            int tl=(int)strlen(tmp); if(olen+tl<(int)sizeof(out)) { memcpy(out+olen,tmp,tl); olen+=tl; }
        } else if (conv=='x' || conv=='X') {
            spec[sp++] = lmod_l ? 'l' : (lmod_h ? 'h' : 0); if(!lmod_h&&!lmod_l) sp--;
            spec[sp++] = (char)conv; spec[sp]='\0';
            unsigned long long v = lmod_l ? (unsigned long long)W64_VA(ap,unsigned long) : (unsigned long long)W64_VA(ap,unsigned int);
            char tmp[64]; snprintf(tmp,sizeof(tmp),spec,v);
            int tl=(int)strlen(tmp); if(olen+tl<(int)sizeof(out)) { memcpy(out+olen,tmp,tl); olen+=tl; }
        } else if (conv=='o') {
            spec[sp++] = 'o'; spec[sp]='\0';
            unsigned int v = W64_VA(ap, unsigned int);
            char tmp[32]; snprintf(tmp,sizeof(tmp),spec,v);
            int tl=(int)strlen(tmp); if(olen+tl<(int)sizeof(out)) { memcpy(out+olen,tmp,tl); olen+=tl; }
        } else if (conv=='p') {
            void* v = W64_VA(ap, void*);
            char tmp[32]; snprintf(tmp,sizeof(tmp),"%p",v);
            int tl=(int)strlen(tmp); if(olen+tl<(int)sizeof(out)) { memcpy(out+olen,tmp,tl); olen+=tl; }
        } else if (conv=='f' || conv=='e' || conv=='E' || conv=='g' || conv=='G') {
            spec[sp++] = (char)conv; spec[sp]='\0';
            double v = W64_VA(ap, double);
            char tmp[64]; snprintf(tmp,sizeof(tmp),spec,v);
            int tl=(int)strlen(tmp); if(olen+tl<(int)sizeof(out)) { memcpy(out+olen,tmp,tl); olen+=tl; }
        } else if (conv=='n') {
            int* p = W64_VA(ap, int*); if(p) *p = olen;
        } else {
            /* Unknown specifier: emit raw */
            spec[sp++] = (char)conv; spec[sp]='\0';
            if(olen+(int)strlen(spec)<(int)sizeof(out)) {
                int sl=(int)strlen(spec); memcpy(out+olen,spec,sl); olen+=sl;
            }
        }
    }
    out[olen] = '\0';
    if (olen == 0) return 0;
    return (int)write(fd, out, olen);
}

int __attribute__((ms_abi)) lsw_wprintf(const wchar_t* format, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, format);
    int r = lsw_wide_vprintf_to_fd(1, format, (char*)ms_ap);
    __builtin_ms_va_end(ms_ap);
    return r;
}

int __attribute__((ms_abi)) lsw_vwprintf(const wchar_t* format, __builtin_ms_va_list ap) {
    return lsw_wide_vprintf_to_fd(1, format, (char*)ap);
}

int __attribute__((ms_abi)) lsw_fwprintf(FILE* stream, const wchar_t* format, ...) {
    typedef struct { char* _ptr; int _cnt; char* _base; int _flag;
                     int _file; int _charbuf; int _bufsiz; char* _tmpfname; } fake_FILE;
    int fd = 1;
    if (stream) {
        fake_FILE* f = (fake_FILE*)stream;
        if (f->_file == 1 || stream == (FILE*)stdout) fd = 1;
        else if (f->_file == 2 || stream == (FILE*)stderr) fd = 2;
        else if (f->_file == 0 || stream == (FILE*)stdin)  fd = 0;
        else fd = f->_file;
    }
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, format);
    int r = lsw_wide_vprintf_to_fd(fd, format, (char*)ms_ap);
    __builtin_ms_va_end(ms_ap);
    return r;
}

int __attribute__((ms_abi)) lsw_vfwprintf(FILE* stream, const wchar_t* format, __builtin_ms_va_list ap) {
    typedef struct { char* _ptr; int _cnt; char* _base; int _flag;
                     int _file; int _charbuf; int _bufsiz; char* _tmpfname; } fake_FILE;
    int fd = 1;
    if (stream) {
        fake_FILE* f = (fake_FILE*)stream;
        if (f->_file == 2 || stream == (FILE*)stderr) fd = 2;
        else if (f->_file == 0 || stream == (FILE*)stdin)  fd = 0;
        else fd = f->_file >= 0 ? f->_file : 1;
    }
    return lsw_wide_vprintf_to_fd(fd, format, (char*)ap);
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
    LSW_LOG_INFO("msvcrt exit(%d) called", status);
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

/* ===== UTF-16LE (uint16_t) string helpers ============================== *
 * Windows wchar_t = 2 bytes (UTF-16LE); Linux wchar_t = 4 bytes (UTF-32). *
 * All Windows PE code passes wchar_t* as uint16_t* pointers.               *
 * We MUST NOT call Linux wcs*() on these — they read 4 bytes per char.     *
 * These helpers operate on uint16_t (2-byte) units throughout.             *
 * ======================================================================== */
typedef uint16_t u16;

static inline size_t u16_len(const u16* s) {
    const u16* p = s; while (*p) p++; return (size_t)(p - s);
}
static inline size_t u16_nlen(const u16* s, size_t maxlen) {
    size_t n = 0; while (n < maxlen && s[n]) n++; return n;
}
static inline u16* u16_cpy(u16* d, const u16* s) {
    u16* r = d; while ((*d++ = *s++)); return r;
}
static inline u16* u16_ncpy(u16* d, const u16* s, size_t n) {
    u16* r = d;
    while (n && (*d = *s)) { d++; s++; n--; }
    while (n--) *d++ = 0;
    return r;
}
static inline u16* u16_cat(u16* d, const u16* s) {
    u16* p = d; while (*p) p++; while ((*p++ = *s++)); return d;
}
static inline u16* u16_ncat(u16* d, const u16* s, size_t n) {
    u16* p = d; while (*p) p++;
    while (n-- && *s) *p++ = *s++;
    *p = 0; return d;
}
static inline int u16_cmp(const u16* a, const u16* b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)*a - (int)*b;
}
static inline int u16_ncmp(const u16* a, const u16* b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (int)*a - (int)*b : 0;
}
static inline int u16_icmp(const u16* a, const u16* b) {
    while (*a && towlower(*a) == towlower(*b)) { a++; b++; }
    return (int)towlower(*a) - (int)towlower(*b);
}
static inline int u16_nicmp(const u16* a, const u16* b, size_t n) {
    while (n && *a && towlower(*a) == towlower(*b)) { a++; b++; n--; }
    return n ? (int)towlower(*a) - (int)towlower(*b) : 0;
}
static inline u16* u16_chr(const u16* s, u16 c) {
    for (;; s++) { if (*s == c) return (u16*)s; if (!*s) break; }
    return NULL;
}
static inline u16* u16_rchr(const u16* s, u16 c) {
    const u16* last = NULL;
    for (; *s; s++) if (*s == c) last = s;
    if (c == 0) return (u16*)s;
    return (u16*)last;
}
static inline u16* u16_str(const u16* h, const u16* n) {
    if (!*n) return (u16*)h;
    size_t nlen = u16_len(n);
    for (; *h; h++) if (*h == *n && u16_ncmp(h, n, nlen) == 0) return (u16*)h;
    return NULL;
}
static inline u16* u16_dup(const u16* s) {
    size_t sz = (u16_len(s) + 1) * sizeof(u16);
    u16* d = malloc(sz); if (d) memcpy(d, s, sz); return d;
}
static inline void u16_to_utf8(const u16* src, char* dst, size_t dstmax) {
    size_t i = 0;
    for (; *src && i + 4 < dstmax; src++) {
        uint32_t c = *src;
        if (c < 0x80) { dst[i++] = (char)c; }
        else if (c < 0x800) { dst[i++]=(char)(0xC0|(c>>6)); dst[i++]=(char)(0x80|(c&0x3F)); }
        else { dst[i++]=(char)(0xE0|(c>>12)); dst[i++]=(char)(0x80|((c>>6)&0x3F)); dst[i++]=(char)(0x80|(c&0x3F)); }
    }
    dst[i] = '\0';
}
static inline unsigned long u16_strtoul(const u16* p, u16** end, int base) {
    char buf[64]; u16_to_utf8(p, buf, sizeof(buf));
    char* ep; unsigned long r = strtoul(buf, &ep, base);
    if (end) *end = (u16*)p + (ep - buf); return r;
}
static inline long u16_strtol(const u16* p, u16** end, int base) {
    char buf[64]; u16_to_utf8(p, buf, sizeof(buf));
    char* ep; long r = strtol(buf, &ep, base);
    if (end) *end = (u16*)p + (ep - buf); return r;
}
static inline double u16_strtod(const u16* p, u16** end) {
    char buf[64]; u16_to_utf8(p, buf, sizeof(buf));
    char* ep; double r = strtod(buf, &ep);
    if (end) *end = (u16*)p + (ep - buf); return r;
}
static inline u16* u16_tok(u16* str, const u16* delim, u16** ctx) {
    u16* s = str ? str : (ctx ? *ctx : NULL);
    if (!s || !delim) return NULL;
    while (*s && u16_chr(delim, *s)) s++;
    if (!*s) { if (ctx) *ctx = NULL; return NULL; }
    u16* tok = s;
    while (*s && !u16_chr(delim, *s)) s++;
    if (*s) { *s++ = 0; }
    if (ctx) *ctx = s; return tok;
}

size_t __attribute__((ms_abi)) lsw_wcslen(const wchar_t* s) {
    return u16_len((const u16*)s);
}

struct lconv* __attribute__((ms_abi)) lsw_localeconv(void) {
    return localeconv();
}

void (*__attribute__((ms_abi)) lsw_signal(int signum, void (*handler)(int)))(int) {
    return signal(signum, handler);
}

// CRT initialization stubs - minimal implementations to get past CRT init
static char** lsw_environ = NULL;

int __attribute__((ms_abi)) lsw__getmainargs(int* argc, char*** argv, char*** env, int do_wildcard, void* startinfo) {
    (void)do_wildcard;
    (void)startinfo;

    /* Use real args from win32_crt_data_init() if available */
    if (lsw_crt_argc > 0 && lsw_crt_argv) {
        *argc = lsw_crt_argc;
        *argv = lsw_crt_argv;
    } else {
        static char* fallback_argv[2] = { "program.exe", NULL };
        *argc = 1;
        *argv = fallback_argv;
    }

    if (!lsw_environ) {
        lsw_environ = malloc(sizeof(char*));
        lsw_environ[0] = NULL;
    }
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

/* Windows CRT FILE structure (_iobuf) layout on x64, 48 bytes */
typedef struct {
    char* _ptr;       /* 0:  current position in buffer */
    int   _cnt;       /* 8:  characters left in buffer */
    /* 4 bytes implicit padding to align next pointer */
    char* _base;      /* 16: base of buffer */
    int   _flag;      /* 24: file status flags */
    int   _file;      /* 28: file descriptor number */
    int   _charbuf;   /* 32: char buffer for ungetch */
    int   _bufsiz;    /* 36: buffer size */
    char* _tmpfname;  /* 40: temporary filename */
} lsw_fake_FILE;     /* total: 48 bytes */

static lsw_fake_FILE lsw_fake_files[3] = {
    {NULL, 0, NULL, 0, 0, 0, 0, NULL},  /* stdin  (fd 0) */
    {NULL, 0, NULL, 0, 1, 0, 0, NULL},  /* stdout (fd 1) */
    {NULL, 0, NULL, 0, 2, 0, 0, NULL},  /* stderr (fd 2) */
};

void* __attribute__((ms_abi)) lsw__iob_func(void) {
    /* Windows CRT __iob_func returns pointer to array of _iobuf structs */
    return (void*)lsw_fake_files;
}

void __attribute__((ms_abi)) lsw__set_app_type(int type) {
    LSW_LOG_INFO("__set_app_type(%d) called", type);
    (void)type;
}

void __attribute__((ms_abi)) lsw__setusermatherr(void* handler) {
    (void)handler;
    // Stub - do nothing
}

void __attribute__((ms_abi)) lsw__amsg_exit(int code) {
    LSW_LOG_INFO("_amsg_exit(%d) called - CRT fatal error", code);
    exit(code);
}

void __attribute__((ms_abi)) lsw__cexit(void) {
    // Stub - CRT cleanup, do nothing
}

void __attribute__((ms_abi)) lsw__c_exit(void) {
    // Stub - quick CRT cleanup without calling atexit handlers
}

/* _beginthreadex — create a thread via MSVC CRT */
#include <pthread.h>
typedef unsigned(__attribute__((ms_abi)) *_beginthreadex_start_t)(void*);
typedef struct { _beginthreadex_start_t fn; void* arg; } _beginthreadex_ctx_t;
static void* _beginthreadex_trampoline(void* arg) {
    _beginthreadex_ctx_t* ctx = (_beginthreadex_ctx_t*)arg;
    unsigned ret = ctx->fn(ctx->arg);
    free(ctx);
    return (void*)(uintptr_t)ret;
}
uintptr_t __attribute__((ms_abi)) lsw__beginthreadex(void* security, unsigned stack_size,
        _beginthreadex_start_t start, void* arglist, unsigned initflag, unsigned* thrdaddr) {
    (void)security; (void)stack_size; (void)initflag;
    _beginthreadex_ctx_t* ctx = malloc(sizeof(_beginthreadex_ctx_t));
    if (!ctx) return 0;
    ctx->fn = start;
    ctx->arg = arglist;
    pthread_t tid;
    if (pthread_create(&tid, NULL, _beginthreadex_trampoline, ctx) != 0) {
        free(ctx);
        return 0;
    }
    if (thrdaddr) *thrdaddr = (unsigned)(uintptr_t)tid;
    pthread_detach(tid);
    return (uintptr_t)tid;
}
void __attribute__((ms_abi)) lsw__endthreadex(unsigned retval) {
    pthread_exit((void*)(uintptr_t)retval);
}

/* Wide-char version of __getmainargs — used by MSVCRT CRT startup in 64-bit apps */
int __attribute__((ms_abi)) lsw__wgetmainargs(int* argc, wchar_t*** wargv, wchar_t*** wenvp,
                                               int expand_wildcards, void* startupinfo) {
    LSW_LOG_DEBUG("__wgetmainargs called");
    (void)expand_wildcards;
    (void)startupinfo;

    /* Build UTF-16LE argv from the real CRT args set by win32_crt_data_init().
     * NOTE: On Linux wchar_t is 4 bytes, but Windows expects 2-byte UTF-16.
     * We use uint16_t storage and cast the pointer to wchar_t** to satisfy the
     * Windows ABI while keeping correct 2-byte characters. */
    int n = (lsw_crt_argc > 0 && lsw_crt_argv) ? lsw_crt_argc : 1;

    static uint16_t  arg_storage[64][512]; /* 64 args × 512 UTF-16 code units */
    static uint16_t* w_ptrs[65];           /* pointers + NULL sentinel */

    int actual = (n > 64) ? 64 : n;
    for (int i = 0; i < actual; i++) {
        const char* src = (lsw_crt_argv && lsw_crt_argv[i]) ? lsw_crt_argv[i] : "program.exe";
        size_t len = strlen(src);
        uint16_t* dst = arg_storage[i];
        size_t j;
        for (j = 0; j < len && j < 511; j++)
            dst[j] = (uint16_t)(unsigned char)src[j];
        dst[j] = 0;
        w_ptrs[i] = dst;
    }
    w_ptrs[actual] = NULL;

    static uint16_t* empty_envp[1] = { NULL };

    *argc  = actual;
    *wargv = (wchar_t**)w_ptrs;
    *wenvp = (wchar_t**)empty_envp;
    LSW_LOG_DEBUG("__wgetmainargs -> argc=%d, argv[0]='%s'%s", actual,
        (actual > 0 && lsw_crt_argv && lsw_crt_argv[0]) ? lsw_crt_argv[0] : "(null)",
        (actual > 1 && lsw_crt_argv && lsw_crt_argv[1]) ? "" : " (no extra args)");
    if (actual > 1 && lsw_crt_argv && lsw_crt_argv[1])
        LSW_LOG_DEBUG("__wgetmainargs -> argv[1]='%s' (w_ptrs[1][0]=0x%04x)", lsw_crt_argv[1], (unsigned)w_ptrs[1][0]);
    return 0;
}

/* _exit — exit without CRT cleanup */
void __attribute__((ms_abi)) lsw__exit(int code) {
    _exit(code);
}

/* _XcptFilter — MSVCRT SEH filter; always continue searching */
int __attribute__((ms_abi)) lsw__XcptFilter(unsigned long xcpt_code, void* xcpt_info) {
    (void)xcpt_info;
    (void)xcpt_code;
    return 0;  /* EXCEPTION_CONTINUE_SEARCH */
}

/* __dllonexit — register atexit handler from within a DLL; stub */
void* __attribute__((ms_abi)) lsw___dllonexit(void* func, void** begin, void** end) {
    (void)func; (void)begin; (void)end;
    return func;
}

/* _fileno — get POSIX fd from Windows FILE* (we use real POSIX FILEs) */
int __attribute__((ms_abi)) lsw__fileno(void* stream) {
    if (!stream) return -1;
    /* Detect our fake CRT streams (from lsw__iob_func / __iob_func) */
    for (int i = 0; i < 3; i++) {
        if (stream == (void*)&lsw_fake_files[i])
            return lsw_fake_files[i]._file;
    }
    /* Genuine POSIX FILE* */
    return fileno((FILE*)stream);
}

/* _get_osfhandle — return a pseudo-HANDLE for a CRT file descriptor */
intptr_t __attribute__((ms_abi)) lsw__get_osfhandle(int fd) {
    /* Return the fd itself as a pseudo-handle — our CloseHandle understands raw fds */
    if (fd < 0) return -1;
    return (intptr_t)fd;
}

/* Wide-char string conversions — thin wrappers over POSIX */
unsigned long __attribute__((ms_abi)) lsw_wcstoul(const wchar_t* nptr, wchar_t** endptr, int base) {
    return u16_strtoul((const u16*)nptr, (u16**)endptr, base);
}
long __attribute__((ms_abi)) lsw_wcstol(const wchar_t* nptr, wchar_t** endptr, int base) {
    return u16_strtol((const u16*)nptr, (u16**)endptr, base);
}
double __attribute__((ms_abi)) lsw_wcstod(const wchar_t* nptr, wchar_t** endptr) {
    return u16_strtod((const u16*)nptr, (u16**)endptr);
}
/* wcstok (msvcrt.dll) — classic 2-argument version with internal static state */
static u16* s_wcstok_state = NULL;
wchar_t* __attribute__((ms_abi)) lsw_wcstok(wchar_t* str, const wchar_t* delimiters) {
    u16* s = str ? (u16*)str : s_wcstok_state;
    const u16* delim = (const u16*)delimiters;
    if (!s || !delim) { s_wcstok_state = NULL; return NULL; }
    while (*s && u16_chr(delim, *s)) s++;
    if (!*s) { s_wcstok_state = NULL; return NULL; }
    u16* tok = s;
    while (*s && !u16_chr(delim, *s)) s++;
    if (*s) *s++ = 0;
    s_wcstok_state = s;
    return (wchar_t*)tok;
}
/* wcstok_s (msvcrt.dll / ucrtbase.dll) — 3-argument safe version */
wchar_t* __attribute__((ms_abi)) lsw_wcstok_s(wchar_t* str, const wchar_t* delimiters, wchar_t** context) {
    return (wchar_t*)u16_tok((u16*)str, (const u16*)delimiters, (u16**)context);
}

/* ?terminate@@YAXXZ / ?terminate@@YAXXX — C++ terminate() */
void __attribute__((ms_abi)) lsw_cxx_terminate(void) {
    LSW_LOG_ERROR("C++ terminate() called — aborting");
    abort();
}

/* ??1type_info@@ destructors — no-op stub */
void __attribute__((ms_abi)) lsw_type_info_dtor(void* self) {
    (void)self;
}

/* _purecall — called on pure virtual call; abort */
void __attribute__((ms_abi)) lsw__purecall(void) {
    LSW_LOG_ERROR("pure virtual function call — aborting");
    abort();
}

/* __CxxFrameHandler — Windows SEH/C++ frame handler stub */
int __attribute__((ms_abi)) lsw___CxxFrameHandler(void* pExcept, void* pRN, void* pContext, void* pDC) {
    (void)pExcept; (void)pRN; (void)pContext; (void)pDC;
    return 0;
}

/* Forward declarations: TLS exception state variables (defined later) */
static __thread void* tls_cxx_exception_obj;
static __thread void* tls_cxx_exception_type;

/* ==========================================================================
 * x64 MSVC C++ Exception Dispatch
 *
 * Implements a minimal but functional version of the Windows x64 C++ exception
 * dispatch mechanism so that PE executables using C++ exceptions (throw/catch)
 * work without the real Windows OS exception infrastructure.
 *
 * How it works:
 *  1. _CxxThrowException captures the current frame pointer (RBP) and
 *     reconstructs the PE caller's RSP / RIP from the GCC frame chain.
 *  2. The .pdata section (RUNTIME_FUNCTION table) is walked via binary search
 *     to find the UNWIND_INFO for each stack frame.
 *  3. For frames with an exception handler (UNW_FLAG_EHANDLER), the FuncInfo3
 *     structure (magic 0x19930520) is parsed to locate TryBlockMap entries
 *     whose IP-to-State range covers the current RIP.
 *  4. When a matching catch(...) (pType == 0) is found, the catch funclet is
 *     called directly with the try-function's frame-entry RSP as its first
 *     argument (RCX).  The funclet runs the catch body and returns the
 *     continuation virtual address.
 *  5. We jump to the continuation with RSP restored to the try-function's
 *     "body" RSP (the RSP that was active at the call site in that frame).
 * ========================================================================== */

/* RUNTIME_FUNCTION — one entry per function in the .pdata section */
typedef struct {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindData;     /* RVA of UNWIND_INFO */
} lsw_RUNTIME_FUNCTION;

/* UNWIND_INFO header (4 bytes) */
#define UNW_FLAG_EHANDLER  1u
#define UNW_FLAG_UHANDLER  2u
#define UNW_FLAG_CHAININFO 4u

/* Unwind opcodes */
#define UWOP_PUSH_NONVOL      0
#define UWOP_ALLOC_LARGE      1
#define UWOP_ALLOC_SMALL      2
#define UWOP_SET_FPREG        3
#define UWOP_SAVE_NONVOL      4
#define UWOP_SAVE_NONVOL_FAR  5
#define UWOP_SAVE_XMM128      8
#define UWOP_SAVE_XMM128_FAR  9
#define UWOP_PUSH_MACHFRAME   10

/* FuncInfo3 (FuncInfo for __CxxFrameHandler3, magic 0x19930520 – 0x19930524) */
typedef struct {
    uint32_t magic;           /* 0x19930520 – 0x19930524 */
    int32_t  maxState;
    uint32_t pUnwindMap;      /* RVA */
    uint32_t nTryBlocks;
    uint32_t pTryBlockMap;    /* RVA */
    uint32_t nIPMap;
    uint32_t pIPMap;          /* RVA */
} lsw_FuncInfo3;

/* TryBlockMapEntry */
typedef struct {
    int32_t  tryLow;
    int32_t  tryHigh;
    int32_t  catchHigh;
    int32_t  nCatches;
    uint32_t pHandlerArray;   /* RVA */
} lsw_TryBlockMapEntry;

/* HandlerType (16 bytes; VS 2019 may append an extra 4-byte dispFrame) */
typedef struct {
    uint32_t adjectives;
    uint32_t pType;           /* RVA; 0 == catch(...) */
    int32_t  dispCatchObj;
    uint32_t addressOfHandler; /* RVA */
} lsw_HandlerType;

/* IPToStateMapEntry */
typedef struct {
    int32_t Ip;    /* RVA from image base */
    int32_t State;
} lsw_IPStateEntry;

/* ThrowInfo — the second arg to _CxxThrowException, embedded as a const in .rdata */
typedef struct {
    uint32_t attributes;
    uint32_t pmfn;                  /* RVA: destructor for thrown obj, or 0 */
    uint32_t fwd;                   /* RVA: forward compat fn, or 0 */
    uint32_t pCatchableTypeArray;   /* RVA: CatchableTypeArray */
} lsw_ThrowInfo;

/* CatchableType — one entry per catchable base class of the thrown type */
typedef struct {
    uint32_t properties;
    uint32_t pType;             /* RVA: TypeDescriptor (mangled name at +16) */
    /* thisDisplacement (PMD, 12 bytes), sizeOrOffset (4), copyFunction (4) follow */
    int32_t  mdisp;
    int32_t  pdisp;
    int32_t  vdisp;
    int32_t  sizeOrOffset;
    uint32_t copyFunction;      /* RVA: copy ctor, or 0 */
} lsw_CatchableType;

/* CatchableTypeArray */
typedef struct {
    int32_t  nCatchableTypes;
    uint32_t arrayOfCatchableTypes[1]; /* RVAs to CatchableType */
} lsw_CatchableTypeArray;

/* Resolve a PE RVA to a mapped virtual address */
static inline void* lsw_rva2va(uint32_t rva) {
    if (!rva) return NULL;
    /* Bounds-check: reject RVAs outside the mapped image to prevent SIGSEGV
     * when garbage values (e.g. GS cookie data) are misread as FuncInfo RVAs. */
    if (g_lsw_image_size && rva >= g_lsw_image_size) return NULL;
    return (void*)(g_lsw_image_base + rva);
}

/* Binary-search .pdata for the RUNTIME_FUNCTION covering 'rip'. */
static lsw_RUNTIME_FUNCTION* lsw_find_rf(uint64_t rip) {
    if (!g_lsw_pdata_va || g_lsw_pdata_size < 12 || !g_lsw_image_base) return NULL;
    if (rip < g_lsw_image_base) return NULL;
    uint32_t rva = (uint32_t)(rip - g_lsw_image_base);
    lsw_RUNTIME_FUNCTION* pdata = (lsw_RUNTIME_FUNCTION*)g_lsw_pdata_va;
    int n = (int)(g_lsw_pdata_size / sizeof(lsw_RUNTIME_FUNCTION));
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if      (rva < pdata[mid].BeginAddress) hi = mid - 1;
        else if (rva >= pdata[mid].EndAddress)  lo = mid + 1;
        else return &pdata[mid];
    }
    return NULL;
}

/*
 * Apply UNWIND_INFO codes to 'current_rsp' to reconstruct the caller's RSP
 * and RIP.  Returns the "entry RSP" (RSP at function entry = points to the
 * return address on the stack).
 */
static uint64_t lsw_unwind_frame(lsw_RUNTIME_FUNCTION* rf,
                                  uint64_t current_rsp,
                                  uint64_t* out_caller_rip,
                                  uint64_t* out_caller_rsp)
{
    if (!rf) return 0;

    /* Resolve UNWIND_INFO header */
    uint8_t* ui = (uint8_t*)lsw_rva2va(rf->UnwindData);
    if (!ui) return 0;

    /* Handle CHAININFO: follow the chained RUNTIME_FUNCTION instead */
    for (int chain_depth = 0; chain_depth < 8; chain_depth++) {
        uint8_t flags      = (ui[0] >> 3) & 0x1fu;
        uint8_t code_count = ui[2];
        int     codes_sz   = (int)(((code_count + 1) & ~1) * 2);
        uint8_t* codes     = ui + 4;

        if (flags & UNW_FLAG_CHAININFO) {
            /* Chained: skip unwind codes, follow chain RUNTIME_FUNCTION */
            lsw_RUNTIME_FUNCTION* chain_rf =
                (lsw_RUNTIME_FUNCTION*)(codes + codes_sz);
            ui = (uint8_t*)lsw_rva2va(chain_rf->UnwindData);
            if (!ui) return 0;
            continue;
        }

        /* Process unwind codes to compute caller's RSP */
        uint64_t rsp = current_rsp;
        uint16_t* c  = (uint16_t*)codes;
        for (int i = 0; i < code_count; ) {
            uint8_t op   = (c[i] >> 8) & 0xFu;
            uint8_t info = (c[i] >> 12) & 0xFu;
            switch (op) {
            case UWOP_PUSH_NONVOL:      rsp += 8;               i += 1; break;
            case UWOP_ALLOC_SMALL:      rsp += 8u*(info+1u);    i += 1; break;
            case UWOP_ALLOC_LARGE:
                if (info == 0) {
                    rsp += 8u * (uint64_t)c[i+1];               i += 2;
                } else {
                    uint32_t v; memcpy(&v, &c[i+1], 4);
                    rsp += v;                                    i += 3;
                }
                break;
            case UWOP_SET_FPREG:        i += 1; break;
            case UWOP_SAVE_NONVOL:      i += 2; break;
            case UWOP_SAVE_NONVOL_FAR:  i += 3; break;
            case UWOP_SAVE_XMM128:      i += 2; break;
            case UWOP_SAVE_XMM128_FAR:  i += 3; break;
            case UWOP_PUSH_MACHFRAME:   i += 1; break;
            default:                    i += 1; break;
            }
        }

        /* After undoing the prolog, rsp points to the saved return address */
        if (rsp < 0x1000 || rsp > (uint64_t)0x7fffffffffff00ULL) return 0;
        uint64_t ret_addr = *(uint64_t*)rsp;
        *out_caller_rip = ret_addr;
        *out_caller_rsp = rsp + 8;
        return rsp;   /* "entry RSP" = function-entry RSP, points to ret addr */
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * EH4 (__CxxFrameHandler4, VS2019+) compressed-integer helpers.
 *
 * EH4 uses the .NET uint32 compressed integer encoding:
 *   low nibble 0bXXX0 → 1 byte,  value = b0 >> 1          (7-bit max)
 *   low nibble 0bXX01 → 2 bytes, value = (b0>>2)|(b1<<6)  (14-bit)
 *   low nibble 0bX011 → 3 bytes, value = (b0>>3)|(b1<<5)|(b2<<13) (21-bit)
 *   low nibble 0b0111 → 4 bytes, value = (b0>>4)|(b1<<4)|(b2<<12)|(b3<<20) (28-bit)
 *   low nibble 0b1111 → 5 bytes, value = b1|(b2<<8)|(b3<<16)|(b4<<24) (32-bit)
 * ----------------------------------------------------------------------- */
static uint32_t lsw_eh4_read_uint(const uint8_t** pp)
{
    const uint8_t *p = *pp;
    uint8_t b0 = p[0];
    uint8_t ln = b0 & 0x0Fu;
    if ((ln & 0x01u) == 0u) {
        *pp += 1;
        return (uint32_t)(b0 >> 1);
    } else if ((ln & 0x03u) == 1u) {
        *pp += 2;
        return ((uint32_t)(b0 >> 2)) | ((uint32_t)p[1] << 6);
    } else if ((ln & 0x07u) == 3u) {
        *pp += 3;
        return ((uint32_t)(b0 >> 3)) | ((uint32_t)p[1] << 5) | ((uint32_t)p[2] << 13);
    } else if ((ln & 0x0Fu) == 7u) {
        *pp += 4;
        return ((uint32_t)(b0 >> 4)) | ((uint32_t)p[1] << 4) |
               ((uint32_t)p[2] << 12) | ((uint32_t)p[3] << 20);
    } else { /* ln == 0x0F → 5-byte form */
        *pp += 5;
        return (uint32_t)p[1] | ((uint32_t)p[2] << 8) |
               ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24);
    }
}

static int32_t lsw_eh4_read_int(const uint8_t** pp)
{
    int32_t v;
    memcpy(&v, *pp, 4);
    *pp += 4;
    return v;
}

/*
 * EH4 IPtoStateMap lookup.  Map entries are delta-encoded:
 *   each entry = (ip_delta: compressed uint, state_enc: compressed uint)
 * where state_enc = actual_state + 1  (so -1 encodes as 0).
 * ip values are function-relative (RVA - func_begin_rva).
 */
static int32_t lsw_eh4_ip_to_state(uint32_t ipts_rva, uint32_t ip_offset)
{
    const uint8_t *p = (const uint8_t *)lsw_rva2va(ipts_rva);
    if (!p) return -1;
    const uint8_t *img_end = (const uint8_t *)(g_lsw_image_base + g_lsw_image_size);

    uint32_t num = lsw_eh4_read_uint(&p);
    if (num == 0 || num > 65536u) return -1;

    int32_t  state  = -1;
    uint32_t abs_ip = 0;
    for (uint32_t i = 0; i < num && p < img_end - 2; i++) {
        uint32_t delta     = lsw_eh4_read_uint(&p);
        abs_ip            += delta;
        uint32_t state_enc = lsw_eh4_read_uint(&p);
        int32_t  s         = (int32_t)state_enc - 1;
        if (abs_ip <= ip_offset)
            state = s;
    }
    return state;
}

/*
 * EH4 catch-handler search.
 *
 * FuncInfo4 layout (variable-length, all ints are compressed unless noted):
 *   [0]    header byte  (FuncInfoHeader bitfield)
 *   [1..4] dispUnwindMap RVA (4 bytes plain, if header bit3)
 *   [5..8] dispTryBlockMap RVA (4 bytes plain, if header bit4)
 *   [9..12] dispIPtoStateMap RVA (4 bytes plain, always)
 *   [13..] dispFrame (compressed uint, if header bit0 isCatch)
 *
 * TryBlockMap4: numEntries(compressed) + [tryLow tryHigh catchHigh(compressed) + dispHandlerArray(4B)]
 * HandlerMap4:  numEntries(compressed) + [hdr(1B) + optional adjectives + optional dispType(4B)
 *               + optional dispCatchObj(compressed) + dispOfHandler(4B) + cont addrs]
 *
 * State storage: TryBlockMap states are DIRECT values.
 *                IPtoStateMap states are encoded as state+1.
 */
static bool lsw_eh4_find_catch(uint32_t funcinfo_rva,
                                uint32_t func_begin_rva,
                                uint64_t rip,
                                lsw_ThrowInfo *throw_info,
                                uint64_t *handler_va,
                                int32_t  *disp_catch_obj,
                                uint32_t *out_adjectives,
                                uint64_t *out_cont_vas,   /* [2]: continuation VAs */
                                uint32_t *out_cont_cnt)   /* number of cont VAs (0-2) */
{
    const uint8_t *fi = (const uint8_t *)lsw_rva2va(funcinfo_rva);
    if (!fi) return false;
    const uint8_t *img_end = (const uint8_t *)(g_lsw_image_base + g_lsw_image_size);
    if (fi >= img_end) return false;

    const uint8_t *p = fi;
    uint8_t hdr = *p++;

    uint32_t disp_uw_map = 0, disp_tb_map = 0, disp_ip_map = 0;
    if (p >= img_end) return false;

    if ((hdr >> 2) & 1u)  lsw_eh4_read_uint(&p);            /* BBT: skip bbtFlags */
    if ((hdr >> 3) & 1u)  disp_uw_map = (uint32_t)lsw_eh4_read_int(&p); /* UnwindMap */
    if ((hdr >> 4) & 1u)  disp_tb_map = (uint32_t)lsw_eh4_read_int(&p); /* TryBlockMap */
    if (p >= img_end - 4) return false;
    disp_ip_map = (uint32_t)lsw_eh4_read_int(&p);           /* IPtoStateMap (always) */
    (void)disp_uw_map;  /* not needed for catch dispatch */

    if (!disp_tb_map) {
        LSW_LOG_INFO("[exception] EH4 func=0x%x: no TryBlockMap", func_begin_rva);
        return false;
    }

    /* Validate that both RVAs look sane before dereferencing */
    if (!lsw_rva2va(disp_tb_map) || !lsw_rva2va(disp_ip_map))
        return false;

    /* Determine current EH state via IPtoStateMap */
    uint32_t ip_offset = (uint32_t)(rip - g_lsw_image_base) - func_begin_rva;
    int32_t  cur_state = lsw_eh4_ip_to_state(disp_ip_map, ip_offset);
    LSW_LOG_INFO("[exception] EH4 func=0x%x ip_offset=0x%x cur_state=%d tbm=0x%x",
                 func_begin_rva, ip_offset, cur_state, disp_tb_map);

    /* Build catchable pType list from ThrowInfo */
    uint32_t catchable_ptype[16];
    int      n_catchable = 0;
    if (throw_info && throw_info->pCatchableTypeArray) {
        lsw_CatchableTypeArray *cta =
            (lsw_CatchableTypeArray *)lsw_rva2va(throw_info->pCatchableTypeArray);
        if (cta && cta->nCatchableTypes > 0 && cta->nCatchableTypes <= 64) {
            for (int ci = 0; ci < cta->nCatchableTypes && n_catchable < 16; ci++) {
                lsw_CatchableType *ct =
                    (lsw_CatchableType *)lsw_rva2va(cta->arrayOfCatchableTypes[ci]);
                if (ct) catchable_ptype[n_catchable++] = ct->pType;
            }
        }
    }

    /* Walk TryBlockMap */
    const uint8_t *tbp = (const uint8_t *)lsw_rva2va(disp_tb_map);
    if (!tbp || tbp >= img_end) return false;

    uint32_t num_tries = lsw_eh4_read_uint(&tbp);
    if (num_tries == 0 || num_tries > 1024u) return false;

    for (uint32_t t = 0; t < num_tries && tbp < img_end - 8; t++) {
        uint32_t try_low  = lsw_eh4_read_uint(&tbp);
        uint32_t try_high = lsw_eh4_read_uint(&tbp);
        /* catchHigh exists in the format but is not needed for dispatch */
        lsw_eh4_read_uint(&tbp);
        int32_t disp_handler_arr = lsw_eh4_read_int(&tbp);

        /* State range check: TryBlockMap states are direct (not state+1) */
        if (cur_state >= 0) {
            int32_t s_low  = (int32_t)try_low;
            int32_t s_high = (int32_t)try_high;
            if (cur_state < s_low || cur_state > s_high) {
                LSW_LOG_INFO("[exception] EH4 func=0x%x try[%u] state %d not in [%d,%d]",
                             func_begin_rva, t, cur_state, s_low, s_high);
                continue;
            }
        }

        if (!disp_handler_arr) continue;

        const uint8_t *hmp = (const uint8_t *)lsw_rva2va((uint32_t)disp_handler_arr);
        if (!hmp || hmp >= img_end) continue;

        uint32_t num_handlers = lsw_eh4_read_uint(&hmp);
        if (num_handlers == 0 || num_handlers > 1024u) continue;

        LSW_LOG_INFO("[exception] EH4 func=0x%x try[%u] [%u,%u] numHandlers=%u",
                     func_begin_rva, t, try_low, try_high, num_handlers);

        for (uint32_t h = 0; h < num_handlers && hmp < img_end - 4; h++) {
            uint8_t  h_hdr    = *hmp++;
            uint32_t adj      = 0;
            int32_t  d_type   = 0;
            uint32_t d_catch  = 0;
            int32_t  d_handler;

            if (h_hdr & 0x01u) adj     = lsw_eh4_read_uint(&hmp); /* adjectives */
            if (h_hdr & 0x02u) d_type  = lsw_eh4_read_int(&hmp);  /* dispType   */
            if (h_hdr & 0x04u) d_catch = lsw_eh4_read_uint(&hmp); /* dispCatchObj */
            d_handler = lsw_eh4_read_int(&hmp);                    /* dispOfHandler (always) */

            /* Read continuation addresses */
            uint8_t  cont_cnt    = (h_hdr >> 4) & 0x03u;
            uint8_t  cont_is_rva = (h_hdr >> 3) & 0x01u;
            uint64_t my_cont_vas[2] = {0, 0};
            uint8_t  my_cont_cnt = (cont_cnt < 2) ? cont_cnt : 2;
            for (uint8_t ca = 0; ca < cont_cnt && hmp < img_end - 4; ca++) {
                if (cont_is_rva) {
                    int32_t rva = lsw_eh4_read_int(&hmp);
                    if (ca < 2) my_cont_vas[ca] = g_lsw_image_base + (uint32_t)rva;
                } else {
                    uint32_t off = lsw_eh4_read_uint(&hmp);
                    if (ca < 2) my_cont_vas[ca] = g_lsw_image_base + func_begin_rva + off;
                }
            }

            if (!d_handler) continue;

            /* Type matching */
            bool matches = false;
            if (d_type == 0) {
                matches = true; /* catch(...) */
            } else {
                for (int ci = 0; ci < n_catchable; ci++) {
                    if ((uint32_t)d_type == catchable_ptype[ci]) {
                        matches = true;
                        break;
                    }
                }
            }

            if (matches) {
                *handler_va     = g_lsw_image_base + (uint32_t)d_handler;
                *disp_catch_obj = (int32_t)d_catch;
                *out_adjectives = adj;
                if (out_cont_cnt) *out_cont_cnt = my_cont_cnt;
                if (out_cont_vas) {
                    out_cont_vas[0] = my_cont_vas[0];
                    out_cont_vas[1] = my_cont_vas[1];
                }
                LSW_LOG_INFO("[exception] EH4 catch %s in func 0x%x handler=0x%lx disp=%d cont_cnt=%u",
                             d_type ? "typed" : "(...)",
                             func_begin_rva,
                             (unsigned long)*handler_va,
                             *disp_catch_obj, my_cont_cnt);
                if (my_cont_cnt > 0)
                    LSW_LOG_INFO("[exception] EH4 cont_vas[0]=0x%lx cont_vas[1]=0x%lx",
                                 (unsigned long)my_cont_vas[0], (unsigned long)my_cont_vas[1]);
                return true;
            }
        }
    }
    return false;
}

/*
 * Look up the "state" for a given RIP in a function's IPToStateMap.
 * Returns -1 if not found or no map.
 */
static int32_t lsw_ip_to_state(lsw_FuncInfo3* fi, uint64_t rip) {
    if (!fi->nIPMap || !fi->pIPMap) return -1;
    lsw_IPStateEntry* map = (lsw_IPStateEntry*)lsw_rva2va(fi->pIPMap);
    if (!map) return -1;
    uint32_t rip_rva = (uint32_t)(rip - g_lsw_image_base);
    int32_t state = -1;
    for (uint32_t i = 0; i < fi->nIPMap; i++) {
        if ((uint32_t)map[i].Ip <= rip_rva)
            state = map[i].State;
        else
            break;
    }
    return state;
}

/*
 * Check whether RUNTIME_FUNCTION rf (for a frame at 'rip' with entry RSP
 * 'entry_rsp') has a matching catch handler.  If found, fills *handler_va
 * and *disp_catch_obj and returns true.
 *
 * We walk the try-block map and match each handler against the thrown type:
 *   - pType == 0 → catch(...)  matches anything
 *   - pType != 0 → compare against every entry in throwInfo's CatchableTypeArray
 * The adjectives field drives how the exception object is placed:
 *   bit 0x8 (reference) → handler slot gets pointer-to-object
 *   bit 0x1 (const)     → same (no copy needed for ref)
 *   neither             → value copy via copyFunction (not yet implemented)
 */
static bool lsw_find_catch_in_frame(lsw_RUNTIME_FUNCTION* rf,
                                     uint64_t rip,
                                     uint64_t entry_rsp,
                                     lsw_ThrowInfo* throw_info,
                                     uint64_t* handler_va,
                                     int32_t*  disp_catch_obj,
                                     uint32_t* out_adjectives,
                                     bool*     out_is_eh4,
                                     uint64_t* out_eh4_cont_vas,
                                     uint32_t* out_eh4_cont_cnt)
{
    /* Load UNWIND_INFO to find the handler function and FuncInfo RVA */
    uint8_t* ui = (uint8_t*)lsw_rva2va(rf->UnwindData);
    if (!ui) return false;

    /* Chase chains to find the real UNWIND_INFO with EHANDLER */
    for (int depth = 0; depth < 8; depth++) {
        uint8_t flags      = (ui[0] >> 3) & 0x1fu;
        uint8_t code_count = ui[2];
        int     codes_sz   = (int)(((code_count + 1) & ~1) * 2);

        if (flags & UNW_FLAG_CHAININFO) {
            lsw_RUNTIME_FUNCTION* chain =
                (lsw_RUNTIME_FUNCTION*)(ui + 4 + codes_sz);
            ui = (uint8_t*)lsw_rva2va(chain->UnwindData);
            if (!ui) return false;
            continue;
        }
        if (!(flags & UNW_FLAG_EHANDLER))
            return false;

        /* handler RVA and FuncInfo RVA follow the unwind codes.
         *
         * For __CxxFrameHandler3:
         *   after[0] = handlerRVA, after[1] = FuncInfo3 RVA
         * For __GSHandlerCheck_EH3 (stack-cookie protected functions):
         *   after[0] = handlerRVA
         *   after[1..4] = GS_HANDLERDATA (GSCookieOffset, GSCookieXorOffset,
         *                                  EHCookieOffset, EHCookieXorOffset)
         *   after[5] = FuncInfo3 RVA
         * We try after[1] first; if magic doesn't match, try after[5].
         */
        uint32_t* after = (uint32_t*)(ui + 4 + codes_sz);

        if ((uint32_t*)after + 2 > (uint32_t*)((uint8_t*)g_lsw_pdata_va + g_lsw_pdata_size + 0x10000))
            return false;  /* rough bounds check */

        /* Try to locate FuncInfo3: check after[1] first (plain EH3),
         * then after[5] (GSHandlerCheck_EH3 with 4-DWORD cookie data). */
        lsw_FuncInfo3* fi = NULL;
        LSW_LOG_INFO("[exception] find_catch func=0x%x after[0]=0x%x after[1]=0x%x after[5]=0x%x",
                     rf->BeginAddress, after[0], after[1], after[5]);
        for (int fi_offset = 1; fi_offset <= 5; fi_offset += 4) {
            uint32_t funcinfo_rva = after[fi_offset];
            lsw_FuncInfo3* candidate = (lsw_FuncInfo3*)lsw_rva2va(funcinfo_rva);
            LSW_LOG_INFO("[exception]   fi_offset=%d rva=0x%x candidate=%p magic=0x%x",
                         fi_offset, funcinfo_rva, (void*)candidate,
                         candidate ? candidate->magic : 0);
            if (candidate &&
                candidate->magic >= 0x19930520u && candidate->magic <= 0x19930524u) {
                fi = candidate;
                break;
            }
        }
        if (!fi) {
            /* EH3 not found — try EH4 (__CxxFrameHandler4, VS2019+).
             * FuncInfo4 starts with a 1-byte header (value 0x00-0x7F) rather
             * than the EH3 magic DWORD.  Try the same after[1] / after[5]
             * offsets used for EH3. */
            LSW_LOG_INFO("[exception]   no FuncInfo3; trying EH4 for func=0x%x",
                         rf->BeginAddress);
            for (int fi4_off = 1; fi4_off <= 5; fi4_off += 4) {
                uint32_t fi4_rva = after[fi4_off];
                uint8_t *fi4_ptr = (uint8_t *)lsw_rva2va(fi4_rva);
                if (!fi4_ptr) continue;
                /* Quick sanity: EH4 header byte must be in 0x00-0x7F range and
                 * must NOT be the lead byte of an EH3 magic (0x20 from 0x19930520
                 * can appear here; we still let the parser try and it will bail if
                 * the derived RVAs are invalid). */
                uint8_t hdr4 = fi4_ptr[0];
                if (hdr4 > 0x1Fu) continue; /* reserved bits set → garbage */
                if (lsw_eh4_find_catch(fi4_rva, rf->BeginAddress, rip,
                                       throw_info, handler_va,
                                       disp_catch_obj, out_adjectives,
                                       out_eh4_cont_vas, out_eh4_cont_cnt)) {
                    if (out_is_eh4) *out_is_eh4 = true;
                    return true;
                }
            }
            return false;
        }

        LSW_LOG_INFO("[exception] fi=%p magic=0x%x nTryBlocks=%u pTryBlockMap=0x%x",
                     (void*)fi, fi->magic, fi->nTryBlocks, fi->pTryBlockMap);

        if (!fi->nTryBlocks || !fi->pTryBlockMap)
            return false;

        int32_t cur_state = lsw_ip_to_state(fi, rip);
        LSW_LOG_INFO("[exception] cur_state=%d for rip=0x%lx func=0x%x",
                     cur_state, (unsigned long)rip, rf->BeginAddress);

        lsw_TryBlockMapEntry* tbm =
            (lsw_TryBlockMapEntry*)lsw_rva2va(fi->pTryBlockMap);
        LSW_LOG_INFO("[exception] tbm=%p", (void*)tbm);
        if (!tbm) return false;

        for (uint32_t t = 0; t < fi->nTryBlocks; t++) {
            lsw_TryBlockMapEntry* tb = &tbm[t];
            /* Check if current state is within this try block */
            if (cur_state >= 0 &&
                (cur_state < tb->tryLow || cur_state > tb->tryHigh))
                continue;

            if (!tb->nCatches || !tb->pHandlerArray) continue;
            lsw_HandlerType* ha =
                (lsw_HandlerType*)lsw_rva2va(tb->pHandlerArray);
            if (!ha) continue;

            /* Build a quick list of catchable pType RVAs from the ThrowInfo
             * so we can match typed handlers as well as catch(...). */
            uint32_t catchable_ptype[16];
            int n_catchable = 0;
            if (throw_info && throw_info->pCatchableTypeArray) {
                lsw_CatchableTypeArray* cta =
                    (lsw_CatchableTypeArray*)lsw_rva2va(throw_info->pCatchableTypeArray);
                if (cta && cta->nCatchableTypes > 0 && cta->nCatchableTypes <= 64) {
                    for (int ci = 0; ci < cta->nCatchableTypes && n_catchable < 16; ci++) {
                        uint32_t ct_rva = cta->arrayOfCatchableTypes[ci];
                        lsw_CatchableType* ct = (lsw_CatchableType*)lsw_rva2va(ct_rva);
                        if (ct) catchable_ptype[n_catchable++] = ct->pType;
                    }
                }
            }

            /* Try 20-byte then 16-byte HandlerType strides.
             * VS2019+ uses 20 bytes (adds dispFrame field); older uses 16. */
            for (int stride = 20; stride >= 16; stride -= 4) {
                bool found = false;
                for (int32_t k = 0; k < tb->nCatches; k++) {
                    lsw_HandlerType* h =
                        (lsw_HandlerType*)((uint8_t*)ha + k * stride);
                    if (!h->addressOfHandler) continue;

                    bool matches = false;
                    if (h->pType == 0) {
                        /* catch(...) — matches anything */
                        matches = true;
                    } else {
                        /* Typed catch — match against thrown type hierarchy */
                        for (int ci = 0; ci < n_catchable; ci++) {
                            if (catchable_ptype[ci] == h->pType) {
                                matches = true;
                                break;
                            }
                        }
                    }

                    if (matches) {
                        *handler_va     = g_lsw_image_base + h->addressOfHandler;
                        *disp_catch_obj = h->dispCatchObj;
                        *out_adjectives = h->adjectives;
                        LSW_LOG_INFO("[exception] catch %s in func 0x%x "
                                     "handler=0x%lx disp=%d state=%d [%d,%d]",
                                     h->pType ? "typed" : "(...)",
                                     rf->BeginAddress,
                                     (unsigned long)*handler_va,
                                     *disp_catch_obj,
                                     cur_state, tb->tryLow, tb->tryHigh);
                        found = true;
                        return true;
                    }
                }
                /* If adj values look reasonable for this stride, stop here.
                 * Adjectives should be small flags (0-15); large values indicate wrong stride. */
                if (!found && stride == 20 && tb->nCatches > 0) {
                    lsw_HandlerType* h0 = ha;
                    if (h0->adjectives <= 0xF) break; /* 20-byte stride fits; no match */
                }
            }
        }
        return false;
    }
    return false;
}

/* _CxxThrowException — throw a C++ exception via x64 exception dispatch */
void __attribute__((ms_abi)) lsw__CxxThrowException(void* obj, void* throwInfo) {
    /* Store exception info for any outer handler that needs it */
    tls_cxx_exception_obj  = obj;
    tls_cxx_exception_type = throwInfo;

    /* ------------------------------------------------------------------ *
     * Reconstruct the PE caller's frame from GCC's RBP chain.             *
     *                                                                      *
     * Stack layout when we enter this ms_abi function (GCC prolog):       *
     *   [PE caller did: sub rsp,0x20 ; call _CxxThrowException]           *
     *   GCC prolog: push rbp ; mov rbp,rsp ; [optional push rbx ...] ;   *
     *               sub rsp,N                                              *
     *                                                                      *
     * So:  my_rbp == RBP after GCC prolog                                 *
     *      [my_rbp]   == saved old RBP                                    *
     *      [my_rbp+8] == return address in PE caller (ret_to_B)           *
     *      PE_caller_body_rsp == my_rbp + 0x30                            *
     *         (my_rbp + 8 = RSP_at_C_entry;                               *
     *          RSP_at_C_entry + 0x28 = PE caller's body RSP before shadow)*
     * ------------------------------------------------------------------ */
    uint64_t my_rbp;
    __asm__ volatile ("mov %%rbp, %0" : "=r"(my_rbp));

    uint64_t ret_to_b  = *(uint64_t*)(my_rbp + 8);
    /* MSVC x64 pre-allocates shadow space in the function prolog — no separate
     * "sub rsp,0x20" before the call to us.  So PE caller's body RSP is simply
     * (entry_RSP_of_us + 8), where entry_RSP_of_us = my_rbp + 8. */
    uint64_t body_rsp  = my_rbp + 0x10;  /* = entry_RSP_of_us + 0x08 */
    uint64_t rip       = ret_to_b - 1;   /* point inside the call instruction */

    LSW_LOG_INFO("[exception] _CxxThrowException obj=%p throw_info=%p",
                 obj, throwInfo);
    LSW_LOG_INFO("[exception] caller ret_addr=0x%lx body_rsp=0x%lx",
                 (unsigned long)ret_to_b, (unsigned long)body_rsp);

    /* Verify we have PE image info before trying to dispatch */
    if (!g_lsw_pdata_va || !g_lsw_image_base) {
        LSW_LOG_ERROR("[exception] No PE image info — cannot dispatch C++ exception");
        abort();
    }

    /* Walk the PE call stack looking for a matching catch handler */
    for (int depth = 0; depth < 128; depth++) {
        if (rip < g_lsw_image_base ||
            rip >= g_lsw_image_base + 0x10000000ULL) {
            LSW_LOG_WARN("[exception] RIP 0x%lx outside PE image, stopping walk",
                         (unsigned long)rip);
            break;
        }

        lsw_RUNTIME_FUNCTION* rf = lsw_find_rf(rip);
        if (!rf) {
            LSW_LOG_WARN("[exception] No RUNTIME_FUNCTION for RIP 0x%lx depth=%d",
                         (unsigned long)rip, depth);
            break;
        }

        LSW_LOG_INFO("[exception] depth=%d rip=0x%lx func=[0x%x,0x%x)",
                     depth, (unsigned long)rip, rf->BeginAddress, rf->EndAddress);

        /* Unwind this frame to get entry RSP */
        uint64_t caller_rip, caller_rsp;
        LSW_LOG_INFO("[exception] calling unwind_frame depth=%d body_rsp=0x%lx",
                     depth, (unsigned long)body_rsp);
        uint64_t entry_rsp = lsw_unwind_frame(rf, body_rsp,
                                               &caller_rip, &caller_rsp);
        LSW_LOG_INFO("[exception] unwind_frame returned entry_rsp=0x%lx caller_rip=0x%lx",
                     (unsigned long)entry_rsp, (unsigned long)caller_rip);
        if (!entry_rsp) {
            LSW_LOG_WARN("[exception] unwind_frame failed at depth=%d", depth);
            break;
        }

        /* Check if this frame has a matching catch */
        uint64_t catch_handler_va = 0;
        int32_t  disp_catch_obj   = 0;
        uint32_t catch_adjectives = 0;
        bool     is_eh4           = false;
        uint64_t eh4_cont_vas[2]  = {0, 0};
        uint32_t eh4_cont_cnt     = 0;
        LSW_LOG_INFO("[exception] calling find_catch depth=%d body_rsp=0x%lx",
                     depth, (unsigned long)body_rsp);
        if (lsw_find_catch_in_frame(rf, rip, entry_rsp,
                                    (lsw_ThrowInfo*)throwInfo,
                                    &catch_handler_va, &disp_catch_obj,
                                    &catch_adjectives,
                                    &is_eh4, eh4_cont_vas, &eh4_cont_cnt)) {
            /* ----------------------------------------------------------
             * Found a matching catch handler.  Execute its funclet.
             *
             * The catch funclet is called with RDX = the try function's
             * "frame base" (body_rsp for EH4, entry_rsp for EH3).
             * EH3 funclets return the continuation VA directly.
             * EH4 funclets return a continuation INDEX (0 or 1).
             * ---------------------------------------------------------- */
            LSW_LOG_INFO("[exception] Dispatching to catch handler 0x%lx "
                         "body_rsp=0x%lx entry_rsp=0x%lx disp=%d adj=0x%x is_eh4=%d",
                         (unsigned long)catch_handler_va,
                         (unsigned long)body_rsp,
                         (unsigned long)entry_rsp, disp_catch_obj,
                         catch_adjectives, (int)is_eh4);

            /* Place the exception object in the catch frame if disp != 0.
             * EH4 uses body_rsp as the frame base; EH3 uses entry_rsp. */
            uint64_t frame_base = is_eh4 ? body_rsp : entry_rsp;
            if (disp_catch_obj != 0) {
                void** slot = (void**)(frame_base + (int64_t)disp_catch_obj);
                if (catch_adjectives & 0x8) {
                    /* reference catch: slot holds pointer to exception object */
                    *slot = obj;
                } else {
                    /* value catch: ideally copy via copyFunction; store ptr for now */
                    *slot = obj;
                }
            }

            /* Call the catch funclet.
             *
             * MSVC x64 catch funclets use RDX (2nd arg) as the frame base,
             * not RCX (1st arg).  The funclet does `mov rbp,rdx` in its
             * prolog.  RCX is overwritten by the funclet itself (it loads
             * a constant into RCX immediately after).
             *
             * Convention: funclet(rcx_ignored, frame_base) → continuation
             * EH3: continuation is a direct VA
             * EH4: continuation is an index into eh4_cont_vas[]
             */
            typedef void* (__attribute__((ms_abi)) *funclet_t)(uint64_t, uint64_t);
            funclet_t funclet = (funclet_t)catch_handler_va;
            void* continuation = funclet(0, frame_base);

            LSW_LOG_INFO("[exception] catch funclet returned continuation=%p",
                         continuation);

            uint64_t cont_va = 0;
            if (is_eh4 && eh4_cont_cnt > 0) {
                /* EH4: continuation is a 0-based index */
                uint64_t cont_idx = (uint64_t)(uintptr_t)continuation;
                if (cont_idx >= eh4_cont_cnt) cont_idx = 0;
                cont_va = eh4_cont_vas[cont_idx];
                LSW_LOG_INFO("[exception] EH4 cont_idx=%lu cont_va=0x%lx",
                             (unsigned long)cont_idx, (unsigned long)cont_va);
            } else if (!is_eh4 && continuation) {
                /* EH3: continuation is a direct VA */
                cont_va = (uint64_t)continuation;
            }

            if (cont_va) {
                /* Jump to the continuation inside the try function with
                 * RSP restored to the body RSP of that frame.             */
                LSW_LOG_INFO("[exception] jumping to continuation 0x%lx "
                             "with rsp=0x%lx",
                             (unsigned long)cont_va, (unsigned long)body_rsp);
                __asm__ volatile (
                    "mov %0, %%rsp\n\t"
                    "jmp *%1\n\t"
                    : : "r"(body_rsp), "r"(cont_va) : "memory"
                );
                __builtin_unreachable();
            }

            /* Funclet returned NULL / index 0 with no cont_vas — treat as
             * successful catch, continue execution normally */
            LSW_LOG_INFO("[exception] catch handler completed (no continuation)");
            return;
        }

        /* No catch in this frame — unwind to parent */
        rip      = caller_rip - 1;   /* point inside the call instruction */
        body_rsp = caller_rsp;       /* MSVC pre-allocates shadow in prolog; no extra offset */
    }

    LSW_LOG_ERROR("[exception] No catch handler found after walking %d frames",
                  128);
    LSW_LOG_ERROR("[exception] C++ exception unhandled — aborting");
    abort();
}


/* _isatty — check if fd refers to a terminal */
int __attribute__((ms_abi)) lsw__isatty(int fd) {
    return isatty(fd);
}

/* _controlfp — FPU control word; stub returning default 0x9001f */
unsigned int __attribute__((ms_abi)) lsw__controlfp(unsigned int newval, unsigned int mask) {
    (void)newval; (void)mask;
    return 0x9001f;
}

/* __p__fmode — pointer to _fmode variable */
int* __attribute__((ms_abi)) lsw___p__fmode(void) { return &lsw_crt_fmode; }

/* __p__commode — pointer to _commode variable */
int* __attribute__((ms_abi)) lsw___p__commode(void) { return &lsw_crt_commode; }

/* _adjust_fdiv — legacy FP rounding; no-op */
void __attribute__((ms_abi)) lsw__adjust_fdiv(void) {}

/* __p___initenv — pointer to the initial environment */
char*** __attribute__((ms_abi)) lsw___p___initenv(void) {
    static char* dummy_env[] = { NULL };
    static char** env_ptr = dummy_env;
    return &env_ptr;
}

/* fputs — write string to FILE* */
int __attribute__((ms_abi)) lsw_fputs(const char* str, void* stream) {
    if (!str) return -1;
    typedef struct { char* _ptr; int _cnt; char* _base; int _flag; int _file; } fake_FILE;
    fake_FILE* fake = (fake_FILE*)stream;
    if (fake && fake->_file >= 0 && fake->_file <= 2) {
        size_t len = strlen(str);
        ssize_t written = write(fake->_file, str, len);
        return written >= 0 ? (int)written : EOF;
    }
    if (!stream) return write(1, str, strlen(str)) >= 0 ? 0 : EOF;
    return fputs(str, (FILE*)stream);
}

/* _iob — pointer to FILE array (alias for __iob_func result) */
void* __attribute__((ms_abi)) lsw__iob(void) {
    return lsw__iob_func();
}

int* __attribute__((ms_abi)) lsw__commode_ptr(void) {
    return &lsw_crt_commode;
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

int __attribute__((ms_abi)) lsw_MultiByteToWideChar(unsigned int codepage, unsigned long flags, const char* src, int srclen, uint16_t* dst, int dstlen) {
    (void)codepage;
    (void)flags;

    int len = srclen >= 0 ? srclen : (src ? (int)strlen(src) : 0);

    if (!dst) {
        LSW_LOG_INFO("MultiByteToWideChar: query size for %d chars", len);
        return len;
    }

    if (len > dstlen) len = dstlen;
    LSW_LOG_INFO("MultiByteToWideChar: cp=%u srclen=%d dstlen=%d -> %d chars", codepage, srclen, dstlen, len);

    /* Write UTF-16LE (2-byte) characters into dst — caller is Windows code expecting uint16_t */
    for (int i = 0; i < len; i++) {
        dst[i] = (uint16_t)(unsigned char)src[i];
    }

    return len;
}

int __attribute__((ms_abi)) lsw_WideCharToMultiByte(unsigned int codepage, unsigned long flags, const wchar_t* src, int srclen, char* dst, int dstlen, const char* defchar, int* used_default) {
    (void)codepage;
    (void)flags;
    (void)defchar;

    if (!src) return 0;

    /* Windows wchar_t is UTF-16 (2 bytes); Linux wchar_t is 4 bytes — treat as uint16_t* */
    const uint16_t* src16 = (const uint16_t*)src;

    size_t actual_srclen;
    if (srclen == -1) {
        actual_srclen = 0;
        while (src16[actual_srclen] != 0) actual_srclen++;
        actual_srclen++; /* include null terminator */
    } else {
        actual_srclen = (size_t)srclen;
    }

    if (!dst || dstlen == 0) {
        /* Query required size */
        return (int)actual_srclen; /* Conservative: 1 byte per wide char for BMP */
    }

    LSW_LOG_INFO("WideCharToMultiByte: cp=%u srclen=%d dstlen=%d actual=%zu", codepage, srclen, dstlen, actual_srclen);

    size_t src_idx = 0, dst_idx = 0;
    while (src_idx < actual_srclen && dst_idx < (size_t)dstlen) {
        uint16_t wc = src16[src_idx++];

        if (wc == 0) {
            if (srclen == -1) dst[dst_idx++] = '\0'; /* include null only if source was null-terminated */
            break;
        } else if (wc < 0x80) {
            dst[dst_idx++] = (char)wc;
        } else if (wc < 0x800) {
            if (dst_idx + 2 > (size_t)dstlen) break;
            dst[dst_idx++] = (char)(0xC0 | ((wc >> 6) & 0x1F));
            dst[dst_idx++] = (char)(0x80 | (wc & 0x3F));
        } else if (wc < 0xD800 || wc >= 0xE000) {
            if (dst_idx + 3 > (size_t)dstlen) break;
            dst[dst_idx++] = (char)(0xE0 | ((wc >> 12) & 0x0F));
            dst[dst_idx++] = (char)(0x80 | ((wc >> 6) & 0x3F));
            dst[dst_idx++] = (char)(0x80 | (wc & 0x3F));
        } else {
            dst[dst_idx++] = '?';
        }
    }

    if (used_default) *used_default = 0;
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

/* UnhandledExceptionFilter — called when no handler catches an exception; return EXCEPTION_EXECUTE_HANDLER (1) */
int __attribute__((ms_abi)) lsw_UnhandledExceptionFilter(void* pExceptionInfo) {
    uint32_t code = 0;
    if (pExceptionInfo) {
        /* EXCEPTION_POINTERS: first field is EXCEPTION_RECORD* */
        uint32_t* rec = *(uint32_t**)pExceptionInfo;
        if (rec) code = rec[0];
    }

    /* Debug print exception (0x40010006 / 0x4001000A): ignore, continue execution */
    if (code == 0x40010006 || code == 0x4001000A)
        return -1; /* EXCEPTION_CONTINUE_EXECUTION */

    /* Breakpoint (0x80000003) or single-step (0x80000004): continue if possible */
    if (code == 0x80000003 || code == 0x80000004)
        return -1; /* EXCEPTION_CONTINUE_EXECUTION */

    LSW_LOG_ERROR("UnhandledExceptionFilter: code=0x%08x — exiting", code);
    /* Print Linux backtrace for diagnosis */
    void *bt[32];
    int n = backtrace(bt, 32);
    backtrace_symbols_fd(bt, n, STDERR_FILENO);

    /* For fatal exceptions, exit cleanly rather than let PE execute DebugBreak */
    _exit(1);
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
    if ((access & GENERIC_READ) && (access & GENERIC_WRITE)) {
        if (creation == CREATE_ALWAYS) {
            flags_unix = O_RDWR | O_CREAT | O_TRUNC;
        } else {
            flags_unix = O_RDWR;
        }
    } else if (access & GENERIC_WRITE) {
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

    /* Windows pseudo-handles (STD_*) are not closeable */
    if (LSW_IS_PSEUDO_HANDLE(handle)) return 1;

    /* Raw file descriptor — small integer, not a heap struct */
    if (!IS_TYPED_HANDLE(handle)) {
        intptr_t fd = (intptr_t)handle;
        if (fd >= 0 && fd < 1024) {
            close((int)fd);
            return 1;
        }
        return 0;
    }

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
    if (IS_TYPED_HANDLE(ev) && ev->magic == LSW_EVENT_MAGIC) {
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
    if (!module_name) {
        /* Return the typed module handle so FormatMessageW(FROM_HMODULE) works */
        if (g_main_exe_hmodule_ready) {
            LSW_LOG_INFO("GetModuleHandleA: NULL -> main exe typed handle (%p)", &g_main_exe_hmodule);
            return (void*)&g_main_exe_hmodule;
        }
        LSW_LOG_INFO("GetModuleHandleA: NULL -> 0x140000000 (base, not yet typed)");
        return (void*)0x140000000;
    }
    LSW_LOG_INFO("GetModuleHandleA: %s -> system hmodule", module_name);
    return (void*)0xDEADBEEF; /* LSW_SYSTEM_HMODULE — route GetProcAddress through our stubs */
}

// KERNEL32 Console I/O Functions
#define STD_INPUT_HANDLE  ((void*)(uintptr_t)(-10))
#define STD_OUTPUT_HANDLE ((void*)(uintptr_t)(-11))
#define STD_ERROR_HANDLE  ((void*)(uintptr_t)(-12))

void* __attribute__((ms_abi)) lsw_GetStdHandle(uint32_t std_handle) {
    // Return Windows-compatible pseudo-handle constants so callers that
    // pass them directly to ReadFile/WriteFile without going through GetStdHandle
    // get consistent behavior. -10=stdin, -11=stdout, -12=stderr.
    switch (std_handle) {
        case (uint32_t)-10: return (void*)(intptr_t)-10;
        case (uint32_t)-11: return (void*)(intptr_t)-11;
        case (uint32_t)-12: return (void*)(intptr_t)-12;
        default: return (void*)(intptr_t)-1;  /* INVALID_HANDLE_VALUE */
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

    /* Windows pseudo-handles: STD_OUTPUT_HANDLE=-11, STD_ERROR_HANDLE=-12 */
    {
        int pfd = lsw_pseudo_handle_to_fd(handle);
        if (pfd >= 0) {
            LSW_LOG_INFO("WriteFile pseudo-handle %p (fd=%d): write=%u bytes '%.*s'", handle, pfd, bytes_to_write, (int)(bytes_to_write > 40 ? 40 : bytes_to_write), (const char*)buffer);
            ssize_t r = write(pfd, buffer, bytes_to_write);
            if (bytes_written) *bytes_written = r < 0 ? 0 : (uint32_t)r;
            return r >= 0 ? 1 : 0;
        }
    }

    /* Named pipe handle — write to Unix domain socket fd */
    {
        lsw_pipe_t* pp = (lsw_pipe_t*)handle;
        if (IS_TYPED_HANDLE(pp) && pp->magic == LSW_PIPE_MAGIC) {
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
    
    int fd = (int)(uintptr_t)handle;
    
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

    /* Windows pseudo-handles: STD_INPUT_HANDLE=-10, STD_OUTPUT_HANDLE=-11, STD_ERROR_HANDLE=-12 */
    {
        int pfd = lsw_pseudo_handle_to_fd(handle);
        if (pfd >= 0) {
            ssize_t r = read(pfd, buffer, bytes_to_read);
            LSW_LOG_INFO("ReadFile pseudo-handle %p (fd=%d): read=%zd/%u", handle, pfd, r, bytes_to_read);
            if (bytes_read) *bytes_read = r < 0 ? 0 : (uint32_t)r;
            return r >= 0 ? 1 : 0;
        }
    }

    /* Named pipe handle — read from Unix domain socket fd */
    {
        lsw_pipe_t* pp = (lsw_pipe_t*)handle;
        if (IS_TYPED_HANDLE(pp) && pp->magic == LSW_PIPE_MAGIC) {
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
    
    int fd = (int)(uintptr_t)handle;
    
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
    
    // Fallback: use fstat on raw fd
    {
        int fd = (int)(intptr_t)handle;
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (file_size_high) *file_size_high = (uint32_t)((uint64_t)st.st_size >> 32);
            return (uint32_t)(st.st_size & 0xFFFFFFFF);
        }
    }
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
    
    // Fallback: use lseek on raw fd
    {
        int fd = (int)(intptr_t)handle;
        int whence = SEEK_SET;
        if (move_method == 1) whence = SEEK_CUR;
        else if (move_method == 2) whence = SEEK_END;
        off_t new_pos = lseek(fd, (off_t)offset, whence);
        if (new_pos != (off_t)-1) {
            if (distance_to_move_high) *distance_to_move_high = (int32_t)(new_pos >> 32);
            return (uint32_t)(new_pos & 0xFFFFFFFF);
        }
    }
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
DWORD __attribute__((ms_abi)) lsw_GetWindowsDirectoryW(uint16_t* buffer, DWORD size) {
    /* "C:\Windows" as UTF-16LE (2-byte chars, not 4-byte wchar_t) */
    static const uint16_t win_dir[] = {'C',':','\\','W','i','n','d','o','w','s',0};
    DWORD len = 10; /* strlen("C:\\Windows") */
    if (!buffer || size == 0) return len + 1;
    if (size <= len) return len + 1;
    for (DWORD i = 0; i <= len; i++) buffer[i] = win_dir[i];
    return len;
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
DWORD __attribute__((ms_abi)) lsw_GetSystemDirectoryW(uint16_t* buffer, DWORD size) {
    /* "C:\Windows\System32" as UTF-16LE (2-byte chars) */
    static const uint16_t sys_dir[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2',0};
    DWORD len = 19; /* strlen("C:\\Windows\\System32") */
    if (!buffer || size == 0) return len + 1;
    if (size <= len) return len + 1;
    for (DWORD i = 0; i <= len; i++) buffer[i] = sys_dir[i];
    return len;
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

// KERNEL32.dll!GetTempPath2A/W - Windows 10 2004+ variant; same semantics as GetTempPathA/W
DWORD __attribute__((ms_abi)) lsw_GetTempPath2A(DWORD size, char* buffer) {
    return lsw_GetTempPathA(size, buffer);
}
DWORD __attribute__((ms_abi)) lsw_GetTempPath2W(DWORD size, wchar_t* buffer) {
    return lsw_GetTempPathW(size, buffer);
}

// KERNEL32.dll!GetTempFileNameA/W - Create a temporary file name
uint32_t __attribute__((ms_abi)) lsw_GetTempFileNameA(const char* lpPathName, const char* lpPrefixString,
                                                   uint32_t uUnique, char* lpTempFileName) {
    if (!lpTempFileName) return 0;
    const char* dir = (lpPathName && lpPathName[0]) ? lpPathName : "/tmp";
    const char* pfx = (lpPrefixString && lpPrefixString[0]) ? lpPrefixString : "tmp";
    if (uUnique == 0) {
        uUnique = (uint32_t)((getpid() ^ (unsigned long)time(NULL)) & 0xFFFF);
        if (uUnique == 0) uUnique = 1;
    }
    // Build Windows-style temp path: dir\pfxXXXX.tmp
    snprintf(lpTempFileName, LSW_MAX_PATH, "%s\\%s%04X.tmp", dir, pfx, uUnique & 0xFFFF);
    // Create the file so the name is reserved
    char linux_path[LSW_MAX_PATH];
    lsw_fs_win_to_linux(lpTempFileName, linux_path, sizeof(linux_path));
    int fd = open(linux_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
    LSW_LOG_INFO("GetTempFileNameA: '%s' (unique=%u)", lpTempFileName, uUnique);
    return uUnique;
}
uint32_t __attribute__((ms_abi)) lsw_GetTempFileNameW(const wchar_t* lpPathName, const wchar_t* lpPrefixString,
                                                    uint32_t uUnique, wchar_t* lpTempFileName) {
    if (!lpTempFileName) return 0;
    char dirA[LSW_MAX_PATH] = {0}, pfxA[32] = {0}, outA[LSW_MAX_PATH] = {0};
    if (lpPathName) lsw_WideCharToMultiByte(CP_UTF8, 0, lpPathName, -1, dirA, sizeof(dirA), NULL, NULL);
    if (lpPrefixString) lsw_WideCharToMultiByte(CP_UTF8, 0, lpPrefixString, -1, pfxA, sizeof(pfxA), NULL, NULL);
    uint32_t r = lsw_GetTempFileNameA(dirA, pfxA, uUnique, outA);
    if (r) lsw_MultiByteToWideChar(CP_UTF8, 0, outA, -1, lpTempFileName, LSW_MAX_PATH);
    return r;
}

// KERNEL32.dll!GetDiskFreeSpaceA - ANSI wrapper for GetDiskFreeSpaceW
int __attribute__((ms_abi)) lsw_GetDiskFreeSpaceA(const char* lpRootPathName,
                                                    uint32_t* lpSectorsPerCluster, uint32_t* lpBytesPerSector,
                                                    uint32_t* lpNumberOfFreeClusters, uint32_t* lpTotalNumberOfClusters) {
    (void)lpRootPathName;
    return lsw_GetDiskFreeSpaceW(NULL, lpSectorsPerCluster, lpBytesPerSector,
                                 lpNumberOfFreeClusters, lpTotalNumberOfClusters);
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
    if (!mem) return (size_t)-1;  /* Windows returns (SIZE_T)-1 for invalid pointer */
    return malloc_usable_size(mem);
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
    if (!handle || handle == INVALID_HANDLE_VALUE) return 0xFFFFFFFF; /* WAIT_FAILED */

    /* ---- Raw process handle (small-integer PID from CreateProcess) ---- */
    if (!IS_TYPED_HANDLE(handle)) {
        pid_t pid = (pid_t)(uintptr_t)handle;
        if (pid > 1) {
            int wstatus = 0;
            if (milliseconds == 0xFFFFFFFF) {
                pid_t r = waitpid(pid, &wstatus, 0);
                if (r == pid) return 0; /* WAIT_OBJECT_0 */
            } else if (milliseconds == 0) {
                pid_t r = waitpid(pid, &wstatus, WNOHANG);
                if (r == pid) return 0;
                return 0x00000102; /* WAIT_TIMEOUT */
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
        return 0xFFFFFFFF; /* WAIT_FAILED for other small integers */
    }

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

/*
 * Translate a PE RVA to a pointer in our raw-file copy.
 * Since we mmap the raw file bytes (not mapped sections), each section's data
 * lives at image + PointerToRawData, NOT at image + VirtualAddress.
 */
static const uint8_t* pe_raw_rva_to_ptr(const uint8_t* image, size_t image_size, uint32_t rva)
{
    if (!image || rva == 0) return NULL;
    uint32_t pe_off = *(const uint32_t*)(image + 0x3C);
    if (pe_off + 24 + 4 > (uint32_t)image_size) return NULL;
    uint16_t num_sec    = *(const uint16_t*)(image + pe_off + 4 + 2);
    uint16_t opt_size   = *(const uint16_t*)(image + pe_off + 4 + 16);
    uint32_t sec_base   = pe_off + 4 + 20 + opt_size;
    for (uint16_t s = 0; s < num_sec; s++) {
        const uint8_t* sh   = image + sec_base + (uint32_t)s * 40;
        uint32_t virt_addr  = *(const uint32_t*)(sh + 12);
        uint32_t virt_size  = *(const uint32_t*)(sh + 16);
        uint32_t raw_off    = *(const uint32_t*)(sh + 20);
        uint32_t raw_size   = *(const uint32_t*)(sh + 24);
        uint32_t effective  = virt_size ? virt_size : raw_size;
        if (rva >= virt_addr && rva < virt_addr + effective) {
            uint32_t off = raw_off + (rva - virt_addr);
            if (off < (uint32_t)image_size) return image + off;
        }
    }
    return NULL;
}

/*
 * Same but for a VA-mapped in-memory PE (like the main executable) where
 * sections are already at VirtualAddress offsets from image base.
 */
static const uint8_t* pe_va_rva_to_ptr(const uint8_t* image, size_t image_size, uint32_t rva)
{
    if (!image || rva == 0 || rva >= (uint32_t)image_size) return NULL;
    return image + rva;
}

/*
 * Check whether a PE image has an RT_MESSAGETABLE (type id=11) resource entry.
 */
static int pe_has_message_table(const uint8_t* image, size_t image_size)
{
    if (!image || image_size < 0x40) return 0;
    uint32_t pe_off = *(const uint32_t*)(image + 0x3C);
    if (pe_off + 28 > (uint32_t)image_size) return 0;
    uint16_t opt_magic = *(const uint16_t*)(image + pe_off + 24);
    uint32_t dd2_off = pe_off + 24 + ((opt_magic == 0x20b) ? 128u : 112u);
    if (dd2_off + 4 > (uint32_t)image_size) return 0;
    uint32_t rsrc_rva = *(const uint32_t*)(image + dd2_off);
    if (!rsrc_rva) return 0;
    const uint8_t* rsrc = pe_raw_rva_to_ptr(image, image_size, rsrc_rva);
    if (!rsrc) return 0;
    uint16_t n_named = *(const uint16_t*)(rsrc + 12);
    uint16_t n_id    = *(const uint16_t*)(rsrc + 14);
    for (int i = 0; i < n_named + n_id; i++) {
        uint32_t name_id = *(const uint32_t*)(rsrc + 16 + (uint32_t)i * 8);
        if (!(name_id & 0x80000000u) && (name_id & 0x7FFFFFFFu) == 11u) return 1;
    }
    return 0;
}

/*
 * Find a message by ID in a PE message-table resource.
 * Returns 1 (Unicode) or 2 (ANSI) on success; sets *out_str and *out_len.
 * For Unicode: *out_str points to UTF-16LE chars (not null included in len).
 * For ANSI:    *out_str points to char bytes  (cast caller side).
 * mapped_va: 0 = flat file (raw offsets), 1 = in-memory PE (VAs are live).
 */
static int pe_find_message_ex(const uint8_t* image, size_t image_size, uint32_t msg_id,
                               const uint16_t** out_str, uint32_t* out_len, int mapped_va)
{
    if (!image || !out_str || !out_len) return 0;

#define RVAPTR(rva) (mapped_va ? pe_va_rva_to_ptr(image, image_size, (rva)) \
                               : pe_raw_rva_to_ptr(image, image_size, (rva)))

    uint32_t pe_off = *(const uint32_t*)(image + 0x3C);
    if (pe_off + 24 + 4 > (uint32_t)image_size) return 0;

    /* DataDirectory[2] (resource) */
    uint16_t opt_magic = *(const uint16_t*)(image + pe_off + 24);
    uint32_t dd2_off = pe_off + 24 + ((opt_magic == 0x20b) ? 128u : 112u);
    uint32_t rsrc_rva = *(const uint32_t*)(image + dd2_off);
    if (!rsrc_rva) return 0;

    const uint8_t* rsrc = RVAPTR(rsrc_rva);
    if (!rsrc) return 0;

    /* Level 1: find RT_MESSAGETABLE (id = 11) */
    uint16_t n_named = *(const uint16_t*)(rsrc + 12);
    uint16_t n_id    = *(const uint16_t*)(rsrc + 14);
    const uint8_t* type_dir = NULL;
    for (int i = 0; i < n_named + n_id; i++) {
        uint32_t name_id = *(const uint32_t*)(rsrc + 16 + (uint32_t)i * 8);
        uint32_t sub_off = *(const uint32_t*)(rsrc + 16 + (uint32_t)i * 8 + 4);
        if (!(name_id & 0x80000000u) && (name_id & 0x7FFFFFFFu) == 11u) {
            if (sub_off & 0x80000000u) type_dir = rsrc + (sub_off & 0x7FFFFFFFu);
            break;
        }
    }
    if (!type_dir) return 0;

    /* Level 2: first name entry (id 1) */
    uint16_t n2 = *(const uint16_t*)(type_dir + 12) + *(const uint16_t*)(type_dir + 14);
    if (n2 == 0) return 0;
    uint32_t sub2 = *(const uint32_t*)(type_dir + 16 + 4);
    const uint8_t* name_dir = (sub2 & 0x80000000u) ? rsrc + (sub2 & 0x7FFFFFFFu) : NULL;
    if (!name_dir) return 0;

    /* Level 3: first language entry → data entry */
    uint16_t n3 = *(const uint16_t*)(name_dir + 14);
    if (n3 == 0) return 0;
    uint32_t data_off = *(const uint32_t*)(name_dir + 16 + 4); /* should NOT have high bit set */
    const uint8_t* de  = rsrc + data_off; /* IMAGE_RESOURCE_DATA_ENTRY */
    uint32_t data_rva  = *(const uint32_t*)(de);

    const uint8_t* msg_data = RVAPTR(data_rva);
    if (!msg_data) return 0;

#undef RVAPTR

    /* Walk MESSAGE_RESOURCE_DATA */
    uint32_t num_blocks = *(const uint32_t*)(msg_data);
    for (uint32_t b = 0; b < num_blocks; b++) {
        uint32_t lo  = *(const uint32_t*)(msg_data + 4 + b * 12);
        uint32_t hi  = *(const uint32_t*)(msg_data + 4 + b * 12 + 4);
        uint32_t off = *(const uint32_t*)(msg_data + 4 + b * 12 + 8);
        if (msg_id < lo || msg_id > hi) continue;

        const uint8_t* entry = msg_data + off;
        for (uint32_t id = lo; id < msg_id; id++) {
            uint16_t entry_len = *(const uint16_t*)(entry);
            if (entry_len < 4) return 0; /* corrupt */
            entry += entry_len;
        }
        uint16_t entry_len   = *(const uint16_t*)(entry);
        uint16_t entry_flags = *(const uint16_t*)(entry + 2);
        const uint8_t* text  = entry + 4;
        uint32_t text_bytes  = entry_len > 4 ? (uint32_t)(entry_len - 4) : 0;

        if (entry_flags & 1) { /* Unicode */
            const uint16_t* wstr = (const uint16_t*)text;
            uint32_t wlen = text_bytes / 2;
            /* trim only trailing null characters — preserve \r\n which is part of the message */
            while (wlen > 0 && wstr[wlen-1] == 0)
                wlen--;
            *out_str = wstr;
            *out_len = wlen;
            return 1;
        } else { /* ANSI */
            uint32_t alen = text_bytes;
            while (alen > 0 && text[alen-1] == 0)
                alen--;
            *out_str = (const uint16_t*)text;
            *out_len = alen;
            return 2;
        }
    }
    return 0;
}

/* Compatibility wrapper: flat-file (raw offsets) version */
static int pe_find_message(const uint8_t* image, size_t image_size, uint32_t msg_id,
                            const uint16_t** out_str, uint32_t* out_len)
{
    return pe_find_message_ex(image, image_size, msg_id, out_str, out_len, 0);
}

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

    /* If name has no .dll extension, append it (e.g. "NETMSG" → "NETMSG.dll") */
    char base_buf[256];
    const char* ext = strrchr(base, '.');
    if (!ext || strcasecmp(ext, ".dll") != 0) {
        snprintf(base_buf, sizeof(base_buf), "%s.dll", base);
        base = base_buf;
        ext  = ".dll";
    }

    /* System DLLs provided by LSW itself */
    if (is_system_dll(base)) {
        LSW_LOG_INFO("LoadLibraryA: system DLL %s -> fake handle", base);
        return LSW_SYSTEM_HMODULE;
    }
    
    /* It's now always a .dll name (extension was added above if missing) */
    if (ext && strcasecmp(ext, ".dll") == 0) {
        /* Search for the file on disk using the chain loader search paths */
        static const char* search_dirs[] = {
            NULL, /* filled from LSW_SYSTEM32 */
            "/mnt/c/Windows/System32",   /* WSL path to Windows system32 */
            "/mnt/c/windows/system32",
            "~/.lsw/system32",
            "~/.wine/drive_c/windows/system32",
            "/opt/lsw/system32",
            "/usr/share/lsw/system32",
            NULL
        };
        const char* env_s32 = getenv("LSW_SYSTEM32");
        search_dirs[0] = env_s32; /* may be NULL — loop skips NULLs */

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

            int ndirs = (int)(sizeof(search_dirs)/sizeof(search_dirs[0]));
            for (int di = 0; di < ndirs && !found[0]; di++) {
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
                                   /* Locate .rsrc section for FormatMessageW FROM_HMODULE */
                                   mod->rsrc_raw = NULL; mod->rsrc_rva = 0;
                                   uint16_t opt_size2  = *(uint16_t*)(b + pe_off2 + 4 + 16);
                                   uint16_t num_sec2   = *(uint16_t*)(b + pe_off2 + 4 + 2);
                                   uint32_t sec_off2   = pe_off2 + 4 + 20 + opt_size2;
                                   for (uint16_t si = 0; si < num_sec2; si++) {
                                       uint8_t* sh = b + sec_off2 + (uint32_t)si * 40;
                                       if (memcmp(sh, ".rsrc\0\0\0", 8) == 0) {
                                           mod->rsrc_rva = *(uint32_t*)(sh + 12);
                                           mod->rsrc_raw = b + *(uint32_t*)(sh + 20);
                                           break;
                                       }
                                   }
                                   LSW_LOG_INFO("LoadLibraryA: PE DLL loaded -> slot %d, base %p, rsrc=%p",
                                                slot, image, mod->rsrc_raw);
                                   /* MUI satellite: if no RT_MESSAGETABLE in main DLL,
                                    * look for en-US/<name>.dll.mui in the same directory */
                                   mod->mui_image = NULL;
                                   mod->mui_image_size = 0;
                                   if (!pe_has_message_table((const uint8_t*)image, (size_t)st.st_size)) {
                                        char dir_part[512]; strncpy(dir_part, found, sizeof(dir_part)-1);
                                        char* sl = strrchr(dir_part, '/');
                                        if (sl) *sl = '\0'; else dir_part[0] = '\0';
                                        char lower_base2[128]; strncpy(lower_base2, base, sizeof(lower_base2)-1);
                                        lower_base2[sizeof(lower_base2)-1] = '\0';
                                        for (char* p = lower_base2; *p; p++) *p = (char)tolower((unsigned char)*p);
                                        char mui_path[600];
                                        snprintf(mui_path, sizeof(mui_path), "%s/en-US/%s.mui", dir_part, lower_base2);
                                        if (access(mui_path, R_OK) != 0)
                                            snprintf(mui_path, sizeof(mui_path), "%s/en-US/%s.mui", dir_part, base);
                                        if (access(mui_path, R_OK) == 0) {
                                           int mfd = open(mui_path, O_RDONLY);
                                           if (mfd >= 0) {
                                               struct stat mst; fstat(mfd, &mst);
                                               void* mdata = mmap(NULL, (size_t)mst.st_size, PROT_READ, MAP_PRIVATE, mfd, 0);
                                               close(mfd);
                                               if (mdata != MAP_FAILED) {
                                                   uint8_t* m8 = (uint8_t*)mdata;
                                                   if (m8[0] == 'M' && m8[1] == 'Z') {
                                                       mod->mui_image = mdata;
                                                       mod->mui_image_size = (size_t)mst.st_size;
                                                       LSW_LOG_INFO("LoadLibraryA: MUI satellite loaded from %s (%zu bytes)",
                                                                    mui_path, mod->mui_image_size);
                                                   } else {
                                                       munmap(mdata, (size_t)mst.st_size);
                                                   }
                                               }
                                           }
                                       }
                                   }
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

    /* System fake handle — resolve from our Win32 stubs (check BEFORE typed handle) */
    if (module == LSW_SYSTEM_HMODULE) {
        void* addr = win32_api_resolve_any(proc_name);
        if (addr) { LSW_LOG_INFO("GetProcAddress: system stub %s -> %p", proc_name, addr); return addr; }
        LSW_LOG_WARN("GetProcAddress: system stub %s not found", proc_name);
        return NULL;
    }

    /* PE module handle? */
    lsw_pe_hmodule_t* pem = (lsw_pe_hmodule_t*)module;
    if (IS_TYPED_HANDLE(pem) && pem->magic == LSW_PE_HMODULE_MAGIC) {
        /* First check our Win32 stub tables (highest priority) */
        void* addr = win32_api_resolve(pem->dll_name, proc_name);
        if (!addr) addr = pe_hmodule_get_proc(pem, proc_name);
        if (addr) { LSW_LOG_INFO("GetProcAddress: PE %s!%s -> %p", pem->dll_name, proc_name, addr); }
        else { LSW_LOG_WARN("GetProcAddress: PE %s!%s not found", pem->dll_name, proc_name); }
        return addr;
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
#define WSAHOST_NOT_FOUND       11001

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
        uint32_t s_addr;   /* must be exactly 4 bytes — use uint32_t not unsigned long */
    } sin_addr;
    char sin_zero[8];
} __attribute__((packed));

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

/* Windows hostent struct layout */
typedef struct {
    char*  h_name;
    char** h_aliases;
    short  h_addrtype;
    short  h_length;
    char** h_addr_list;
} lsw_hostent_t;

// ws2_32.dll!gethostbyname — synchronous DNS lookup
lsw_hostent_t* __attribute__((ms_abi)) lsw_gethostbyname(const char* name) {
    if (!name) { g_last_wsa_error = WSAEFAULT; return NULL; }
    struct hostent* h = gethostbyname(name);
    if (!h) { g_last_wsa_error = WSAHOST_NOT_FOUND; return NULL; }
    /* Return POSIX hostent — layout is identical to Windows hostent */
    return (lsw_hostent_t*)h;
}

// ws2_32.dll!gethostbyaddr
lsw_hostent_t* __attribute__((ms_abi)) lsw_gethostbyaddr(const char* addr, int len, int type) {
    struct hostent* h = gethostbyaddr(addr, len, type);
    if (!h) { g_last_wsa_error = WSAHOST_NOT_FOUND; return NULL; }
    return (lsw_hostent_t*)h;
}

/* ---- GetAddrInfoW / FreeAddrInfoW / GetNameInfoW ---- */

/* Windows ADDRINFOW layout (x64, 48 bytes) */
typedef struct lsw_addrinfow {
    int                    ai_flags;
    int                    ai_family;
    int                    ai_socktype;
    int                    ai_protocol;
    uint64_t               ai_addrlen;   /* size_t = 8 bytes on x64 */
    uint16_t*              ai_canonname;
    struct sockaddr*       ai_addr;
    struct lsw_addrinfow*  ai_next;
} lsw_addrinfow_t;

static uint16_t* lsw_utf8_to_u16_alloc(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    uint16_t* w = malloc(n * sizeof(uint16_t));
    if (!w) return NULL;
    for (size_t i = 0; i < n; i++) w[i] = (uint16_t)(unsigned char)s[i];
    return w;
}

static void lsw_u16_to_utf8(const uint16_t* src, char* dst, size_t maxbytes) {
    size_t n = 0;
    for (; *src && n < maxbytes - 4; src++) {
        uint32_t c = *src;
        if (c < 0x80)       { dst[n++] = (char)c; }
        else if (c < 0x800) { dst[n++] = (char)(0xC0|(c>>6)); dst[n++] = (char)(0x80|(c&0x3F)); }
        else                { dst[n++] = (char)(0xE0|(c>>12)); dst[n++] = (char)(0x80|((c>>6)&0x3F)); dst[n++] = (char)(0x80|(c&0x3F)); }
    }
    dst[n] = '\0';
}

int __attribute__((ms_abi)) lsw_GetAddrInfoW(const uint16_t* pNodeName, const uint16_t* pServiceName,
                                               const lsw_addrinfow_t* pHints, lsw_addrinfow_t** ppResult) {
    if (!ppResult) { g_last_wsa_error = WSAEFAULT; return WSAEFAULT; }
    *ppResult = NULL;

    char node[256] = {0}, service[64] = {0};
    if (pNodeName) lsw_u16_to_utf8(pNodeName, node, sizeof(node));
    if (pServiceName) lsw_u16_to_utf8(pServiceName, service, sizeof(service));

    struct addrinfo hints = {0};
    if (pHints) {
        hints.ai_flags    = pHints->ai_flags;
        hints.ai_family   = pHints->ai_family;
        hints.ai_socktype = pHints->ai_socktype;
        hints.ai_protocol = pHints->ai_protocol;
    }

    LSW_LOG_INFO("GetAddrInfoW: node='%s' service='%s'", node, service);

    struct addrinfo* res = NULL;
    int err = getaddrinfo(pNodeName ? node : NULL, pServiceName ? service : NULL, &hints, &res);
    if (err != 0) {
        LSW_LOG_WARN("GetAddrInfoW: getaddrinfo failed: %s", gai_strerror(err));
        g_last_wsa_error = WSAHOST_NOT_FOUND;
        return WSAHOST_NOT_FOUND;
    }

    lsw_addrinfow_t** tail = ppResult;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        lsw_addrinfow_t* w = calloc(1, sizeof(*w));
        if (!w) { freeaddrinfo(res); return ENOBUFS; }
        w->ai_flags    = ai->ai_flags;
        w->ai_family   = ai->ai_family;
        w->ai_socktype = ai->ai_socktype;
        w->ai_protocol = ai->ai_protocol;
        w->ai_addrlen  = ai->ai_addrlen;
        if (ai->ai_canonname) w->ai_canonname = lsw_utf8_to_u16_alloc(ai->ai_canonname);
        if (ai->ai_addrlen > 0 && ai->ai_addr) {
            w->ai_addr = malloc(ai->ai_addrlen);
            if (w->ai_addr) memcpy(w->ai_addr, ai->ai_addr, ai->ai_addrlen);
        }
        *tail = w;
        tail = &w->ai_next;
    }
    freeaddrinfo(res);
    return 0;
}

void __attribute__((ms_abi)) lsw_FreeAddrInfoW(lsw_addrinfow_t* pAddrInfo) {
    while (pAddrInfo) {
        lsw_addrinfow_t* next = pAddrInfo->ai_next;
        if (pAddrInfo->ai_canonname) free(pAddrInfo->ai_canonname);
        if (pAddrInfo->ai_addr) free(pAddrInfo->ai_addr);
        free(pAddrInfo);
        pAddrInfo = next;
    }
}

int __attribute__((ms_abi)) lsw_GetNameInfoW(const struct sockaddr* pSockaddr, int SockaddrLength,
                                               uint16_t* pNodeBuffer, uint32_t NodeBufferSize,
                                               uint16_t* pServiceBuffer, uint32_t ServiceBufferSize, int Flags) {
    char node[256] = {0}, service[64] = {0};
    int err = getnameinfo(pSockaddr, (socklen_t)SockaddrLength,
                          node, sizeof(node), service, sizeof(service), Flags);
    if (err != 0) { g_last_wsa_error = WSAHOST_NOT_FOUND; return WSAHOST_NOT_FOUND; }
    if (pNodeBuffer && NodeBufferSize > 0) {
        uint32_t i;
        for (i = 0; i < NodeBufferSize - 1 && node[i]; i++) pNodeBuffer[i] = (uint16_t)(unsigned char)node[i];
        pNodeBuffer[i] = 0;
    }
    if (pServiceBuffer && ServiceBufferSize > 0) {
        uint32_t i;
        for (i = 0; i < ServiceBufferSize - 1 && service[i]; i++) pServiceBuffer[i] = (uint16_t)(unsigned char)service[i];
        pServiceBuffer[i] = 0;
    }
    return 0;
}

/* ---- ICMP helpers ---- */
#include <netinet/ip_icmp.h>
#include <sys/select.h>

static uint16_t lsw_icmp_checksum(const void* data, int len) {
    const uint16_t* p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Windows ICMP_ECHO_REPLY layout (x64):
 * +0  uint32 Address
 * +4  uint32 Status
 * +8  uint32 RoundTripTime
 * +12 uint16 DataSize
 * +14 uint16 Reserved
 * +16 void*  Data         (8 bytes)
 * +24 uint8  Ttl
 * +25 uint8  Tos
 * +26 uint8  Flags
 * +27 uint8  OptionsSize
 * +28 (4 bytes pad)
 * +32 void*  OptionsData  (8 bytes)
 * = 40 bytes total */

uint32_t __attribute__((ms_abi)) lsw_IcmpSendEcho(
    void* IcmpHandle, uint32_t DestinationAddress,
    void* RequestData, uint16_t RequestSize,
    void* RequestOptions, void* ReplyBuffer, uint32_t ReplySize, uint32_t Timeout)
{
    (void)IcmpHandle; (void)RequestOptions;

    LSW_LOG_INFO("IcmpSendEcho: dest=%u.%u.%u.%u size=%u timeout=%u",
        (DestinationAddress & 0xFF), ((DestinationAddress >> 8) & 0xFF),
        ((DestinationAddress >> 16) & 0xFF), ((DestinationAddress >> 24) & 0xFF),
        RequestSize, Timeout);

    if (!ReplyBuffer || ReplySize < 28) { g_last_wsa_error = 87; return 0; }

    /* Use SOCK_DGRAM + IPPROTO_ICMP (unprivileged ICMP on Linux) */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        /* Fall back to SOCK_RAW if DGRAM fails */
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            LSW_LOG_WARN("IcmpSendEcho: cannot create ICMP socket: %s", strerror(errno));
            g_last_wsa_error = 5; /* ERROR_ACCESS_DENIED */
            return 0;
        }
    }

    /* Set timeout */
    struct timeval tv = { (long)(Timeout / 1000), (long)((Timeout % 1000) * 1000) };
    if (tv.tv_sec == 0 && tv.tv_usec == 0) { tv.tv_sec = 4; }
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Build ICMP echo request */
    uint16_t payload = RequestSize > 0 ? RequestSize : 32;
    uint8_t* packet = calloc(8 + payload, 1);
    if (!packet) { close(sock); g_last_wsa_error = 8; return 0; }

    uint16_t ident = (uint16_t)getpid();
    uint16_t seq   = 1;
    packet[0] = 8;  /* ICMP_ECHO = 8 */
    packet[1] = 0;  /* code */
    packet[2] = 0;  packet[3] = 0;  /* checksum placeholder */
    packet[4] = (uint8_t)(ident >> 8);   packet[5] = (uint8_t)ident;
    packet[6] = (uint8_t)(seq >> 8);     packet[7] = (uint8_t)seq;
    if (RequestData && RequestSize > 0) memcpy(packet + 8, RequestData, payload);
    else memset(packet + 8, 'A', payload);

    uint16_t csum = lsw_icmp_checksum(packet, 8 + payload);
    packet[2] = (uint8_t)(csum >> 8);
    packet[3] = (uint8_t)csum;

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = DestinationAddress; /* already in network byte order for IPv4 */

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ssize_t sent = sendto(sock, packet, 8 + payload, 0, (struct sockaddr*)&dest, sizeof(dest));
    free(packet);
    if (sent < 0) {
        LSW_LOG_WARN("IcmpSendEcho: sendto failed: %s", strerror(errno));
        close(sock);
        g_last_wsa_error = 5;
        return 0;
    }

    /* Receive reply (may have IP header if SOCK_RAW) */
    uint8_t recv_buf[256];
    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);
    ssize_t rlen = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&src, &srclen);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(sock);

    if (rlen < 0) {
        LSW_LOG_WARN("IcmpSendEcho: recvfrom failed: %s", strerror(errno));
        g_last_wsa_error = 11010; /* WSAETIMEDOUT */
        return 0;
    }

    uint64_t rtt_us = ((uint64_t)(t1.tv_sec - t0.tv_sec)) * 1000000 +
                      ((uint64_t)(t1.tv_nsec - t0.tv_nsec)) / 1000;
    uint32_t rtt_ms = (uint32_t)(rtt_us / 1000);

    /* Parse reply — skip IP header if present (SOCK_RAW includes 20-byte IP header) */
    uint8_t* icmp_reply = recv_buf;
    ssize_t icmp_len = rlen;
    if (rlen >= 20 && (recv_buf[0] >> 4) == 4) {
        int ihl = (recv_buf[0] & 0xF) * 4;
        if (ihl < rlen) { icmp_reply = recv_buf + ihl; icmp_len = rlen - ihl; }
    }

    /* Fill ICMP_ECHO_REPLY at ReplyBuffer (Windows x64 layout) */
    uint8_t* rb = (uint8_t*)ReplyBuffer;
    memset(rb, 0, ReplySize < 40 ? ReplySize : 40);
    *(uint32_t*)(rb + 0)  = src.sin_addr.s_addr;  /* Address */
    *(uint32_t*)(rb + 4)  = 0;                     /* Status = IP_SUCCESS */
    *(uint32_t*)(rb + 8)  = rtt_ms;                /* RoundTripTime */
    *(uint16_t*)(rb + 12) = (uint16_t)(icmp_len > 8 ? icmp_len - 8 : 0); /* DataSize */
    *(uint16_t*)(rb + 14) = 0;                     /* Reserved */
    *(void**)(rb + 16)    = rb + 40;               /* Data pointer (after struct) */
    rb[24] = 64;  /* Ttl */
    rb[25] = 0;   /* Tos */
    rb[26] = 0;   /* Flags */
    rb[27] = 0;   /* OptionsSize */

    /* Copy echo reply payload into reply buffer after struct */
    if (icmp_len > 8 && ReplySize >= 40 + (uint32_t)(icmp_len - 8)) {
        memcpy(rb + 40, icmp_reply + 8, icmp_len - 8);
    }

    LSW_LOG_INFO("IcmpSendEcho: reply from %s rtt=%ums", inet_ntoa(src.sin_addr), rtt_ms);
    return 1; /* 1 reply received */
}

/* IcmpSendEcho2Ex — extended version with source address selection */
uint32_t __attribute__((ms_abi)) lsw_IcmpSendEcho2Ex(
    void* IcmpHandle, void* hEvent, void* ApcRoutine, void* ApcContext,
    uint32_t SourceAddress, uint32_t DestinationAddress,
    void* RequestData, uint16_t RequestSize,
    void* RequestOptions, void* ReplyBuffer, uint32_t ReplySize, uint32_t Timeout)
{
    (void)hEvent; (void)ApcRoutine; (void)ApcContext; (void)SourceAddress;
    /* Delegate to synchronous version */
    return lsw_IcmpSendEcho(IcmpHandle, DestinationAddress, RequestData, RequestSize,
                            RequestOptions, ReplyBuffer, ReplySize, Timeout);
}

/* IPv6 ICMP stubs (no real implementation for now) */
void* __attribute__((ms_abi)) lsw_Icmp6CreateFile(void) { return (void*)0xB002; }
uint32_t __attribute__((ms_abi)) lsw_Icmp6SendEcho2(
    void* h, void* ev, void* apc, void* ctx,
    const struct sockaddr* src, const struct sockaddr* dst,
    void* req_data, uint16_t req_size, void* req_opts,
    void* reply_buf, uint32_t reply_size, uint32_t timeout)
{
    (void)h;(void)ev;(void)apc;(void)ctx;(void)src;(void)dst;
    (void)req_data;(void)req_size;(void)req_opts;(void)reply_buf;(void)reply_size;(void)timeout;
    g_last_wsa_error = 50; /* ERROR_NOT_SUPPORTED */
    return 0;
}

uint32_t __attribute__((ms_abi)) lsw_GetIpErrorString(uint32_t ErrorCode, uint16_t* pBuffer, uint32_t* pSize) {
    const char* msg = "IP error";
    if (ErrorCode == 11010) msg = "Request timed out.";
    else if (ErrorCode == 0) msg = "Success.";
    if (pBuffer && pSize && *pSize > 0) {
        uint32_t i;
        for (i = 0; i < *pSize - 1 && msg[i]; i++) pBuffer[i] = (uint16_t)(unsigned char)msg[i];
        pBuffer[i] = 0;
        *pSize = i;
    }
    return 0;
}

// ============================================================================
// SECTION: OLEAUT32 BSTR APIs
// BSTR layout: [uint32_t byte_len][wchar_t data...][wchar_t NUL]
// The BSTR pointer points to the data, NOT the length prefix.
// ============================================================================

static inline void* __attribute__((ms_abi)) lsw_SysAllocString(const wchar_t* str) {
    if (!str) return NULL;
    uint32_t len = 0;
    while (str[len]) len++;
    uint32_t byte_len = len * sizeof(wchar_t);
    uint8_t* buf = malloc(4 + (len + 1) * sizeof(wchar_t));
    if (!buf) return NULL;
    *(uint32_t*)buf = byte_len;
    wchar_t* data = (wchar_t*)(buf + 4);
    for (uint32_t i = 0; i < len; i++) data[i] = str[i];
    data[len] = 0;
    return data;
}

static inline void __attribute__((ms_abi)) lsw_SysFreeString(void* bstr) {
    if (!bstr) return;
    free((uint8_t*)bstr - 4);
}

static inline uint32_t __attribute__((ms_abi)) lsw_SysStringLen(void* bstr) {
    if (!bstr) return 0;
    uint32_t byte_len = *(uint32_t*)((uint8_t*)bstr - 4);
    return byte_len / sizeof(wchar_t);
}

static inline uint32_t __attribute__((ms_abi)) lsw_SysStringByteLen(void* bstr) {
    if (!bstr) return 0;
    return *(uint32_t*)((uint8_t*)bstr - 4);
}

static inline void* __attribute__((ms_abi)) lsw_SysAllocStringLen(const wchar_t* str, uint32_t len) {
    uint32_t byte_len = len * sizeof(wchar_t);
    uint8_t* buf = malloc(4 + (len + 1) * sizeof(wchar_t));
    if (!buf) return NULL;
    *(uint32_t*)buf = byte_len;
    wchar_t* data = (wchar_t*)(buf + 4);
    if (str) { for (uint32_t i = 0; i < len; i++) data[i] = str[i]; }
    else       memset(data, 0, len * sizeof(wchar_t));
    data[len] = 0;
    return data;
}

static inline void* __attribute__((ms_abi)) lsw_SysAllocStringByteLen(const char* str, uint32_t byte_len) {
    uint8_t* buf = malloc(4 + byte_len + 2);
    if (!buf) return NULL;
    *(uint32_t*)buf = byte_len;
    uint8_t* data = buf + 4;
    if (str) memcpy(data, str, byte_len);
    else      memset(data, 0, byte_len);
    data[byte_len] = 0; data[byte_len+1] = 0;
    return data;
}

static inline int __attribute__((ms_abi)) lsw_SysReAllocString(void** pbstr, const wchar_t* str) {
    if (!pbstr) return 0;
    void* old = *pbstr;
    void* nw = lsw_SysAllocString(str);
    if (!nw && str) return 0;
    lsw_SysFreeString(old);
    *pbstr = nw;
    return 1;
}

static inline int __attribute__((ms_abi)) lsw_SysReAllocStringLen(void** pbstr, const wchar_t* str, uint32_t len) {
    if (!pbstr) return 0;
    void* old = *pbstr;
    void* nw = lsw_SysAllocStringLen(str, len);
    if (!nw) return 0;
    lsw_SysFreeString(old);
    *pbstr = nw;
    return 1;
}

// ============================================================================
// END OLEAUT32 BSTR APIs
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

// KERNEL32.dll!GetVersion
uint32_t __attribute__((ms_abi)) lsw_GetVersion(void) {
    /* Returns: low byte = major, next byte = minor, high word = build */
    LSW_LOG_INFO("GetVersion called");
    return (uint32_t)((19041u << 16) | (0u << 8) | 10u);  /* Windows 10.0 Build 19041 */
}

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
/* Process-global persistent hostname storage — outlives NetApiBufferFree.
 * Net1.exe stores the result of GetComputerNameW in a stack buffer, then stores
 * that pointer in its args[] array. By the time FormatMessageW is called, the
 * stack frame is gone and the pointer points to zeroed/overwritten stack memory.
 * We fix this by keeping a persistent copy and substituting it in FormatMessageW
 * when an args entry is non-null but points to an empty wide string. */
static uint16_t* g_computername_w = NULL;
static char      g_computername_a[256] = "";
static void lsw_ensure_computername(void) {
    if (g_computername_w) return;
    char hostname[64] = "LSW";
    gethostname(hostname, sizeof(hostname) - 1);
    int hlen = (int)strlen(hostname);
    g_computername_w = (uint16_t*)malloc((size_t)(hlen + 1) * 2);
    if (!g_computername_w) return;
    for (int i = 0; i < hlen; i++) g_computername_w[i] = (uint16_t)(unsigned char)hostname[i];
    g_computername_w[hlen] = 0;
    strncpy(g_computername_a, hostname, 255);
    g_computername_a[255] = '\0';
}

/* Perform FormatMessage %N and %N!fmt! argument substitution into a UTF-16LE buffer.
 * FORMAT_MESSAGE_ARGUMENT_ARRAY (0x2000): args is uint64_t* array (indexed 0-based for arg 1..99).
 * Returns number of UTF-16 chars written (not counting null terminator). */
static uint32_t fm_substitute(const uint16_t* tmpl, uint32_t tlen,
                               uint16_t* out, uint32_t outsize,
                               uint32_t flags, void* args)
{
    if (!out || outsize == 0) return 0;
    uint32_t oi = 0;
    for (uint32_t i = 0; i < tlen && oi < outsize - 1; ) {
        uint16_t c = tmpl[i++];
        if (c != '%') { out[oi++] = c; continue; }
        if (i >= tlen) { out[oi++] = '%'; break; }
        c = tmpl[i++];
        switch (c) {
            case '%': out[oi++] = '%'; break;
            case 'n': out[oi++] = '\n'; break;
            case 'r': out[oi++] = '\r'; break;
            case 'b': out[oi++] = ' ';  break;
            case 't': out[oi++] = '\t'; break;
            case '0': goto fm_done;
            case '.': out[oi++] = '.'; break;
            case '!': out[oi++] = '!'; break;
            default:
                if (c >= '1' && c <= '9') {
                    int argidx = c - '0';
                    if (i < tlen && tmpl[i] >= '0' && tmpl[i] <= '9')
                        argidx = argidx * 10 + (tmpl[i++] - '0');
                    /* Parse optional !format! spec */
                    char fmt[80] = "ls";
                    int has_fmt = 0;
                    if (i < tlen && tmpl[i] == '!') {
                        i++; has_fmt = 1;
                        int fi = 0;
                        while (i < tlen && tmpl[i] != '!' && fi < 78) fmt[fi++] = (char)tmpl[i++];
                        fmt[fi] = '\0';
                        if (i < tlen) i++; /* skip closing ! */
                    }
                    (void)has_fmt;
                    /* Get arg value (treat as pointer) */
                    uint64_t argval = 0;
                    if (args) {
                        if (flags & 0x2000) { /* FORMAT_MESSAGE_ARGUMENT_ARRAY */
                            argval = ((uint64_t*)args)[argidx - 1];
                        } else {
                            /* va_list*: on MSVC x64, va_list is char* pointing to first arg.
                             * args = va_list* = char** -> dereference to get the actual arg array */
                            uint64_t* va_arr = *(uint64_t**)args;
                            if (va_arr) argval = va_arr[argidx - 1];
                        }
                    }
                    /* Parse format string: flags, width, precision, length modifier, type */
                    int left = 0, width = 0, prec = -1;
                    const char* fp = fmt;
                    /* Flags */
                    while (*fp == '-' || *fp == '+' || *fp == ' ' || *fp == '#' ||
                           *fp == '0' || *fp == 'F') {
                        if (*fp == '-') left = 1;
                        fp++;
                    }
                    /* Width */
                    while (*fp >= '1' && *fp <= '9') width = width * 10 + (*fp++ - '0');
                    /* Precision */
                    if (*fp == '.') { fp++; prec = 0; while (*fp >= '0' && *fp <= '9') prec = prec * 10 + (*fp++ - '0'); }
                    /* Length modifier (w, l, h, I, L) — skip */
                    while (*fp == 'w' || *fp == 'l' || *fp == 'h' || *fp == 'I' || *fp == 'L') fp++;
                    char type_ch = *fp ? *fp : 's';
                    int is_num = (type_ch=='d'||type_ch=='i'||type_ch=='u'||
                                  type_ch=='x'||type_ch=='X'||type_ch=='o');
                    if (is_num) {
                        /* Numeric arg */
                        char pfmt[90], nbuf[64];
                        snprintf(pfmt, sizeof(pfmt), "%%%s", fmt);
                        int n = snprintf(nbuf, sizeof(nbuf), pfmt, (long long)argval);
                        if (n > 0) for (int k = 0; k < n && oi < outsize-1; k++) out[oi++] = (uint16_t)(unsigned char)nbuf[k];
                    } else {
                        /* String arg — pointer is to UTF-16LE (Windows WCHAR*), not Linux wchar_t */
                        const uint16_t* warg = (const uint16_t*)(uintptr_t)argval;
                        if (!warg) warg = (const uint16_t*)L"";
                        uint32_t slen = 0;
                        while (warg[slen]) slen++;
                        uint32_t trunc = slen;
                        if (prec >= 0 && trunc > (uint32_t)prec) trunc = (uint32_t)prec;
                        /* Right-align padding (spaces before string) */
                        if (width > 0 && !left) {
                            for (int pad = (int)trunc; pad < width && oi < outsize-1; pad++) out[oi++] = ' ';
                        }
                        for (uint32_t k = 0; k < trunc && oi < outsize-1; k++) out[oi++] = (uint16_t)warg[k];
                        /* Left-align padding (spaces after string) */
                        if (width > 0 && left) {
                            for (int pad = (int)trunc; pad < width && oi < outsize-1; pad++) out[oi++] = ' ';
                        }
                    }
                } else {
                    out[oi++] = '%'; out[oi++] = c;
                }
                break;
        }
    }
fm_done:
    out[oi] = 0;
    return oi;
}

uint32_t __attribute__((ms_abi)) lsw_FormatMessageW(
    uint32_t flags, const void* source, uint32_t message_id,
    uint32_t language_id, uint16_t* buffer, uint32_t size, void* args)
{
    (void)language_id;

    /* FORMAT_MESSAGE_FROM_HMODULE (0x800): look up message in PE resource table */
    /* On Windows, NULL source with FROM_HMODULE means "use the calling module's message table" */
    if ((flags & 0x800) && !source && g_main_exe_hmodule_ready) {
        source = &g_main_exe_hmodule;
    }
    if ((flags & 0x800) && source && source != (void*)0xDEADBEEFu) {
        lsw_pe_hmodule_t* pem = (lsw_pe_hmodule_t*)source;
        if (IS_TYPED_HANDLE(pem) && pem->magic == LSW_PE_HMODULE_MAGIC) {
            const uint16_t* wstr = NULL;
            uint32_t wlen = 0;
            /* Try MUI satellite first (Vista+ message-only DLLs) */
            int r = 0;
            if (pem->mui_image) {
                r = pe_find_message_ex((const uint8_t*)pem->mui_image, pem->mui_image_size,
                                       message_id, &wstr, &wlen, 0 /* MUI is flat file */);
            }
            if (!r) {
                r = pe_find_message_ex((const uint8_t*)pem->image_base, pem->image_size,
                                       message_id, &wstr, &wlen, pem->mapped_va);
            }
            if (r > 0) {
                /* Build a null-terminated UTF-16 template */
                uint16_t* tmpl = NULL;
                int tmpl_alloc = 0;
                if (r == 1) {
                    tmpl = (uint16_t*)wstr;
                } else {
                    tmpl = (uint16_t*)malloc((wlen + 1) * sizeof(uint16_t));
                    if (!tmpl) { lsw_SetLastError(8); return 0; }
                    tmpl_alloc = 1;
                    const uint8_t* astr = (const uint8_t*)wstr;
                    for (uint32_t i = 0; i < wlen; i++) tmpl[i] = (uint16_t)astr[i];
                    tmpl[wlen] = 0;
                }
                /* Log raw template */
                {
                    char dbg[256]; int di = 0;
                    for (uint32_t k = 0; k < wlen && k < 80 && di < 252; k++) {
                        uint16_t wc = tmpl[k];
                        if (wc >= 32 && wc < 127) dbg[di++] = (char)wc;
                        else { snprintf(dbg+di, 8, "\\x%04x", wc); di += 6; }
                    }
                    dbg[di] = '\0';
                    LSW_LOG_INFO("FormatMessageW: id=0x%x flags=0x%x len=%u tmpl=\"%s\" args=%p",
                                 message_id, flags, wlen, dbg, args);
                }
                /* When args[N] points to an empty string but is non-null (stale stack pointer),
                 * substitute with the persistent hostname — this fixes net1.exe's "User accounts for \\%1"
                 * header where GetComputerNameW writes to a stack buffer that becomes invalid
                 * before FormatMessageW is called. */
                if (args && (flags & 0x2000)) {
                    uint64_t* argarr = (uint64_t*)args;
                    for (int ai = 0; ai < 9; ai++) {
                        uint64_t av = argarr[ai];
                        if (!av) break;
                        const uint16_t* sp = (const uint16_t*)(uintptr_t)av;
                        if (sp[0] == 0) {
                            /* Empty string from stale stack — replace with persistent hostname */
                            lsw_ensure_computername();
                            if (g_computername_w && g_computername_w[0])
                                argarr[ai] = (uint64_t)(uintptr_t)g_computername_w;
                        }
                    }
                }
                /* Apply substitution and copy to output */
                uint32_t outlen;
                if (flags & 0x100) {  /* ALLOCATE_BUFFER */
                    uint16_t** ppBuf = (uint16_t**)buffer;
                    if (!ppBuf) { if (tmpl_alloc) free(tmpl); return 0; }
                    uint32_t alloc_sz = wlen * 4 + 256;
                    uint16_t* wbuf = (uint16_t*)malloc(alloc_sz * sizeof(uint16_t));
                    if (!wbuf) { if (tmpl_alloc) free(tmpl); lsw_SetLastError(8); return 0; }
                    outlen = fm_substitute(tmpl, wlen, wbuf, alloc_sz, flags, args);
                    *ppBuf = wbuf;
                } else {
                    if (!buffer || size == 0) { if (tmpl_alloc) free(tmpl); return 0; }
                    outlen = fm_substitute(tmpl, wlen, buffer, size, flags, args);
                }
                if (tmpl_alloc) free(tmpl);
                return outlen;
            }
        }
    }

    char tmp[512];
    if (flags & 0x1000) {  /* FORMAT_MESSAGE_FROM_SYSTEM */
        /* Map Windows error codes to something readable */
        const char* msg = NULL;
        switch (message_id) {
            case 0:   msg = "The operation completed successfully."; break;
            case 1:   msg = "Incorrect function."; break;
            case 2:   msg = "The system cannot find the file specified."; break;
            case 3:   msg = "The system cannot find the path specified."; break;
            case 4:   msg = "The system cannot open the file."; break;
            case 5:   msg = "Access is denied."; break;
            case 6:   msg = "The handle is invalid."; break;
            case 7:   msg = "The storage control blocks were destroyed."; break;
            case 8:   msg = "Not enough memory resources are available to process this command."; break;
            case 9:   msg = "The storage control block address is invalid."; break;
            case 10:  msg = "The environment is incorrect."; break;
            case 11:  msg = "An attempt was made to load a program with an incorrect format."; break;
            case 12:  msg = "The access code is invalid."; break;
            case 13:  msg = "The data is invalid."; break;
            case 14:  msg = "Not enough storage is available to complete this operation."; break;
            case 15:  msg = "The system cannot find the drive specified."; break;
            case 16:  msg = "The directory cannot be removed."; break;
            case 17:  msg = "The system cannot move the file to a different disk drive."; break;
            case 18:  msg = "There are no more files."; break;
            case 19:  msg = "The media is write protected."; break;
            case 20:  msg = "The system cannot find the device specified."; break;
            case 21:  msg = "The device is not ready."; break;
            case 23:  msg = "Data error (cyclic redundancy check)."; break;
            case 24:  msg = "The program issued a command but the command length is incorrect."; break;
            case 25:  msg = "The drive cannot locate a specific area or track on the disk."; break;
            case 26:  msg = "The specified disk or diskette cannot be accessed."; break;
            case 27:  msg = "The drive cannot find the sector requested."; break;
            case 28:  msg = "The printer is out of paper."; break;
            case 29:  msg = "The system cannot write to the specified device."; break;
            case 30:  msg = "The system cannot read from the specified device."; break;
            case 31:  msg = "A device attached to the system is not functioning."; break;
            case 32:  msg = "The process cannot access the file because it is being used by another process."; break;
            case 33:  msg = "The process cannot access the file because another process has locked a portion of the file."; break;
            case 36:  msg = "Too many files opened for sharing."; break;
            case 38:  msg = "Reached the end of the file."; break;
            case 39:  msg = "The disk is full."; break;
            case 50:  msg = "The request is not supported."; break;
            case 51:  msg = "Windows cannot find the network path."; break;
            case 52:  msg = "You were not connected because a duplicate name exists on the network."; break;
            case 53:  msg = "The network path was not found."; break;
            case 54:  msg = "The network is busy."; break;
            case 55:  msg = "The specified network resource or device is no longer available."; break;
            case 58:  msg = "The specified server cannot perform the requested operation."; break;
            case 59:  msg = "An unexpected network error occurred."; break;
            case 64:  msg = "The specified network name is no longer available."; break;
            case 65:  msg = "Network access is denied."; break;
            case 67:  msg = "The network name cannot be found."; break;
            case 80:  msg = "The file exists."; break;
            case 82:  msg = "The directory or file cannot be created."; break;
            case 83:  msg = "Fail on INT 24."; break;
            case 84:  msg = "Storage to process this request is not available."; break;
            case 85:  msg = "The local device name is already in use."; break;
            case 86:  msg = "The specified network password is not correct."; break;
            case 87:  msg = "The parameter is incorrect."; break;
            case 88:  msg = "A write fault occurred on the network."; break;
            case 89:  msg = "The system cannot start another process at this time."; break;
            case 100: msg = "Cannot create another system semaphore."; break;
            case 101: msg = "The exclusive semaphore is owned by another process."; break;
            case 102: msg = "The semaphore is set and cannot be closed."; break;
            case 103: msg = "The semaphore cannot be set again."; break;
            case 104: msg = "Cannot request exclusive semaphores at interrupt time."; break;
            case 105: msg = "The previous ownership of this semaphore has ended."; break;
            case 106: msg = "Insert the diskette for drive %1."; break;
            case 107: msg = "The program stopped because an alternate diskette was not inserted."; break;
            case 108: msg = "The disk is in use or locked by another process."; break;
            case 109: msg = "The pipe has been ended."; break;
            case 110: msg = "The system cannot open the device or file specified."; break;
            case 111: msg = "The file name is too long."; break;
            case 112: msg = "There is not enough space on the disk."; break;
            case 113: msg = "No more internal file identifiers available."; break;
            case 114: msg = "The target internal file identifier is incorrect."; break;
            case 117: msg = "The IOCTL call made by the application program is not correct."; break;
            case 118: msg = "The verify-on-write switch parameter value is not correct."; break;
            case 119: msg = "The system does not support the command requested."; break;
            case 120: msg = "This function is not supported on this system."; break;
            case 121: msg = "The semaphore timeout period has expired."; break;
            case 122: msg = "The data area passed to a system call is too small."; break;
            case 123: msg = "The filename, directory name, or volume label syntax is incorrect."; break;
            case 124: msg = "The system call level is not correct."; break;
            case 125: msg = "The disk has no volume label."; break;
            case 126: msg = "The specified module could not be found."; break;
            case 127: msg = "The specified procedure could not be found."; break;
            case 128: msg = "There are no child processes to wait for."; break;
            case 129: msg = "The %1 application cannot be run in Win32 mode."; break;
            case 130: msg = "Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O."; break;
            case 131: msg = "An attempt was made to move the file pointer before the beginning of the file."; break;
            case 132: msg = "The file pointer cannot be set on the specified device or file."; break;
            case 133: msg = "A JOIN or SUBST command cannot be used for a drive that contains previously joined drives."; break;
            case 160: msg = "One or more arguments are not correct."; break;
            case 161: msg = "The specified path is invalid."; break;
            case 162: msg = "A signal is already pending."; break;
            case 164: msg = "No more threads can be created in the system."; break;
            case 167: msg = "Unable to lock a region of a file."; break;
            case 170: msg = "The requested resource is in use."; break;
            case 183: msg = "Cannot create a file when that file already exists."; break;
            case 193: msg = "The %1 application is not a valid Win32 application."; break;
            case 197: msg = "The operating system cannot run this application program."; break;
            case 203: msg = "The system could not find the environment option that was entered."; break;
            case 206: msg = "The filename or extension is too long."; break;
            case 214: msg = "Too many dynamic-link modules are attached to this program or dynamic-link module."; break;
            case 234: msg = "More data is available."; break;
            case 258: msg = "The wait operation timed out."; break;
            case 259: msg = "No more data is available."; break;
            case 267: msg = "The directory name is invalid."; break;
            case 298: msg = "Too many posts were made to a semaphore."; break;
            case 299: msg = "Only part of a ReadProcessMemory or WriteProcessMemory request was completed."; break;
            case 317: msg = "The system cannot find message text for message number 0x%1 in the message file for %2."; break;
            case 487: msg = "Attempt to access invalid address."; break;
            case 534: msg = "Arithmetic result exceeded 32 bits."; break;
            case 535: msg = "There is a process on other end of the pipe."; break;
            case 536: msg = "Waiting for a process to open the other end of the pipe."; break;
            case 568: msg = "An attempt was made to create more links on a file than the file system supports."; break;
            case 997: msg = "Overlapped I/O operation is in progress."; break;
            case 998: msg = "Invalid access to memory location."; break;
            case 999: msg = "Error performing inpage operation."; break;
            case 1001: msg = "Recursion too deep; the stack overflowed."; break;
            case 1002: msg = "The window cannot act on the sent message."; break;
            case 1003: msg = "Cannot complete this function."; break;
            case 1004: msg = "Invalid flags."; break;
            case 1005: msg = "The volume does not contain a recognized file system."; break;
            case 1006: msg = "The volume for a file has been externally altered so that the opened file is no longer valid."; break;
            case 1007: msg = "The requested operation cannot be performed in full-screen mode."; break;
            case 1008: msg = "An attempt was made to reference a token that does not exist."; break;
            case 1009: msg = "The configuration registry database is corrupt."; break;
            case 1010: msg = "The configuration registry key is invalid."; break;
            case 1011: msg = "The configuration registry key could not be opened."; break;
            case 1012: msg = "The configuration registry key could not be read."; break;
            case 1013: msg = "The configuration registry key could not be written."; break;
            case 1014: msg = "One of the files in the registry database had to be recovered by use of a log or alternate copy."; break;
            case 1015: msg = "The registry is corrupted."; break;
            case 1016: msg = "An I/O operation initiated by the registry failed unrecoverably."; break;
            case 1017: msg = "The system has attempted to load or restore a file into the registry, but the specified file is not in a registry file format."; break;
            case 1018: msg = "Illegal operation attempted on a registry key that has been marked for deletion."; break;
            case 1019: msg = "System could not allocate the required space in a registry log."; break;
            case 1020: msg = "Cannot create a symbolic link in a registry key that already has subkeys or values."; break;
            case 1021: msg = "Cannot create a stable subkey under a volatile parent key."; break;
            case 1022: msg = "A notify change request is being completed and the information is not being returned in the caller's buffer."; break;
            case 1051: msg = "A stop control has been sent to a service that other running services are dependent on."; break;
            case 1052: msg = "The requested control is not valid for this service."; break;
            case 1053: msg = "The service did not respond to the start or control request in a timely fashion."; break;
            case 1054: msg = "A thread could not be created for the service."; break;
            case 1055: msg = "The service database is locked."; break;
            case 1056: msg = "An instance of the service is already running."; break;
            case 1057: msg = "The account name is invalid or does not exist, or the password is invalid for the account name specified."; break;
            case 1058: msg = "The service cannot be started, either because it is disabled or because it has no enabled devices associated with it."; break;
            case 1059: msg = "Circular service dependency was specified."; break;
            case 1060: msg = "The specified service does not exist as an installed service."; break;
            case 1061: msg = "The service cannot accept control messages at this time."; break;
            case 1062: msg = "The service has not been started."; break;
            case 1063: msg = "The service process could not connect to the service controller."; break;
            case 1064: msg = "An exception occurred in the service when handling the control request."; break;
            case 1065: msg = "The database specified does not exist."; break;
            case 1066: msg = "The service has returned a service-specific error code."; break;
            case 1067: msg = "The process terminated unexpectedly."; break;
            case 1068: msg = "The dependency service or group failed to start."; break;
            case 1069: msg = "The service did not start due to a logon failure."; break;
            case 1070: msg = "After starting, the service hung in a start-pending state."; break;
            case 1071: msg = "The specified service database lock is invalid."; break;
            case 1072: msg = "The specified service has been marked for deletion."; break;
            case 1073: msg = "The specified service already exists."; break;
            case 1074: msg = "The system is currently running with the last-known-good configuration."; break;
            case 1075: msg = "The dependency service does not exist or has been marked for deletion."; break;
            case 1076: msg = "The current boot has already been accepted for use as the last-known-good control set."; break;
            case 1077: msg = "No attempts to start the service have been made since the last boot."; break;
            case 1078: msg = "The name is already in use as either a service name or a service display name."; break;
            case 1079: msg = "The account specified for this service is different from the account specified for other services running in the same process."; break;
            case 1080: msg = "Failure actions can only be set for Win32 services, not for drivers."; break;
            case 1082: msg = "No recovery program has been configured for this service."; break;
            case 1083: msg = "The executable program that this service is configured to run in does not implement the service."; break;
            case 1084: msg = "This service cannot be started from the command prompt."; break;
            case 1085: msg = "The service has not been set up for this computer."; break;
            case 1100: msg = "The physical end of the tape has been reached."; break;
            case 1101: msg = "A tape access reached a filemark."; break;
            case 1102: msg = "The beginning of the tape or a partition was encountered."; break;
            case 1103: msg = "A tape access reached the end of a set of files."; break;
            case 1104: msg = "No more data is on the tape."; break;
            case 1105: msg = "Tape could not be partitioned."; break;
            case 1106: msg = "When accessing a new tape of a multivolume partition, the current block size is incorrect."; break;
            case 1107: msg = "Tape partition information could not be found when loading a tape."; break;
            case 1108: msg = "Unable to lock the media eject mechanism."; break;
            case 1109: msg = "Unable to unload the media."; break;
            case 1110: msg = "The media in the drive may have changed."; break;
            case 1111: msg = "The I/O bus was reset."; break;
            case 1112: msg = "No media in drive."; break;
            case 1113: msg = "No mapping for the Unicode character exists in the target multi-byte code page."; break;
            case 1114: msg = "A dynamic link library (DLL) initialization routine failed."; break;
            case 1115: msg = "A system shutdown is in progress."; break;
            case 1116: msg = "Unable to abort the system shutdown because no shutdown was in progress."; break;
            case 1117: msg = "The request could not be performed because of an I/O device error."; break;
            case 1118: msg = "No serial device was successfully initialized. The serial driver will unload."; break;
            case 1119: msg = "Unable to open a device that was sharing an interrupt request (IRQ) with other devices."; break;
            case 1120: msg = "A serial I/O operation was completed by another write to the serial port."; break;
            case 1121: msg = "A serial I/O operation completed because the timeout period expired."; break;
            case 1122: msg = "No ID address mark was found on the floppy disk."; break;
            case 1123: msg = "Mismatch between the floppy disk sector ID field and the floppy disk controller track address."; break;
            case 1124: msg = "The floppy disk controller reported an error that is not recognized by the floppy disk driver."; break;
            case 1125: msg = "The floppy disk controller returned inconsistent results in its registers."; break;
            case 1126: msg = "While accessing the hard disk, a recalibrate operation failed, even after retries."; break;
            case 1127: msg = "While accessing the hard disk, a disk operation failed even after retries."; break;
            case 1128: msg = "While accessing the hard disk, a disk controller reset was needed, but even that failed."; break;
            case 1129: msg = "Physical end of tape encountered."; break;
            case 1130: msg = "Not enough server storage is available to process this command."; break;
            case 1131: msg = "A potential deadlock condition has been detected."; break;
            case 1132: msg = "The base address or the file offset specified does not have the proper alignment."; break;
            case 1140: msg = "An attempt to change the system power state was vetoed by another application or driver."; break;
            case 1141: msg = "The system BIOS failed an attempt to change the system power state."; break;
            case 1142: msg = "An attempt was made to create more links on a file than the file system supports."; break;
            case 1150: msg = "The specified program requires a newer version of Windows."; break;
            case 1151: msg = "The specified program is not a Windows or MS-DOS program."; break;
            case 1152: msg = "Cannot start more than one instance of the specified program."; break;
            case 1153: msg = "The specified program was written for an earlier version of Windows."; break;
            case 1154: msg = "One of the library files needed to run this application is damaged."; break;
            case 1155: msg = "No application is associated with the specified file for this operation."; break;
            case 1156: msg = "An error occurred in sending the command to the application."; break;
            case 1157: msg = "One of the library files needed to run this application cannot be found."; break;
            case 1158: msg = "The current process has used all of its system allowance of handles for Window Manager objects."; break;
            case 1159: msg = "The message can be used only with synchronous operations."; break;
            case 1160: msg = "The indicated source element has no media."; break;
            case 1161: msg = "The indicated destination element already contains media."; break;
            case 1162: msg = "The indicated element does not exist."; break;
            case 1163: msg = "The indicated element is part of a magazine that is not present."; break;
            case 1164: msg = "The indicated device requires reinitialization due to hardware errors."; break;
            case 1165: msg = "The device has indicated that cleaning is required before further operations are attempted."; break;
            case 1166: msg = "The device has indicated that its door is open."; break;
            case 1167: msg = "The device is not connected."; break;
            case 1168: msg = "Element not found."; break;
            case 1169: msg = "There was no match for the specified key in the index."; break;
            case 1170: msg = "The property set specified does not exist on the object."; break;
            case 1171: msg = "The point passed to GetMouseMovePoints is not in the buffer."; break;
            case 1172: msg = "The tracking (workstation) service is not running."; break;
            case 1173: msg = "The Volume ID could not be found."; break;
            case 1175: msg = "Unable to remove the file to be replaced."; break;
            case 1176: msg = "Unable to move the replacement file to the file to be replaced. The file to be replaced has retained its original name."; break;
            case 1177: msg = "Unable to move the replacement file to the file to be replaced. The file to be replaced has been renamed using the backup name."; break;
            case 1178: msg = "The volume change journal is being deleted."; break;
            case 1179: msg = "The volume change journal is not active."; break;
            case 1180: msg = "A file was found, but it may not be the correct file."; break;
            case 1181: msg = "The journal entry has been deleted from the journal."; break;
            case 1200: msg = "The specified device name is invalid."; break;
            case 1201: msg = "The device is not currently connected but it is a remembered connection."; break;
            case 1202: msg = "The local device name has a remembered connection to another network resource."; break;
            case 1203: msg = "The network path was either typed incorrectly, does not exist, or the network provider is not currently available."; break;
            case 1204: msg = "The specified network provider name is invalid."; break;
            case 1205: msg = "Unable to open the network connection profile."; break;
            case 1206: msg = "The network connection profile is corrupted."; break;
            case 1207: msg = "Cannot enumerate a noncontainer."; break;
            case 1208: msg = "An extended error has occurred."; break;
            case 1209: msg = "The format of the specified group name is invalid."; break;
            case 1210: msg = "The format of the specified computer name is invalid."; break;
            case 1211: msg = "The format of the specified event name is invalid."; break;
            case 1212: msg = "The format of the specified domain name is invalid."; break;
            case 1213: msg = "The format of the specified service name is invalid."; break;
            case 1214: msg = "The format of the specified network name is invalid."; break;
            case 1215: msg = "The format of the specified share name is invalid."; break;
            case 1216: msg = "The format of the specified password is invalid."; break;
            case 1217: msg = "The format of the specified message name is invalid."; break;
            case 1218: msg = "The format of the specified message destination is invalid."; break;
            case 1219: msg = "Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed."; break;
            case 1220: msg = "An attempt was made to establish a session to a network server, but there are already too many sessions established to that server."; break;
            case 1221: msg = "The workgroup or domain name is already in use by another computer on the network."; break;
            case 1222: msg = "The network is not present or not started."; break;
            case 1223: msg = "The operation was canceled by the user."; break;
            case 1224: msg = "The requested operation cannot be performed on a file with a user-mapped section open."; break;
            case 1225: msg = "The remote computer refused the network connection."; break;
            case 1226: msg = "The network connection was gracefully closed."; break;
            case 1227: msg = "The network transport endpoint already has an address associated with it."; break;
            case 1228: msg = "An address has not yet been associated with the network endpoint."; break;
            case 1229: msg = "An operation was attempted on a nonexistent network connection."; break;
            case 1230: msg = "An invalid operation was attempted on an active network connection."; break;
            case 1231: msg = "The network location cannot be reached."; break;
            case 1232: msg = "The network location cannot be reached."; break;
            case 1233: msg = "The network location cannot be reached."; break;
            case 1234: msg = "No service is operating at the destination network endpoint on the remote system."; break;
            case 1235: msg = "The request was aborted."; break;
            case 1236: msg = "The network connection was aborted by the local system."; break;
            case 1237: msg = "The operation could not be completed. A retry should be performed."; break;
            case 1238: msg = "A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached."; break;
            case 1239: msg = "Attempting to log in during an unauthorized time of day for this account."; break;
            case 1240: msg = "The account is not authorized to log in from this station."; break;
            case 1241: msg = "The network address could not be used for the operation requested."; break;
            case 1242: msg = "The service is already registered."; break;
            case 1243: msg = "The specified service does not exist."; break;
            case 1244: msg = "The operation being requested was not performed because the user has not been authenticated."; break;
            case 1245: msg = "The operation being requested was not performed because the user has not logged on to the network."; break;
            case 1246: msg = "Return that wants caller to continue with work in progress."; break;
            case 1247: msg = "An attempt was made to perform an initialization operation when initialization has already been completed."; break;
            case 1248: msg = "No more local devices."; break;
            case 1249: msg = "The specified site does not exist."; break;
            case 1250: msg = "A domain controller with the specified name already exists."; break;
            case 1251: msg = "This operation is supported only when you are connected to the server."; break;
            case 1300: msg = "Not all privileges or groups referenced are assigned to the caller."; break;
            case 1301: msg = "Some mapping between account names and security IDs was not done."; break;
            case 1302: msg = "No system quota limits are specifically set for this account."; break;
            case 1303: msg = "No encryption key is available. A well-known encryption key was returned."; break;
            case 1304: msg = "The password is too complex to be converted to a LAN Manager password."; break;
            case 1305: msg = "The revision level is unknown."; break;
            case 1306: msg = "Indicates two revision levels are incompatible."; break;
            case 1307: msg = "This security ID may not be assigned as the owner of this object."; break;
            case 1308: msg = "This security ID may not be assigned as the primary group of an object."; break;
            case 1309: msg = "An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client."; break;
            case 1310: msg = "The group may not be disabled."; break;
            case 1311: msg = "There are currently no logon servers available to service the logon request."; break;
            case 1312: msg = "A specified logon session does not exist. It may already have been terminated."; break;
            case 1313: msg = "A specified privilege does not exist."; break;
            case 1314: msg = "A required privilege is not held by the client."; break;
            case 1315: msg = "The name provided is not a properly formed account name."; break;
            case 1316: msg = "The specified account already exists."; break;
            case 1317: msg = "The specified account does not exist."; break;
            case 1318: msg = "The specified group already exists."; break;
            case 1319: msg = "The specified group does not exist."; break;
            case 1320: msg = "Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member."; break;
            case 1321: msg = "The specified user account is not a member of the specified group account."; break;
            case 1322: msg = "This operation is disallowed as it could result in an administration account being disabled, deleted or unable to log on."; break;
            case 1323: msg = "Unable to update the password. The value provided as the current password is incorrect."; break;
            case 1324: msg = "Unable to update the password. The value provided for the new password contains values that are not allowed in passwords."; break;
            case 1325: msg = "Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain."; break;
            case 1326: msg = "The user name or password is incorrect."; break;
            case 1327: msg = "Account restrictions are preventing this user from signing in."; break;
            case 1328: msg = "Your account has time restrictions that keep you from signing in right now."; break;
            case 1329: msg = "This user isn't allowed to sign in to this computer."; break;
            case 1330: msg = "The password for this account has expired."; break;
            case 1331: msg = "This user can't sign in because this account is currently disabled."; break;
            case 1332: msg = "No mapping between account names and security IDs was done."; break;
            case 1333: msg = "Too many local user identifiers (LUIDs) were requested at one time."; break;
            case 1334: msg = "No more local user identifiers (LUIDs) are available."; break;
            case 1335: msg = "The sub-authority part of a security ID is out of range."; break;
            case 1336: msg = "The access control list (ACL) structure is invalid."; break;
            case 1337: msg = "The security ID structure is invalid."; break;
            case 1338: msg = "The security descriptor structure is invalid."; break;
            case 1339: msg = "The inherited access control list (ACL) or access control entry (ACE) could not be built."; break;
            case 1340: msg = "The server is currently disabled."; break;
            case 1341: msg = "The server is currently enabled."; break;
            case 1342: msg = "The value provided was an invalid value for an identifier authority."; break;
            case 1343: msg = "No more memory is available for security information updates."; break;
            case 1344: msg = "The specified attributes are invalid, or incompatible with the attributes for the group as a whole."; break;
            case 1345: msg = "Either a required impersonation level was not provided, or the provided impersonation level is invalid."; break;
            case 1346: msg = "It is not possible to open an anonymous level token."; break;
            case 1347: msg = "The validation information class requested was invalid."; break;
            case 1348: msg = "The type of the token is inappropriate for its attempted use."; break;
            case 1349: msg = "Unable to perform a security operation on an object that has no associated security."; break;
            case 1350: msg = "Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied."; break;
            case 1351: msg = "The security account manager (SAM) or local security authority (LSA) server was in the wrong state to perform the security operation."; break;
            case 1352: msg = "The domain was in the wrong state to perform the security operation."; break;
            case 1353: msg = "This operation is only allowed for the Primary Domain Controller of the domain."; break;
            case 1354: msg = "Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk."; break;
            case 1355: msg = "The specified domain either does not exist or could not be contacted."; break;
            case 1356: msg = "The specified domain already exists."; break;
            case 1357: msg = "An attempt was made to exceed the limit on the number of domains per server."; break;
            case 1358: msg = "Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk."; break;
            case 1359: msg = "An internal error occurred."; break;
            case 1360: msg = "Generic access types were contained in an access mask which should already be mapped to nongeneric types."; break;
            case 1361: msg = "A security descriptor is not in the right format (absolute or self-relative)."; break;
            case 1362: msg = "The requested action is restricted for use by logon processes only."; break;
            case 1363: msg = "Cannot start a new logon session with an ID that is already in use."; break;
            case 1364: msg = "A specified authentication package is unknown."; break;
            case 1365: msg = "The logon session is not in a state that is consistent with the requested operation."; break;
            case 1366: msg = "The logon session ID is already in use."; break;
            case 1367: msg = "A logon request contained an invalid logon type value."; break;
            case 1368: msg = "Unable to impersonate using a named pipe until data has been read from that pipe."; break;
            case 1369: msg = "The transaction state of a registry subtree is incompatible with the requested operation."; break;
            case 1370: msg = "An internal security database corruption has been encountered."; break;
            case 1371: msg = "Cannot perform this operation on built-in accounts."; break;
            case 1372: msg = "Cannot perform this operation on this built-in special group."; break;
            case 1373: msg = "Cannot perform this operation on this built-in special user."; break;
            case 1374: msg = "The user cannot be removed from a group because the group is currently the user's primary group."; break;
            case 1375: msg = "The token is already in use as a primary token."; break;
            case 1376: msg = "The specified local group does not exist."; break;
            case 1377: msg = "The specified account name is not a member of the group."; break;
            case 1378: msg = "The specified account name is already a member of the group."; break;
            case 1379: msg = "The specified local group already exists."; break;
            case 1380: msg = "Logon failure: the user has not been granted the requested logon type at this computer."; break;
            case 1381: msg = "The maximum number of secrets that may be stored in a single system has been exceeded."; break;
            case 1382: msg = "The length of a secret exceeds the maximum length allowed."; break;
            case 1383: msg = "The local security authority database contains an internal inconsistency."; break;
            case 1384: msg = "During a logon attempt, the user's security context accumulated too many security IDs."; break;
            case 1385: msg = "Logon failure: the user has not been granted the requested logon type at this computer."; break;
            case 1386: msg = "A cross-encrypted password is necessary to change a user password."; break;
            case 1387: msg = "A member could not be added to or removed from the local group because the member does not exist."; break;
            case 1388: msg = "A new member could not be added to a local group because the member has the wrong account type."; break;
            case 1389: msg = "Too many security IDs have been specified."; break;
            case 1390: msg = "A cross-encrypted password is necessary to change this user password."; break;
            case 1391: msg = "Indicates an ACL contains no inheritable components."; break;
            case 1392: msg = "The file or directory is corrupted and unreadable."; break;
            case 1393: msg = "The disk structure is corrupted and unreadable."; break;
            case 1394: msg = "There is no user session key for the specified logon session."; break;
            case 1395: msg = "The service being accessed is licensed for a particular number of connections."; break;
            case 1396: msg = "Logon failure: the target account name is incorrect."; break;
            case 1397: msg = "Mutual Authentication failed. The server's password is out of date at the domain controller."; break;
            case 1398: msg = "There is a time and/or date difference between the client and server."; break;
            case 1399: msg = "This operation cannot be performed on the current domain."; break;
            case 1400: msg = "Invalid window handle."; break;
            case 1401: msg = "Invalid menu handle."; break;
            case 1402: msg = "Invalid cursor handle."; break;
            case 1403: msg = "Invalid accelerator table handle."; break;
            case 1404: msg = "Invalid hook handle."; break;
            case 1405: msg = "Invalid handle to a multiple-window position structure."; break;
            case 1406: msg = "Cannot create a top-level child window."; break;
            case 1407: msg = "Cannot find window class."; break;
            case 1408: msg = "Invalid window; it belongs to other thread."; break;
            case 1409: msg = "Hot key is already registered."; break;
            case 1410: msg = "Class already exists."; break;
            case 1411: msg = "Class does not exist."; break;
            case 1412: msg = "Class still has open windows."; break;
            case 1413: msg = "Invalid index."; break;
            case 1414: msg = "Invalid icon handle."; break;
            case 1415: msg = "Using private DIALOG window words."; break;
            case 1416: msg = "The list box identifier was not found."; break;
            case 1417: msg = "No wildcards were found."; break;
            case 1418: msg = "Thread does not have a clipboard open."; break;
            case 1419: msg = "Hot key is not registered."; break;
            case 1420: msg = "The window is not a valid dialog window."; break;
            case 1421: msg = "Control ID not found."; break;
            case 1422: msg = "Invalid message for a combo box because it does not have an edit control."; break;
            case 1423: msg = "The window is not a combo box."; break;
            case 1424: msg = "Height must be less than 256."; break;
            case 1425: msg = "Invalid device context (DC) handle."; break;
            case 1426: msg = "Invalid hook procedure type."; break;
            case 1427: msg = "Invalid hook procedure."; break;
            case 1428: msg = "Cannot set nonlocal hook without a module handle."; break;
            case 1429: msg = "This hook procedure can only be set globally."; break;
            case 1430: msg = "The journal hook procedure is already installed."; break;
            case 1431: msg = "The hook procedure is not installed."; break;
            case 1432: msg = "Invalid message for single-selection list box."; break;
            case 1433: msg = "LB_SETCOUNT sent to non-lazy list box."; break;
            case 1434: msg = "This list box does not support tab stops."; break;
            case 1435: msg = "Cannot destroy object created by another thread."; break;
            case 1436: msg = "Child windows cannot have menus."; break;
            case 1437: msg = "The window does not have a system menu."; break;
            case 1438: msg = "Invalid message box style."; break;
            case 1439: msg = "Invalid system-wide (SPI_*) parameter."; break;
            case 1440: msg = "Screen already locked."; break;
            case 1441: msg = "All handles to windows in a multiple-window position structure must have the same parent."; break;
            case 1442: msg = "The window is not a child window."; break;
            case 1443: msg = "Invalid GW_* command."; break;
            case 1444: msg = "Invalid thread identifier."; break;
            case 1445: msg = "Cannot process a message from a window that is not a multiple document interface (MDI) window."; break;
            case 1446: msg = "Popup menu already active."; break;
            case 1447: msg = "The window does not have scroll bars."; break;
            case 1448: msg = "Scroll bar range cannot be greater than MAXLONG."; break;
            case 1449: msg = "Cannot show or remove the window in the way specified."; break;
            case 1450: msg = "Insufficient system resources exist to complete the requested service."; break;
            case 1451: msg = "Insufficient system resources exist to complete the requested service."; break;
            case 1452: msg = "Insufficient system resources exist to complete the requested service."; break;
            case 1453: msg = "Insufficient quota to complete the requested service."; break;
            case 1454: msg = "Insufficient quota to complete the requested service."; break;
            case 1455: msg = "The paging file is too small for this operation to complete."; break;
            case 1456: msg = "A menu item was not found."; break;
            case 1457: msg = "Invalid keyboard layout handle."; break;
            case 1458: msg = "Hook type not allowed."; break;
            case 1459: msg = "This operation requires an interactive window station."; break;
            case 1460: msg = "This operation returned because the timeout period expired."; break;
            case 1461: msg = "Invalid monitor handle."; break;
            case 1462: msg = "Incorrect size argument."; break;
            case 1463: msg = "The symbolic link cannot be followed because its type is disabled."; break;
            case 1464: msg = "This application does not support the current operation on symbolic links."; break;
            case 1465: msg = "Windows was unable to parse the requested XML data."; break;
            case 1466: msg = "An error was encountered while processing an XML digital signature."; break;
            case 1467: msg = "This application must be restarted."; break;
            case 1468: msg = "The caller made the connection request in the wrong routing compartment."; break;
            case 1469: msg = "There was an AuthIP failure when attempting to connect to the remote host."; break;
            case 1470: msg = "Insufficient NVRAM resources exist to complete the requested service. A reboot might be required."; break;
            case 1471: msg = "Unable to finish the requested operation because the specified process is not a GUI process."; break;
            case 1500: msg = "The event log file is corrupted."; break;
            case 1501: msg = "No event log file could be opened, so the event logging service did not start."; break;
            case 1502: msg = "The event log file is full."; break;
            case 1503: msg = "The event log file has changed between read operations."; break;
            case 1504: msg = "The specified Job already has a container assigned to it."; break;
            case 1700: msg = "The string binding is invalid."; break;
            case 1701: msg = "The binding handle is not the correct type."; break;
            case 1702: msg = "The binding handle is invalid."; break;
            case 1703: msg = "The RPC protocol sequence is not supported."; break;
            case 1704: msg = "The RPC protocol sequence is invalid."; break;
            case 1705: msg = "The string universal unique identifier (UUID) is invalid."; break;
            case 1706: msg = "The endpoint format is invalid."; break;
            case 1707: msg = "The network address is invalid."; break;
            case 1708: msg = "No endpoint was found."; break;
            case 1709: msg = "The timeout value is invalid."; break;
            case 1710: msg = "The object universal unique identifier (UUID) was not found."; break;
            case 1711: msg = "The object universal unique identifier (UUID) has already been registered."; break;
            case 1712: msg = "The type universal unique identifier (UUID) has already been registered."; break;
            case 1713: msg = "The RPC server is already listening."; break;
            case 1714: msg = "No protocol sequences have been registered."; break;
            case 1715: msg = "The RPC server is not listening."; break;
            case 1716: msg = "The manager type is unknown."; break;
            case 1717: msg = "The interface is unknown."; break;
            case 1718: msg = "There are no bindings."; break;
            case 1719: msg = "There are no protocol sequences."; break;
            case 1720: msg = "The endpoint cannot be created."; break;
            case 1721: msg = "Not enough resources are available to complete this operation."; break;
            case 1722: msg = "The RPC server is unavailable."; break;
            case 1723: msg = "The RPC server is too busy to complete this operation."; break;
            case 1724: msg = "The network options are invalid."; break;
            case 1725: msg = "There are no remote procedure calls active on this thread."; break;
            case 1726: msg = "The remote procedure call failed."; break;
            case 1727: msg = "The remote procedure call failed and did not execute."; break;
            case 1728: msg = "A remote procedure call (RPC) protocol error occurred."; break;
            case 1730: msg = "The transfer syntax is not supported by the RPC server."; break;
            case 1732: msg = "The universal unique identifier (UUID) type is not supported."; break;
            case 1733: msg = "The tag is invalid."; break;
            case 1734: msg = "The array bounds are invalid."; break;
            case 1735: msg = "The binding does not contain an entry name."; break;
            case 1736: msg = "The name syntax is invalid."; break;
            case 1737: msg = "The name syntax is not supported."; break;
            case 1739: msg = "No network address is available to use to construct a universal unique identifier (UUID)."; break;
            case 1740: msg = "The endpoint is a duplicate."; break;
            case 1741: msg = "The authentication type is unknown."; break;
            case 1742: msg = "The maximum number of calls is too small."; break;
            case 1743: msg = "The string is too long."; break;
            case 1744: msg = "The RPC protocol sequence was not found."; break;
            case 1745: msg = "The procedure number is out of range."; break;
            case 1746: msg = "The binding does not contain any authentication information."; break;
            case 1747: msg = "The authentication service is unknown."; break;
            case 1748: msg = "The authentication level is unknown."; break;
            case 1749: msg = "The security context is invalid."; break;
            case 1750: msg = "The authorization service is unknown."; break;
            case 1751: msg = "The entry is invalid."; break;
            case 1752: msg = "The server endpoint cannot perform the operation."; break;
            case 1753: msg = "There are no more endpoints available from the endpoint mapper."; break;
            case 1754: msg = "No interfaces have been exported."; break;
            case 1755: msg = "The entry name is incomplete."; break;
            case 1756: msg = "The version option is invalid."; break;
            case 1757: msg = "There are no more members."; break;
            case 1758: msg = "There is nothing to unexport."; break;
            case 1759: msg = "The interface was not found."; break;
            case 1760: msg = "The entry already exists."; break;
            case 1761: msg = "The entry is not found."; break;
            case 1762: msg = "The name service is unavailable."; break;
            case 1763: msg = "The network address family is invalid."; break;
            case 1764: msg = "The requested operation is not supported."; break;
            case 1765: msg = "No security context is available to allow impersonation."; break;
            case 1766: msg = "An internal error occurred in a remote procedure call (RPC)."; break;
            case 1767: msg = "The RPC server attempted an integer division by zero."; break;
            case 1768: msg = "An addressing error occurred in the RPC server."; break;
            case 1769: msg = "A floating-point operation at the RPC server caused a division by zero."; break;
            case 1770: msg = "A floating-point underflow occurred at the RPC server."; break;
            case 1771: msg = "A floating-point overflow occurred at the RPC server."; break;
            case 1772: msg = "The list of RPC servers available for the binding of auto handles has been exhausted."; break;
            case 1773: msg = "Unable to open the character translation table file."; break;
            case 1774: msg = "The file containing the character translation table has fewer than 512 bytes."; break;
            case 1775: msg = "A null context handle was passed from the client to the host during a remote procedure call."; break;
            case 1777: msg = "The context handle changed during a remote procedure call."; break;
            case 1778: msg = "The binding handles passed to a remote procedure call do not match."; break;
            case 1779: msg = "The stub is unable to get the remote procedure call handle."; break;
            case 1780: msg = "A null reference pointer was passed to the stub."; break;
            case 1781: msg = "The enumeration value is out of range."; break;
            case 1782: msg = "The byte count is too small."; break;
            case 1783: msg = "The stub received bad data."; break;
            case 1784: msg = "The supplied user buffer is not valid for the requested operation."; break;
            case 1785: msg = "The disk media is not recognized. It may not be formatted."; break;
            case 1786: msg = "The workstation does not have a trust secret."; break;
            case 1787: msg = "The security database on the server does not have a computer account for this workstation trust relationship."; break;
            case 1788: msg = "The trust relationship between the primary domain and the trusted domain failed."; break;
            case 1789: msg = "The trust relationship between this workstation and the primary domain failed."; break;
            case 1790: msg = "The network logon failed."; break;
            case 1791: msg = "A remote procedure call is already in progress for this thread."; break;
            case 1792: msg = "An attempt was made to logon, but the network logon service was not started."; break;
            case 1793: msg = "The user's account has expired."; break;
            case 1794: msg = "The redirector is in use and cannot be unloaded."; break;
            case 1795: msg = "The specified printer driver is already installed."; break;
            case 1796: msg = "The specified port is unknown."; break;
            case 1797: msg = "The printer driver is unknown."; break;
            case 1798: msg = "The print processor is unknown."; break;
            case 1799: msg = "The specified separator file is invalid."; break;
            case 1800: msg = "The specified priority is invalid."; break;
            case 1801: msg = "The printer name is invalid."; break;
            case 1802: msg = "The printer already exists."; break;
            case 1803: msg = "The printer command is invalid."; break;
            case 1804: msg = "The specified datatype is invalid."; break;
            case 1805: msg = "The environment specified is invalid."; break;
            case 1806: msg = "There are no more bindings."; break;
            case 1807: msg = "The account used is an interdomain trust account. Use your global user account or local user account to access this server."; break;
            case 1808: msg = "The account used is a computer account. Use your global user account or local user account to access this server."; break;
            case 1809: msg = "The account used is a server trust account. Use your global user account or local user account to access this server."; break;
            case 1810: msg = "The name or security ID (SID) of the domain specified is inconsistent with the trust information for that domain."; break;
            case 1811: msg = "The server is in use and cannot be unloaded."; break;
            case 1812: msg = "The specified image file did not contain a resource section."; break;
            case 1813: msg = "The specified resource type cannot be found in the image file."; break;
            case 1814: msg = "The specified resource name cannot be found in the image file."; break;
            case 1815: msg = "The specified resource language ID cannot be found in the image file."; break;
            case 1816: msg = "Not enough quota is available to process this command."; break;
            case 1817: msg = "No interfaces have been registered."; break;
            case 1818: msg = "The remote procedure call was cancelled."; break;
            case 1819: msg = "The binding handle does not contain all required information."; break;
            case 1820: msg = "A communications failure occurred during a remote procedure call."; break;
            case 1821: msg = "The requested authentication level is not supported."; break;
            case 1822: msg = "No principal name registered."; break;
            case 1823: msg = "The error specified is not a valid Windows RPC error code."; break;
            case 1824: msg = "A UUID that is valid only on this computer has been allocated."; break;
            case 1825: msg = "A security package specific error occurred."; break;
            case 1826: msg = "Thread is not canceled."; break;
            case 1827: msg = "Invalid operation on the encoding/decoding handle."; break;
            case 1828: msg = "Incompatible version of the serializing package."; break;
            case 1829: msg = "Incompatible version of the RPC stub."; break;
            case 1898: msg = "The list of servers available for this workgroup is not currently available."; break;
            case 2202: msg = "The specified username is invalid."; break;
            case 2250: msg = "The network connection does not exist."; break;
            default: {
                /* Try strerror as a fallback */
                const char* s = strerror((int)message_id);
                if (s && s[0]) msg = s;
                break;
            }
        }
        if (msg) snprintf(tmp, sizeof(tmp), "%s", msg);
        else     snprintf(tmp, sizeof(tmp), "Windows error %u.", message_id);
    } else {
        snprintf(tmp, sizeof(tmp), "Error 0x%x", message_id);
    }

    uint32_t len = (uint32_t)strlen(tmp);
    LSW_LOG_INFO("FormatMessageW(flags=0x%x, id=%u) -> \"%s\" (len=%u)", flags, message_id, tmp, len);

    if (flags & 0x100) {  /* FORMAT_MESSAGE_ALLOCATE_BUFFER — buffer is uint16_t** */
        uint16_t** ppBuf = (uint16_t**)buffer;
        if (!ppBuf) return 0;
        uint16_t* wbuf = (uint16_t*)malloc((len + 1) * sizeof(uint16_t));
        if (!wbuf) { lsw_SetLastError(8); return 0; }
        for (uint32_t i = 0; i <= len; i++) wbuf[i] = (uint16_t)(unsigned char)tmp[i];
        *ppBuf = wbuf;
    } else {
        if (!buffer || size == 0) return 0;
        if (len >= size) len = size - 1;
        for (uint32_t i = 0; i <= len; i++) buffer[i] = (uint16_t)(unsigned char)tmp[i];
    }
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
        return lsw_GetModuleHandleA(NULL);
    }
    char buf[256];
    int i = 0;
    while (name[i] && i < 254) { buf[i] = (char)(name[i] & 0xFF); i++; }
    buf[i] = '\0';
    LSW_LOG_INFO("GetModuleHandleW(%s) -> using GetModuleHandleA", buf);
    return lsw_GetModuleHandleA(buf);
}

/* Convert a Linux path (/mnt/c/...) to Windows path (C:\...) for wide output */
static uint32_t lsw_linux_to_winpath_w(const char* src, uint16_t* buf, uint32_t size) {
    if (!buf || size == 0) return 0;
    char win[4096];
    uint32_t wi = 0;
    /* /mnt/<letter>/... → <letter>:\... */
    if (src[0] == '/' && src[1] == 'm' && src[2] == 'n' && src[3] == 't' &&
        src[4] == '/' && src[5] && src[6] == '/') {
        win[wi++] = (char)((unsigned char)src[5] >= 'a' ? src[5] - 32 : src[5]); /* drive letter */
        win[wi++] = ':';
        win[wi++] = '\\';
        src += 7; /* skip /mnt/x/ */
    }
    for (; *src && wi < (uint32_t)sizeof(win) - 1; src++, wi++) {
        win[wi] = (*src == '/') ? '\\' : *src;
    }
    win[wi] = '\0';
    uint32_t i = 0;
    while (win[i] && i < size - 1) { buf[i] = (uint16_t)(unsigned char)win[i]; i++; }
    buf[i] = 0;
    return i;
}

uint32_t __attribute__((ms_abi)) lsw_GetModuleFileNameW(void* module, uint16_t* buf, uint32_t size) {
    (void)module;
    if (!buf || size == 0) return 0;
    const char* src = (g_lsw_exe_path[0]) ? g_lsw_exe_path : "";
    uint32_t i = lsw_linux_to_winpath_w(src, buf, size);
    char dbg[256]; uint32_t di = 0;
    while (buf[di] && di < 255) { dbg[di] = (char)(buf[di] & 0xFF); di++; } dbg[di] = '\0';
    LSW_LOG_INFO("GetModuleFileNameW -> %s (%u chars)", dbg, i);
    return i;
}

uint32_t __attribute__((ms_abi)) lsw_GetModuleFileNameA(void* module, char* buf, uint32_t size) {
    (void)module;
    if (!buf || size == 0) return 0;
    /* Convert Linux path to Windows path */
    uint16_t wbuf[4096];
    const char* src = (g_lsw_exe_path[0]) ? g_lsw_exe_path : "";
    uint32_t wlen = lsw_linux_to_winpath_w(src, wbuf, 4095);
    uint32_t len = wlen < size - 1 ? wlen : size - 1;
    for (uint32_t i = 0; i < len; i++) buf[i] = (char)(wbuf[i] & 0xFF);
    buf[len] = '\0';
    LSW_LOG_INFO("GetModuleFileNameA -> %s (%u chars)", buf, len);
    return len;
}

// ============================================================================
// END Missing high-priority KERNEL32 APIs
// ============================================================================

// ============================================================================
// SECTION: Additional msvcrt.dll stubs (sprintf, string, math, ctype, I/O)
// ============================================================================

int __attribute__((ms_abi)) lsw_sprintf(char* buf, const char* fmt, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    int r = vsnprintf(buf, 65536, fmt, ap);
    __builtin_ms_va_end(ms_ap); return r;
}
int __attribute__((ms_abi)) lsw_snprintf(char* buf, size_t n, const char* fmt, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    int r = vsnprintf(buf, n, fmt, ap);
    __builtin_ms_va_end(ms_ap); return r;
}
// _snprintf (Windows, not null-terminated if truncated)
int __attribute__((ms_abi)) lsw__snprintf(char* buf, size_t n, const char* fmt, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    int r = vsnprintf(buf, n, fmt, ap);
    __builtin_ms_va_end(ms_ap); return r;
}
int __attribute__((ms_abi)) lsw_vsprintf(char* buf, const char* fmt, va_list ap) {
    return vsprintf(buf, fmt, ap);
}
int __attribute__((ms_abi)) lsw_vsnprintf(char* buf, size_t n, const char* fmt, va_list ap) {
    return vsnprintf(buf, n, fmt, ap);
}
int __attribute__((ms_abi)) lsw_sscanf(const char* s, const char* fmt, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    int r = vsscanf(s, fmt, ap);
    __builtin_ms_va_end(ms_ap); return r;
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
wchar_t* __attribute__((ms_abi)) lsw_wcscpy(wchar_t* d, const wchar_t* s)            { return (wchar_t*)u16_cpy((u16*)d, (const u16*)s); }
wchar_t* __attribute__((ms_abi)) lsw_wcsncpy(wchar_t* d, const wchar_t* s, size_t n) { return (wchar_t*)u16_ncpy((u16*)d, (const u16*)s, n); }
wchar_t* __attribute__((ms_abi)) lsw_wcscat(wchar_t* d, const wchar_t* s)            { return (wchar_t*)u16_cat((u16*)d, (const u16*)s); }
wchar_t* __attribute__((ms_abi)) lsw_wcsncat(wchar_t* d, const wchar_t* s, size_t n) { return (wchar_t*)u16_ncat((u16*)d, (const u16*)s, n); }
int      __attribute__((ms_abi)) lsw_wcscmp(const wchar_t* a, const wchar_t* b)      { return u16_cmp((const u16*)a, (const u16*)b); }
int      __attribute__((ms_abi)) lsw_wcsncmp(const wchar_t* a, const wchar_t* b, size_t n) { return u16_ncmp((const u16*)a, (const u16*)b, n); }
wchar_t* __attribute__((ms_abi)) lsw_wcschr(const wchar_t* s, wchar_t c)             { return (wchar_t*)u16_chr((const u16*)s, (u16)c); }
wchar_t* __attribute__((ms_abi)) lsw_wcsrchr(const wchar_t* s, wchar_t c)            { return (wchar_t*)u16_rchr((const u16*)s, (u16)c); }
wchar_t* __attribute__((ms_abi)) lsw_wcsstr(const wchar_t* h, const wchar_t* n)      { return (wchar_t*)u16_str((const u16*)h, (const u16*)n); }
wchar_t* __attribute__((ms_abi)) lsw__wcsdup(const wchar_t* s)                       { return (wchar_t*)u16_dup((const u16*)s); }

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
/* ABI bridge for qsort/bsearch: libc uses SysV (rdi/rsi), PE callbacks use ms_abi (rcx/rdx).
 * Store the ms_abi comparator in TLS, then call it from a SysV trampoline. */
typedef int (*lsw_ms_cmp_t)(const void*, const void*) __attribute__((ms_abi));
static __thread lsw_ms_cmp_t tls_ms_cmp = NULL;
static int lsw_ms_cmp_bridge(const void* a, const void* b) {
    /* SysV entry: a in rdi, b in rsi — GCC will emit ms_abi call to tls_ms_cmp */
    return tls_ms_cmp(a, b);
}
void __attribute__((ms_abi)) lsw_qsort(void* base, size_t n, size_t size,
    lsw_ms_cmp_t cmp) {
    LSW_LOG_INFO("qsort: n=%zu size=%zu", n, size);
    lsw_ms_cmp_t saved = tls_ms_cmp;
    tls_ms_cmp = cmp;
    qsort(base, n, size, lsw_ms_cmp_bridge);
    tls_ms_cmp = saved;
}
void* __attribute__((ms_abi)) lsw_bsearch(const void* key, const void* base, size_t n, size_t size,
    lsw_ms_cmp_t cmp) {
    lsw_ms_cmp_t saved = tls_ms_cmp;
    tls_ms_cmp = cmp;
    void* result = bsearch(key, base, n, size, lsw_ms_cmp_bridge);
    tls_ms_cmp = saved;
    return result;
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
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    int r = vfscanf((FILE*)f, fmt, ap);
    __builtin_ms_va_end(ms_ap); return r;
}
int __attribute__((ms_abi)) lsw_vprintf(const char* fmt, va_list ap) {
    /* ap is Windows va_list (char*); convert to sysv */
    va_list sysv_ap; LSW_MS_TO_SYSV_VA(sysv_ap, ap);
    char* buf = NULL; vasprintf(&buf, fmt, sysv_ap);
    if (!buf) return -1;
    int n = (int)write(1, buf, strlen(buf));
    free(buf); return n;
}
/* Forward declaration — defined later in this file */
int __attribute__((ms_abi)) lsw__vsnwprintf(wchar_t* buf_w, size_t count, const wchar_t* fmt_w, char* ap_in);
int   __attribute__((ms_abi)) lsw_swprintf(wchar_t* buf, const wchar_t* fmt, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    int r = lsw__vsnwprintf(buf, 65536, fmt, (char*)ms_ap);
    __builtin_ms_va_end(ms_ap); return r;
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
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    va_list ap; LSW_MS_TO_SYSV_VA(ap, ms_ap);
    int r = vsnprintf(dst, sz, fmt, ap);
    __builtin_ms_va_end(ms_ap); return r;
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
    if (!src) { dst[0] = 0; return 0; } /* NULL src → empty string, no crash */
    u16_ncpy((u16*)dst, (const u16*)src, sz); ((u16*)dst)[sz-1] = 0; return 0;
}
int __attribute__((ms_abi)) lsw_wcscat_s(wchar_t* dst, size_t sz, const wchar_t* src) {
    if (!dst || !sz) return 22;
    size_t used = u16_len((const u16*)dst);
    if (used >= sz) return 22;
    u16_ncat((u16*)dst, (const u16*)src, sz - used - 1); return 0;
}
int __attribute__((ms_abi)) lsw_swprintf_s(wchar_t* dst, size_t sz, const wchar_t* fmt, ...) {
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    int r = lsw__vsnwprintf(dst, sz, fmt, (char*)ms_ap);
    __builtin_ms_va_end(ms_ap); return r;
}

// String collation functions (locale-aware comparison)
// Use simple strcmp/wcscmp semantics - good enough for most sort use cases
int __attribute__((ms_abi)) lsw_strcoll(const char* s1, const char* s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    LSW_LOG_INFO("strcoll('%s', '%s')", s1, s2);
    return strcoll(s1, s2);
}
int __attribute__((ms_abi)) lsw__stricoll(const char* s1, const char* s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    return strcasecmp(s1, s2);
}
int __attribute__((ms_abi)) lsw__strncoll(const char* s1, const char* s2, size_t n) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    return strncmp(s1, s2, n);
}
int __attribute__((ms_abi)) lsw__strnicoll(const char* s1, const char* s2, size_t n) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    return strncasecmp(s1, s2, n);
}
int __attribute__((ms_abi)) lsw_wcscoll(const wchar_t* s1, const wchar_t* s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    return wcscoll(s1, s2);
}
int __attribute__((ms_abi)) lsw__wcsicoll(const wchar_t* s1, const wchar_t* s2) {
    // Wide case-insensitive collation - compare using _wcsicmp semantics
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    const u16* a = (const u16*)s1;
    const u16* b = (const u16*)s2;
    while (*a && *b) {
        u16 ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        u16 cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)*a - (int)*b;
}
int __attribute__((ms_abi)) lsw__wcsncoll(const wchar_t* s1, const wchar_t* s2, size_t n) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    return wcsncmp(s1, s2, n);
}
int __attribute__((ms_abi)) lsw__wcsnicoll(const wchar_t* s1, const wchar_t* s2, size_t n) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    const u16* a = (const u16*)s1;
    const u16* b = (const u16*)s2;
    for (size_t i = 0; i < n && *a && *b; i++, a++, b++) {
        u16 ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        u16 cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return (int)ca - (int)cb;
    }
    if (n == 0) return 0;
    u16 ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
    u16 cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
    return (int)ca - (int)cb;
}

// ADVAPI32.dll!IsTextUnicode - Heuristic check if buffer contains Unicode text
// Returns TRUE/FALSE; sets out_result flags if provided
int __attribute__((ms_abi)) lsw_IsTextUnicode(const void* lpv, int iSize, int* lpiResult) {
    if (!lpv || iSize <= 0) { if (lpiResult) *lpiResult = 0; return 0; }
    const unsigned char* p = (const unsigned char*)lpv;
    int is_unicode = (iSize >= 2 && p[0] == 0xFF && p[1] == 0xFE);
    if (!is_unicode && iSize >= 2) {
        int zero_count = 0;
        for (int i = 0; i < iSize && i < 256; i += 2)
            if (p[i] == 0 || (i + 1 < iSize && p[i+1] == 0)) zero_count++;
        is_unicode = (zero_count > iSize / 8);
    }
    if (lpiResult) *lpiResult = is_unicode ? 1 : 0;
    return is_unicode ? 1 : 0;
}

// Wide I/O
void* __attribute__((ms_abi)) lsw__wfopen(const wchar_t* path, const wchar_t* mode) {
    char p[1024], m[32];
    u16_to_utf8((const u16*)path, p, sizeof(p));
    u16_to_utf8((const u16*)mode, m, sizeof(m));
    return fopen(p, m);
}
int __attribute__((ms_abi)) lsw__waccess(const wchar_t* path, int mode) {
    char p[1024]; u16_to_utf8((const u16*)path, p, sizeof(p)); return access(p, mode);
}
int __attribute__((ms_abi)) lsw__wrename(const wchar_t* o, const wchar_t* n_) {
    char o2[1024], n2[1024];
    u16_to_utf8((const u16*)o, o2, sizeof(o2));
    u16_to_utf8((const u16*)n_, n2, sizeof(n2));
    return rename(o2, n2);
}
int __attribute__((ms_abi)) lsw__wremove(const wchar_t* path) {
    char p[1024]; u16_to_utf8((const u16*)path, p, sizeof(p)); return remove(p);
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
typedef int __attribute__((ms_abi)) (*initterm_e_fn_t)(void);
int __attribute__((ms_abi)) lsw__initterm_e(initterm_e_fn_t *start, initterm_e_fn_t *end) {
    LSW_LOG_DEBUG("_initterm_e: start=%p end=%p count=%zu", (void*)start, (void*)end,
                 (start && end && end > start) ? (size_t)(end - start) : 0);
    if (!start || !end || start >= end) return 0;
    for (initterm_e_fn_t *fn = start; fn < end; fn++) {
        if (*fn) {
            LSW_LOG_DEBUG("_initterm_e: calling fn[%zu]=%p", (size_t)(fn - start), (void*)(uintptr_t)*fn);
            int r = (*fn)();
            LSW_LOG_DEBUG("_initterm_e: fn[%zu]=%p returned %d", (size_t)(fn - start), (void*)(uintptr_t)*fn, r);
            if (r) {
                LSW_LOG_ERROR("_initterm_e: fn[%zu]=%p FAILED with %d — aborting init", (size_t)(fn - start), (void*)(uintptr_t)*fn, r);
                return r;
            }
        }
    }
    return 0;
}
void __attribute__((ms_abi)) lsw___security_init_cookie(void) {}
void __attribute__((ms_abi)) lsw___security_check_cookie(uintptr_t c) { (void)c; }

// Additional wide string helpers
size_t __attribute__((ms_abi)) lsw_wcsnlen(const wchar_t* s, size_t max) {
    return u16_nlen((const u16*)s, max);
}
int __attribute__((ms_abi)) lsw__wcsicmp(const wchar_t* a, const wchar_t* b) { return u16_icmp((const u16*)a, (const u16*)b); }
int __attribute__((ms_abi)) lsw__wcsnicmp(const wchar_t* a, const wchar_t* b, size_t n) { return u16_nicmp((const u16*)a, (const u16*)b, n); }
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
    uint64_t opts, wchar_t* buf, size_t n, const wchar_t* fmt, void* locale, char* ap)
{
    (void)opts; (void)locale;
    return lsw__vsnwprintf(buf, n, fmt, ap);
}
int __attribute__((ms_abi)) lsw___stdio_common_vfwprintf(
    uint64_t opts, void* f, const wchar_t* fmt, void* locale, va_list ap)
{
    (void)opts; (void)locale;
    return vfwprintf((FILE*)f, fmt, ap);
}

// _configure_narrow_argv / _configure_wide_argv — CRT startup config, return 0 = success
int __attribute__((ms_abi)) lsw__configure_narrow_argv(int mode) { (void)mode; return 0; }
int __attribute__((ms_abi)) lsw__configure_wide_argv(int mode) {
    (void)mode;
    // Build lsw_crt_wargv from lsw_crt_argv using uint16_t (Windows UTF-16, 2 bytes/char)
    // NOTE: Linux wchar_t is 4 bytes; Windows wchar_t is 2 bytes. We must use uint16_t.
    int argc = lsw_crt_argc;
    char** argv = lsw_crt_argv;
    if (!argv || argc <= 0) return 0;

    uint16_t** wargv = malloc((size_t)(argc + 1) * sizeof(uint16_t*));
    if (!wargv) return -1;

    for (int i = 0; i < argc; i++) {
        const char* s = argv[i] ? argv[i] : "";
        size_t len = strlen(s) + 1;
        uint16_t* ws = malloc(len * sizeof(uint16_t));
        if (!ws) return -1;
        for (size_t j = 0; j < len; j++) ws[j] = (uint16_t)(unsigned char)s[j];
        wargv[i] = ws;
    }
    wargv[argc] = NULL;

    /* Build wide command line string for GetCommandLineW (also uint16_t) */
    if (!lsw_crt_wcmdln && lsw_crt_acmdln) {
        size_t cmdlen = strlen(lsw_crt_acmdln) + 1;
        uint16_t* wcmd = malloc(cmdlen * sizeof(uint16_t));
        if (wcmd) {
            for (size_t j = 0; j < cmdlen; j++) wcmd[j] = (uint16_t)(unsigned char)lsw_crt_acmdln[j];
            lsw_crt_wcmdln = (wchar_t*)wcmd;
        }
    }

    lsw_crt_wargv = (wchar_t**)wargv;
    LSW_LOG_INFO("_configure_wide_argv: built wargv with %d args, wargv[0]='%s'",
                 argc, argv[0] ? argv[0] : "(null)");
    return 0;
}

// _initialize_narrow_environment / _initialize_wide_environment — return 0 = success
int __attribute__((ms_abi)) lsw__initialize_narrow_environment(void) { return 0; }
int __attribute__((ms_abi)) lsw__initialize_wide_environment(void) {
    if (lsw_crt_wenvp) return 0;  // Already initialized
    // Count environ entries
    char** env = lsw_crt_environ ? lsw_crt_environ : environ;
    if (!env) return 0;
    int count = 0;
    while (env[count]) count++;
    // Build wide env using uint16_t (Windows UTF-16, 2 bytes/char)
    uint16_t** wenv = malloc((size_t)(count + 1) * sizeof(uint16_t*));
    if (!wenv) return 0;
    for (int i = 0; i < count; i++) {
        size_t len = strlen(env[i]) + 1;
        uint16_t* ws = malloc(len * sizeof(uint16_t));
        if (!ws) { wenv[i] = NULL; continue; }
        for (size_t j = 0; j < len; j++) ws[j] = (uint16_t)(unsigned char)env[i][j];
        wenv[i] = ws;
    }
    wenv[count] = NULL;
    lsw_crt_wenvp = (wchar_t**)wenv;
    return 0;
}

/* _onexit_table_t layout: { void** _first; void** _last; void** _end; } */
typedef struct { void** _first; void** _last; void** _end; } lsw_onexit_table_t;

int __attribute__((ms_abi)) lsw__initialize_onexit_table(void* t) {
    if (t) {
        lsw_onexit_table_t* tbl = (lsw_onexit_table_t*)t;
        tbl->_first = tbl->_last = tbl->_end = NULL;
    }
    return 0;
}
int __attribute__((ms_abi)) lsw__register_onexit_function(void* t, void* fn) {
    if (!t || !fn) return 0;
    lsw_onexit_table_t* tbl = (lsw_onexit_table_t*)t;
    /* grow table by 4 slots if needed */
    if (!tbl->_first || tbl->_last >= tbl->_end) {
        size_t old = (size_t)(tbl->_last - tbl->_first);
        size_t cap = old + 4;
        void** p = realloc(tbl->_first, cap * sizeof(void*));
        if (!p) return -1;
        tbl->_first = p;
        tbl->_last  = p + old;
        tbl->_end   = p + cap;
    }
    *tbl->_last++ = fn;
    return 0;
}
void __attribute__((ms_abi)) lsw__execute_onexit_table(void* t) {
    if (!t) return;
    lsw_onexit_table_t* tbl = (lsw_onexit_table_t*)t;
    if (!tbl->_first) return;
    /* call in reverse order */
    void** p = tbl->_last;
    while (p > tbl->_first) {
        --p;
        if (*p) ((void(*)(void))(*p))();
    }
    free(tbl->_first);
    tbl->_first = tbl->_last = tbl->_end = NULL;
}
int* __attribute__((ms_abi)) lsw___p___argc(void)     { return &lsw_crt_argc; }
char*** __attribute__((ms_abi)) lsw___p___argv(void)  { return &lsw_crt_argv; }
wchar_t*** __attribute__((ms_abi)) lsw___p___wargv(void) { return &lsw_crt_wargv; }
/* lsw___p__commode defined earlier with correct int* return type */

/* __current_exception / __current_exception_context — used by ucrtbase SEH */
static void* lsw_current_exception_ptr = NULL;
static void* lsw_current_exception_context_ptr = NULL;
void** __attribute__((ms_abi)) lsw___current_exception(void) { return &lsw_current_exception_ptr; }
void** __attribute__((ms_abi)) lsw___current_exception_context(void) { return &lsw_current_exception_context_ptr; }

/* _register_thread_local_exe_atexit_callback — no-op for single-threaded stubs */
void __attribute__((ms_abi)) lsw__register_thread_local_exe_atexit_callback(void* cb) { (void)cb; }

/* _set_fmode / _set_new_mode / _seh_filter_exe / _resetstkoflw */
void __attribute__((ms_abi)) lsw__set_fmode(int mode) { lsw_crt_fmode = mode; }
void __attribute__((ms_abi)) lsw__set_new_mode(int mode) { (void)mode; }
int __attribute__((ms_abi)) lsw__seh_filter_exe(uint32_t code, void* ep) { (void)code; (void)ep; return 0; }
int __attribute__((ms_abi)) lsw__resetstkoflw(void) { return 1; }

/* _get_initial_wide_environment — return pointer to wenvp */
wchar_t** __attribute__((ms_abi)) lsw__get_initial_wide_environment(void) { return lsw_crt_wenvp; }

/* _configthreadlocale — no-op */
int __attribute__((ms_abi)) lsw__configthreadlocale(int per_thread) { (void)per_thread; return 0; }

/* _wcstoui64 — wide string to uint64 */
uint64_t __attribute__((ms_abi)) lsw__wcstoui64(const wchar_t* s, wchar_t** end, int base) {
    return (uint64_t)wcstoull(s, end, base);
}

/* getwchar / getwc */
int __attribute__((ms_abi)) lsw_getwchar(void) { return (int)getwchar(); }

/* _fileno is already defined earlier; only add the missing new stubs below */

// terminate / unexpected
void __attribute__((ms_abi)) lsw__crt_atexit(void* fn) { (void)fn; }
void __attribute__((ms_abi)) lsw___crt_at_quick_exit(void* fn) { (void)fn; }

// vcruntime: memory functions
void* __attribute__((ms_abi)) lsw___std_type_info_destroy_list(void* p) { (void)p; return NULL; }

// C++ exception helpers (vcruntime)
/* tls_cxx_exception_obj / tls_cxx_exception_type defined near _CxxThrowException */

/* lsw__CxxThrowException defined earlier */

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
    if (!buf || nchars == 0) { if (written) *written = 0; return 1; }
    /* Debug: log first 64 chars as narrow for tracing */
    char dbgbuf[130] = {0};
    uint32_t dbglen = nchars < 64 ? nchars : 64;
    for (uint32_t i = 0; i < dbglen; i++)
        dbgbuf[i] = (buf[i] < 128 && buf[i] >= 32) ? (char)buf[i] : (buf[i] == 10 ? '\n' : '.');
    dbgbuf[dbglen] = '\0';
    LSW_LOG_INFO("WriteConsoleW(buf=%p, %u chars): \"%s\"", (void*)buf, nchars, dbgbuf);
    // Simple Latin-1 downcast for console output
    for (uint32_t i = 0; i < nchars; i++) {
        uint16_t c = buf[i];
        if (c < 128) putchar((char)c);
        else putchar('?');
    }
    fflush(stdout);
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
    if (IS_TYPED_HANDLE(m) && m->magic == LSW_MUTEX_MAGIC) {
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
    if (IS_TYPED_HANDLE(s) && s->magic == LSW_SEMA_MAGIC) {
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
    /* Build wide command line as UTF-16LE (uint16_t, NOT wchar_t which is 4 bytes on Linux) */
    static uint16_t wcmdline[4096];
    const char* src = lsw_crt_acmdln ? lsw_crt_acmdln : "";
    size_t i;
    for (i = 0; src[i] && i < 4095; i++)
        wcmdline[i] = (uint16_t)(unsigned char)src[i];
    wcmdline[i] = 0;
    LSW_LOG_DEBUG("GetCommandLineW() -> '%s'", src);
    return (void*)wcmdline;
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
    if (IS_TYPED_HANDLE(pem) && pem->magic == LSW_PE_HMODULE_MAGIC) {
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

// ---- DLL search order / directory management ----
// SetDefaultDllDirectories(DWORD DirectoryFlags) — sets DLL search order flags
// We ignore the flags since we handle DLL loading ourselves
int __attribute__((ms_abi)) lsw_SetDefaultDllDirectories(uint32_t dwFlags) {
    (void)dwFlags;
    LSW_LOG_INFO("SetDefaultDllDirectories(0x%x) called (no-op)", dwFlags);
    return 1; /* TRUE */
}
// AddDllDirectory — adds a directory to the process DLL search path
void* __attribute__((ms_abi)) lsw_AddDllDirectory(const uint16_t* NewDirectory) {
    (void)NewDirectory;
    return (void*)0x1; /* non-NULL cookie */
}
// RemoveDllDirectory — removes a directory added by AddDllDirectory
int __attribute__((ms_abi)) lsw_RemoveDllDirectory(void* Cookie) {
    (void)Cookie;
    return 1; /* TRUE */
}
// SetDllDirectoryW/A — sets a single extra DLL search directory
int __attribute__((ms_abi)) lsw_SetDllDirectoryW(const uint16_t* lpPathName) {
    (void)lpPathName;
    return 1;
}
int __attribute__((ms_abi)) lsw_SetDllDirectoryA(const char* lpPathName) {
    (void)lpPathName;
    return 1;
}
// GetDllDirectoryW/A — returns the DLL search directory (empty string = default)
uint32_t __attribute__((ms_abi)) lsw_GetDllDirectoryW(uint32_t nBufferLength, uint16_t* lpBuffer) {
    if (lpBuffer && nBufferLength > 0) lpBuffer[0] = 0;
    return 0;
}
uint32_t __attribute__((ms_abi)) lsw_GetDllDirectoryA(uint32_t nBufferLength, char* lpBuffer) {
    if (lpBuffer && nBufferLength > 0) lpBuffer[0] = 0;
    return 0;
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
    int result = (r < 0) ? 1 : (r == 0) ? 2 : 3; // CSTR_LESS_THAN=1, CSTR_EQUAL=2, CSTR_GREATER_THAN=3
    LSW_LOG_DEBUG("CompareStringW('%s', '%s', flags=0x%x) -> %d", s1, s2, dwCmpFlags, result);
    return result;
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
    if (p && IS_TYPED_HANDLE(p) && p->magic == LSW_PIPE_MAGIC) {
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
        char rest[512]; strncpy(rest, wpath + 3, sizeof(rest)-1); rest[sizeof(rest)-1]='\0';
        /* replace backslashes */
        for (char* p = rest; *p; p++) if (*p == '\\') *p = '/';
        /* Try candidate prefixes in order of preference:
         * 1. WSL auto-mount (running under WSL: /mnt/c/...)
         * 2. LSW_PREFIX environment variable
         * 3. ~/.lsw/drives (default lsw prefix) */
        const char* candidates[] = { "/mnt", NULL, NULL, NULL };
        char env_prefix[512] = {0};
        const char* lsw_pref = getenv("LSW_PREFIX");
        if (lsw_pref) { strncpy(env_prefix, lsw_pref, sizeof(env_prefix)-1); candidates[1] = env_prefix; }
        /* Check ~/.lsw/drives */
        char home_prefix[512];
        const char* home = getenv("HOME"); if (!home) home = "/root";
        snprintf(home_prefix, sizeof(home_prefix), "%s/.lsw/drives", home);
        candidates[2] = home_prefix;
        /* Try each candidate, pick first where <prefix>/<drive>/<rest[.exe]> exists */
        for (int ci = 0; candidates[ci]; ci++) {
            char try_path[1024];
            snprintf(try_path, sizeof(try_path), "%s/%c/%s", candidates[ci], drive, rest);
            if (access(try_path, F_OK) == 0) { strncpy(out, try_path, outsz-1); out[outsz-1]='\0'; return; }
            /* also try with .exe appended */
            char try_exe[1024];
            snprintf(try_exe, sizeof(try_exe), "%s.exe", try_path);
            if (access(try_exe, F_OK) == 0) { strncpy(out, try_exe, outsz-1); out[outsz-1]='\0'; return; }
        }
        /* No candidate found — default to WSL mount */
        snprintf(out, outsz, "/mnt/%c/%s", drive, rest);
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

    /* Build argv for pe-loader: lsw-pe-loader --launch <exe> [args...] */
    char* child_argv[64];
    int ci = 0;
    child_argv[ci++] = loader;
    child_argv[ci++] = "--launch";
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
    } else if (!lpApplicationName && lpCommandLine) {
        /* cmdline only: extra args start at index 1 (after exe name) */
        extra = parse_cmdline(lpCommandLine, &extra_cnt);
        for (int i = 1; i < extra_cnt && ci < 62; i++)
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
    LSW_LOG_DEBUG("CreateProcessW: appA='%s' cmdA='%s'", appA[0]?appA:"(null)", cmdA[0]?cmdA:"(null)");
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

// ============================================================================
// SECTION: Missing KERNEL32/ADVAPI32/msvcrt stubs for real-world apps
// ============================================================================

/* InterlockedIncrement/Decrement/Exchange — atomic ops via GCC builtins */
long __attribute__((ms_abi)) lsw_InterlockedIncrement(volatile long* Addend) {
    return __atomic_add_fetch(Addend, 1, __ATOMIC_SEQ_CST);
}
long __attribute__((ms_abi)) lsw_InterlockedDecrement(volatile long* Addend) {
    return __atomic_sub_fetch(Addend, 1, __ATOMIC_SEQ_CST);
}
long __attribute__((ms_abi)) lsw_InterlockedExchange(volatile long* Target, long Value) {
    return __atomic_exchange_n(Target, Value, __ATOMIC_SEQ_CST);
}
long __attribute__((ms_abi)) lsw_InterlockedCompareExchange(volatile long* Dest, long Exchange, long Comperand) {
    __atomic_compare_exchange_n(Dest, &Comperand, Exchange, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return Comperand;
}

/* GetThreadLocale — return the default locale (English US) */
uint32_t __attribute__((ms_abi)) lsw_GetThreadLocale(void) {
    return 0x0409;  /* MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) */
}

/* SetThreadUILanguage — when called with 0 (query mode), return current language */
uint16_t __attribute__((ms_abi)) lsw_SetThreadUILanguage(uint16_t langId) {
    uint16_t result = langId ? langId : 0x0409; /* 0x0409 = LANG_ENGLISH/SUBLANG_ENGLISH_US */
    LSW_LOG_DEBUG("SetThreadUILanguage(%u) -> %u", langId, result);
    return result;
}

/* GetTimeFormatW — format time as wchar_t string; return a simple stub */
int __attribute__((ms_abi)) lsw_GetTimeFormatW(uint32_t Locale, uint32_t dwFlags,
                                                const void* lpTime, const wchar_t* lpFormat,
                                                wchar_t* lpTimeStr, int cchTime) {
    (void)Locale; (void)dwFlags; (void)lpTime; (void)lpFormat;
    if (lpTimeStr && cchTime > 0) {
        static const wchar_t dummy[] = L"00:00:00";
        size_t len = sizeof(dummy)/sizeof(dummy[0]);
        if ((int)len > cchTime) len = (size_t)cchTime;
        memcpy(lpTimeStr, dummy, len * sizeof(wchar_t));
        return (int)len;
    }
    return 9;
}

/* FindStringOrdinal — find a substring by ordinal (locale-independent)
 * Windows strings are UTF-16LE (2 bytes/char); we must use u16* indexing. */
int __attribute__((ms_abi)) lsw_FindStringOrdinal(uint32_t dwFindStringOrdinalFlags,
                                                   const wchar_t* lpStringSource, int cchSource,
                                                   const wchar_t* lpStringValue, int cchValue,
                                                   int bIgnoreCase) {
    (void)dwFindStringOrdinalFlags;
    if (!lpStringSource || !lpStringValue) return -1;
    const u16* src = (const u16*)lpStringSource;
    const u16* val = (const u16*)lpStringValue;
    if (cchSource < 0) cchSource = (int)u16_len(src);
    if (cchValue  < 0) cchValue  = (int)u16_len(val);
    LSW_LOG_DEBUG("FindStringOrdinal(flags=%u, cchSrc=%d cchVal=%d ignoreCase=%d)",
                  dwFindStringOrdinalFlags, cchSource, cchValue, bIgnoreCase);
    for (int i = 0; i <= cchSource - cchValue; i++) {
        int match = 1;
        for (int j = 0; j < cchValue && match; j++) {
            u16 a = src[i+j];
            u16 b = val[j];
            if (bIgnoreCase) {
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
            }
            if (a != b) match = 0;
        }
        if (match) {
            LSW_LOG_DEBUG("FindStringOrdinal -> %d", i);
            return i;
        }
    }
    LSW_LOG_DEBUG("FindStringOrdinal -> -1 (not found)");
    return -1;
}

/* SetFileApisToOEM — switch file API to OEM charset; stub */
void __attribute__((ms_abi)) lsw_SetFileApisToOEM(void) {}
void __attribute__((ms_abi)) lsw_SetFileApisToANSI(void) {}

/* IsProcessorFeaturePresent — return false for all features (safe default) */
int __attribute__((ms_abi)) lsw_IsProcessorFeaturePresent(uint32_t ProcessorFeature) {
    (void)ProcessorFeature;
    return 0;
}

/* GlobalMemoryStatus — return generous memory figures */
typedef struct {
    uint32_t dwLength;
    uint32_t dwMemoryLoad;
    uint64_t dwTotalPhys;
    uint64_t dwAvailPhys;
    uint64_t dwTotalPageFile;
    uint64_t dwAvailPageFile;
    uint64_t dwTotalVirtual;
    uint64_t dwAvailVirtual;
} MEMORYSTATUS_LSW;

void __attribute__((ms_abi)) lsw_GlobalMemoryStatus(MEMORYSTATUS_LSW* lpBuffer) {
    if (!lpBuffer) return;
    lpBuffer->dwLength       = sizeof(MEMORYSTATUS_LSW);
    lpBuffer->dwMemoryLoad   = 50;
    lpBuffer->dwTotalPhys    = 8ULL * 1024 * 1024 * 1024;
    lpBuffer->dwAvailPhys    = 4ULL * 1024 * 1024 * 1024;
    lpBuffer->dwTotalPageFile= 16ULL * 1024 * 1024 * 1024;
    lpBuffer->dwAvailPageFile= 12ULL * 1024 * 1024 * 1024;
    lpBuffer->dwTotalVirtual = (uint64_t)127 * 1024 * 1024 * 1024;
    lpBuffer->dwAvailVirtual = (uint64_t)126 * 1024 * 1024 * 1024;
}

/* GlobalMemoryStatusEx — like GlobalMemoryStatus but 64-bit aware */
int __attribute__((ms_abi)) lsw_GlobalMemoryStatusEx(MEMORYSTATUS_LSW* lpBuffer) {
    if (!lpBuffer) return 0;
    lpBuffer->dwLength       = sizeof(MEMORYSTATUS_LSW);
    lpBuffer->dwMemoryLoad   = 50;
    lpBuffer->dwTotalPhys    = 8ULL * 1024 * 1024 * 1024;
    lpBuffer->dwAvailPhys    = 4ULL * 1024 * 1024 * 1024;
    lpBuffer->dwTotalPageFile= 16ULL * 1024 * 1024 * 1024;
    lpBuffer->dwAvailPageFile= 12ULL * 1024 * 1024 * 1024;
    lpBuffer->dwTotalVirtual = (uint64_t)127 * 1024 * 1024 * 1024;
    lpBuffer->dwAvailVirtual = (uint64_t)126 * 1024 * 1024 * 1024;
    return 1;
}

/* GetLargePageMinimum — large page size (not supported → 0) */
size_t __attribute__((ms_abi)) lsw_GetLargePageMinimum(void) {
    return 0;
}

/* FindFirstStreamW / FindNextStreamW — NTFS streams enumeration (not supported) */
void* __attribute__((ms_abi)) lsw_FindFirstStreamW(const uint16_t* lpFileName, int InfoLevel,
                                                     void* lpFindStreamData, uint32_t dwFlags) {
    (void)lpFileName; (void)InfoLevel; (void)lpFindStreamData; (void)dwFlags;
    /* SetLastError(ERROR_HANDLE_EOF) — no streams */
    extern void __attribute__((ms_abi)) lsw_SetLastError(uint32_t);
    lsw_SetLastError(38); /* ERROR_HANDLE_EOF */
    return (void*)(uintptr_t)-1; /* INVALID_HANDLE_VALUE */
}
int __attribute__((ms_abi)) lsw_FindNextStreamW(void* hFindStream, void* lpFindStreamData) {
    (void)hFindStream; (void)lpFindStreamData;
    extern void __attribute__((ms_abi)) lsw_SetLastError(uint32_t);
    lsw_SetLastError(18); /* ERROR_NO_MORE_FILES */
    return 0;
}

/* FileTimeToLocalFileTime — stub: return the same time */
int __attribute__((ms_abi)) lsw_FileTimeToLocalFileTime(const uint64_t* lpFileTime, uint64_t* lpLocalFileTime) {
    if (!lpFileTime || !lpLocalFileTime) return 0;
    *lpLocalFileTime = *lpFileTime;
    return 1;
}

/* FileTimeToDosDateTime — convert FILETIME to MS-DOS date/time */
int __attribute__((ms_abi)) lsw_FileTimeToDosDateTime(const uint64_t* lpFileTime,
                                                       uint16_t* lpFatDate, uint16_t* lpFatTime) {
    if (!lpFileTime || !lpFatDate || !lpFatTime) return 0;
    /* Default: 2000-01-01 00:00:00 */
    *lpFatDate = (uint16_t)((20 << 9) | (1 << 5) | 1);  /* year=2000-1980=20, month=1, day=1 */
    *lpFatTime = 0;
    return 1;
}

/* CompareFileTime — compare two FILETIME values */
int __attribute__((ms_abi)) lsw_CompareFileTime(const uint64_t* lpFileTime1, const uint64_t* lpFileTime2) {
    if (!lpFileTime1 || !lpFileTime2) return 0;
    if (*lpFileTime1 < *lpFileTime2) return -1;
    if (*lpFileTime1 > *lpFileTime2) return  1;
    return 0;
}

/* MoveFileWithProgressW — move file with optional progress callback */
int __attribute__((ms_abi)) lsw_MoveFileWithProgressW(const wchar_t* lpExistingFileName,
                                                       const wchar_t* lpNewFileName,
                                                       void* lpProgressRoutine,
                                                       void* lpData, uint32_t dwFlags) {
    (void)lpProgressRoutine; (void)lpData; (void)dwFlags;
    if (!lpExistingFileName || !lpNewFileName) return 0;
    char src[4096], dst[4096];
    /* Convert wchar_t paths to multibyte */
    wcstombs(src, lpExistingFileName, sizeof(src));
    wcstombs(dst, lpNewFileName, sizeof(dst));
    if (rename(src, dst) == 0) return 1;
    /* Cross-device: copy then remove */
    FILE* fs = fopen(src, "rb");
    if (!fs) return 0;
    FILE* fd = fopen(dst, "wb");
    if (!fd) { fclose(fs); return 0; }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fs)) > 0) fwrite(buf, 1, n, fd);
    fclose(fs); fclose(fd);
    unlink(src);
    return 1;
}

/* OpenEventW — stub returning a non-null handle */
void* __attribute__((ms_abi)) lsw_OpenEventW(uint32_t dwDesiredAccess, int bInheritHandle, const wchar_t* lpName) {
    (void)dwDesiredAccess; (void)bInheritHandle; (void)lpName;
    return (void*)1;  /* non-null fake handle */
}

/* ADVAPI32 stubs — GetSidIdentifierAuthority, InitializeSid, LookupPrivilegeDisplayNameW
   (OpenProcessToken and GetTokenInformation are defined in advapi32_api.c) */
void* __attribute__((ms_abi)) lsw_GetSidIdentifierAuthority(void* pSid) {
    /* The SID layout is: Revision(1), SubAuthorityCount(1), IdentifierAuthority[6], ...
     * Return a pointer directly into the SID's IdentifierAuthority bytes. */
    if (!pSid) {
        static uint8_t zero_auth[6] = {0};
        return zero_auth;
    }
    /* IdentifierAuthority starts at byte offset 2 in the SID */
    return (uint8_t*)pSid + 2;
}

int __attribute__((ms_abi)) lsw_InitializeSid(void* pSid, void* pIdentifierAuthority, uint8_t nSubAuthorityCount) {
    (void)pSid; (void)pIdentifierAuthority; (void)nSubAuthorityCount;
    return 1;
}

int __attribute__((ms_abi)) lsw_LookupPrivilegeDisplayNameW(const wchar_t* lpSystemName, const wchar_t* lpName,
                                                              wchar_t* lpDisplayName, uint32_t* cchDisplayName,
                                                              uint32_t* lpLanguageId);
/* implemented in advapi32_api.c */

// ============================================================================
// SECTION: Additional stubs for whoami.exe / real Windows apps
// ============================================================================

/*
 * _vsnwprintf — Windows-ABI wide-char printf into a UTF-16LE buffer.
 *
 * We cannot use Linux vswprintf() here because:
 *  1. Linux wchar_t = 4 bytes, Windows wchar_t = 2 bytes (UTF-16LE)
 *  2. The fmt string and all %s args are 2-byte UTF-16LE pointers
 *  3. args is a Windows va_list (plain char* to first variadic arg on stack),
 *     not a SysV struct va_list
 *
 * This implementation parses the UTF-16LE format string directly and reads
 * args using the Windows va_list convention (each arg is 8 bytes aligned).
 */
int __attribute__((ms_abi)) lsw__vsnwprintf(wchar_t* buf_w, size_t count, const wchar_t* fmt_w, char* ap_in) {
    if (!buf_w || count == 0 || !fmt_w) return -1;

    uint16_t* out = (uint16_t*)buf_w;
    const uint16_t* f = (const uint16_t*)fmt_w;
    size_t n = 0;
    const char* ap = ap_in; /* Windows va_list: ptr to arg area */

#define W_PUT(c)  do { if (n < count - 1) out[n++] = (uint16_t)(c); } while (0)

    while (*f) {
        if (*f != '%') { W_PUT(*f++); continue; }
        f++; /* skip '%' */

        /* flags */
        int flag_minus = 0, flag_zero = 0;
        for (;;) {
            if (*f == '-') { flag_minus = 1; f++; }
            else if (*f == '0') { flag_zero = 1; f++; }
            else if (*f == '+' || *f == ' ' || *f == '#' || *f == 'F') { f++; } /* F = Windows flag, skip */
            else break;
        }
        /* width */
        int width = 0;
        if (*f == '*') { width = *(int*)ap; ap += 8; if (width < 0) { flag_minus = 1; width = -width; } f++; }
        else { while (*f >= '0' && *f <= '9') { width = width * 10 + (*f - '0'); f++; } }
        /* precision */
        int prec = -1;
        if (*f == '.') {
            f++; prec = 0;
            if (*f == '*') { prec = *(int*)ap; ap += 8; if (prec < 0) prec = 0; f++; }
            else { while (*f >= '0' && *f <= '9') { prec = prec * 10 + (*f - '0'); f++; } }
        }
        /* length modifier — track 64-bit ('ll', 'I64', 'I' for Windows %Id) */
        int size64 = 0;
        if (*f == 'l' && *(f+1) == 'l') { size64 = 1; f += 2; }
        else if (*f == 'I' && *(f+1) == '6' && *(f+2) == '4') { size64 = 1; f += 3; }
        else { while (*f == 'l' || *f == 'h' || *f == 'L' || *f == 'z' || *f == 'I' || *f == 'w' || *f == 'F') f++; } /* w/F = Windows modifiers */

        char spec = (char)*f++;
        switch (spec) {
        case '%':
            W_PUT('%');
            break;
        case 's': {
            /* %s in Windows wprintf = wide (UTF-16LE) string */
            const uint16_t* s = *(const uint16_t**)ap; ap += 8;
            if (!s) s = (const uint16_t*)L"(null)"; /* safe fallback */
            int slen = 0; for (const uint16_t* p = s; *p; p++) slen++;
            if (prec >= 0 && slen > prec) slen = prec;
            int pad = width - slen;
            if (!flag_minus) while (pad-- > 0) W_PUT(' ');
            for (int i = 0; i < slen; i++) W_PUT(s[i]);
            if (flag_minus)  while (pad-- > 0) W_PUT(' ');
            break;
        }
        case 'S': {
            /* %S in Windows wprintf = narrow (char) string */
            const char* s = *(const char**)ap; ap += 8;
            if (!s) s = "(null)";
            int slen = (int)strlen(s);
            if (prec >= 0 && slen > prec) slen = prec;
            int pad = width - slen;
            if (!flag_minus) while (pad-- > 0) W_PUT(' ');
            for (int i = 0; i < slen; i++) W_PUT((unsigned char)s[i]);
            if (flag_minus)  while (pad-- > 0) W_PUT(' ');
            break;
        }
        case 'c': {
            unsigned int c = *(unsigned int*)ap; ap += 8;
            W_PUT(c);
            break;
        }
        case 'd': case 'i': {
            long long v = size64 ? *(long long*)ap : (long long)(*(int*)ap); ap += 8;
            char tmp[32]; int tlen = snprintf(tmp, sizeof(tmp), size64 ? "%lld" : "%d", size64 ? v : (int)v);
            int pad = width - tlen;
            char fc = (flag_zero && !flag_minus) ? '0' : ' ';
            if (!flag_minus) while (pad-- > 0) W_PUT(fc);
            for (int i = 0; i < tlen; i++) W_PUT((unsigned char)tmp[i]);
            if (flag_minus)  while (pad-- > 0) W_PUT(' ');
            break;
        }
        case 'u': {
            unsigned long long v = size64 ? *(unsigned long long*)ap : (unsigned long long)(*(unsigned int*)ap); ap += 8;
            char tmp[32]; int tlen = snprintf(tmp, sizeof(tmp), size64 ? "%llu" : "%u", size64 ? v : (unsigned int)v);
            int pad = width - tlen;
            char fc = (flag_zero && !flag_minus) ? '0' : ' ';
            if (!flag_minus) while (pad-- > 0) W_PUT(fc);
            for (int i = 0; i < tlen; i++) W_PUT((unsigned char)tmp[i]);
            if (flag_minus)  while (pad-- > 0) W_PUT(' ');
            break;
        }
        case 'x': case 'X': {
            unsigned long long v = size64 ? *(unsigned long long*)ap : (unsigned long long)(*(unsigned int*)ap); ap += 8;
            char tmp[32];
            int tlen;
            if (size64) tlen = snprintf(tmp, sizeof(tmp), spec == 'x' ? "%llx" : "%llX", v);
            else        tlen = snprintf(tmp, sizeof(tmp), spec == 'x' ? "%x"   : "%X",   (unsigned int)v);
            int pad = width - tlen;
            char fc = (flag_zero && !flag_minus) ? '0' : ' ';
            if (!flag_minus) while (pad-- > 0) W_PUT(fc);
            for (int i = 0; i < tlen; i++) W_PUT((unsigned char)tmp[i]);
            if (flag_minus)  while (pad-- > 0) W_PUT(' ');
            break;
        }
        case 'o': {
            unsigned long long v = size64 ? *(unsigned long long*)ap : (unsigned long long)(*(unsigned int*)ap); ap += 8;
            char tmp[32]; int tlen = snprintf(tmp, sizeof(tmp), size64 ? "%llo" : "%o", size64 ? v : (unsigned int)v);
            int pad = width - tlen;
            if (!flag_minus) while (pad-- > 0) W_PUT(' ');
            for (int i = 0; i < tlen; i++) W_PUT((unsigned char)tmp[i]);
            if (flag_minus)  while (pad-- > 0) W_PUT(' ');
            break;
        }
        case 'p': {
            void* v = *(void**)ap; ap += 8;
            char tmp[32]; int tlen = snprintf(tmp, sizeof(tmp), "%p", v);
            for (int i = 0; i < tlen; i++) W_PUT((unsigned char)tmp[i]);
            break;
        }
        default:
            /* Unknown specifier — pass through */
            W_PUT('%'); W_PUT(spec);
            break;
        }
    }
#undef W_PUT
    out[n] = 0;
    return (int)n;
}

/* _ultow — convert unsigned long to wchar_t (UTF-16LE) string
 * NOTE: Host swprintf uses 4-byte wchar_t (Linux UTF-32), but Windows callers
 * expect 2-byte UTF-16LE.  We must write uint16_t digits manually. */
wchar_t* __attribute__((ms_abi)) lsw__ultow(unsigned long val, wchar_t* str, int radix) {
    if (!str) return NULL;
    if (radix < 2 || radix > 36) { ((uint16_t*)str)[0] = 0; return str; }
    uint16_t* s = (uint16_t*)str;
    uint16_t  tmp[64];
    int n = 0;
    unsigned long v = val;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0) {
            unsigned int d = (unsigned int)(v % (unsigned long)radix);
            tmp[n++] = (uint16_t)(d < 10 ? '0' + d : 'a' + d - 10);
            v /= (unsigned long)radix;
        }
    }
    for (int i = 0; i < n; i++) s[i] = tmp[n - 1 - i];
    s[n] = 0;
    return str;
}

/* _memicmp — case-insensitive memcmp */
int __attribute__((ms_abi)) lsw__memicmp(const void* s1, const void* s2, size_t n) {
    const unsigned char* p1 = (const unsigned char*)s1;
    const unsigned char* p2 = (const unsigned char*)s2;
    for (size_t i = 0; i < n; i++) {
        int c = tolower(p1[i]) - tolower(p2[i]);
        if (c != 0) return c;
    }
    return 0;
}

/* _callnewh — called by operator new on allocation failure; return 0 = rethrow */
int __attribute__((ms_abi)) lsw__callnewh(size_t size) {
    (void)size;
    return 0;
}

/* operator delete(void*) — ??3@YAXPEAX@Z */
void __attribute__((ms_abi)) lsw_operator_delete(void* p) {
    free(p);
}

/* C++ exception class stubs — these are normally provided by the C++ runtime */
void __attribute__((ms_abi)) lsw_exception_ctor_cstr(void* self, const char* msg) {
    (void)self; (void)msg;
}
void __attribute__((ms_abi)) lsw_exception_ctor_cstr_h(void* self, const char* msg, int h) {
    (void)self; (void)msg; (void)h;
}
void __attribute__((ms_abi)) lsw_exception_copy_ctor(void* self, const void* other) {
    (void)self; (void)other;
}
void __attribute__((ms_abi)) lsw_exception_dtor(void* self) {
    (void)self;
}
const char* __attribute__((ms_abi)) lsw_exception_what(const void* self) {
    (void)self;
    return "exception";
}

/* ntdll stubs needed by whoami */
int __attribute__((ms_abi)) lsw_RtlVerifyVersionInfo(void* VersionInfo, uint32_t TypeMask, uint64_t ConditionMask) {
    (void)VersionInfo; (void)TypeMask; (void)ConditionMask;
    return 0; /* STATUS_SUCCESS */
}
uint64_t __attribute__((ms_abi)) lsw_VerSetConditionMask(uint64_t ConditionMask, uint32_t TypeMask, uint8_t Condition) {
    (void)TypeMask; (void)Condition;
    return ConditionMask;
}
int __attribute__((ms_abi)) lsw_RtlVirtualUnwind(uint32_t HandlerType, uint64_t ImageBase, uint64_t ControlPc,
                                                   void* FunctionEntry, void* ContextRecord, void** HandlerData,
                                                   uint64_t* EstablisherFrame, void* ContextPointers) {
    (void)HandlerType; (void)ImageBase; (void)ControlPc; (void)FunctionEntry;
    (void)ContextRecord; (void)HandlerData; (void)EstablisherFrame; (void)ContextPointers;
    return 0;
}

/* ----------------------------------------------------------------
 * SECTION: New stubs for hostname, ipconfig, and broader app compat
 * ---------------------------------------------------------------- */
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

/* --- msvcrt: _write(fd, buf, n) — low-level fd write --- */
int __attribute__((ms_abi)) lsw__write(int fd, const void* buf, unsigned int count) {
    ssize_t r = write(fd, buf, count);
    return (r < 0) ? -1 : (int)r;
}
/* --- msvcrt: _setmode(fd, mode) — set text/binary mode (no-op on Linux) --- */
int __attribute__((ms_abi)) lsw__setmode(int fd, int mode) {
    (void)fd; (void)mode;
    return 0; /* O_BINARY */
}
/* --- msvcrt: setlocale(cat, locale) --- */
char* __attribute__((ms_abi)) lsw_setlocale(int cat, const char* locale) {
    return setlocale(cat, locale);
}
/* --- msvcrt: fgetpos(stream, pos) --- */
int __attribute__((ms_abi)) lsw_fgetpos(FILE* stream, fpos_t* pos) {
    return fgetpos(stream, pos);
}
/* --- msvcrt: _vscwprintf(fmt, ap) — count wide chars that would be written --- */
int __attribute__((ms_abi)) lsw__vscwprintf(const wchar_t* fmt_w, char* ap) {
    /* Delegate to our _vsnwprintf with a null buffer trick (count=max, discard) */
    static uint16_t _discard[4096];
    return lsw__vsnwprintf((wchar_t*)_discard, sizeof(_discard)/sizeof(_discard[0]), fmt_w, ap);
}
/* --- msvcrt: vswprintf_s(buf, count, fmt, ap) --- */
int __attribute__((ms_abi)) lsw_vswprintf_s(wchar_t* buf, size_t count, const wchar_t* fmt, char* ap) {
    return lsw__vsnwprintf(buf, count, fmt, ap);
}
/* --- msvcrt: _wcsrev(str) — reverse UTF-16LE string in-place --- */
wchar_t* __attribute__((ms_abi)) lsw__wcsrev(wchar_t* str) {
    if (!str) return str;
    uint16_t* s = (uint16_t*)str;
    int len = 0;
    while (s[len]) len++;
    for (int i = 0, j = len - 1; i < j; i++, j--) {
        uint16_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }
    return str;
}

/* --- Helper: convert ASCII C string to UTF-16LE into a buffer, returns char count --- */
static int lsw_ascii_to_u16(const char* src, uint16_t* dst, int maxchars) {
    int n = 0;
    while (*src && n < maxchars - 1) dst[n++] = (uint16_t)(unsigned char)*src++;
    if (n < maxchars) dst[n] = 0;
    return n;
}

/* --- WS2_32: GetHostNameW(name, namelen) — wide version of gethostname --- */
int __attribute__((ms_abi)) lsw_GetHostNameW(wchar_t* name, int namelen) {
    if (!name || namelen <= 0) return -1; /* SOCKET_ERROR */
    char host[256] = {0};
    if (gethostname(host, sizeof(host)) != 0) return -1;
    lsw_ascii_to_u16(host, (uint16_t*)name, namelen);
    return 0;
}
/* --- WS2_32: InetNtopW(af, src, dst, size) — convert binary IP to wide string --- */
const wchar_t* __attribute__((ms_abi)) lsw_InetNtopW(int af, const void* src, wchar_t* dst, size_t size) {
    if (!dst || size == 0) return NULL;
    char tmp[INET6_ADDRSTRLEN] = {0};
    if (!inet_ntop(af, src, tmp, sizeof(tmp))) return NULL;
    lsw_ascii_to_u16(tmp, (uint16_t*)dst, (int)size);
    return dst;
}

/* --- KERNEL32: GetComputerNameExW(class, buf, size) --- */
/* NOTE: implementations are in advapi32_api.c */
extern int __attribute__((ms_abi)) lsw_GetComputerNameW(wchar_t* buf, uint32_t* size);
extern int __attribute__((ms_abi)) lsw_GetComputerNameA(char* buf, uint32_t* size);
extern int __attribute__((ms_abi)) lsw_GetComputerNameExW(int class_, wchar_t* buf, uint32_t* size);
extern int32_t __attribute__((ms_abi)) lsw_RegOpenKeyExW(void* hKey, void* lpSubKey, uint32_t ulOptions, uint32_t samDesired, void** phkResult);

/* --- KERNEL32: GetDateFormatW(locale, flags, date, fmt, datestr, cnt) --- */
int __attribute__((ms_abi)) lsw_GetDateFormatW(uint32_t locale, uint32_t flags, const void* date,
                                                 const wchar_t* fmt, wchar_t* datestr, int cnt) {
    (void)locale; (void)flags; (void)date; (void)fmt;
    /* Return a simple placeholder date */
    const char* placeholder = "2026-01-01";
    if (!datestr || cnt <= 0) return (int)(strlen(placeholder) + 1);
    lsw_ascii_to_u16(placeholder, (uint16_t*)datestr, cnt);
    return (int)(strlen(placeholder) + 1);
}

/* --- KERNEL32: RtlCaptureContext, RtlLookupFunctionEntry --- */
/* NOTE: implementations are in ntdll_api.c — just need KERNEL32 alias mappings */
extern void __attribute__((ms_abi)) lsw_RtlCaptureContext(void* ContextRecord);
extern void* __attribute__((ms_abi)) lsw_RtlLookupFunctionEntry(uint64_t pc, uint64_t* imagebase, void* history);

/* --- IPHLPAPI stubs moved to misc_api.c --- */

/* GetAdaptersAddresses — real implementation using getifaddrs() */
uint32_t __attribute__((ms_abi)) lsw_GetAdaptersAddresses_real(uint32_t Family, uint32_t Flags,
                                                                  void* Reserved, uint8_t* AdapterAddresses,
                                                                  uint32_t* SizePointer) {
    (void)Flags; (void)Reserved;
    /* Windows IP_ADAPTER_ADDRESSES struct is complex; we build a minimal subset.
     * The minimal layout for the first fixed fields (x64):
     *   +0    ULONG Length (4 bytes)
     *   +4    DWORD IfIndex (4 bytes)
     *   +8    PSIP_ADAPTER_ADDRESSES Next (8 bytes)
     *   +16   PCHAR AdapterName (8 bytes) -- ASCII GUID-style name
     *   +24   PIP_ADAPTER_UNICAST_ADDRESS FirstUnicastAddress (8 bytes)
     *   +32   ... many more fields we'll fill with 0
     *   Structure size we'll use: 448 bytes (Windows SDK value)
     */
#define LSW_AA_SIZE 448
#define LSW_MAX_ADAPTERS 8

    struct ifaddrs* ifa_head = NULL;
    if (getifaddrs(&ifa_head) != 0) {
        if (SizePointer) *SizePointer = 0;
        return 0; /* NO_ERROR but empty */
    }

    /* Count unique interface names (excluding loopback if Family == AF_INET only) */
    char seen[LSW_MAX_ADAPTERS][IF_NAMESIZE];
    int nif = 0;
    for (struct ifaddrs* p = ifa_head; p && nif < LSW_MAX_ADAPTERS; p = p->ifa_next) {
        if (!p->ifa_name || !p->ifa_addr) continue;
        if (p->ifa_addr->sa_family != AF_INET && p->ifa_addr->sa_family != AF_INET6) continue;
        if (Family == 2 /* AF_INET */ && p->ifa_addr->sa_family != AF_INET) continue;
        if (Family == 23 /* AF_INET6 */ && p->ifa_addr->sa_family != AF_INET6) continue;
        int found = 0;
        for (int i = 0; i < nif; i++) if (strcmp(seen[i], p->ifa_name) == 0) { found = 1; break; }
        if (!found) { strncpy(seen[nif++], p->ifa_name, IF_NAMESIZE-1); }
    }

    /* Each adapter: LSW_AA_SIZE bytes + adapter name string */
    uint32_t needed = (uint32_t)(nif * (LSW_AA_SIZE + 64));
    if (!AdapterAddresses || (SizePointer && *SizePointer < needed)) {
        if (SizePointer) *SizePointer = needed;
        freeifaddrs(ifa_head);
        return 111; /* ERROR_BUFFER_OVERFLOW */
    }
    if (SizePointer) *SizePointer = needed;
    memset(AdapterAddresses, 0, needed);

    uint8_t* cur = AdapterAddresses;
    for (int i = 0; i < nif; i++) {
        uint8_t* next = (i < nif-1) ? (cur + LSW_AA_SIZE + 64) : NULL;
        /* Length */
        *(uint32_t*)(cur + 0) = LSW_AA_SIZE;
        /* IfIndex: use if_nametoindex */
        *(uint32_t*)(cur + 4) = (uint32_t)if_nametoindex(seen[i]);
        /* Next pointer */
        *(uint64_t*)(cur + 8) = (uint64_t)(uintptr_t)next;
        /* AdapterName (ASCII): placed after the struct */
        char* namearea = (char*)(cur + LSW_AA_SIZE);
        strncpy(namearea, seen[i], 63);
        *(uint64_t*)(cur + 16) = (uint64_t)(uintptr_t)namearea;
        /* FriendlyName (wide): reuse namearea+64 - not strictly needed but helps */
        cur = cur + LSW_AA_SIZE + 64;
    }
    freeifaddrs(ifa_head);
    return 0; /* NO_ERROR */
}
#undef LSW_AA_SIZE
#undef LSW_MAX_ADAPTERS

/* MSWSOCK stubs */
int __attribute__((ms_abi)) lsw_GetSocketErrorMessageW(uint32_t code, wchar_t* buf, uint32_t len) {
    (void)code; if (buf && len) { ((uint16_t*)buf)[0] = 0; } return 0;
}

/* USER32 stubs */

/* ---- LoadStringW with MUI file fallback ---- *
 * Windows system executables store all strings in a side-by-side MUI file.
 * Path convention: <exe_dir>/en-US/<exe_name>.mui
 *
 * RT_STRING resource layout (type 6):
 *   - Resources stored in blocks of 16 strings per group node
 *   - Group ID = (stringID / 16) + 1
 *   - Within the group: uint16_t length followed by <length> UTF-16LE code units
 *     (NO null terminator; length==0 means empty/absent string)
 */

/* Helper: parse a PE32 or PE32+ file already mmap'd at `data`, find the
 * RT_STRING resource directory, then locate and copy string uID to lpBuffer.
 * lpBuffer is treated as a uint16_t array (Windows UTF-16, 2 bytes/char).
 * Returns char count (not including null) on success, 0 on failure.
 */
static int lsw_pe_load_string_from_image(const uint8_t* data, size_t data_len,
                                          uint32_t uID, uint16_t* lpBuffer, int cchMax) {
    if (data_len < 0x40) return 0;
    /* DOS header: e_magic at 0, e_lfanew at 0x3c */
    if (data[0] != 'M' || data[1] != 'Z') return 0;
    uint32_t pe_off = *(uint32_t*)(data + 0x3c);
    if (pe_off + 4 > data_len) return 0;
    if (memcmp(data + pe_off, "PE\0\0", 4) != 0) return 0;
    /* COFF header immediately follows "PE\0\0" */
    const uint8_t* coff = data + pe_off + 4;  /* machine, numSections, ... */
    uint16_t machine = *(uint16_t*)coff;       /* 0x8664 = x64, 0x14c = i386 */
    uint16_t num_sections = *(uint16_t*)(coff + 2);
    uint16_t opt_size     = *(uint16_t*)(coff + 16);
    const uint8_t* opt    = coff + 20;         /* start of optional header */
    if (opt + 2 > data + data_len) return 0;
    uint16_t magic = *(uint16_t*)opt;
    int is64 = (magic == 0x20b);               /* 0x10b = PE32, 0x20b = PE32+ */
    /* Offset of data directories from start of optional header:
     *   PE32:  96  (ImageBase=4B, then DWORD stack/heap values)
     *   PE32+: 112 (ImageBase=8B, then QWORD stack/heap values)
     */
    uint32_t dd_off  = is64 ? 112 : 96;
    uint32_t rsrc_rva  = 0, rsrc_size_bytes = 0;
    if (opt + dd_off + 8*3 > data + data_len) return 0; /* need at least first 3 DDs */
    /* Data directory [2] is the resource directory */
    rsrc_rva        = *(uint32_t*)(opt + dd_off + 8*2);
    rsrc_size_bytes = *(uint32_t*)(opt + dd_off + 8*2 + 4);
    if (!rsrc_rva || !rsrc_size_bytes) return 0;

    /* Section table starts after optional header */
    const uint8_t* sections = coff + 20 + opt_size;
    /* Find the section that contains rsrc_rva */
    uint32_t rsrc_raw_off = 0;
    for (int s = 0; s < num_sections; s++) {
        const uint8_t* sec = sections + s * 40;
        uint32_t vaddr     = *(uint32_t*)(sec + 12);
        uint32_t vsize     = *(uint32_t*)(sec + 16);
        uint32_t raw_off   = *(uint32_t*)(sec + 20);
        if (rsrc_rva >= vaddr && rsrc_rva < vaddr + vsize) {
            rsrc_raw_off = raw_off + (rsrc_rva - vaddr);
            break;
        }
    }
    if (!rsrc_raw_off || rsrc_raw_off + rsrc_size_bytes > data_len) return 0;

    const uint8_t* rsrc_base = data + rsrc_raw_off;  /* raw data at resource directory */

    /* Resource directory entry layout (8 bytes):
     *   DWORD NameOrID    (high bit set = named, else ID)
     *   DWORD OffsetToData (high bit set = subdirectory offset, else leaf RVA)
     */
    /* Level 1: find RT_STRING (type ID = 6) */
    uint16_t root_named  = *(uint16_t*)(rsrc_base + 12);
    uint16_t root_id     = *(uint16_t*)(rsrc_base + 14);
    uint32_t total_root  = root_named + root_id;
    uint32_t rt_string_off = 0;
    for (uint32_t i = 0; i < total_root; i++) {
        const uint8_t* entry = rsrc_base + 16 + i * 8;
        uint32_t id  = *(uint32_t*)entry;
        uint32_t off = *(uint32_t*)(entry + 4);
        if ((id & 0x80000000) == 0 && id == 6) {  /* RT_STRING = 6, not named */
            if (off & 0x80000000) rt_string_off = off & 0x7FFFFFFF;
            break;
        }
    }
    if (!rt_string_off) return 0;

    /* Level 2: find group (gid = uID/16 + 1) */
    uint32_t gid = (uID / 16) + 1;
    const uint8_t* l2 = rsrc_base + rt_string_off;
    uint16_t l2_named  = *(uint16_t*)(l2 + 12);
    uint16_t l2_id     = *(uint16_t*)(l2 + 14);
    uint32_t total_l2  = l2_named + l2_id;
    uint32_t group_off = 0;
    for (uint32_t i = 0; i < total_l2; i++) {
        const uint8_t* entry = l2 + 16 + i * 8;
        uint32_t id  = *(uint32_t*)entry;
        uint32_t off = *(uint32_t*)(entry + 4);
        if ((id & 0x80000000) == 0 && id == gid) {
            if (off & 0x80000000) group_off = off & 0x7FFFFFFF;
            break;
        }
    }
    if (!group_off) return 0;

    /* Level 3: first (only) language entry — gives us the leaf data entry */
    const uint8_t* l3 = rsrc_base + group_off;
    if (*(uint16_t*)(l3 + 12) + *(uint16_t*)(l3 + 14) == 0) return 0;
    /* The level-3 directory entry OffsetToData points (high bit CLEAR) to
     * an IMAGE_RESOURCE_DATA_ENTRY: [DataRVA(4)][Size(4)][CodePage(4)][Reserved(4)] */
    const uint8_t* l3_entry  = l3 + 16;
    uint32_t leaf_de_off = *(uint32_t*)(l3_entry + 4);  /* OffsetToData → offset to DATA_ENTRY */
    const uint8_t* de    = rsrc_base + leaf_de_off;
    uint32_t data_rva  = *(uint32_t*)(de + 0);
    uint32_t data_size = *(uint32_t*)(de + 4);
    /* Convert RVA to raw offset */
    uint32_t data_raw = 0;
    for (int s = 0; s < num_sections; s++) {
        const uint8_t* sec = sections + s * 40;
        uint32_t vaddr   = *(uint32_t*)(sec + 12);
        uint32_t vsize   = *(uint32_t*)(sec + 16);
        uint32_t raw_off = *(uint32_t*)(sec + 20);
        if (data_rva >= vaddr && data_rva < vaddr + vsize) {
            data_raw = raw_off + (data_rva - vaddr);
            break;
        }
    }
    if (!data_raw || data_raw + data_size > data_len) return 0;

    /* Walk the string block to find index (uID % 16) */
    const uint8_t* p   = data + data_raw;
    const uint8_t* end = p + data_size;
    uint32_t idx = uID % 16;
    for (uint32_t i = 0; i < 16 && p + 2 <= end; i++) {
        uint16_t len = *(uint16_t*)p;
        p += 2;
        if (i == idx) {
            if (len == 0) return 0;  /* empty string */
            int copy = (int)len < (cchMax - 1) ? (int)len : (cchMax - 1);
            memcpy(lpBuffer, p, copy * sizeof(uint16_t));
            lpBuffer[copy] = 0;   /* null-terminate as uint16_t (2 bytes) */
            return copy;
        }
        p += len * 2;  /* skip UTF-16 chars */
    }
    return 0;
    (void)machine; /* suppress unused warning for non-64-bit paths */
}

/* Build MUI path: /path/to/foo.exe → /path/to/en-US/foo.exe.mui */
static void lsw_build_mui_path(const char* exe_path, char* mui_out, size_t mui_sz) {
    /* Find last '/' */
    const char* slash = strrchr(exe_path, '/');
    const char* base  = slash ? slash + 1 : exe_path;
    size_t dir_len    = slash ? (size_t)(slash - exe_path) : 0;
    if (dir_len + strlen("/en-US/") + strlen(base) + strlen(".mui") + 1 > mui_sz) {
        mui_out[0] = '\0';
        return;
    }
    if (dir_len > 0) {
        memcpy(mui_out, exe_path, dir_len);
        mui_out[dir_len] = '\0';
    } else {
        mui_out[0] = '.';
        mui_out[1] = '\0';
    }
    strcat(mui_out, "/en-US/");
    strcat(mui_out, base);
    strcat(mui_out, ".mui");
}

/* Cached MUI data */
static uint8_t* g_mui_data    = NULL;
static size_t   g_mui_data_len = 0;

int __attribute__((ms_abi)) lsw_LoadStringW(void* hInstance, uint32_t uID, uint16_t* lpBuffer, int cchBufferMax) {
    (void)hInstance;
    LSW_LOG_DEBUG("LoadStringW(hInst=%p, uID=%u, buf=%p, max=%d)", hInstance, uID, (void*)lpBuffer, cchBufferMax);
    if (!lpBuffer || cchBufferMax <= 0) return 0;
    lpBuffer[0] = 0;

    /* Lazy-load and cache the MUI file */
    if (!g_mui_data && g_lsw_exe_path[0]) {
        char mui_path[4200];
        lsw_build_mui_path(g_lsw_exe_path, mui_path, sizeof(mui_path));
        LSW_LOG_INFO("LoadStringW: trying MUI file: %s", mui_path);
        int fd = open(mui_path, O_RDONLY);
        if (fd >= 0) {
            off_t fsz = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);
            if (fsz > 0) {
                g_mui_data = malloc((size_t)fsz);
                if (g_mui_data) {
                    ssize_t rd = read(fd, g_mui_data, (size_t)fsz);
                    if (rd > 0) {
                        g_mui_data_len = (size_t)rd;
                        LSW_LOG_INFO("LoadStringW: loaded MUI (%zu bytes)", g_mui_data_len);
                    } else {
                        free(g_mui_data); g_mui_data = NULL;
                    }
                }
            }
            close(fd);
        } else {
            LSW_LOG_WARN("LoadStringW: MUI file not found: %s", mui_path);
        }
    }

    /* Also try the main EXE's resources (in case strings are embedded) */
    if (!g_mui_data && g_lsw_exe_path[0]) {
        LSW_LOG_DEBUG("LoadStringW: no MUI, trying main EXE resources");
        int fd = open(g_lsw_exe_path, O_RDONLY);
        if (fd >= 0) {
            off_t fsz = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);
            if (fsz > 0) {
                uint8_t* tmp = malloc((size_t)fsz);
                if (tmp) {
                    ssize_t rd = read(fd, tmp, (size_t)fsz);
                    if (rd > 0) {
                        int r = lsw_pe_load_string_from_image(tmp, (size_t)rd, uID, lpBuffer, cchBufferMax);
                        free(tmp);
                        close(fd);
                        if (r > 0) {
                            LSW_LOG_DEBUG("LoadStringW: uID=%u found in main EXE (%d chars)", uID, r);
                            return r;
                        }
                        goto not_found;
                    }
                    free(tmp);
                }
            }
            close(fd);
        }
    }

    if (g_mui_data && g_mui_data_len > 0) {
        int r = lsw_pe_load_string_from_image(g_mui_data, g_mui_data_len, uID, lpBuffer, cchBufferMax);
        if (r > 0) {
            char narrow[256] = {0};
            int  nc = r < 127 ? r : 127;
            for (int i = 0; i < nc; i++) narrow[i] = (lpBuffer[i] < 128) ? (char)lpBuffer[i] : '?';
            LSW_LOG_DEBUG("LoadStringW: uID=%u buf=%p -> \"%s\" (%d chars)", uID, (void*)lpBuffer, narrow, r);
            return r;
        }
    }

not_found:
    LSW_LOG_DEBUG("LoadStringW: uID=%u not found", uID);
    return 0;
}

/* LoadStringA — narrow wrapper around LoadStringW */
int __attribute__((ms_abi)) lsw_LoadStringA(void* hInstance, uint32_t uID, char* lpBuffer, int cchBuffer) {
    if (!lpBuffer || cchBuffer <= 0) {
        /* Probe: call W version with NULL buffer to get length */
        uint16_t tmp[512];
        return lsw_LoadStringW(hInstance, uID, tmp, 512);
    }
    uint16_t wbuf[512];
    int r = lsw_LoadStringW(hInstance, uID, wbuf, 512);
    if (r <= 0) return 0;
    int out = 0;
    for (int i = 0; i < r && out < cchBuffer - 1; i++)
        lpBuffer[out++] = (char)(wbuf[i] < 0x80 ? wbuf[i] : '?');
    lpBuffer[out] = '\0';
    return out;
}
wchar_t* __attribute__((ms_abi)) lsw_CharLowerW(wchar_t* lpsz) {
    if (!lpsz) return NULL;
    for (u16* p = (u16*)lpsz; *p; p++) *p = (u16)towlower(*p);
    return lpsz;
}
wchar_t* __attribute__((ms_abi)) lsw_CharUpperW(wchar_t* lpsz) {
    if (!lpsz) return NULL;
    for (u16* p = (u16*)lpsz; *p; p++) *p = (u16)towupper(*p);
    return lpsz;
}

/* SspiCli stubs */
int __attribute__((ms_abi)) lsw_GetUserNameExW(int NameFormat, wchar_t* lpNameBuffer, uint32_t* nSize) {
    struct passwd* pw = getpwuid(getuid());
    const char* user = pw ? pw->pw_name : "user";
    char full[256];
    /* NameSamCompatible (2) returns "DOMAIN\user" */
    if (NameFormat == 2)
        snprintf(full, sizeof(full), "LSW\\%s", user);
    else
        snprintf(full, sizeof(full), "%s", user);
    uint32_t len = (uint32_t)strlen(full);
    LSW_LOG_DEBUG("GetUserNameExW(fmt=%d) -> \"%s\"", NameFormat, full);
    if (!nSize) return 0;
    if (*nSize < len + 1) {
        *nSize = len + 1;
        lsw_SetLastError(122); /* ERROR_INSUFFICIENT_BUFFER */
        return 0;
    }
    if (lpNameBuffer) {
        for (uint32_t i = 0; i <= len; i++)
            lpNameBuffer[i] = (uint16_t)(unsigned char)full[i];
    }
    *nSize = len;
    return 1;
}
int __attribute__((ms_abi)) lsw_LsaConnectUntrusted(void** LsaHandle) {
    if (LsaHandle) *LsaHandle = (void*)(uintptr_t)0xBEEF2;
    return 0;
}
int __attribute__((ms_abi)) lsw_LsaCallAuthenticationPackage(void* LsaHandle, uint32_t AuthPackage,
                                                               void* ProtocolSubmitBuffer, uint32_t SubmitBufferLength,
                                                               void** ProtocolReturnBuffer, uint32_t* ReturnBufferLength,
                                                               int* ProtocolStatus) {
    (void)LsaHandle; (void)AuthPackage; (void)ProtocolSubmitBuffer; (void)SubmitBufferLength;
    if (ProtocolReturnBuffer) *ProtocolReturnBuffer = NULL;
    if (ReturnBufferLength) *ReturnBufferLength = 0;
    if (ProtocolStatus) *ProtocolStatus = 0xC0000001; /* STATUS_UNSUCCESSFUL */
    return 0xC0000001;
}
int __attribute__((ms_abi)) lsw_LsaLookupAuthenticationPackage(void* LsaHandle, void* PackageName, uint32_t* AuthPackage) {
    (void)LsaHandle; (void)PackageName;
    if (AuthPackage) *AuthPackage = 0;
    return 0;
}

/* LsaOpenPolicy / LsaQueryInformationPolicy stubs for net user <name> display */
static void* g_lsa_policy_handle = (void*)(uintptr_t)0xBEEF3;
int __attribute__((ms_abi)) lsw_LsaOpenPolicy(void* SystemName, void* ObjectAttributes,
                                                uint32_t DesiredAccess, void** PolicyHandle) {
    (void)SystemName; (void)ObjectAttributes; (void)DesiredAccess;
    LSW_LOG_INFO("LsaOpenPolicy called");
    if (PolicyHandle) *PolicyHandle = g_lsa_policy_handle;
    return 0; /* STATUS_SUCCESS */
}
int __attribute__((ms_abi)) lsw_LsaQueryInformationPolicy(void* PolicyHandle, uint32_t InformationClass,
                                                            void** Buffer) {
    (void)PolicyHandle;
    LSW_LOG_INFO("LsaQueryInformationPolicy(class=%u)", InformationClass);
    if (!Buffer) return 0xC000000D; /* STATUS_INVALID_PARAMETER */
    *Buffer = NULL;
    if (InformationClass == 5) {
        /* PolicyAccountDomainInformation — returns POLICY_ACCOUNT_DOMAIN_INFO
         * Layout (x64): [0] LSA_UNICODE_STRING DomainName (16 bytes)
         *                   +0 Length(u16), +2 MaxLen(u16), +4 pad, +8 Buffer*
         *               [16] DomainSid (PSID, 8 bytes)
         * Total header: 24 bytes + string data appended */
        lsw_ensure_computername();
        size_t name_len = 0;
        for (const uint16_t* p = g_computername_w; *p; p++) name_len++;
        size_t str_bytes = (name_len + 1) * 2;
        uint8_t* buf = (uint8_t*)calloc(24 + str_bytes, 1);
        if (!buf) return 0xC0000017; /* STATUS_NO_MEMORY */
        uint16_t* str = (uint16_t*)(buf + 24);
        for (size_t i = 0; i <= name_len; i++) str[i] = g_computername_w[i];
        *(uint16_t*)(buf +  0) = (uint16_t)(name_len * 2);   /* Length */
        *(uint16_t*)(buf +  2) = (uint16_t)(str_bytes);       /* MaximumLength */
        *(uint64_t*)(buf +  8) = (uint64_t)(uintptr_t)str;    /* Buffer */
        *(uint64_t*)(buf + 16) = 0;                            /* DomainSid = NULL */
        *Buffer = buf;
        return 0; /* STATUS_SUCCESS */
    }
    /* Unsupported class — return empty buffer */
    uint8_t* buf = (uint8_t*)calloc(32, 1);
    *Buffer = buf;
    return 0;
}
int __attribute__((ms_abi)) lsw_LsaFreeMemory(void* Buffer) {
    if (Buffer) free(Buffer);
    return 0;
}
int __attribute__((ms_abi)) lsw_LsaClose(void* ObjectHandle) {
    (void)ObjectHandle;
    return 0;
}
int __attribute__((ms_abi)) lsw_LsaLookupSids(void* PolicyHandle, uint32_t Count,
                                                void** Sids, void** ReferencedDomains, void** Names) {
    (void)PolicyHandle; (void)Count; (void)Sids;
    if (ReferencedDomains) *ReferencedDomains = NULL;
    if (Names) *Names = NULL;
    return 0xC0000073; /* STATUS_NONE_MAPPED */
}
int __attribute__((ms_abi)) lsw_LsaLookupNames2(void* PolicyHandle, uint32_t Flags, uint32_t Count,
                                                  void* Names, void** ReferencedDomains, void** Sids) {
    (void)PolicyHandle; (void)Flags; (void)Count; (void)Names;
    if (ReferencedDomains) *ReferencedDomains = NULL;
    if (Sids) *Sids = NULL;
    return 0xC0000073; /* STATUS_NONE_MAPPED */
}
int __attribute__((ms_abi)) lsw_LsaOpenPolicy2(void* SystemName, void* ObjectAttributes,
                                                 uint32_t DesiredAccess, void** PolicyHandle) {
    (void)SystemName; (void)ObjectAttributes; (void)DesiredAccess;
    if (PolicyHandle) *PolicyHandle = g_lsa_policy_handle;
    return 0;
}

/* AUTHZ stubs */
void __attribute__((ms_abi)) lsw_FreeClaimDefinitions(void* p) { (void)p; }
int  __attribute__((ms_abi)) lsw_InitializeClaimDictionary(void** dict) { if (dict) *dict = NULL; return 0; }
int  __attribute__((ms_abi)) lsw_GetClaimDefinitions(void* a, void* b, void* c) { (void)a;(void)b;(void)c; return 0; }
void __attribute__((ms_abi)) lsw_FreeClaimDictionary(void* p) { (void)p; }

/* wkscli / netutils stubs */
int  __attribute__((ms_abi)) lsw_NetGetJoinInformation(const wchar_t* server, wchar_t** name, int* type) {
    (void)server;
    if (name) *name = NULL;
    if (type) *type = 0;
    return 2; /* NERR_WkstaNotStarted */
}
int __attribute__((ms_abi)) lsw_NetApiBufferFree(void* Buffer) { free(Buffer); return 0; }
int __attribute__((ms_abi)) lsw_NetWkstaUserGetInfo(uint16_t* server, uint32_t level, uint8_t** bufptr) {
    (void)server;
    LSW_LOG_INFO("NetWkstaUserGetInfo(level=%u)", level);
    if (!bufptr) return 87;
    if (level != 0 && level != 1) { *bufptr = NULL; return 2102; }
    lsw_ensure_computername();
    /* Get current username */
    char uname[64] = "user";
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_name) strncpy(uname, pw->pw_name, 63);
    int ulen = (int)strlen(uname);
    const char* dom  = "WORKGROUP";  int dlen = (int)strlen(dom);
    const char* odom = "";           int olen = 0;
    /* WKSTA_USER_INFO_1: 4 LPWSTR at offsets 0,8,16,24 = 32 bytes + strings */
    int hdr = (level == 1) ? 32 : 8;
    uint8_t* buf = (uint8_t*)calloc((size_t)hdr + (size_t)(ulen+1)*2 + (size_t)(dlen+1)*2
                                    + (size_t)(olen+1)*2, 1);
    if (!buf) { *bufptr = NULL; return 8; }
    uint16_t* uptr = (uint16_t*)(buf + hdr);
    uint16_t* dptr = uptr + ulen + 1;
    uint16_t* optr = dptr + dlen + 1;
    *(uint64_t*)(buf + 0) = (uint64_t)(uintptr_t)uptr;
    if (level == 1) {
        *(uint64_t*)(buf + 8)  = (uint64_t)(uintptr_t)dptr;
        *(uint64_t*)(buf + 16) = (uint64_t)(uintptr_t)optr;
        *(uint64_t*)(buf + 24) = (uint64_t)(uintptr_t)g_computername_w;
    }
    for (int i = 0; i < ulen; i++) uptr[i] = (uint16_t)(unsigned char)uname[i];
    for (int i = 0; i < dlen; i++) dptr[i] = (uint16_t)(unsigned char)dom[i];
    *bufptr = buf;
    LSW_LOG_INFO("NetWkstaUserGetInfo: user='%s' domain='%s'", uname, dom);
    return 0;
}
/* WKSTA_INFO_100: platform_id(+0 DWORD), pad(+4), computername(+8 ptr), langroup(+16 ptr),
 *                 ver_major(+24 DWORD), ver_minor(+28 DWORD) = 32 bytes header + strings */
int __attribute__((ms_abi)) lsw_NetWkstaGetInfo(uint16_t* server, uint32_t level, uint8_t** bufptr) {
    (void)server;
    LSW_LOG_INFO("NetWkstaGetInfo(level=%u)", level);
    if (!bufptr) return 87; /* ERROR_INVALID_PARAMETER */
    if (level != 100 && level != 101 && level != 102) { *bufptr = NULL; return 2102; }
    lsw_ensure_computername();
    const char* wg = "WORKGROUP";
    int wglen = (int)strlen(wg);
    /* struct header: 40 bytes for level 101 (includes lanroot ptr), 32 bytes for 100 */
    int hdr = (level >= 101) ? 40 : 32;
    uint8_t* buf = (uint8_t*)calloc((size_t)hdr + (size_t)(wglen + 1) * 2, 1);
    if (!buf) { *bufptr = NULL; return 8; }
    *(uint32_t*)(buf + 0) = 500; /* SV_PLATFORM_ID_NT */
    uint16_t* wg_ptr = (uint16_t*)(buf + hdr);
    *(uint64_t*)(buf + 8)  = (uint64_t)(uintptr_t)g_computername_w; /* persistent — survives free */
    *(uint64_t*)(buf + 16) = (uint64_t)(uintptr_t)wg_ptr;
    *(uint32_t*)(buf + 24) = 10; /* ver_major: Windows 10 */
    *(uint32_t*)(buf + 28) = 0;  /* ver_minor */
    if (level >= 101) *(uint64_t*)(buf + 32) = 0; /* wki101_lanroot: null */
    for (int i = 0; i < wglen; i++) wg_ptr[i] = (uint16_t)(unsigned char)wg[i];
    *bufptr = buf;
    LSW_LOG_INFO("NetWkstaGetInfo: returning hostname='%s' ptr=%p", g_computername_a, (void*)g_computername_w);
    return 0; /* NERR_Success */
}
int __attribute__((ms_abi)) lsw_NetServerEnum(uint16_t* server, uint32_t level, uint8_t** bufptr,
    uint32_t prefmaxlen, uint32_t* entriesread, uint32_t* totalentries,
    uint32_t servertype, uint16_t* domain, uint32_t* resume_handle) {
    (void)server; (void)level; (void)prefmaxlen; (void)servertype; (void)domain; (void)resume_handle;
    if (bufptr) *bufptr = NULL;
    if (entriesread) *entriesread = 0;
    if (totalentries) *totalentries = 0;
    return 2118; /* NERR_NetworkError */
}
int __attribute__((ms_abi)) lsw_CredUICmdLinePromptForCredentialsW(
    const uint16_t* pszTargetName, void* pContext, uint32_t dwAuthError,
    uint16_t* UserName, uint32_t ulUserNameBufferSize,
    uint16_t* pszPassword, uint32_t ulPasswordBufferSize,
    int* pfSave, uint32_t dwFlags) {
    (void)pszTargetName; (void)pContext; (void)dwAuthError; (void)dwFlags;
    if (UserName && ulUserNameBufferSize > 0) UserName[0] = 0;
    if (pszPassword && ulPasswordBufferSize > 0) pszPassword[0] = 0;
    if (pfSave) *pfSave = 0;
    return 1223; /* ERROR_CANCELLED */
}

/* NetApiBufferAllocate / NetapipBufferAllocate — actual malloc so callers can use the pointer */
int __attribute__((ms_abi)) lsw_NetApiBufferAllocate(uint32_t ByteCount, void** Buffer) {
    if (!Buffer) return 87; /* ERROR_INVALID_PARAMETER */
    *Buffer = calloc(1, ByteCount ? ByteCount : 1);
    return *Buffer ? 0 : 8; /* 0=NERR_Success, 8=ERROR_NOT_ENOUGH_MEMORY */
}
int __attribute__((ms_abi)) lsw_NetapipBufferAllocate(uint32_t ByteCount, void** Buffer) {
    return lsw_NetApiBufferAllocate(ByteCount, Buffer);
}
int __attribute__((ms_abi)) lsw_NetApiBufferReallocate(void* OldBuffer, uint32_t NewByteCount, void** NewBuffer) {
    if (!NewBuffer) return 87;
    *NewBuffer = realloc(OldBuffer, NewByteCount ? NewByteCount : 1);
    return *NewBuffer ? 0 : 8;
}
/* NetpwNameValidate / NetpwPathType — stub (validation always passes) */
int __attribute__((ms_abi)) lsw_NetpwNameValidate(uint16_t* Name, uint32_t NameType, uint32_t Flags) {
    (void)Name; (void)NameType; (void)Flags; return 0;
}
int __attribute__((ms_abi)) lsw_NetpwPathType(uint16_t* PathName, uint32_t* PathType, uint32_t Flags) {
    (void)PathName; (void)Flags; if (PathType) *PathType = 0; return 0;
}

/* GetCPInfo — fill CPINFO for a given code page; report UTF-8 / no lead bytes */
typedef struct { uint32_t MaxCharSize; uint8_t DefaultChar[2]; uint8_t LeadByte[12]; } LSW_CPINFO;
int __attribute__((ms_abi)) lsw_GetCPInfo(uint32_t CodePage, LSW_CPINFO* lpCPInfo) {
    (void)CodePage;
    if (!lpCPInfo) { lsw_SetLastError(87); return 0; }
    lpCPInfo->MaxCharSize    = 1;
    lpCPInfo->DefaultChar[0] = '?';
    lpCPInfo->DefaultChar[1] = 0;
    memset(lpCPInfo->LeadByte, 0, sizeof(lpCPInfo->LeadByte));
    return 1; /* TRUE */
}

/* ApiSetQueryApiSetPresence — always report "not present" (safe no-op) */
int __attribute__((ms_abi)) lsw_ApiSetQueryApiSetPresence(uint16_t* Namespace, int* Present) {
    (void)Namespace;
    if (Present) *Present = 0;
    return 1; /* TRUE */
}

/* RegOpenKeyW — thin wrapper around RegOpenKeyExW */
int32_t __attribute__((ms_abi)) lsw_RegOpenKeyW(void* hKey, uint16_t* lpSubKey, void** phkResult) {
    return lsw_RegOpenKeyExW((void*)hKey, (void*)lpSubKey, 0, 0x20019 /* KEY_READ */, (void*)phkResult);
}

/* --- Wide-string functions missing from msvcrt.dll mappings --- */
/* These operate on UTF-16LE (2-byte) strings, not 4-byte Linux wchar_t. */
static size_t u16_wcsspn(const uint16_t* str, const uint16_t* accept)
{
    if (!str || !accept) return 0;
    size_t n = 0;
    while (str[n]) {
        const uint16_t* a = accept;
        int found = 0;
        while (*a) { if (*a == str[n]) { found = 1; break; } a++; }
        if (!found) break;
        n++;
    }
    return n;
}
static size_t u16_wcscspn(const uint16_t* str, const uint16_t* reject)
{
    if (!str || !reject) return 0;
    size_t n = 0;
    while (str[n]) {
        const uint16_t* r = reject;
        while (*r) { if (*r == str[n]) return n; r++; }
        n++;
    }
    return n;
}
static uint16_t* u16_wcspbrk(const uint16_t* str, const uint16_t* accept)
{
    if (!str || !accept) return NULL;
    for (; *str; str++) {
        const uint16_t* a = accept;
        while (*a) { if (*a == *str) return (uint16_t*)str; a++; }
    }
    return NULL;
}
size_t __attribute__((ms_abi)) lsw_wcsspn(const uint16_t* str, const uint16_t* accept) {
    return u16_wcsspn(str, accept);
}
uint16_t* __attribute__((ms_abi)) lsw_wcspbrk(const uint16_t* str, const uint16_t* accept) {
    return u16_wcspbrk(str, accept);
}
size_t __attribute__((ms_abi)) lsw_wcscspn(const uint16_t* str, const uint16_t* reject) {
    return u16_wcscspn(str, reject);
}
uint16_t* __attribute__((ms_abi)) lsw__wcsupr(uint16_t* str) {
    if (!str) return NULL;
    for (uint16_t* p = str; *p; p++) {
        uint16_t c = *p;
        if (c >= 'a' && c <= 'z') *p = c - 32;
    }
    return str;
}
int __attribute__((ms_abi)) lsw__wtoi(const uint16_t* str) {
    if (!str) return 0;
    while (*str == ' ' || *str == '\t') str++;
    int neg = 0; int val = 0;
    if (*str == '-') { neg = 1; str++; } else if (*str == '+') str++;
    while (*str >= '0' && *str <= '9') { val = val * 10 + (*str - '0'); str++; }
    return neg ? -val : val;
}
int64_t __attribute__((ms_abi)) lsw__wtoi64(const uint16_t* str) {
    if (!str) return 0;
    while (*str == ' ' || *str == '\t') str++;
    int neg = 0; int64_t val = 0;
    if (*str == '-') { neg = 1; str++; } else if (*str == '+') str++;
    while (*str >= '0' && *str <= '9') { val = val * 10 + (*str - '0'); str++; }
    return neg ? -val : val;
}
int __attribute__((ms_abi)) lsw_iswctype(wint_t c, unsigned long desc) {
    return iswctype(c, desc);
}
int __attribute__((ms_abi)) lsw_wcsncat_s(u16* dst, size_t dstSz, const u16* src, size_t count) {
    if (!dst || !src || dstSz == 0) return 22; /* EINVAL */
    size_t len = u16_len(dst);
    if (len >= dstSz) return 22;
    size_t rem = dstSz - len - 1;
    size_t n = (count == (size_t)-1 || count > rem) ? rem : count;
    u16_ncpy(dst + len, src, n);
    dst[len + n] = 0;
    return 0;
}
int __attribute__((ms_abi)) lsw_wcsncpy_s(u16* dst, size_t dstSz, const u16* src, size_t count) {
    if (!dst || dstSz == 0) return 22;
    if (!src) { dst[0] = 0; return 0; }
    size_t n = (count == (size_t)-1 || count >= dstSz) ? dstSz - 1 : count;
    u16_ncpy(dst, src, n);
    dst[n] = 0;
    return 0;
}
int __attribute__((ms_abi)) lsw__snwprintf_s(wchar_t* buf, size_t bufSz, size_t count, const wchar_t* fmt, ...) {
    if (!buf || bufSz == 0) return -1;
    (void)count;
    __builtin_ms_va_list ms_ap; __builtin_ms_va_start(ms_ap, fmt);
    int r = lsw__vsnwprintf(buf, bufSz, fmt, (char*)ms_ap);
    __builtin_ms_va_end(ms_ap); return r;
}
int __attribute__((ms_abi)) lsw__vsnwprintf_s(wchar_t* buf, size_t bufSz, size_t count, const wchar_t* fmt, char* ap) {
    if (!buf || bufSz == 0) return -1;
    (void)count;
    return lsw__vsnwprintf(buf, bufSz, fmt, ap);
}
void __attribute__((ms_abi)) lsw__local_unwind(void* frame, void* target) {
    (void)frame; (void)target; /* no-op on Linux — no SEH unwinding needed */
}

/* --- NetAPI / SMB / MPR stubs --- */
int __attribute__((ms_abi)) lsw_NetUseGetInfo(uint16_t* server, uint16_t* useName, uint32_t level, uint8_t** bufptr) {
    (void)server; (void)useName; (void)level; if (bufptr) *bufptr = NULL; return 2102;
}
int __attribute__((ms_abi)) lsw_NetUseEnum(uint16_t* server, uint32_t level, uint8_t** bufptr,
    uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 2102;
}
/* NetUserGetInfo — look up a Linux user in /etc/passwd */
int __attribute__((ms_abi)) lsw_NetUserGetInfo(uint16_t* server, uint16_t* username, uint32_t level, uint8_t** bufptr) {
    (void)server;
    if (bufptr) *bufptr = NULL;
    if (!username) { lsw_SetLastError(87); return 87; }
    LSW_LOG_INFO("NetUserGetInfo(level=%u)", level);
    if (level != 0 && level != 1 && level != 3 && level != 10 && level != 20 && level != 23) return 50; /* ERROR_NOT_SUPPORTED */
    /* Convert UTF-16LE username to UTF-8 */
    char name[64] = {0};
    for (int i = 0; i < 63 && username[i]; i++) name[i] = (char)(unsigned char)username[i];
    /* Look up in /etc/passwd */
    struct passwd* pw_ent = getpwnam(name);
    if (!pw_ent) {
        /* Also check case-insensitively */
        struct passwd* e; setpwent();
        while ((e = getpwent()) != NULL) {
            if (strcasecmp(e->pw_name, name) == 0) { pw_ent = e; break; }
        }
        endpwent();
    }
    if (!pw_ent) return 2221; /* NERR_UserNotFound */
    /* Get the real username (canonical case) */
    const char* rname = pw_ent->pw_name;
    const char* gecos = pw_ent->pw_gecos ? pw_ent->pw_gecos : "";
    /* Strip trailing comma from GECOS field if present */
    char fullname[128] = {0};
    strncpy(fullname, gecos, sizeof(fullname) - 1);
    char* comma = strchr(fullname, ',');
    if (comma) *comma = '\0';
    const char* comment = "";
    const char* homedir = pw_ent->pw_dir ? pw_ent->pw_dir : "";
    const char* shell = pw_ent->pw_shell ? pw_ent->pw_shell : "";
    /* Helper: append UTF-16LE string and return pointer to it */
#define WSTR_APPEND(buf, pos, s) ({ \
    uint16_t* _p = (uint16_t*)((buf) + (pos)); \
    size_t _l = strlen(s); \
    for (size_t _i = 0; _i < _l; _i++) _p[_i] = (uint16_t)(unsigned char)(s)[_i]; \
    _p[_l] = 0; \
    (pos) += ((int)_l + 1) * 2; \
    _p; })
    if (level == 0) {
        /* USER_INFO_0: { LPWSTR name } */
        size_t nlen = strlen(rname);
        uint8_t* buf = (uint8_t*)calloc(1, 8 + (nlen + 1) * 2);
        if (!buf) return 8;
        int pos = 8;
        *(uint16_t**)(buf + 0) = WSTR_APPEND(buf, pos, rname);
        *bufptr = buf; return 0;
    }
    if (level == 1) {
        /* USER_INFO_1: name, password(NULL), password_age(DWORD), priv(DWORD), home_dir, comment, flags(DWORD), script_path */
        /* Layout: 4 LPWSTR (@0,8,24,40) + 3 DWORD (at 16,20,32) padded + 1 LPWSTR (@40)... */
        /* +0  LPWSTR name, +8 LPWSTR password, +16 DWORD age, +20 DWORD priv,
           +24 LPWSTR home_dir, +32 LPWSTR comment, +40 DWORD flags, +44 pad, +48 LPWSTR script */
        size_t strsz = (strlen(rname)+1)*2 + (strlen(comment)+1)*2 + (strlen(homedir)+1)*2 + 2 /* empty script */;
        uint8_t* buf = (uint8_t*)calloc(1, 56 + strsz);
        if (!buf) return 8;
        int pos = 56;
        *(uint16_t**)(buf + 0)  = WSTR_APPEND(buf, pos, rname);
        *(uint16_t**)(buf + 8)  = NULL; /* password */
        *(uint32_t*)(buf + 16)  = 0;   /* password_age */
        *(uint32_t*)(buf + 20)  = 1;   /* USER_PRIV_USER */
        *(uint16_t**)(buf + 24) = WSTR_APPEND(buf, pos, homedir);
        *(uint16_t**)(buf + 32) = WSTR_APPEND(buf, pos, comment);
        *(uint32_t*)(buf + 40)  = 0x200; /* UF_NORMAL_ACCOUNT */
        *(uint16_t**)(buf + 48) = WSTR_APPEND(buf, pos, "");
        *bufptr = buf; return 0;
    }
    if (level == 3) {
        /* USER_INFO_3 x64 layout (184-byte header):
         * +0   LPWSTR name         +8   LPWSTR password(NULL)
         * +16  DWORD  password_age +20  DWORD  priv
         * +24  LPWSTR home_dir     +32  LPWSTR comment
         * +40  DWORD  flags        [+44 pad]
         * +48  LPWSTR script_path  +56  DWORD  auth_flags  [+60 pad]
         * +64  LPWSTR full_name    +72  LPWSTR usr_comment
         * +80  LPWSTR parms        +88  LPWSTR workstations
         * +96  DWORD  last_logon   +100 DWORD  last_logoff
         * +104 DWORD  acct_expires +108 DWORD  max_storage
         * +112 DWORD  units_per_wk [+116 pad]
         * +120 PBYTE  logon_hours  +128 DWORD  bad_pw_count
         * +132 DWORD  num_logons   [+136 aligned]
         * +136 LPWSTR logon_server +144 DWORD  country_code
         * +148 DWORD  code_page    +152 DWORD  user_id
         * +156 DWORD  prim_grp_id  +160 LPWSTR profile
         * +168 LPWSTR home_dir_drv +176 DWORD  password_expired
         * [+180 pad → struct = 184 bytes] */
        const char* logon_server = "\\\\*";
        size_t strsz = (strlen(rname)+1)*2 + (strlen(fullname)+1)*2 + (strlen(comment)+1)*2
                     + (strlen(homedir)+1)*2 + (strlen(logon_server)+1)*2 + 4*2 /* 4 empty strs */;
        uint8_t* buf = (uint8_t*)calloc(1, 184 + strsz);
        if (!buf) return 8;
        int pos = 184;
        *(uint16_t**)(buf + 0)   = WSTR_APPEND(buf, pos, rname);
        *(uint16_t**)(buf + 8)   = NULL;                            /* password */
        *(uint32_t*)(buf + 16)   = 0;                               /* password_age: 0 days */
        *(uint32_t*)(buf + 20)   = 1;                               /* USER_PRIV_USER */
        *(uint16_t**)(buf + 24)  = WSTR_APPEND(buf, pos, homedir);
        *(uint16_t**)(buf + 32)  = WSTR_APPEND(buf, pos, comment);
        *(uint32_t*)(buf + 40)   = 0x10200; /* UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD */
        *(uint16_t**)(buf + 48)  = WSTR_APPEND(buf, pos, "");      /* script_path */
        *(uint32_t*)(buf + 56)   = 0;                               /* auth_flags */
        *(uint16_t**)(buf + 64)  = WSTR_APPEND(buf, pos, fullname);
        *(uint16_t**)(buf + 72)  = WSTR_APPEND(buf, pos, "");      /* usr_comment */
        *(uint16_t**)(buf + 80)  = WSTR_APPEND(buf, pos, "");      /* parms */
        *(uint16_t**)(buf + 88)  = WSTR_APPEND(buf, pos, "");      /* workstations: all */
        *(uint32_t*)(buf + 96)   = 0;                               /* last_logon: never */
        *(uint32_t*)(buf + 100)  = 0;                               /* last_logoff: never */
        *(uint32_t*)(buf + 104)  = 0xFFFFFFFF;                     /* acct_expires: TIMEQ_FOREVER */
        *(uint32_t*)(buf + 108)  = 0xFFFFFFFF;                     /* max_storage: unlimited */
        *(uint32_t*)(buf + 112)  = 168;                             /* units_per_week (7*24) */
        *(uint8_t**)(buf + 120)  = NULL;                            /* logon_hours: all */
        *(uint32_t*)(buf + 128)  = 0;                               /* bad_pw_count */
        *(uint32_t*)(buf + 132)  = 0;                               /* num_logons: unknown */
        *(uint16_t**)(buf + 136) = WSTR_APPEND(buf, pos, logon_server);
        *(uint32_t*)(buf + 144)  = 0;                               /* country_code */
        *(uint32_t*)(buf + 148)  = 0;                               /* code_page */
        *(uint32_t*)(buf + 152)  = (uint32_t)pw_ent->pw_uid;
        *(uint32_t*)(buf + 156)  = 513;                             /* DOMAIN_GROUP_RID_USERS */
        *(uint16_t**)(buf + 160) = WSTR_APPEND(buf, pos, "");      /* profile */
        *(uint16_t**)(buf + 168) = WSTR_APPEND(buf, pos, "");      /* home_dir_drive */
        *(uint32_t*)(buf + 176)  = 0;                               /* password_expired: no */
        *bufptr = buf; return 0;
    }
    if (level == 10) {
        /* USER_INFO_10: name(+0), comment(+8), usr_comment(+16), full_name(+24) — 4 LPWSTR = 32 bytes */
        size_t strsz = (strlen(rname)+1)*2 + (strlen(comment)+1)*2 + (strlen(fullname)+1)*2 + 2;
        uint8_t* buf = (uint8_t*)calloc(1, 32 + strsz);
        if (!buf) return 8;
        int pos = 32;
        *(uint16_t**)(buf + 0)  = WSTR_APPEND(buf, pos, rname);
        *(uint16_t**)(buf + 8)  = WSTR_APPEND(buf, pos, comment);
        *(uint16_t**)(buf + 16) = WSTR_APPEND(buf, pos, "");   /* usr_comment */
        *(uint16_t**)(buf + 24) = WSTR_APPEND(buf, pos, fullname);
        *bufptr = buf; return 0;
    }
    if (level == 20 || level == 23) {
        /* USER_INFO_20: name(+0), full_name(+8), comment(+16), flags(DWORD +24), user_id(DWORD +28) = 32 bytes */
        size_t strsz = (strlen(rname)+1)*2 + (strlen(fullname)+1)*2 + (strlen(comment)+1)*2;
        uint8_t* buf = (uint8_t*)calloc(1, 32 + strsz);
        if (!buf) return 8;
        int pos = 32;
        *(uint16_t**)(buf + 0)  = WSTR_APPEND(buf, pos, rname);
        *(uint16_t**)(buf + 8)  = WSTR_APPEND(buf, pos, fullname);
        *(uint16_t**)(buf + 16) = WSTR_APPEND(buf, pos, comment);
        *(uint32_t*)(buf + 24)  = 0x200; /* UF_NORMAL_ACCOUNT */
        *(uint32_t*)(buf + 28)  = (uint32_t)pw_ent->pw_uid;
        *bufptr = buf; return 0;
    }
    return 50;
#undef WSTR_APPEND
}
int __attribute__((ms_abi)) lsw_NetServerGetInfo(uint16_t* server, uint32_t level, uint8_t** bufptr) {
    (void)server;
    LSW_LOG_INFO("NetServerGetInfo(level=%u)", level);
    if (!bufptr) return 2102;
    if (level != 100 && level != 101) { *bufptr = NULL; return 2102; }
    lsw_ensure_computername();
    /* SERVER_INFO_100: platform_id (DWORD @0, pad @4), sv100_name (ptr @8) = 16 bytes */
    uint8_t* buf = (uint8_t*)calloc(16, 1);
    if (!buf) { *bufptr = NULL; return 8; /* ERROR_NOT_ENOUGH_MEMORY */ }
    *(uint32_t*)(buf + 0) = 500; /* SV_PLATFORM_ID_NT */
    *(uint64_t*)(buf + 8) = (uint64_t)(uintptr_t)g_computername_w; /* persistent — survives free */
    *bufptr = buf;
    return 0; /* NERR_Success */
}
int __attribute__((ms_abi)) lsw_NetShareEnum(uint16_t* server, uint32_t level, uint8_t** bufptr,
    uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 2102;
}

/* samcli.dll stubs — all return NERR_ServerNotStarted (2102) */
int __attribute__((ms_abi)) lsw_NetUserAdd(uint16_t* server, uint32_t level, uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)level; (void)buf; if (parm_err) *parm_err = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetUserDel(uint16_t* server, uint16_t* username) {
    (void)server; (void)username; return 2102;
}
int __attribute__((ms_abi)) lsw_NetUserSetInfo(uint16_t* server, uint16_t* username, uint32_t level, uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)username; (void)level; (void)buf; if (parm_err) *parm_err = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetUserGetGroups(uint16_t* server, uint16_t* username, uint32_t level,
    uint8_t** bufptr, uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries) {
    (void)server; (void)username; (void)level; (void)prefMaxLen;
    LSW_LOG_INFO("NetUserGetGroups(level=%u)", level);
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 0; /* success — empty list */
}
int __attribute__((ms_abi)) lsw_NetUserGetLocalGroups(uint16_t* server, uint16_t* username, uint32_t level,
    uint32_t flags, uint8_t** bufptr, uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries) {
    (void)server; (void)username; (void)level; (void)flags; (void)prefMaxLen;
    LSW_LOG_INFO("NetUserGetLocalGroups(level=%u)", level);
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 0; /* success — empty list */
}
int __attribute__((ms_abi)) lsw_NetUserEnum(uint16_t* server, uint32_t level, uint32_t filter,
    uint8_t** bufptr, uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)filter; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL;
    if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0;
    if (level != 0) return 50; /* ERROR_NOT_SUPPORTED */
    /* Read usernames from /etc/passwd */
    char names[256][64];
    int count = 0;
    FILE* pw = fopen("/etc/passwd", "r");
    if (!pw) return 0; /* empty list */
    char line[1024];
    while (fgets(line, sizeof(line), pw) && count < 256) {
        char* colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        /* Find uid field (3rd ':' separated field) */
        char* f2 = colon + 1; char* f3 = strchr(f2, ':');
        if (!f3) continue;
        char* uidstr = f3 + 1; char* f4end = strchr(uidstr, ':');
        if (f4end) *f4end = '\0';
        int uid = atoi(uidstr);
        if (uid == 0 || uid >= 1000) {
            strncpy(names[count], line, 63);
            names[count++][63] = '\0';
        }
    }
    fclose(pw);
    if (count == 0) return 0;
    /* Allocate flat buffer: array of (uint16_t*) structs + string area */
    size_t struct_sz = (size_t)count * sizeof(uint16_t*);
    size_t str_sz    = (size_t)count * 64 * sizeof(uint16_t);
    uint8_t* buf = (uint8_t*)calloc(1, struct_sz + str_sz);
    if (!buf) return 8; /* ERROR_NOT_ENOUGH_MEMORY */
    uint16_t** structs = (uint16_t**)buf;
    uint16_t*  strarea = (uint16_t*)(buf + struct_sz);
    for (int i = 0; i < count; i++) {
        structs[i] = strarea;
        int j = 0;
        while (names[i][j]) { strarea[j] = (uint16_t)(unsigned char)names[i][j]; j++; }
        strarea[j] = 0;
        strarea += j + 1;
    }
    *bufptr = buf;
    if (entriesRead) *entriesRead = (uint32_t)count;
    if (totalEntries) *totalEntries = (uint32_t)count;
    return 0; /* NERR_Success */
}
int __attribute__((ms_abi)) lsw_NetUserModalsGet(uint16_t* server, uint32_t level, uint8_t** bufptr) {
    (void)server;
    LSW_LOG_INFO("NetUserModalsGet(level=%u)", level);
    if (!bufptr) return 87; /* ERROR_INVALID_PARAMETER */
    *bufptr = NULL;
    if (level == 0) {
        /* USER_MODALS_INFO_0: min_passwd_len, max_passwd_age, min_passwd_age, force_logoff, password_hist_len */
        uint8_t* buf = (uint8_t*)calloc(20, 1);
        if (!buf) return 8;
        *(uint32_t*)(buf +  0) = 0;           /* min_passwd_len: no minimum */
        *(uint32_t*)(buf +  4) = 0xFFFFFFFF;  /* max_passwd_age: TIMEQ_FOREVER (never expires) */
        *(uint32_t*)(buf +  8) = 0;           /* min_passwd_age: 0 */
        *(uint32_t*)(buf + 12) = 0xFFFFFFFF;  /* force_logoff: TIMEQ_FOREVER */
        *(uint32_t*)(buf + 16) = 0;           /* password_hist_len: 0 */
        *bufptr = buf; return 0;
    }
    if (level == 1) {
        /* USER_MODALS_INFO_1: role, primary (ptr) — 16 bytes */
        uint8_t* buf = (uint8_t*)calloc(16, 1);
        if (!buf) return 8;
        *(uint32_t*)(buf + 0) = 2;  /* UAS_ROLE_STANDALONE */
        *(uint64_t*)(buf + 8) = 0;  /* no primary DC */
        *bufptr = buf; return 0;
    }
    if (level == 2) {
        /* USER_MODALS_INFO_2: domain_name ptr, domain_id ptr — 16 bytes */
        lsw_ensure_computername();
        uint8_t* buf = (uint8_t*)calloc(16, 1);
        if (!buf) return 8;
        *(uint64_t*)(buf + 0) = (uint64_t)(uintptr_t)g_computername_w; /* domain name = hostname */
        *(uint64_t*)(buf + 8) = 0; /* no SID */
        *bufptr = buf; return 0;
    }
    return 50; /* ERROR_NOT_SUPPORTED */
}
int __attribute__((ms_abi)) lsw_NetUserModalsSet(uint16_t* server, uint32_t level, uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)level; (void)buf; if (parm_err) *parm_err = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetGroupAdd(uint16_t* server, uint32_t level, uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)level; (void)buf; if (parm_err) *parm_err = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetGroupDel(uint16_t* server, uint16_t* groupname) {
    (void)server; (void)groupname; return 2102;
}
int __attribute__((ms_abi)) lsw_NetGroupGetInfo(uint16_t* server, uint16_t* groupname, uint32_t level, uint8_t** bufptr) {
    (void)server; (void)groupname; (void)level; if (bufptr) *bufptr = NULL; return 2102;
}
int __attribute__((ms_abi)) lsw_NetGroupSetInfo(uint16_t* server, uint16_t* groupname, uint32_t level, uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)groupname; (void)level; (void)buf; if (parm_err) *parm_err = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetGroupGetUsers(uint16_t* server, uint16_t* groupname, uint32_t level,
    uint8_t** bufptr, uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)groupname; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 0; /* empty list */
}
int __attribute__((ms_abi)) lsw_NetGroupEnum(uint16_t* server, uint32_t level,
    uint8_t** bufptr, uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)level; (void)prefMaxLen; (void)resumeHandle;
    LSW_LOG_INFO("NetGroupEnum(level=%u)", level);
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 0; /* empty list */
}
int __attribute__((ms_abi)) lsw_NetGroupAddUser(uint16_t* server, uint16_t* groupname, uint16_t* username) {
    (void)server; (void)groupname; (void)username; return 2102;
}
int __attribute__((ms_abi)) lsw_NetGroupDelUser(uint16_t* server, uint16_t* groupname, uint16_t* username) {
    (void)server; (void)groupname; (void)username; return 2102;
}

/* ---- missing wkscli.dll stubs ---- */
int __attribute__((ms_abi)) lsw_NetWkstaTransportEnum(uint16_t* server, uint32_t level, uint8_t** bufptr,
    uint32_t prefMaxLen, uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetWkstaStatisticsGet(uint16_t* server, uint16_t* service,
    uint32_t level, uint32_t options, uint8_t** bufptr) {
    (void)server; (void)service; (void)level; (void)options;
    if (bufptr) *bufptr = NULL; return 2102;
}

/* ---- missing netutils.dll stubs ---- */
int __attribute__((ms_abi)) lsw_NetpwListCanonicalize(uint16_t* path, uint16_t* out, uint32_t outSz,
    uint16_t* prefix, uint32_t* type, uint32_t flags) {
    (void)path; (void)out; (void)outSz; (void)prefix; (void)type; (void)flags; return 0;
}
int __attribute__((ms_abi)) lsw_NetpwNameCompare(uint16_t* a, uint16_t* b, uint32_t type, uint32_t flags) {
    (void)a; (void)b; (void)type; (void)flags; return 0;
}
int __attribute__((ms_abi)) lsw_NetpwListTraverse(void* list, void** cookie, uint32_t flags) {
    (void)list; (void)cookie; (void)flags; return 0;
}
int __attribute__((ms_abi)) lsw_NetpwNameCanonicalize(uint16_t* name, uint16_t* out,
    uint32_t outSz, uint32_t type, uint32_t flags) {
    (void)name; (void)out; (void)outSz; (void)type; (void)flags; return 0;
}

/* ---- DSROLE.dll stubs ---- */
/* DSROLE_PRIMARY_DOMAIN_INFO_BASIC: MachineRole=0(standalone), Flags=0, all names NULL, GUID=0 */
typedef struct {
    uint32_t MachineRole;
    uint32_t Flags;
    uint16_t* DomainNameFlat;
    uint16_t* DomainNameDns;
    uint16_t* DomainForestName;
    uint8_t   DomainGuid[16];
} lsw_dsrole_info_t;
uint32_t __attribute__((ms_abi)) lsw_DsRoleGetPrimaryDomainInformation(
    uint16_t* server, uint32_t infoLevel, uint8_t** buffer) {
    (void)server; (void)infoLevel;
    if (!buffer) return 87; /* ERROR_INVALID_PARAMETER */
    /* DomainNameFlat must not be NULL — net1.exe copies it unconditionally.
     * For a standalone workstation, use "WORKGROUP" as the flat domain name. */
    const char* domain = "WORKGROUP";
    size_t dlen = strlen(domain);
    lsw_dsrole_info_t* info = (lsw_dsrole_info_t*)calloc(
        1, sizeof(lsw_dsrole_info_t) + (dlen + 1) * sizeof(uint16_t));
    if (!info) return 8;
    info->MachineRole = 0; /* DsRole_RoleStandaloneWorkstation */
    info->Flags = 0;
    uint16_t* flat = (uint16_t*)((uint8_t*)info + sizeof(lsw_dsrole_info_t));
    for (size_t i = 0; i < dlen; i++) flat[i] = (uint16_t)(unsigned char)domain[i];
    flat[dlen] = 0;
    info->DomainNameFlat = flat;
    /* DomainNameDns and DomainForestName remain NULL (standalone, no DNS domain) */
    *buffer = (uint8_t*)info;
    return 0;
}
void __attribute__((ms_abi)) lsw_DsRoleFreeMemory(void* buffer) {
    free(buffer);
}

/* ---- DSROLE / DS Client stubs ---- */
uint32_t __attribute__((ms_abi)) lsw_DsGetDcNameW(uint16_t* computer, uint16_t* domain,
    void* domainGuid, uint16_t* site, uint32_t flags, void** dcinfo) {
    (void)computer; (void)domain; (void)domainGuid; (void)site; (void)flags;
    if (dcinfo) *dcinfo = NULL;
    return 1355; /* ERROR_NO_SUCH_DOMAIN */
}
uint32_t __attribute__((ms_abi)) lsw_DsBindWithSpnExW(uint16_t* domainCtrl, uint16_t* dnsDomain,
    void* authIdent, uint16_t* spn, uint32_t bindFlags, void** phDS) {
    (void)domainCtrl; (void)dnsDomain; (void)authIdent; (void)spn; (void)bindFlags;
    if (phDS) *phDS = NULL; return 1355;
}
uint32_t __attribute__((ms_abi)) lsw_DsUnBindW(void** phDS) {
    if (phDS) *phDS = NULL; return 0;
}
uint32_t __attribute__((ms_abi)) lsw_DsFreeNameResultW(void* result) {
    free(result); return 0;
}
uint32_t __attribute__((ms_abi)) lsw_DsCrackNamesW(void* hDS, uint32_t flags, uint32_t formatOffered,
    uint32_t formatDesired, uint32_t cNames, uint16_t** rpNames, void** ppResult) {
    (void)hDS; (void)flags; (void)formatOffered; (void)formatDesired; (void)cNames; (void)rpNames;
    if (ppResult) *ppResult = NULL; return 8453; /* DS_NAME_ERROR_NOT_FOUND */
}

/* ---- missing srvcli.dll stubs ---- */
int __attribute__((ms_abi)) lsw_NetFileEnum(uint16_t* server, uint16_t* basepath, uint16_t* user,
    uint32_t level, uint8_t** bufptr, uint32_t prefMaxLen,
    uint32_t* entriesRead, uint32_t* totalEntries, uint64_t* resumeHandle) {
    (void)server; (void)basepath; (void)user; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetFileGetInfo(uint16_t* server, uint32_t fileId, uint32_t level, uint8_t** bufptr) {
    (void)server; (void)fileId; (void)level; if (bufptr) *bufptr = NULL; return 2102;
}
int __attribute__((ms_abi)) lsw_NetFileClose(uint16_t* server, uint32_t fileId) {
    (void)server; (void)fileId; return 2102;
}
int __attribute__((ms_abi)) lsw_NetSessionEnum(uint16_t* server, uint16_t* client, uint16_t* user,
    uint32_t level, uint8_t** bufptr, uint32_t prefMaxLen,
    uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)client; (void)user; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetSessionGetInfo(uint16_t* server, uint16_t* client,
    uint16_t* user, uint32_t level, uint8_t** bufptr) {
    (void)server; (void)client; (void)user; (void)level;
    if (bufptr) *bufptr = NULL; return 2102;
}
int __attribute__((ms_abi)) lsw_NetSessionDel(uint16_t* server, uint16_t* client, uint16_t* user) {
    (void)server; (void)client; (void)user; return 2102;
}
int __attribute__((ms_abi)) lsw_NetConnectionEnum(uint16_t* server, uint16_t* qualifier,
    uint32_t level, uint8_t** bufptr, uint32_t prefMaxLen,
    uint32_t* entriesRead, uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)qualifier; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetServerTransportEnum(uint16_t* server, uint32_t level,
    uint8_t** bufptr, uint32_t prefMaxLen, uint32_t* entriesRead,
    uint32_t* totalEntries, uint32_t* resumeHandle) {
    (void)server; (void)level; (void)prefMaxLen; (void)resumeHandle;
    if (bufptr) *bufptr = NULL; if (entriesRead) *entriesRead = 0;
    if (totalEntries) *totalEntries = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetServerSetInfo(uint16_t* server, uint32_t level, uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)level; (void)buf; if (parm_err) *parm_err = 0; return 2102;
}
int __attribute__((ms_abi)) lsw_NetShareGetInfo(uint16_t* server, uint16_t* sharename, uint32_t level, uint8_t** bufptr) {
    (void)server; (void)sharename; (void)level; if (bufptr) *bufptr = NULL; return 2310; /* NERR_NetNameNotFound */
}
int __attribute__((ms_abi)) lsw_NetShareCheck(uint16_t* server, uint16_t* device, uint32_t* type) {
    (void)server; (void)device; if (type) *type = 0; return 2312; /* NERR_DeviceNotShared */
}
int __attribute__((ms_abi)) lsw_NetShareSetInfo(uint16_t* server, uint16_t* sharename, uint32_t level,
    uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)sharename; (void)level; (void)buf;
    if (parm_err) *parm_err = 0; return 2310;
}
int __attribute__((ms_abi)) lsw_NetShareDel(uint16_t* server, uint16_t* sharename, uint32_t reserved) {
    (void)server; (void)sharename; (void)reserved; return 2310;
}
int __attribute__((ms_abi)) lsw_NetShareDelSticky(uint16_t* server, uint16_t* sharename, uint32_t reserved) {
    (void)server; (void)sharename; (void)reserved; return 2310;
}
int __attribute__((ms_abi)) lsw_NetShareAdd(uint16_t* server, uint32_t level, uint8_t* buf, uint32_t* parm_err) {
    (void)server; (void)level; (void)buf; if (parm_err) *parm_err = 0; return 2118; /* NERR_NetworkError */
}
typedef struct { uint32_t tod_elapsedt; uint32_t tod_msecs; uint32_t tod_hours; uint32_t tod_mins;
    uint32_t tod_secs; uint32_t tod_hunds; int32_t tod_timezone; uint32_t tod_tinterval;
    uint32_t tod_day; uint32_t tod_month; uint32_t tod_year; uint32_t tod_weekday; } lsw_time_of_day_t;
int __attribute__((ms_abi)) lsw_NetRemoteTOD(uint16_t* server, uint8_t** bufptr) {
    (void)server;
    if (!bufptr) return 87;
    lsw_time_of_day_t* tod = (lsw_time_of_day_t*)calloc(1, sizeof(lsw_time_of_day_t));
    if (!tod) return 8;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    time_t now = ts.tv_sec;
    struct tm tm; gmtime_r(&now, &tm);
    tod->tod_elapsedt  = (uint32_t)now;
    tod->tod_msecs     = (uint32_t)(ts.tv_nsec / 1000000);
    tod->tod_hours     = (uint32_t)tm.tm_hour;
    tod->tod_mins      = (uint32_t)tm.tm_min;
    tod->tod_secs      = (uint32_t)tm.tm_sec;
    tod->tod_hunds     = 0;
    tod->tod_timezone  = 0;
    tod->tod_tinterval = 310; /* 100ths of seconds per clock tick */
    tod->tod_day       = (uint32_t)tm.tm_mday;
    tod->tod_month     = (uint32_t)(tm.tm_mon + 1);
    tod->tod_year      = (uint32_t)(tm.tm_year + 1900);
    tod->tod_weekday   = (uint32_t)tm.tm_wday;
    *bufptr = (uint8_t*)tod;
    return 0;
}

/* ---- KERNEL32 SetLocalTime / SetSystemTime ---- */
int __attribute__((ms_abi)) lsw_SetLocalTime(void* lpSystemTime) {
    (void)lpSystemTime; lsw_SetLastError(1314 /* ERROR_PRIVILEGE_NOT_HELD */); return 0;
}
int __attribute__((ms_abi)) lsw_SetSystemTime(void* lpSystemTime) {
    (void)lpSystemTime; lsw_SetLastError(1314); return 0;
}

/* ---- CRYPTBASE.dll SystemFunction036 = RtlGenRandom ---- */
int __attribute__((ms_abi)) lsw_SystemFunction036(void* buf, uint32_t len) {
    if (!buf || !len) return 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 1 : 0; /* TRUE on success */
}

/* ---- Service management stubs (no SCM on Linux) ---- */
int __attribute__((ms_abi)) lsw_GetServiceDisplayNameW(void* hSCManager,
    uint16_t* lpServiceName, uint16_t* lpDisplayName, uint32_t* lpcchBuffer) {
    (void)hSCManager; (void)lpServiceName; (void)lpDisplayName; (void)lpcchBuffer;
    lsw_SetLastError(1060 /* ERROR_SERVICE_DOES_NOT_EXIST */); return 0;
}
int __attribute__((ms_abi)) lsw_GetServiceKeyNameW(void* hSCManager,
    uint16_t* lpDisplayName, uint16_t* lpServiceName, uint32_t* lpcchBuffer) {
    (void)hSCManager; (void)lpDisplayName; (void)lpServiceName; (void)lpcchBuffer;
    lsw_SetLastError(1060); return 0;
}
int __attribute__((ms_abi)) lsw_EnumServicesStatusExW(void* hSCManager,
    uint32_t InfoLevel, uint32_t dwServiceType, uint32_t dwServiceState, uint8_t* lpServices,
    uint32_t cbBufSize, uint32_t* pcbBytesNeeded, uint32_t* lpServicesReturned,
    uint32_t* lpResumeHandle, uint16_t* pszGroupName) {
    (void)hSCManager; (void)InfoLevel; (void)dwServiceType; (void)dwServiceState;
    (void)lpServices; (void)cbBufSize; (void)pszGroupName; (void)lpResumeHandle;
    if (pcbBytesNeeded) *pcbBytesNeeded = 0;
    if (lpServicesReturned) *lpServicesReturned = 0;
    lsw_SetLastError(6 /* ERROR_INVALID_HANDLE */); return 0;
}
int __attribute__((ms_abi)) lsw_EnumDependentServicesW(void* hService,
    uint32_t dwServiceState, uint8_t* lpServices, uint32_t cbBufSize,
    uint32_t* pcbBytesNeeded, uint32_t* lpServicesReturned) {
    (void)hService; (void)dwServiceState; (void)lpServices; (void)cbBufSize;
    if (pcbBytesNeeded) *pcbBytesNeeded = 0;
    if (lpServicesReturned) *lpServicesReturned = 0;
    lsw_SetLastError(6); return 0;
}

/* imagehlp.dll / dbghelp.dll stubs */
int __attribute__((ms_abi)) lsw_EnumerateLoadedModulesW64(void* hProcess,
    void* EnumLoadedModulesCallbackW64, void* UserContext) {
    (void)hProcess; (void)EnumLoadedModulesCallbackW64; (void)UserContext;
    return 0; /* FALSE — no modules enumerated */
}
void* __attribute__((ms_abi)) lsw_ImagehlpApiVersion(void) {
    /* Returns pointer to static API_VERSION struct: MajorVersion, MinorVersion, Revision, Reserved */
    static uint16_t ver[4] = {12, 0, 0, 0}; /* version 12.0 */
    return ver;
}
int __attribute__((ms_abi)) lsw_SymInitialize(void* hProcess, const char* UserSearchPath, int fInvadeProcess) {
    (void)hProcess; (void)UserSearchPath; (void)fInvadeProcess; return 1; /* TRUE */
}
int __attribute__((ms_abi)) lsw_SymCleanup(void* hProcess) {
    (void)hProcess; return 1; /* TRUE */
}

/* MPR (Multiple Provider Router) stubs */
int __attribute__((ms_abi)) lsw_WNetGetLastErrorW(uint32_t* lpError, uint16_t* lpErrorBuf,
    uint32_t nErrorBufSize, uint16_t* lpNameBuf, uint32_t nNameBufSize) {
    (void)nErrorBufSize; (void)nNameBufSize;
    if (lpError) *lpError = 0;
    if (lpErrorBuf) *lpErrorBuf = 0;
    if (lpNameBuf) *lpNameBuf = 0;
    return 0;
}
int __attribute__((ms_abi)) lsw_WNetCancelConnection2W(uint16_t* lpName, uint32_t dwFlags, int fForce) {
    (void)lpName; (void)dwFlags; (void)fForce; return 2250; /* ERROR_NOT_CONNECTED */
}
int __attribute__((ms_abi)) lsw_WNetOpenEnumW(uint32_t dwScope, uint32_t dwType, uint32_t dwUsage,
    void* lpNetResource, void** lphEnum) {
    (void)dwScope; (void)dwType; (void)dwUsage; (void)lpNetResource;
    if (lphEnum) *lphEnum = NULL; return 1; /* ERROR_INVALID_FUNCTION */
}
int __attribute__((ms_abi)) lsw_WNetAddConnection4W(void* hwndOwner, void* lpNetResource, void* lpAuthBuffer,
    uint32_t cbAuthBuffer, uint32_t dwFlags, uint8_t* lpUseOptions, uint32_t cbUseOptions) {
    (void)hwndOwner; (void)lpNetResource; (void)lpAuthBuffer; (void)cbAuthBuffer;
    (void)dwFlags; (void)lpUseOptions; (void)cbUseOptions; return 1; /* ERROR_INVALID_FUNCTION */
}
int __attribute__((ms_abi)) lsw_WNetEnumResourceW(void* hEnum, uint32_t* lpcCount, void* lpBuffer, uint32_t* lpBufferSize) {
    (void)hEnum; (void)lpcCount; (void)lpBuffer; (void)lpBufferSize; return 259; /* ERROR_NO_MORE_ITEMS */
}
int __attribute__((ms_abi)) lsw_WNetGetConnectionW(uint16_t* lpLocalName, uint16_t* lpRemoteName, uint32_t* lpnLength) {
    (void)lpLocalName;
    if (lpRemoteName && lpnLength && *lpnLength > 0) *lpRemoteName = 0;
    return 2250; /* ERROR_NOT_CONNECTED */
}
int __attribute__((ms_abi)) lsw_WNetCloseEnum(void* hEnum) { (void)hEnum; return 0; }

/* SSPI auth identity stubs */
int __attribute__((ms_abi)) lsw_SspiMarshalAuthIdentity(void* AuthIdentity, uint32_t* MarshaledLength, uint8_t** MarshaledAuthIdentity) {
    (void)AuthIdentity; if (MarshaledLength) *MarshaledLength = 0;
    if (MarshaledAuthIdentity) *MarshaledAuthIdentity = NULL; return 1; /* SEC_E_UNSUPPORTED_FUNCTION */
}
int __attribute__((ms_abi)) lsw_SsspiFreeAuthIdentity(void* AuthIdentity) { (void)AuthIdentity; return 0; }
int __attribute__((ms_abi)) lsw_SspiLocalFree(void* DataBuffer) { (void)DataBuffer; return 0; }
int __attribute__((ms_abi)) lsw_SspiEncodeStringsAsAuthIdentity(uint16_t* user, uint16_t* dom, uint16_t* pass, void** ppAuthIdentity) {
    (void)user; (void)dom; (void)pass; if (ppAuthIdentity) *ppAuthIdentity = NULL; return 1;
}
/* SspiCli — also has these names */
int __attribute__((ms_abi)) lsw_SspiFreeAuthIdentity(void* AuthIdentity) { (void)AuthIdentity; return 0; }

/* ResolveDelayLoadedAPI / DelayLoadFailureHook — delay-load stubs (no-op on our loader) */
void* __attribute__((ms_abi)) lsw_ResolveDelayLoadedAPI(void* base, void* desc, void* resolver, void* hook,
    void* ibn, uint32_t flags) {
    (void)base; (void)desc; (void)resolver; (void)hook; (void)ibn; (void)flags;
    return NULL;
}
void* __attribute__((ms_abi)) lsw_DelayLoadFailureHook(const char* dllName, void* thunk) {
    (void)dllName; (void)thunk; return NULL;
}
/* PeekConsoleInputW */
int __attribute__((ms_abi)) lsw_PeekConsoleInputW(void* hConsoleInput, void* lpBuffer, uint32_t nLength, uint32_t* lpNumberOfEventsRead) {
    (void)hConsoleInput; (void)lpBuffer; (void)nLength;
    if (lpNumberOfEventsRead) *lpNumberOfEventsRead = 0; return 1;
}

// ============================================================================
// END Additional stubs for whoami.exe
// ============================================================================

/* GetProfileStringW — returns default value (no .ini file support) */
int __attribute__((ms_abi)) lsw_GetProfileStringW(const uint16_t* lpAppName, const uint16_t* lpKeyName,
    const uint16_t* lpDefault, uint16_t* lpReturnedString, uint32_t nSize) {
    (void)lpAppName; (void)lpKeyName;
    if (!lpReturnedString || nSize == 0) return 0;
    if (!lpDefault) { *lpReturnedString = 0; return 0; }
    uint32_t i = 0;
    while (i < nSize - 1 && lpDefault[i]) { lpReturnedString[i] = lpDefault[i]; i++; }
    lpReturnedString[i] = 0;
    return i;
}

/* InitializeAcl — zero-fills buffer and sets ACL header (revision + size) */
int __attribute__((ms_abi)) lsw_InitializeAcl(void* pAcl, uint32_t nAclLength, uint32_t dwAclRevision) {
    if (!pAcl || nAclLength < 8) { return 0; } /* FALSE */
    memset(pAcl, 0, nAclLength);
    uint8_t* p = (uint8_t*)pAcl;
    p[0] = (uint8_t)dwAclRevision; /* AclRevision */
    p[1] = 0;                       /* Sbz1 */
    /* AclSize (little-endian WORD at offset 2) */
    p[2] = (uint8_t)(nAclLength & 0xff);
    p[3] = (uint8_t)((nAclLength >> 8) & 0xff);
    /* AceCount, Sbz2 remain 0 */
    return 1; /* TRUE */
}

/* GetSidLengthRequired — 8-byte SID header + 4 bytes per sub-authority */
uint32_t __attribute__((ms_abi)) lsw_GetSidLengthRequired(uint8_t nSubAuthorityCount) {
    return 8 + 4 * (uint32_t)nSubAuthorityCount;
}

/* GetAce — return FALSE; empty ACL has no ACEs */
int __attribute__((ms_abi)) lsw_GetAce(void* pAcl, uint32_t dwAceIndex, void** pAce) {
    (void)pAcl; (void)dwAceIndex;
    if (pAce) *pAce = NULL;
    lsw_SetLastError(24); /* ERROR_NO_MORE_ITEMS */
    return 0; /* FALSE */
}

/* AddAccessAllowedAce — stub that succeeds (SID/DACL building not needed on Linux) */
int __attribute__((ms_abi)) lsw_AddAccessAllowedAce(void* pAcl, uint32_t dwAclRevision,
    uint32_t AccessMask, void* pSid) {
    (void)pAcl; (void)dwAclRevision; (void)AccessMask; (void)pSid;
    return 1; /* TRUE */
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

/* Forward declarations for functions defined in other translation units */
extern uint32_t __attribute__((ms_abi)) lsw_GetUserDefaultLCID(void);
/* advapi32 security functions */
extern int    __attribute__((ms_abi)) lsw_EqualSid(void*, void*);
extern int    __attribute__((ms_abi)) lsw_CopySid(uint32_t, void*, void*);
extern uint32_t __attribute__((ms_abi)) lsw_GetLengthSid(void*);
extern int    __attribute__((ms_abi)) lsw_CreateWellKnownSid(int, void*, void*, uint32_t*);
extern int    __attribute__((ms_abi)) lsw_InitializeSecurityDescriptor(void*, uint32_t);
extern int    __attribute__((ms_abi)) lsw_SetSecurityDescriptorDacl(void*, int, void*, int);
extern int    __attribute__((ms_abi)) lsw_GetSecurityDescriptorDacl(void*, int*, void**, int*);
extern uint8_t* __attribute__((ms_abi)) lsw_GetSidSubAuthorityCount(void*);
extern uint32_t* __attribute__((ms_abi)) lsw_GetSidSubAuthority(void*, uint32_t);
/* advapi32 registry */
extern long   __attribute__((ms_abi)) lsw_RegQueryValueExW(void*, const uint16_t*, uint32_t*, uint32_t*, uint8_t*, uint32_t*);
extern long   __attribute__((ms_abi)) lsw_RegCloseKey(void*);
/* ntdll memory */
extern size_t __attribute__((ms_abi)) lsw_RtlCompareMemory(const void*, const void*, size_t);

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
    {"msvcrt.dll", "wprintf", (void*)lsw_wprintf},
    {"msvcrt.dll", "vwprintf", (void*)lsw_vwprintf},
    {"msvcrt.dll", "fwprintf", (void*)lsw_fwprintf},
    {"msvcrt.dll", "vfwprintf", (void*)lsw_vfwprintf},
    {"msvcrt.dll", "_wprintf", (void*)lsw_wprintf},
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
    {"msvcrt.dll", "__wgetmainargs", (void*)lsw__wgetmainargs},
    {"msvcrt.dll", "_wgetmainargs", (void*)lsw__wgetmainargs},
    {"msvcrt.dll", "__initenv", (void*)lsw__initenv},
    {"msvcrt.dll", "__iob_func", (void*)lsw__iob_func},
    {"msvcrt.dll", "_iob",       (void*)lsw__iob},
    {"msvcrt.dll", "__set_app_type", (void*)lsw__set_app_type},
    {"msvcrt.dll", "__setusermatherr", (void*)lsw__setusermatherr},
    {"msvcrt.dll", "_amsg_exit", (void*)lsw__amsg_exit},
    {"msvcrt.dll", "_cexit", (void*)lsw__cexit},
    {"msvcrt.dll", "_c_exit", (void*)lsw__c_exit},
    {"msvcrt.dll", "_beginthreadex", (void*)lsw__beginthreadex},
    {"msvcrt.dll", "_endthreadex", (void*)lsw__endthreadex},
    {"msvcrt.dll", "_exit",  (void*)lsw__exit},
    {"msvcrt.dll", "_commode", (void*)&lsw_crt_commode},  // Direct pointer to variable
    {"msvcrt.dll", "_fmode", (void*)&lsw_crt_fmode},      // Direct pointer to variable
    {"msvcrt.dll", "_errno", (void*)lsw__errno_func},
    {"msvcrt.dll", "_initterm", (void*)lsw__initterm},
    {"msvcrt.dll", "_lock", (void*)lsw__lock},
    {"msvcrt.dll", "_unlock", (void*)lsw__unlock},
    {"msvcrt.dll", "_onexit", (void*)lsw__onexit},
    {"msvcrt.dll", "__C_specific_handler", (void*)lsw___C_specific_handler},
    {"msvcrt.dll", "___lc_codepage_func", (void*)lsw___lc_codepage_func},
    {"msvcrt.dll", "___mb_cur_max_func", (void*)lsw___mb_cur_max_func},
    {"msvcrt.dll", "_XcptFilter",         (void*)lsw__XcptFilter},
    {"msvcrt.dll", "__dllonexit",         (void*)lsw___dllonexit},
    {"msvcrt.dll", "_fileno",             (void*)lsw__fileno},
    {"msvcrt.dll", "_get_osfhandle",      (void*)lsw__get_osfhandle},
    {"msvcrt.dll", "_isatty",             (void*)lsw__isatty},
    {"msvcrt.dll", "_controlfp",          (void*)lsw__controlfp},
    {"msvcrt.dll", "__p__fmode",          (void*)lsw___p__fmode},
    {"msvcrt.dll", "__p__commode",        (void*)lsw___p__commode},
    {"msvcrt.dll", "_adjust_fdiv",        (void*)lsw__adjust_fdiv},
    {"msvcrt.dll", "__p___initenv",       (void*)lsw___p___initenv},
    {"msvcrt.dll", "fputs",               (void*)lsw_fputs},
    {"msvcrt.dll", "_purecall",           (void*)lsw__purecall},
    {"msvcrt.dll", "_CxxThrowException",  (void*)lsw__CxxThrowException},
    {"msvcrt.dll", "__CxxFrameHandler",   (void*)lsw___CxxFrameHandler},
    {"msvcrt.dll", "?terminate@@YAXXZ",   (void*)lsw_cxx_terminate},
    {"msvcrt.dll", "?terminate@@YAXXX",   (void*)lsw_cxx_terminate},
    {"msvcrt.dll", "??1type_info@@UAE@XZ",(void*)lsw_type_info_dtor},
    {"msvcrt.dll", "??1type_info@@UEAA@XZ",(void*)lsw_type_info_dtor},
    {"msvcrt.dll", "wcstok",              (void*)lsw_wcstok},
    {"msvcrt.dll", "wcstok_s",            (void*)lsw_wcstok_s},
    {"ucrtbase.dll", "wcstok_s",          (void*)lsw_wcstok_s},
    {"msvcrt.dll", "wcstoul",             (void*)lsw_wcstoul},
    {"msvcrt.dll", "wcstol",              (void*)lsw_wcstol},
    {"msvcrt.dll", "wcstod",              (void*)lsw_wcstod},
    {"msvcrt.dll", "__CxxFrameHandler3",  (void*)lsw___CxxFrameHandler3},
    {"msvcrt.dll", "__CxxFrameHandler4",  (void*)lsw___CxxFrameHandler3},
    {"msvcrt.dll", "_vsnwprintf",         (void*)lsw__vsnwprintf},
    {"msvcrt.dll", "_ultow",              (void*)lsw__ultow},
    {"msvcrt.dll", "_memicmp",            (void*)lsw__memicmp},
    {"msvcrt.dll", "_callnewh",           (void*)lsw__callnewh},
    {"msvcrt.dll", "??3@YAXPEAX@Z",       (void*)lsw_operator_delete},
    {"msvcrt.dll", "??0exception@@QEAA@AEBQEBD@Z",  (void*)lsw_exception_ctor_cstr},
    {"msvcrt.dll", "??0exception@@QEAA@AEBQEBDH@Z", (void*)lsw_exception_ctor_cstr_h},
    {"msvcrt.dll", "??0exception@@QEAA@AEBV0@@Z",   (void*)lsw_exception_copy_ctor},
    {"msvcrt.dll", "??1exception@@UEAA@XZ",          (void*)lsw_exception_dtor},
    {"msvcrt.dll", "?what@exception@@UEBAPEBDXZ",    (void*)lsw_exception_what},
    
    // KERNEL32.dll
    {"KERNEL32.dll", "Sleep", (void*)lsw_Sleep},
    {"KERNEL32.dll", "GetLastError", (void*)lsw_GetLastError},
    {"KERNEL32.dll", "SetUnhandledExceptionFilter", (void*)lsw_SetUnhandledExceptionFilter},
    {"KERNEL32.dll", "UnhandledExceptionFilter",    (void*)lsw_UnhandledExceptionFilter},
    {"KERNEL32.dll", "InterlockedIncrement",         (void*)lsw_InterlockedIncrement},
    {"KERNEL32.dll", "InterlockedDecrement",         (void*)lsw_InterlockedDecrement},
    {"KERNEL32.dll", "InterlockedExchange",          (void*)lsw_InterlockedExchange},
    {"KERNEL32.dll", "InterlockedCompareExchange",   (void*)lsw_InterlockedCompareExchange},
    {"KERNEL32.dll", "GetThreadLocale",              (void*)lsw_GetThreadLocale},
    {"KERNEL32.dll", "SetThreadUILanguage",          (void*)lsw_SetThreadUILanguage},
    {"KERNEL32.dll", "GetTimeFormatW",               (void*)lsw_GetTimeFormatW},
    {"KERNEL32.dll", "FindStringOrdinal",            (void*)lsw_FindStringOrdinal},
    {"KERNEL32.dll", "SetFileApisToOEM",             (void*)lsw_SetFileApisToOEM},
    {"KERNEL32.dll", "SetFileApisToANSI",            (void*)lsw_SetFileApisToANSI},
    {"KERNEL32.dll", "IsProcessorFeaturePresent",    (void*)lsw_IsProcessorFeaturePresent},
    {"KERNEL32.dll", "GlobalMemoryStatus",           (void*)lsw_GlobalMemoryStatus},
    {"KERNEL32.dll", "GlobalMemoryStatusEx",         (void*)lsw_GlobalMemoryStatusEx},
    {"KERNEL32.dll", "GetLargePageMinimum",          (void*)lsw_GetLargePageMinimum},
    {"KERNEL32.dll", "FindFirstStreamW",             (void*)lsw_FindFirstStreamW},
    {"KERNEL32.dll", "FindNextStreamW",              (void*)lsw_FindNextStreamW},
    {"KERNEL32.dll", "FileTimeToLocalFileTime",      (void*)lsw_FileTimeToLocalFileTime},
    {"KERNEL32.dll", "FileTimeToDosDateTime",        (void*)lsw_FileTimeToDosDateTime},
    {"KERNEL32.dll", "CompareFileTime",              (void*)lsw_CompareFileTime},
    {"KERNEL32.dll", "MoveFileWithProgressW",        (void*)lsw_MoveFileWithProgressW},
    {"KERNEL32.dll", "OpenEventW",                   (void*)lsw_OpenEventW},
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

    // ADVAPI32.dll — extra stubs not in advapi32_api.c
    {"advapi32.dll", "GetSidIdentifierAuthority",  (void*)lsw_GetSidIdentifierAuthority},
    {"ADVAPI32.dll", "GetSidIdentifierAuthority",  (void*)lsw_GetSidIdentifierAuthority},
    {"advapi32.dll", "InitializeSid",              (void*)lsw_InitializeSid},
    {"ADVAPI32.dll", "InitializeSid",              (void*)lsw_InitializeSid},
    {"advapi32.dll", "LookupPrivilegeDisplayNameW",(void*)lsw_LookupPrivilegeDisplayNameW},
    {"ADVAPI32.dll", "LookupPrivilegeDisplayNameW",(void*)lsw_LookupPrivilegeDisplayNameW},
    /* LSA policy functions — needed by net user <name> for domain/SID lookups */
    {"ADVAPI32.dll", "LsaOpenPolicy",              (void*)lsw_LsaOpenPolicy},
    {"ADVAPI32.dll", "LsaQueryInformationPolicy",  (void*)lsw_LsaQueryInformationPolicy},
    {"ADVAPI32.dll", "LsaFreeMemory",              (void*)lsw_LsaFreeMemory},
    {"ADVAPI32.dll", "LsaClose",                   (void*)lsw_LsaClose},
    {"ADVAPI32.dll", "LsaLookupSids",              (void*)lsw_LsaLookupSids},
    {"ADVAPI32.dll", "LsaLookupNames2",            (void*)lsw_LsaLookupNames2},
    /* apiset forwarding for LSA policy DLL */
    {"api-ms-win-security-lsapolicy-l1-1-0.dll", "LsaOpenPolicy",             (void*)lsw_LsaOpenPolicy},
    {"api-ms-win-security-lsapolicy-l1-1-0.dll", "LsaQueryInformationPolicy", (void*)lsw_LsaQueryInformationPolicy},
    {"api-ms-win-security-lsapolicy-l1-1-0.dll", "LsaFreeMemory",             (void*)lsw_LsaFreeMemory},
    {"api-ms-win-security-lsapolicy-l1-1-0.dll", "LsaClose",                  (void*)lsw_LsaClose},
    {"api-ms-win-security-lsapolicy-l1-1-0.dll", "LsaLookupSids",             (void*)lsw_LsaLookupSids},
    {"api-ms-win-security-lsapolicy-l1-1-0.dll", "LsaLookupNames2",           (void*)lsw_LsaLookupNames2},

    // ntdll.dll — additional stubs
    {"ntdll.dll", "RtlVerifyVersionInfo",  (void*)lsw_RtlVerifyVersionInfo},
    {"ntdll.dll", "VerSetConditionMask",   (void*)lsw_VerSetConditionMask},
    {"ntdll.dll", "RtlVirtualUnwind",      (void*)lsw_RtlVirtualUnwind},

    // USER32.dll — additional stubs
    {"USER32.dll", "LoadStringW",          (void*)lsw_LoadStringW},
    {"USER32.dll", "LoadStringA",          (void*)lsw_LoadStringA},
    {"USER32.dll", "CharLowerW",           (void*)lsw_CharLowerW},
    {"USER32.dll", "CharUpperW",           (void*)lsw_CharUpperW},

    // SspiCli.dll stubs (Kerberos/NTLM auth — whoami needs these)
    {"SspiCli.dll", "GetUserNameExW",                  (void*)lsw_GetUserNameExW},
    {"SspiCli.dll", "LsaConnectUntrusted",             (void*)lsw_LsaConnectUntrusted},
    {"SspiCli.dll", "LsaCallAuthenticationPackage",    (void*)lsw_LsaCallAuthenticationPackage},
    {"SspiCli.dll", "LsaLookupAuthenticationPackage",  (void*)lsw_LsaLookupAuthenticationPackage},

    // AUTHZ.dll stubs
    {"AUTHZ.dll", "FreeClaimDefinitions",      (void*)lsw_FreeClaimDefinitions},
    {"AUTHZ.dll", "InitializeClaimDictionary", (void*)lsw_InitializeClaimDictionary},
    {"AUTHZ.dll", "GetClaimDefinitions",       (void*)lsw_GetClaimDefinitions},
    {"AUTHZ.dll", "FreeClaimDictionary",       (void*)lsw_FreeClaimDictionary},

    // wkscli.dll / netutils.dll stubs
    {"wkscli.dll",   "NetGetJoinInformation",  (void*)lsw_NetGetJoinInformation},
    {"wkscli.dll",   "NetUseGetInfo",           (void*)lsw_NetUseGetInfo},
    {"wkscli.dll",   "NetUseEnum",              (void*)lsw_NetUseEnum},
    {"wkscli.dll",   "NetWkstaUserGetInfo",     (void*)lsw_NetWkstaUserGetInfo},
    {"wkscli.dll",   "NetWkstaGetInfo",         (void*)lsw_NetWkstaGetInfo},
    {"netutils.dll", "NetApiBufferFree",        (void*)lsw_NetApiBufferFree},
    {"netutils.dll", "NetApiBufferAllocate",    (void*)lsw_NetApiBufferAllocate},
    {"netutils.dll", "NetapipBufferAllocate",   (void*)lsw_NetapipBufferAllocate},
    {"netutils.dll", "NetApiBufferReallocate",  (void*)lsw_NetApiBufferReallocate},
    {"netutils.dll", "NetpwNameValidate",       (void*)lsw_NetpwNameValidate},
    {"netutils.dll", "NetpwPathType",           (void*)lsw_NetpwPathType},
    {"samcli.dll",   "NetUserGetInfo",          (void*)lsw_NetUserGetInfo},
    {"samcli.dll",   "NetUserAdd",              (void*)lsw_NetUserAdd},
    {"samcli.dll",   "NetUserDel",              (void*)lsw_NetUserDel},
    {"samcli.dll",   "NetUserSetInfo",          (void*)lsw_NetUserSetInfo},
    {"samcli.dll",   "NetUserGetGroups",        (void*)lsw_NetUserGetGroups},
    {"samcli.dll",   "NetUserGetLocalGroups",   (void*)lsw_NetUserGetLocalGroups},
    {"samcli.dll",   "NetUserEnum",             (void*)lsw_NetUserEnum},
    {"samcli.dll",   "NetUserModalsGet",        (void*)lsw_NetUserModalsGet},
    {"samcli.dll",   "NetUserModalsSet",        (void*)lsw_NetUserModalsSet},
    {"samcli.dll",   "NetGroupAdd",             (void*)lsw_NetGroupAdd},
    {"samcli.dll",   "NetGroupDel",             (void*)lsw_NetGroupDel},
    {"samcli.dll",   "NetGroupGetInfo",         (void*)lsw_NetGroupGetInfo},
    {"samcli.dll",   "NetGroupSetInfo",         (void*)lsw_NetGroupSetInfo},
    {"samcli.dll",   "NetGroupGetUsers",        (void*)lsw_NetGroupGetUsers},
    {"samcli.dll",   "NetGroupEnum",            (void*)lsw_NetGroupEnum},
    {"samcli.dll",   "NetGroupAddUser",         (void*)lsw_NetGroupAddUser},
    {"samcli.dll",   "NetGroupDelUser",         (void*)lsw_NetGroupDelUser},
    {"srvcli.dll",   "NetServerGetInfo",        (void*)lsw_NetServerGetInfo},
    {"srvcli.dll",   "NetShareEnum",            (void*)lsw_NetShareEnum},
    {"srvcli.dll",   "NetServerEnum",           (void*)lsw_NetServerEnum},
    {"KERNEL32.dll", "NetServerEnum",           (void*)lsw_NetServerEnum},  /* some binaries import from KERNEL32 */
    /* credui.dll stubs */
    {"credui.dll",   "CredUICmdLinePromptForCredentialsW", (void*)lsw_CredUICmdLinePromptForCredentialsW},
    {"KERNEL32.dll", "CredUICmdLinePromptForCredentialsW", (void*)lsw_CredUICmdLinePromptForCredentialsW},
    /* MPR stubs */
    {"MPR.dll",   "WNetGetLastErrorW",       (void*)lsw_WNetGetLastErrorW},
    {"MPR.dll",   "WNetCancelConnection2W",  (void*)lsw_WNetCancelConnection2W},
    {"MPR.dll",   "WNetOpenEnumW",           (void*)lsw_WNetOpenEnumW},
    {"MPR.dll",   "WNetAddConnection4W",     (void*)lsw_WNetAddConnection4W},
    {"MPR.dll",   "WNetEnumResourceW",       (void*)lsw_WNetEnumResourceW},
    {"MPR.dll",   "WNetGetConnectionW",      (void*)lsw_WNetGetConnectionW},
    {"MPR.dll",   "WNetCloseEnum",           (void*)lsw_WNetCloseEnum},
    /* SspiCli stubs */
    {"SspiCli.dll", "SspiMarshalAuthIdentity",         (void*)lsw_SspiMarshalAuthIdentity},
    {"SspiCli.dll", "SsspiFreeAuthIdentity",           (void*)lsw_SsspiFreeAuthIdentity},
    {"SspiCli.dll", "SspiLocalFree",                   (void*)lsw_SspiLocalFree},
    {"SspiCli.dll", "SspiEncodeStringsAsAuthIdentity", (void*)lsw_SspiEncodeStringsAsAuthIdentity},
    {"SspiCli.dll", "SspiFreeAuthIdentity",            (void*)lsw_SspiFreeAuthIdentity},
    
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
    {"ws2_32.dll", "gethostbyname", (void*)lsw_gethostbyname},
    {"ws2_32.dll", "gethostbyaddr", (void*)lsw_gethostbyaddr},
    {"ws2_32.dll", "GetHostNameW",  (void*)lsw_GetHostNameW},
    {"ws2_32.dll", "InetNtopW",     (void*)lsw_InetNtopW},
    
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
    {"KERNEL32.dll", "GetTempPath2A", (void*)lsw_GetTempPath2A},
    {"KERNEL32.dll", "GetTempPath2W", (void*)lsw_GetTempPath2W},
    {"KERNEL32.dll", "GetTempFileNameA", (void*)lsw_GetTempFileNameA},
    {"KERNEL32.dll", "GetTempFileNameW", (void*)lsw_GetTempFileNameW},
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
    {"KERNEL32.dll", "GetVersion", (void*)lsw_GetVersion},
    {"KERNEL32.dll", "GetVersionExA", (void*)lsw_GetVersionExW},
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
    {"msvcrt.dll",   "strcpy_s",     (void*)lsw_strcpy_s},
    {"msvcrt.dll",   "strncpy_s",    (void*)lsw_strncpy_s},
    {"msvcrt.dll",   "strcat_s",     (void*)lsw_strcat_s},
    {"msvcrt.dll",   "strcoll",      (void*)lsw_strcoll},
    {"msvcrt.dll",   "_stricoll",    (void*)lsw__stricoll},
    {"msvcrt.dll",   "_strncoll",    (void*)lsw__strncoll},
    {"msvcrt.dll",   "_strnicoll",   (void*)lsw__strnicoll},
    {"msvcrt.dll",   "wcscoll",      (void*)lsw_wcscoll},
    {"msvcrt.dll",   "_wcsicoll",    (void*)lsw__wcsicoll},
    {"msvcrt.dll",   "_wcsncoll",    (void*)lsw__wcsncoll},
    {"msvcrt.dll",   "_wcsnicoll",   (void*)lsw__wcsnicoll},
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
    {"ucrtbase.dll", "__p___wargv",                 (void*)lsw___p___wargv},
    {"ucrtbase.dll", "__p__commode",                (void*)lsw___p__commode},
    {"ucrtbase.dll", "__current_exception",         (void*)lsw___current_exception},
    {"ucrtbase.dll", "__current_exception_context", (void*)lsw___current_exception_context},
    {"ucrtbase.dll", "_register_thread_local_exe_atexit_callback", (void*)lsw__register_thread_local_exe_atexit_callback},
    /* ucrtbase.dll _o_* onecore aliases — same implementations, _o_ prefix */
    {"ucrtbase.dll", "_o__errno",                   (void*)lsw__errno},
    {"ucrtbase.dll", "_o__exit",                    (void*)lsw_exit},
    {"ucrtbase.dll", "_o__cexit",                   (void*)lsw__cexit},
    {"ucrtbase.dll", "_o__c_exit",                  (void*)lsw__c_exit},
    {"ucrtbase.dll", "_o_exit",                     (void*)lsw_exit},
    {"ucrtbase.dll", "_o_terminate",                (void*)lsw_abort},
    {"ucrtbase.dll", "_o_fflush",                   (void*)lsw_fflush},
    {"ucrtbase.dll", "_o_getwchar",                 (void*)lsw_getwchar},
    {"ucrtbase.dll", "_o__fileno",                  (void*)lsw__fileno},
    {"ucrtbase.dll", "_o__get_osfhandle",            (void*)lsw__get_osfhandle},
    {"ucrtbase.dll", "_o__memicmp",                 (void*)lsw__memicmp},
    {"ucrtbase.dll", "_o__wcstoui64",               (void*)lsw__wcstoui64},
    {"ucrtbase.dll", "_o_wcstol",                   (void*)lsw_wcstol},
    {"ucrtbase.dll", "_o_wcstoul",                  (void*)lsw_wcstoul},
    {"ucrtbase.dll", "_o__set_app_type",             (void*)lsw__set_app_type},
    {"ucrtbase.dll", "_o__set_fmode",               (void*)lsw__set_fmode},
    {"ucrtbase.dll", "_o__set_new_mode",             (void*)lsw__set_new_mode},
    {"ucrtbase.dll", "_o__seh_filter_exe",           (void*)lsw__seh_filter_exe},
    {"ucrtbase.dll", "_o__resetstkoflw",             (void*)lsw__resetstkoflw},
    {"ucrtbase.dll", "_o__get_initial_wide_environment", (void*)lsw__get_initial_wide_environment},
    {"ucrtbase.dll", "_o__initialize_wide_environment",  (void*)lsw__initialize_wide_environment},
    {"ucrtbase.dll", "_o__configure_wide_argv",     (void*)lsw__configure_wide_argv},
    {"ucrtbase.dll", "_o__configthreadlocale",      (void*)lsw__configthreadlocale},
    {"ucrtbase.dll", "_o__initialize_onexit_table", (void*)lsw__initialize_onexit_table},
    {"ucrtbase.dll", "_o__register_onexit_function",(void*)lsw__register_onexit_function},
    {"ucrtbase.dll", "_o__crt_atexit",              (void*)lsw__crt_atexit},
    {"ucrtbase.dll", "_o___acrt_iob_func",          (void*)lsw___acrt_iob_func},
    {"ucrtbase.dll", "_o___stdio_common_vfprintf",  (void*)lsw___stdio_common_vfprintf},
    {"ucrtbase.dll", "_o___stdio_common_vswprintf", (void*)lsw___stdio_common_vswprintf},
    {"ucrtbase.dll", "_o___p___argc",               (void*)lsw___p___argc},
    {"ucrtbase.dll", "_o___p___wargv",              (void*)lsw___p___wargv},
    {"ucrtbase.dll", "_o___p__commode",             (void*)lsw___p__commode},
    {"ucrtbase.dll", "__C_specific_handler",        (void*)lsw___C_specific_handler},
    {"ucrtbase.dll", "_c_exit",                     (void*)lsw__c_exit},
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
    {"KERNEL32.dll", "SetDefaultDllDirectories", (void*)lsw_SetDefaultDllDirectories},
    {"KERNEL32.dll", "AddDllDirectory",          (void*)lsw_AddDllDirectory},
    {"KERNEL32.dll", "RemoveDllDirectory",       (void*)lsw_RemoveDllDirectory},
    {"KERNEL32.dll", "SetDllDirectoryW",         (void*)lsw_SetDllDirectoryW},
    {"KERNEL32.dll", "SetDllDirectoryA",         (void*)lsw_SetDllDirectoryA},
    {"KERNEL32.dll", "GetDllDirectoryW",         (void*)lsw_GetDllDirectoryW},
    {"KERNEL32.dll", "GetDllDirectoryA",         (void*)lsw_GetDllDirectoryA},
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
    {"KERNEL32.dll", "GetDiskFreeSpaceA",        (void*)lsw_GetDiskFreeSpaceA},
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
    /* New KERNEL32 entries for broader app compat */
    {"KERNEL32.dll", "GetComputerNameW",         (void*)lsw_GetComputerNameW},
    {"KERNEL32.dll", "GetComputerNameA",         (void*)lsw_GetComputerNameA},
    {"KERNEL32.dll", "GetComputerNameExW",       (void*)lsw_GetComputerNameExW},
    {"KERNEL32.dll", "GetDateFormatW",           (void*)lsw_GetDateFormatW},
    {"KERNEL32.dll", "RtlCaptureContext",        (void*)lsw_RtlCaptureContext},
    {"KERNEL32.dll", "RtlLookupFunctionEntry",   (void*)lsw_RtlLookupFunctionEntry},
    {"KERNEL32.dll", "RtlVirtualUnwind",         (void*)lsw_RtlVirtualUnwind},
    {"KERNEL32.dll", "GetCPInfo",                (void*)lsw_GetCPInfo},
    {"KERNEL32.dll", "ApiSetQueryApiSetPresence",(void*)lsw_ApiSetQueryApiSetPresence},
    {"KERNEL32.dll", "ResolveDelayLoadedAPI",    (void*)lsw_ResolveDelayLoadedAPI},
    {"KERNEL32.dll", "DelayLoadFailureHook",     (void*)lsw_DelayLoadFailureHook},
    {"KERNEL32.dll", "PeekConsoleInputW",        (void*)lsw_PeekConsoleInputW},
    {"ntdll.dll",    "RtlCaptureContext",        (void*)lsw_RtlCaptureContext},
    {"ntdll.dll",    "RtlLookupFunctionEntry",   (void*)lsw_RtlLookupFunctionEntry},
    /* msvcrt.dll new entries */
    {"msvcrt.dll",   "_wcsicmp",    (void*)lsw__wcsicmp},
    {"msvcrt.dll",   "_wcsnicmp",   (void*)lsw__wcsnicmp},
    {"msvcrt.dll",   "_write",      (void*)lsw__write},
    {"msvcrt.dll",   "_setmode",    (void*)lsw__setmode},
    {"msvcrt.dll",   "setlocale",   (void*)lsw_setlocale},
    {"msvcrt.dll",   "fgetpos",     (void*)lsw_fgetpos},
    {"msvcrt.dll",   "_vscwprintf", (void*)lsw__vscwprintf},
    {"msvcrt.dll",   "vswprintf_s", (void*)lsw_vswprintf_s},
    {"msvcrt.dll",   "swprintf_s",  (void*)lsw_swprintf_s},
    {"msvcrt.dll",   "_wcsrev",     (void*)lsw__wcsrev},
    /* msvcrt.dll — additional missing entries for net.exe and similar */
    {"msvcrt.dll",   "sprintf_s",   (void*)lsw_sprintf_s},
    {"msvcrt.dll",   "wcscpy_s",    (void*)lsw_wcscpy_s},
    {"msvcrt.dll",   "wcscat_s",    (void*)lsw_wcscat_s},
    {"msvcrt.dll",   "wcsncat_s",   (void*)lsw_wcsncat_s},
    {"msvcrt.dll",   "wcsncpy_s",   (void*)lsw_wcsncpy_s},
    {"msvcrt.dll",   "wcsspn",      (void*)lsw_wcsspn},
    {"msvcrt.dll",   "wcspbrk",     (void*)lsw_wcspbrk},
    {"msvcrt.dll",   "wcscspn",     (void*)lsw_wcscspn},
    {"msvcrt.dll",   "_wcsupr",     (void*)lsw__wcsupr},
    {"msvcrt.dll",   "_wtoi",       (void*)lsw__wtoi},
    {"msvcrt.dll",   "_wtoi64",     (void*)lsw__wtoi64},
    {"msvcrt.dll",   "iswctype",    (void*)lsw_iswctype},
    {"msvcrt.dll",   "_snwprintf_s",(void*)lsw__snwprintf_s},
    {"msvcrt.dll",   "_vsnwprintf_s",(void*)lsw__vsnwprintf_s},
    {"msvcrt.dll",   "_local_unwind",(void*)lsw__local_unwind},
    {"ucrtbase.dll", "_wcsicmp",    (void*)lsw__wcsicmp},
    {"ucrtbase.dll", "_wcsnicmp",   (void*)lsw__wcsnicmp},
    {"ucrtbase.dll", "_write",      (void*)lsw__write},
    {"ucrtbase.dll", "_setmode",    (void*)lsw__setmode},
    {"ucrtbase.dll", "setlocale",   (void*)lsw_setlocale},
    {"ucrtbase.dll", "fgetpos",     (void*)lsw_fgetpos},
    {"ucrtbase.dll", "_vscwprintf", (void*)lsw__vscwprintf},
    {"ucrtbase.dll", "vswprintf_s", (void*)lsw_vswprintf_s},
    // USER32 SystemParametersInfo (also lives under user32.dll)
    {"user32.dll",   "SystemParametersInfoW",    (void*)lsw_SystemParametersInfoW},
    {"user32.dll",   "SystemParametersInfoA",    (void*)lsw_SystemParametersInfoA},
    /* OLEAUT32.dll BSTR API (also exported by name in some DLL chains) */
    {"OLEAUT32.dll", "SysAllocString",            (void*)lsw_SysAllocString},
    {"OLEAUT32.dll", "SysAllocStringLen",         (void*)lsw_SysAllocStringLen},
    {"OLEAUT32.dll", "SysAllocStringByteLen",     (void*)lsw_SysAllocStringByteLen},
    {"OLEAUT32.dll", "SysReAllocString",          (void*)lsw_SysReAllocString},
    {"OLEAUT32.dll", "SysReAllocStringLen",       (void*)lsw_SysReAllocStringLen},
    {"OLEAUT32.dll", "SysFreeString",             (void*)lsw_SysFreeString},
    {"OLEAUT32.dll", "SysStringLen",              (void*)lsw_SysStringLen},
    {"OLEAUT32.dll", "SysStringByteLen",          (void*)lsw_SysStringByteLen},
    /* ADVAPI32.dll — RegOpenKeyW (thin wrapper without SAM/options) */
    {"ADVAPI32.dll", "RegOpenKeyW",               (void*)lsw_RegOpenKeyW},
    {"ADVAPI32.dll", "IsTextUnicode",             (void*)lsw_IsTextUnicode},

    /* wkscli.dll */
    {"wkscli.dll",   "NetWkstaTransportEnum",      (void*)lsw_NetWkstaTransportEnum},
    {"wkscli.dll",   "NetWkstaStatisticsGet",      (void*)lsw_NetWkstaStatisticsGet},

    /* netutils.dll */
    {"netutils.dll", "NetpwListCanonicalize",      (void*)lsw_NetpwListCanonicalize},
    {"netutils.dll", "NetpwNameCompare",           (void*)lsw_NetpwNameCompare},
    {"netutils.dll", "NetpwListTraverse",          (void*)lsw_NetpwListTraverse},
    {"netutils.dll", "NetpwNameCanonicalize",      (void*)lsw_NetpwNameCanonicalize},

    /* DSROLE.dll */
    {"DSROLE.dll",   "DsRoleGetPrimaryDomainInformation", (void*)lsw_DsRoleGetPrimaryDomainInformation},
    {"DSROLE.dll",   "DsRoleFreeMemory",           (void*)lsw_DsRoleFreeMemory},

    /* logoncli.dll / netlogon DS client */
    {"logoncli.dll", "DsGetDcNameW",               (void*)lsw_DsGetDcNameW},
    {"logoncli.dll", "DsBindWithSpnExW",           (void*)lsw_DsBindWithSpnExW},
    {"logoncli.dll", "DsUnBindW",                  (void*)lsw_DsUnBindW},
    {"logoncli.dll", "DsFreeNameResultW",          (void*)lsw_DsFreeNameResultW},
    {"logoncli.dll", "DsCrackNamesW",              (void*)lsw_DsCrackNamesW},

    /* srvcli.dll */
    {"srvcli.dll",   "NetFileEnum",                (void*)lsw_NetFileEnum},
    {"srvcli.dll",   "NetFileGetInfo",             (void*)lsw_NetFileGetInfo},
    {"srvcli.dll",   "NetFileClose",               (void*)lsw_NetFileClose},
    {"srvcli.dll",   "NetSessionEnum",             (void*)lsw_NetSessionEnum},
    {"srvcli.dll",   "NetSessionGetInfo",          (void*)lsw_NetSessionGetInfo},
    {"srvcli.dll",   "NetSessionDel",              (void*)lsw_NetSessionDel},
    {"srvcli.dll",   "NetConnectionEnum",          (void*)lsw_NetConnectionEnum},
    {"srvcli.dll",   "NetServerTransportEnum",     (void*)lsw_NetServerTransportEnum},
    {"srvcli.dll",   "NetServerSetInfo",           (void*)lsw_NetServerSetInfo},
    {"srvcli.dll",   "NetShareGetInfo",            (void*)lsw_NetShareGetInfo},
    {"srvcli.dll",   "NetShareCheck",              (void*)lsw_NetShareCheck},
    {"srvcli.dll",   "NetShareSetInfo",            (void*)lsw_NetShareSetInfo},
    {"srvcli.dll",   "NetShareDel",                (void*)lsw_NetShareDel},
    {"srvcli.dll",   "NetShareDelSticky",          (void*)lsw_NetShareDelSticky},
    {"srvcli.dll",   "NetShareAdd",                (void*)lsw_NetShareAdd},
    {"srvcli.dll",   "NetRemoteTOD",               (void*)lsw_NetRemoteTOD},

    /* KERNEL32.dll missing stubs */
    {"KERNEL32.dll", "SetLocalTime",               (void*)lsw_SetLocalTime},
    {"KERNEL32.dll", "SetSystemTime",              (void*)lsw_SetSystemTime},

    /* CRYPTBASE.dll — RtlGenRandom alias */
    {"CRYPTBASE.dll","SystemFunction036",          (void*)lsw_SystemFunction036},

    /* advapi32.dll — same RtlGenRandom export */
    {"ADVAPI32.dll", "SystemFunction036",          (void*)lsw_SystemFunction036},

    /* api-ms-win-service-management-l1-1-0.dll aliases */
    {"api-ms-win-service-management-l1-1-0.dll", "GetServiceDisplayNameW", (void*)lsw_GetServiceDisplayNameW},
    {"api-ms-win-service-management-l1-1-0.dll", "GetServiceKeyNameW",     (void*)lsw_GetServiceKeyNameW},
    {"api-ms-win-service-management-l1-1-0.dll", "EnumServicesStatusExW",  (void*)lsw_EnumServicesStatusExW},
    {"api-ms-win-service-management-l1-1-0.dll", "EnumDependentServicesW", (void*)lsw_EnumDependentServicesW},

    /* api-ms-win-service-core-l1-1-1.dll aliases */
    {"api-ms-win-service-core-l1-1-1.dll",       "GetServiceDisplayNameW", (void*)lsw_GetServiceDisplayNameW},
    {"api-ms-win-service-core-l1-1-1.dll",       "GetServiceKeyNameW",     (void*)lsw_GetServiceKeyNameW},
    {"api-ms-win-service-core-l1-1-1.dll",       "EnumServicesStatusExW",  (void*)lsw_EnumServicesStatusExW},
    {"api-ms-win-service-core-l1-1-1.dll",       "EnumDependentServicesW", (void*)lsw_EnumDependentServicesW},

    /* api-ms-win-service-core-l1-1-2.dll aliases */
    {"api-ms-win-service-core-l1-1-2.dll",       "GetServiceDisplayNameW", (void*)lsw_GetServiceDisplayNameW},
    {"api-ms-win-service-core-l1-1-2.dll",       "GetServiceKeyNameW",     (void*)lsw_GetServiceKeyNameW},
    {"api-ms-win-service-core-l1-1-2.dll",       "EnumServicesStatusExW",  (void*)lsw_EnumServicesStatusExW},
    {"api-ms-win-service-core-l1-1-2.dll",       "EnumDependentServicesW", (void*)lsw_EnumDependentServicesW},

    /* api-ms-win-security-activedirectoryclient-l1-1-0.dll */
    {"api-ms-win-security-activedirectoryclient-l1-1-0.dll", "DsGetDcNameW", (void*)lsw_DsGetDcNameW},

    /* ── api-ms-win-core-* DLL aliases ──────────────────────────────── */
    /* api-ms-win-core-apiquery */
    {"api-ms-win-core-apiquery-l1-1-0.dll", "ApiSetQueryApiSetPresence", (void*)lsw_ApiSetQueryApiSetPresence},

    /* api-ms-win-core-console */
    {"api-ms-win-core-console-l1-1-0.dll",  "GetConsoleMode",        (void*)lsw_GetConsoleMode},
    {"api-ms-win-core-console-l1-1-0.dll",  "SetConsoleMode",        (void*)lsw_SetConsoleMode},
    {"api-ms-win-core-console-l1-1-0.dll",  "ReadConsoleW",          (void*)lsw_ReadConsoleW},
    {"api-ms-win-core-console-l1-1-0.dll",  "GetConsoleOutputCP",    (void*)lsw_GetConsoleOutputCP},
    {"api-ms-win-core-console-l1-1-0.dll",  "WriteConsoleW",         (void*)lsw_WriteConsoleW},
    {"api-ms-win-core-console-l1-2-0.dll",  "PeekConsoleInputW",     (void*)lsw_PeekConsoleInputW},

    /* api-ms-win-core-datetime */
    {"api-ms-win-core-datetime-l1-1-0.dll", "GetDateFormatW",        (void*)lsw_GetDateFormatW},
    {"api-ms-win-core-datetime-l1-1-0.dll", "GetTimeFormatW",        (void*)lsw_GetTimeFormatW},

    /* api-ms-win-core-delayload */
    {"api-ms-win-core-delayload-l1-1-0.dll","DelayLoadFailureHook",  (void*)lsw_DelayLoadFailureHook},
    {"api-ms-win-core-delayload-l1-1-1.dll","ResolveDelayLoadedAPI", (void*)lsw_ResolveDelayLoadedAPI},

    /* api-ms-win-core-errorhandling */
    {"api-ms-win-core-errorhandling-l1-1-0.dll","SetLastError",               (void*)lsw_SetLastError},
    {"api-ms-win-core-errorhandling-l1-1-0.dll","GetLastError",               (void*)lsw_GetLastError},
    {"api-ms-win-core-errorhandling-l1-1-0.dll","SetUnhandledExceptionFilter",(void*)lsw_SetUnhandledExceptionFilter},
    {"api-ms-win-core-errorhandling-l1-1-0.dll","UnhandledExceptionFilter",   (void*)lsw_UnhandledExceptionFilter},

    /* api-ms-win-core-file */
    {"api-ms-win-core-file-l1-1-0.dll",     "GetFileType",           (void*)lsw_GetFileType},
    {"api-ms-win-core-file-l1-1-0.dll",     "WriteFile",             (void*)lsw_WriteFile},
    {"api-ms-win-core-file-l1-1-0.dll",     "GetDriveTypeW",         (void*)lsw_GetDriveTypeW},

    /* api-ms-win-core-heap */
    {"api-ms-win-core-heap-l1-1-0.dll",     "HeapSetInformation",    (void*)lsw_HeapSetInformation},
    {"api-ms-win-core-heap-l2-1-0.dll",     "LocalAlloc",            (void*)lsw_LocalAlloc},
    {"api-ms-win-core-heap-l2-1-0.dll",     "LocalFree",             (void*)lsw_LocalFree},
    {"api-ms-win-core-heap-l2-1-0.dll",     "GlobalFree",            (void*)lsw_GlobalFree},
    {"api-ms-win-core-heap-l2-1-0.dll",     "GlobalAlloc",           (void*)lsw_GlobalAlloc},

    /* api-ms-win-core-libraryloader */
    {"api-ms-win-core-libraryloader-l1-2-0.dll","GetProcAddress",    (void*)lsw_GetProcAddress},
    {"api-ms-win-core-libraryloader-l1-2-0.dll","GetModuleHandleW",  (void*)lsw_GetModuleHandleW},
    {"api-ms-win-core-libraryloader-l1-2-0.dll","GetModuleFileNameW",(void*)lsw_GetModuleFileNameW},
    {"api-ms-win-core-libraryloader-l1-2-0.dll","FreeLibrary",       (void*)lsw_FreeLibrary},
    {"api-ms-win-core-libraryloader-l1-2-0.dll","LoadLibraryExW",    (void*)lsw_LoadLibraryExW},

    /* api-ms-win-core-localization */
    {"api-ms-win-core-localization-l1-2-0.dll","SetThreadUILanguage",(void*)lsw_SetThreadUILanguage},
    {"api-ms-win-core-localization-l1-2-0.dll","FormatMessageW",     (void*)lsw_FormatMessageW},
    {"api-ms-win-core-localization-l1-2-0.dll","GetUserDefaultLCID", (void*)lsw_GetUserDefaultLCID},
    {"api-ms-win-core-localization-l1-2-0.dll","GetCPInfo",          (void*)lsw_GetCPInfo},

    /* api-ms-win-core-privateprofile */
    {"api-ms-win-core-privateprofile-l1-1-0.dll","GetProfileStringW",(void*)lsw_GetProfileStringW},

    /* api-ms-win-core-processenvironment */
    {"api-ms-win-core-processenvironment-l1-1-0.dll","GetCommandLineW",(void*)lsw_GetCommandLineW},
    {"api-ms-win-core-processenvironment-l1-1-0.dll","GetStdHandle",   (void*)lsw_GetStdHandle},

    /* api-ms-win-core-processthreads */
    {"api-ms-win-core-processthreads-l1-1-0.dll","TerminateProcess",    (void*)lsw_TerminateProcess},
    {"api-ms-win-core-processthreads-l1-1-0.dll","GetCurrentThreadId",  (void*)lsw_GetCurrentThreadId},
    {"api-ms-win-core-processthreads-l1-1-0.dll","GetCurrentProcessId", (void*)lsw_GetCurrentProcessId},
    {"api-ms-win-core-processthreads-l1-1-0.dll","GetCurrentProcess",   (void*)lsw_GetCurrentProcess},

    /* api-ms-win-core-profile */
    {"api-ms-win-core-profile-l1-1-0.dll",  "QueryPerformanceCounter",(void*)lsw_QueryPerformanceCounter},

    /* api-ms-win-core-registry */
    {"api-ms-win-core-registry-l1-1-0.dll", "RegOpenKeyExW",         (void*)lsw_RegOpenKeyExW},
    {"api-ms-win-core-registry-l1-1-0.dll", "RegQueryValueExW",      (void*)lsw_RegQueryValueExW},
    {"api-ms-win-core-registry-l1-1-0.dll", "RegCloseKey",           (void*)lsw_RegCloseKey},

    /* api-ms-win-core-rtlsupport */
    {"api-ms-win-core-rtlsupport-l1-1-0.dll","RtlCompareMemory",     (void*)lsw_RtlCompareMemory},
    {"api-ms-win-core-rtlsupport-l1-1-0.dll","RtlLookupFunctionEntry",(void*)lsw_RtlLookupFunctionEntry},
    {"api-ms-win-core-rtlsupport-l1-1-0.dll","RtlCaptureContext",    (void*)lsw_RtlCaptureContext},
    {"api-ms-win-core-rtlsupport-l1-1-0.dll","RtlVirtualUnwind",     (void*)lsw_RtlVirtualUnwind},

    /* api-ms-win-core-string */
    {"api-ms-win-core-string-l1-1-0.dll",   "CompareStringW",        (void*)lsw_CompareStringW},
    {"api-ms-win-core-string-l1-1-0.dll",   "WideCharToMultiByte",   (void*)lsw_WideCharToMultiByte},

    /* api-ms-win-core-synch */
    {"api-ms-win-core-synch-l1-2-0.dll",    "Sleep",                 (void*)lsw_Sleep},

    /* api-ms-win-core-sysinfo */
    {"api-ms-win-core-sysinfo-l1-1-0.dll",  "GetTickCount",          (void*)lsw_GetTickCount},
    {"api-ms-win-core-sysinfo-l1-1-0.dll",  "GetSystemTimeAsFileTime",(void*)lsw_GetSystemTimeAsFileTime},
    {"api-ms-win-core-sysinfo-l1-1-0.dll",  "SetLocalTime",          (void*)lsw_SetLocalTime},
    {"api-ms-win-core-sysinfo-l1-1-0.dll",  "GetSystemDirectoryW",   (void*)lsw_GetSystemDirectoryW},
    {"api-ms-win-core-sysinfo-l1-1-0.dll",  "GetComputerNameExW",    (void*)lsw_GetComputerNameExW},
    {"api-ms-win-core-sysinfo-l1-2-0.dll",  "SetSystemTime",         (void*)lsw_SetSystemTime},

    /* api-ms-win-core-timezone */
    {"api-ms-win-core-timezone-l1-1-0.dll", "GetTimeZoneInformation",(void*)lsw_GetTimeZoneInformation},

    /* api-ms-win-security-activedirectoryclient (DS bind/crack) */
    {"api-ms-win-security-activedirectoryclient-l1-1-0.dll","DsBindWithSpnExW", (void*)lsw_DsBindWithSpnExW},
    {"api-ms-win-security-activedirectoryclient-l1-1-0.dll","DsFreeNameResultW",(void*)lsw_DsFreeNameResultW},
    {"api-ms-win-security-activedirectoryclient-l1-1-0.dll","DsUnBindW",        (void*)lsw_DsUnBindW},
    {"api-ms-win-security-activedirectoryclient-l1-1-0.dll","DsCrackNamesW",    (void*)lsw_DsCrackNamesW},

    /* api-ms-win-security-base */
    {"api-ms-win-security-base-l1-1-0.dll", "InitializeAcl",              (void*)lsw_InitializeAcl},
    {"api-ms-win-security-base-l1-1-0.dll", "InitializeSecurityDescriptor",(void*)lsw_InitializeSecurityDescriptor},
    {"api-ms-win-security-base-l1-1-0.dll", "GetSidLengthRequired",       (void*)lsw_GetSidLengthRequired},
    {"api-ms-win-security-base-l1-1-0.dll", "EqualSid",                   (void*)lsw_EqualSid},
    {"api-ms-win-security-base-l1-1-0.dll", "CopySid",                    (void*)lsw_CopySid},
    {"api-ms-win-security-base-l1-1-0.dll", "CreateWellKnownSid",         (void*)lsw_CreateWellKnownSid},
    {"api-ms-win-security-base-l1-1-0.dll", "GetLengthSid",               (void*)lsw_GetLengthSid},
    {"api-ms-win-security-base-l1-1-0.dll", "GetAce",                     (void*)lsw_GetAce},
    {"api-ms-win-security-base-l1-1-0.dll", "AddAccessAllowedAce",        (void*)lsw_AddAccessAllowedAce},
    {"api-ms-win-security-base-l1-1-0.dll", "GetSecurityDescriptorDacl",  (void*)lsw_GetSecurityDescriptorDacl},
    {"api-ms-win-security-base-l1-1-0.dll", "SetSecurityDescriptorDacl",  (void*)lsw_SetSecurityDescriptorDacl},
    {"api-ms-win-security-base-l1-1-0.dll", "GetSidSubAuthorityCount",    (void*)lsw_GetSidSubAuthorityCount},
    {"api-ms-win-security-base-l1-1-0.dll", "GetSidSubAuthority",         (void*)lsw_GetSidSubAuthority},

    /* imagehlp.dll — debugging/module enumeration */
    {"imagehlp.dll", "EnumerateLoadedModulesW64", (void*)lsw_EnumerateLoadedModulesW64},
    {"imagehlp.dll", "EnumerateLoadedModules64",  (void*)lsw_EnumerateLoadedModulesW64},
    {"imagehlp.dll", "EnumerateLoadedModules",    (void*)lsw_EnumerateLoadedModulesW64},
    {"imagehlp.dll", "ImagehlpApiVersion",        (void*)lsw_ImagehlpApiVersion},

    /* dbghelp.dll — debug helper stubs */
    {"dbghelp.dll",  "SymInitialize",             (void*)lsw_SymInitialize},
    {"dbghelp.dll",  "SymCleanup",                (void*)lsw_SymCleanup},
    {"dbghelp.dll",  "EnumerateLoadedModulesW64", (void*)lsw_EnumerateLoadedModulesW64},
    {"dbghelp.dll",  "EnumerateLoadedModules64",  (void*)lsw_EnumerateLoadedModulesW64},
    {"dbghelp.dll",  "ImagehlpApiVersion",        (void*)lsw_ImagehlpApiVersion},

    /* ws2_32.dll — wide-char address/name resolution */
    {"ws2_32.dll",   "GetAddrInfoW",              (void*)lsw_GetAddrInfoW},
    {"ws2_32.dll",   "FreeAddrInfoW",             (void*)lsw_FreeAddrInfoW},
    {"ws2_32.dll",   "GetNameInfoW",              (void*)lsw_GetNameInfoW},
    {"WS2_32.dll",   "GetAddrInfoW",              (void*)lsw_GetAddrInfoW},
    {"WS2_32.dll",   "FreeAddrInfoW",             (void*)lsw_FreeAddrInfoW},
    {"WS2_32.dll",   "GetNameInfoW",              (void*)lsw_GetNameInfoW},

    /* IPHLPAPI.DLL — extended ICMP */
    {"IPHLPAPI.DLL", "IcmpSendEcho2Ex",           (void*)lsw_IcmpSendEcho2Ex},
    {"IPHLPAPI.DLL", "Icmp6CreateFile",           (void*)lsw_Icmp6CreateFile},
    {"IPHLPAPI.DLL", "Icmp6SendEcho2",            (void*)lsw_Icmp6SendEcho2},
    {"IPHLPAPI.DLL", "GetIpErrorString",          (void*)lsw_GetIpErrorString},
    {"iphlpapi.dll", "IcmpSendEcho2Ex",           (void*)lsw_IcmpSendEcho2Ex},
    {"iphlpapi.dll", "Icmp6CreateFile",           (void*)lsw_Icmp6CreateFile},
    {"iphlpapi.dll", "Icmp6SendEcho2",            (void*)lsw_Icmp6SendEcho2},
    {"iphlpapi.dll", "GetIpErrorString",          (void*)lsw_GetIpErrorString},
};

#pragma GCC diagnostic pop

static const size_t api_mappings_count = sizeof(api_mappings) / sizeof(api_mappings[0]);

// Generic stub for unresolved functions
static int generic_stub(void) {
    void* caller = __builtin_return_address(0);
    LSW_LOG_WARN("Called unresolved Win32 API function (called from %p) - returning 0", caller);
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
    /* OLEAUT32.dll BSTR functions — exported by ordinal */
    {"OLEAUT32.dll",  2, "SysAllocString"},
    {"OLEAUT32.dll",  3, "SysReAllocString"},
    {"OLEAUT32.dll",  4, "SysAllocStringLen"},
    {"OLEAUT32.dll",  5, "SysReAllocStringLen"},
    {"OLEAUT32.dll",  6, "SysFreeString"},
    {"OLEAUT32.dll",  7, "SysStringLen"},
    {"OLEAUT32.dll",  8, "SysStringByteLen"},
    {"OLEAUT32.dll",  9, "SysAllocStringByteLen"},
    {"OLEAUT32.dll", 10, "SysAllocStringByteLen"},  /* alias ordinal 10 */
    {"OLEAUT32.dll", 12, "VariantInit"},             /* Variant init — VT_EMPTY */
    {"OLEAUT32.dll", 13, "VariantClear"},
    {"OLEAUT32.dll", 14, "VariantCopy"},
    {"OLEAUT32.dll", 16, "VariantChangeType"},
    {"OLEAUT32.dll", 150, "VariantTimeToSystemTime"},/* Var time conversions */
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
