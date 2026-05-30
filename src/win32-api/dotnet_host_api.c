/*
 * dotnet_host_api.c — .NET CLR hosting bridge for LSW
 *
 * Enables framework-dependent .NET 8+ applications to run on Linux via LSW.
 *
 * How it works:
 *   1. The Windows .NET apphost tries to LoadLibrary("...hostfxr.dll")
 *   2. lsw_LoadLibraryA intercepts by basename (hostfxr.dll is in system_dlls)
 *      and returns LSW_SYSTEM_HMODULE
 *   3. GetProcAddress("hostfxr_main", ...) routes to our ms_abi wrappers here
 *   4. Our wrappers convert UTF-16LE paths → UTF-8, Windows paths → Linux paths,
 *      then call the Linux libhostfxr.so with System V ABI
 *
 * Path resolution:
 *   C:\Program Files\dotnet  →  Linux .NET root (auto-detected)
 *   The fake bridge directory at ~/.lsw/dotnet/ mirrors the Windows install
 *   structure so that GetFileAttributesW / FindFirstFileW succeed before
 *   LoadLibraryW is called.
 *
 * P/Invoke from managed code:
 *   .NET managed code that uses standard BCL APIs (no raw Win32 P/Invoke) will
 *   run transparently.  Apps that P/Invoke into KERNEL32.dll etc. will hit the
 *   LSW stub layer only if those DLLs are mapped; otherwise P/Invoke returns an
 *   error (same as missing DLL on Windows).
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"

/* ---- Forward declarations ---- */
extern lsw_status_t lsw_fs_win_to_linux(const char* wpath, char* lpath, size_t lsz);

/* ---- Module-level state ---- */

static void*  g_hostfxr_so      = NULL;  /* dlopen handle to libhostfxr.so */
static char   g_linux_dotnet_root[512] = "";
static char   g_fxr_version[64]        = "";
static int    g_dotnet_detected        = 0;  /* 1 = detected, -1 = not found, 0 = uninitialized */
static char   g_bridge_dir[512]        = "";  /* ~/.lsw/dotnet/ bridge directory */

/* Fake Windows path for the dotnet installation seen by Windows apps */
#define LSW_DOTNET_WIN_PATH "C:\\Program Files\\dotnet"

/* ---- UTF-16LE → UTF-8 ---- */
static void u16_to_u8(const uint16_t* src, char* dst, size_t maxbytes) {
    size_t n = 0;
    if (!src || !dst || maxbytes == 0) { if (dst) dst[0] = '\0'; return; }
    for (; *src && n < maxbytes - 4; src++) {
        uint32_t c = *src;
        if      (c < 0x80)  { dst[n++] = (char)c; }
        else if (c < 0x800) { dst[n++] = (char)(0xC0|(c>>6)); dst[n++]=(char)(0x80|(c&0x3f)); }
        else                 { dst[n++]=(char)(0xE0|(c>>12)); dst[n++]=(char)(0x80|((c>>6)&0x3f)); dst[n++]=(char)(0x80|(c&0x3f)); }
    }
    dst[n] = '\0';
}

/* ---- UTF-8 → UTF-16LE ---- */
static void u8_to_u16(const char* src, uint16_t* dst, size_t maxwords) {
    size_t n = 0;
    if (!src || !dst || maxwords == 0) { if (dst) dst[0] = 0; return; }
    for (; *src && n < maxwords - 1; ) {
        uint8_t b = (uint8_t)*src++;
        if      (b < 0x80) { dst[n++] = b; }
        else if ((b & 0xE0) == 0xC0 && *src) { dst[n++] = (uint16_t)(((b&0x1f)<<6)|(*src++&0x3f)); }
        else if ((b & 0xF0) == 0xE0 && src[0] && src[1]) {
            uint32_t c = ((uint32_t)(b&0x0f)<<12)|((uint32_t)(src[0]&0x3f)<<6)|(src[1]&0x3f);
            src += 2; dst[n++] = (uint16_t)c;
        } else { dst[n++] = '?'; }
    }
    dst[n] = 0;
}

/* ---- Windows path → Linux path ---- */
static void fxr_wpath_to_linux(const uint16_t* wpath, char* out, size_t outsz) {
    if (!wpath) { if (out && outsz > 0) out[0] = '\0'; return; }
    char utf8[4096];
    u16_to_u8(wpath, utf8, sizeof(utf8));

    /* Redirect C:\Program Files\dotnet (and variants) to Linux dotnet root */
    static const char* win_prefix[] = {
        "C:\\Program Files\\dotnet",
        "C:/Program Files/dotnet",
        NULL
    };
    for (int i = 0; win_prefix[i]; i++) {
        size_t plen = strlen(win_prefix[i]);
        if (strncasecmp(utf8, win_prefix[i], plen) == 0) {
            const char* rest = utf8 + plen;
            snprintf(out, outsz, "%s%s", g_linux_dotnet_root[0] ? g_linux_dotnet_root : "/usr/lib/dotnet", rest);
            for (char* p = out; *p; p++) if (*p == '\\') *p = '/';
            return;
        }
    }
    /* Also redirect bridge dir paths */
    if (g_bridge_dir[0] && strncmp(utf8, g_bridge_dir, strlen(g_bridge_dir)) == 0) {
        const char* rest = utf8 + strlen(g_bridge_dir);
        snprintf(out, outsz, "%s%s", g_linux_dotnet_root[0] ? g_linux_dotnet_root : "/usr/lib/dotnet", rest);
        for (char* p = out; *p; p++) if (*p == '\\') *p = '/';
        return;
    }
    /* General LSW path translation */
    if (lsw_fs_win_to_linux(utf8, out, outsz) != 0) {
        snprintf(out, outsz, "%s", utf8);
    }
}

/* Narrow (char*) Windows path → Linux path */
static void fxr_path_to_linux(const char* wpath, char* out, size_t outsz) {
    if (!wpath) { if (out && outsz > 0) out[0] = '\0'; return; }
    static const char* win_prefix[] = {
        "C:\\Program Files\\dotnet",
        "C:/Program Files/dotnet",
        NULL
    };
    for (int i = 0; win_prefix[i]; i++) {
        size_t plen = strlen(win_prefix[i]);
        if (strncasecmp(wpath, win_prefix[i], plen) == 0) {
            const char* rest = wpath + plen;
            snprintf(out, outsz, "%s%s", g_linux_dotnet_root[0] ? g_linux_dotnet_root : "/usr/lib/dotnet", rest);
            for (char* p = out; *p; p++) if (*p == '\\') *p = '/';
            return;
        }
    }
    if (lsw_fs_win_to_linux(wpath, out, outsz) != 0) {
        snprintf(out, outsz, "%s", wpath);
    }
}

/* ---- Dynamic linker helpers ---- */

static void* lsw_hostfxr_fn(const char* name) {
    if (!g_hostfxr_so) {
        LSW_LOG_WARN("dotnet_host: libhostfxr.so not loaded, cannot get %s", name);
        return NULL;
    }
    void* fn = dlsym(g_hostfxr_so, name);
    if (!fn) LSW_LOG_WARN("dotnet_host: dlsym(%s) failed: %s", name, dlerror());
    return fn;
}

/* ---- Detection and bridge directory creation ---- */

/* Find the Linux .NET root (checks common locations and $DOTNET_ROOT) */
static int detect_linux_dotnet(void) {
    static const char* candidates[] = {
        "/usr/lib/dotnet",
        "/usr/share/dotnet",
        "/usr/local/share/dotnet",
        NULL
    };
    /* Check DOTNET_ROOT first */
    const char* env = getenv("LSW_DOTNET_LINUX_ROOT");
    if (env && access(env, F_OK) == 0) {
        snprintf(g_linux_dotnet_root, sizeof(g_linux_dotnet_root), "%s", env);
        return 1;
    }
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], F_OK) == 0) {
            snprintf(g_linux_dotnet_root, sizeof(g_linux_dotnet_root), "%s", candidates[i]);
            return 1;
        }
    }
    return 0;
}

/* Find the installed hostfxr version under <dotnet_root>/host/fxr/ */
static int detect_fxr_version(void) {
    char fxr_dir[512];
    snprintf(fxr_dir, sizeof(fxr_dir), "%s/host/fxr", g_linux_dotnet_root);
    DIR* d = opendir(fxr_dir);
    if (!d) return 0;
    /* Find latest version directory */
    char best[64] = "";
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strlen(ent->d_name) > sizeof(best) - 1) continue;
        /* Simple lexicographic pick — versions are like 8.0.27 */
        if (strcmp(ent->d_name, best) > 0) {
            snprintf(best, sizeof(best), "%s", ent->d_name);
        }
    }
    closedir(d);
    if (best[0]) {
        snprintf(g_fxr_version, sizeof(g_fxr_version), "%s", best);
        return 1;
    }
    return 0;
}

/* Create ~/.lsw/dotnet/ bridge directory structure so that
 * GetFileAttributesW / FindFirstFileW / FindNextFileW succeed when the
 * .NET apphost looks for "C:\Program Files\dotnet\host\fxr\<ver>". */
static void create_bridge_dir(void) {
    const char* home = getenv("HOME");
    if (!home) home = "/root";
    snprintf(g_bridge_dir, sizeof(g_bridge_dir), "%s/.lsw/dotnet", home);

    /* Create directory tree: ~/.lsw/dotnet/host/fxr/<version>/ */
    char path[1024];
    snprintf(path, sizeof(path), "%s/host/fxr/%s", g_bridge_dir, g_fxr_version);
    /* mkdir -p equivalent */
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);

    /* Create a tiny stub "hostfxr.dll" marker file so file_exists() works.
     * LoadLibraryA intercepts by basename before reaching this file. */
    snprintf(path, sizeof(path), "%s/host/fxr/%s/hostfxr.dll", g_bridge_dir, g_fxr_version);
    if (access(path, F_OK) != 0) {
        FILE* f = fopen(path, "w");
        if (f) { fprintf(f, "LSW dotnet bridge\n"); fclose(f); }
    }

    /* Create shared framework symlinks so app DLL lookup works.
     * ~/.lsw/dotnet/shared/ → <linux_dotnet_root>/shared/ */
    char lnk[1024], tgt[1024];
    snprintf(lnk, sizeof(lnk), "%s/shared", g_bridge_dir);
    snprintf(tgt, sizeof(tgt), "%s/shared", g_linux_dotnet_root);
    if (access(lnk, F_OK) != 0) symlink(tgt, lnk);

    /* packs/ symlink for SDK paths */
    snprintf(lnk, sizeof(lnk), "%s/packs", g_bridge_dir);
    snprintf(tgt, sizeof(tgt), "%s/packs", g_linux_dotnet_root);
    if (access(lnk, F_OK) != 0) symlink(tgt, lnk);

    LSW_LOG_INFO("dotnet_host: bridge dir %s -> %s (fxr %s)",
                 g_bridge_dir, g_linux_dotnet_root, g_fxr_version);
}

/* Load the Linux libhostfxr.so */
static void load_hostfxr_so(void) {
    char so_path[512];
    snprintf(so_path, sizeof(so_path), "%s/host/fxr/%s/libhostfxr.so",
             g_linux_dotnet_root, g_fxr_version);
    g_hostfxr_so = dlopen(so_path, RTLD_LAZY | RTLD_LOCAL);
    if (!g_hostfxr_so) {
        LSW_LOG_WARN("dotnet_host: dlopen(%s) failed: %s — trying libhostfxr.so fallback", so_path, dlerror());
        g_hostfxr_so = dlopen("libhostfxr.so", RTLD_LAZY | RTLD_LOCAL);
    }
    if (g_hostfxr_so)
        LSW_LOG_INFO("dotnet_host: libhostfxr.so loaded from %s", so_path);
    else
        LSW_LOG_WARN("dotnet_host: libhostfxr.so not available — .NET framework-dependent apps will fail");
}

/* Public init — called from win32_api_init() */
void lsw_dotnet_init(void) {
    if (g_dotnet_detected != 0) return;

    if (!detect_linux_dotnet()) {
        LSW_LOG_INFO("dotnet_host: Linux .NET not found — framework-dependent .NET apps unsupported");
        g_dotnet_detected = -1;
        return;
    }
    if (!detect_fxr_version()) {
        LSW_LOG_WARN("dotnet_host: .NET found at %s but no hostfxr version found", g_linux_dotnet_root);
        g_dotnet_detected = -1;
        return;
    }
    LSW_LOG_INFO("dotnet_host: found .NET %s at %s", g_fxr_version, g_linux_dotnet_root);
    create_bridge_dir();
    load_hostfxr_so();
    g_dotnet_detected = 1;

    /* Inject Windows-style env vars so the .NET apphost can discover dotnet */
    setenv("ProgramFiles",    "C:\\Program Files", 0);
    setenv("ProgramFiles(x86)", "C:\\Program Files (x86)", 0);
    /* DOTNET_ROOT tells the apphost exactly where .NET is (Windows fake path) */
    setenv("DOTNET_ROOT", LSW_DOTNET_WIN_PATH, 1);
    LSW_LOG_INFO("dotnet_host: DOTNET_ROOT=%s ProgramFiles set", LSW_DOTNET_WIN_PATH);
}

/* Return the Linux dotnet root (for path translation in filesystem layer) */
const char* lsw_dotnet_get_linux_root(void) {
    return (g_dotnet_detected == 1) ? g_linux_dotnet_root : NULL;
}

/* Return the bridge dir (for path translation in filesystem layer) */
const char* lsw_dotnet_get_bridge_dir(void) {
    return (g_dotnet_detected == 1 && g_bridge_dir[0]) ? g_bridge_dir : NULL;
}

/* Return the detected fxr version */
const char* lsw_dotnet_get_fxr_version(void) {
    return (g_fxr_version[0]) ? g_fxr_version : NULL;
}

/* Return 1 if the given Windows path is under our fake dotnet install path */
int lsw_dotnet_is_win_dotnet_path(const char* utf8_path) {
    if (!utf8_path) return 0;
    return (strncasecmp(utf8_path, LSW_DOTNET_WIN_PATH, strlen(LSW_DOTNET_WIN_PATH)) == 0);
}

/*
 * Translate a Windows dotnet path (C:\Program Files\dotnet\...) to the
 * Linux bridge dir (~/.lsw/dotnet/...).
 * Returns 1 on success (out filled), 0 if not a dotnet path or no bridge.
 */
int lsw_dotnet_translate_win_path(const char* win_utf8, char* out, size_t outsz) {
    if (!lsw_dotnet_is_win_dotnet_path(win_utf8)) return 0;
    const char* bridge = lsw_dotnet_get_bridge_dir();
    if (!bridge) return 0;
    const char* rest = win_utf8 + strlen(LSW_DOTNET_WIN_PATH);
    snprintf(out, outsz, "%s%s", bridge, rest);
    for (char* p = out; *p; p++) if (*p == '\\') *p = '/';
    return 1;
}

/* ============================================================
 * hostfxr.dll ABI wrappers (ms_abi → System V ABI bridge)
 * ============================================================ */

/*
 * hostfxr_set_error_writer
 *
 * Windows: void* hostfxr_set_error_writer(void* error_writer)  [wchar_t* param in callback]
 * Linux:   void* hostfxr_set_error_writer(void* error_writer)  [char* param in callback]
 *
 * We stub the error_writer: ignore the Windows callback (it uses ms_abi and wchar_t).
 * Instead hook NULL so the Linux hostfxr prints to stderr directly.
 */
void* __attribute__((ms_abi)) lsw_hostfxr_set_error_writer(void* error_writer) {
    (void)error_writer;
    typedef void* (*fn_t)(void*);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_set_error_writer");
    if (fn) fn(NULL);  /* ignore the Windows callback — let hostfxr write to stderr */
    return NULL;
}

/*
 * hostfxr_main — legacy entry point used by older .NET apphosts
 *
 * Windows: int hostfxr_main(int argc, const wchar_t* argv[])
 * Linux:   int hostfxr_main(int argc, const char*    argv[])
 */
int __attribute__((ms_abi)) lsw_hostfxr_main(int argc, const uint16_t** wargv) {
    LSW_LOG_INFO("hostfxr_main: argc=%d", argc);
    typedef int (*fn_t)(int, const char**);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_main");
    if (!fn) return -1;

    char** argv = (char**)calloc((size_t)(argc + 1), sizeof(char*));
    if (!argv) return -1;
    for (int i = 0; i < argc; i++) {
        char buf[4096];
        fxr_wpath_to_linux(wargv[i], buf, sizeof(buf));
        argv[i] = strdup(buf);
        LSW_LOG_INFO("  argv[%d] = %s", i, argv[i]);
    }
    int rc = fn(argc, (const char**)argv);
    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    LSW_LOG_INFO("hostfxr_main: returned %d", rc);
    return rc;
}

/*
 * hostfxr_main_startupinfo — launch app with explicit paths
 *
 * Windows: int hostfxr_main_startupinfo(int argc, const wchar_t* argv[],
 *                                        const wchar_t* host_path,
 *                                        const wchar_t* dotnet_root,
 *                                        const wchar_t* app_path)
 * Linux:   same but char*
 */
int __attribute__((ms_abi)) lsw_hostfxr_main_startupinfo(
        int argc, const uint16_t** wargv,
        const uint16_t* whost, const uint16_t* wdotnet_root,
        const uint16_t* wapp) {
    LSW_LOG_INFO("hostfxr_main_startupinfo: argc=%d", argc);
    typedef int (*fn_t)(int, const char**, const char*, const char*, const char*);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_main_startupinfo");
    if (!fn) return -1;

    char host[4096], dotnet_root[4096], app[4096];
    fxr_wpath_to_linux(whost,        host,        sizeof(host));
    fxr_wpath_to_linux(wdotnet_root, dotnet_root, sizeof(dotnet_root));
    fxr_wpath_to_linux(wapp,         app,         sizeof(app));
    /* Use Linux dotnet root if the Windows path translation ends up invalid */
    if (g_linux_dotnet_root[0]) snprintf(dotnet_root, sizeof(dotnet_root), "%s", g_linux_dotnet_root);
    LSW_LOG_INFO("  host=%s dotnet_root=%s app=%s", host, dotnet_root, app);

    char** argv = (char**)calloc((size_t)(argc + 1), sizeof(char*));
    if (!argv) return -1;
    for (int i = 0; i < argc; i++) {
        char buf[4096];
        fxr_wpath_to_linux(wargv[i], buf, sizeof(buf));
        argv[i] = strdup(buf);
    }
    int rc = fn(argc, (const char**)argv, host, dotnet_root, app);
    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    return rc;
}

/*
 * hostfxr_main_bundle_startupinfo — single-file bundle variant
 * Used by single-file self-contained bundles (not NativeAOT; those embed hostfxr).
 *
 * Windows: int hostfxr_main_bundle_startupinfo(int argc, const wchar_t* argv[],
 *              const wchar_t* host_path, const wchar_t* dotnet_root,
 *              const wchar_t* app_path, int64_t bundle_header_offset)
 */
int __attribute__((ms_abi)) lsw_hostfxr_main_bundle_startupinfo(
        int argc, const uint16_t** wargv,
        const uint16_t* whost, const uint16_t* wdotnet_root,
        const uint16_t* wapp, int64_t bundle_header_offset) {
    LSW_LOG_INFO("hostfxr_main_bundle_startupinfo: argc=%d offset=%lld", argc, (long long)bundle_header_offset);
    typedef int (*fn_t)(int, const char**, const char*, const char*, const char*, int64_t);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_main_bundle_startupinfo");
    if (!fn) return -1;

    char host[4096], dotnet_root[4096], app[4096];
    fxr_wpath_to_linux(whost,        host,        sizeof(host));
    fxr_wpath_to_linux(wdotnet_root, dotnet_root, sizeof(dotnet_root));
    fxr_wpath_to_linux(wapp,         app,         sizeof(app));
    if (g_linux_dotnet_root[0]) snprintf(dotnet_root, sizeof(dotnet_root), "%s", g_linux_dotnet_root);

    char** argv = (char**)calloc((size_t)(argc + 1), sizeof(char*));
    if (!argv) return -1;
    for (int i = 0; i < argc; i++) {
        char buf[4096]; fxr_wpath_to_linux(wargv[i], buf, sizeof(buf)); argv[i] = strdup(buf);
    }
    int rc = fn(argc, (const char**)argv, host, dotnet_root, app, bundle_header_offset);
    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    return rc;
}

/* ---- New hosting API (hostfxr_initialize_for_*) ---- */

/*
 * hostfxr_initialize_for_dotnet_command_line
 *
 * Windows: int hostfxr_initialize_for_dotnet_command_line(
 *              int argc, const wchar_t* argv[],
 *              const hostfxr_initialize_parameters* params,
 *              hostfxr_handle* out_handle)
 *
 * hostfxr_initialize_parameters contains:
 *   size_t size;
 *   const wchar_t* host_path;
 *   const wchar_t* dotnet_root;
 *
 * Linux: same but char* for strings
 */
typedef struct {
    size_t        size;
    const char*   host_path;
    const char*   dotnet_root;
} lsw_hostfxr_init_params_linux_t;

typedef struct {
    size_t           size;
    const uint16_t*  host_path;
    const uint16_t*  dotnet_root;
} lsw_hostfxr_init_params_win_t;

int __attribute__((ms_abi)) lsw_hostfxr_initialize_for_dotnet_command_line(
        int argc, const uint16_t** wargv,
        const lsw_hostfxr_init_params_win_t* win_params,
        void** out_handle) {
    LSW_LOG_INFO("hostfxr_initialize_for_dotnet_command_line: argc=%d", argc);
    typedef int (*fn_t)(int, const char**, const void*, void**);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_initialize_for_dotnet_command_line");
    if (!fn) return -1;

    char** argv = (char**)calloc((size_t)(argc + 1), sizeof(char*));
    if (!argv) return -1;
    for (int i = 0; i < argc; i++) {
        char buf[4096]; fxr_wpath_to_linux(wargv[i], buf, sizeof(buf));
        argv[i] = strdup(buf);
        LSW_LOG_INFO("  argv[%d]=%s", i, argv[i]);
    }

    /* Build Linux params struct */
    lsw_hostfxr_init_params_linux_t linux_params = {0};
    char host_path[4096] = "", dotnet_root[4096] = "";
    if (win_params && win_params->size >= sizeof(*win_params)) {
        fxr_wpath_to_linux(win_params->host_path,    host_path,   sizeof(host_path));
        fxr_wpath_to_linux(win_params->dotnet_root,  dotnet_root, sizeof(dotnet_root));
    }
    if (g_linux_dotnet_root[0]) snprintf(dotnet_root, sizeof(dotnet_root), "%s", g_linux_dotnet_root);
    linux_params.size        = sizeof(linux_params);
    linux_params.host_path   = host_path[0]   ? host_path   : NULL;
    linux_params.dotnet_root = dotnet_root[0] ? dotnet_root : NULL;
    LSW_LOG_INFO("  host_path=%s dotnet_root=%s", host_path, dotnet_root);

    int rc = fn(argc, (const char**)argv, &linux_params, out_handle);
    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    LSW_LOG_INFO("hostfxr_initialize_for_dotnet_command_line: rc=%d handle=%p", rc, out_handle ? *out_handle : NULL);
    return rc;
}

/*
 * hostfxr_initialize_for_runtime_config — used for library/custom hosting
 */
int __attribute__((ms_abi)) lsw_hostfxr_initialize_for_runtime_config(
        const uint16_t* wruntime_config_path,
        const lsw_hostfxr_init_params_win_t* win_params,
        void** out_handle) {
    LSW_LOG_INFO("hostfxr_initialize_for_runtime_config");
    typedef int (*fn_t)(const char*, const void*, void**);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_initialize_for_runtime_config");
    if (!fn) return -1;

    char config_path[4096] = "", host_path[4096] = "", dotnet_root[4096] = "";
    fxr_wpath_to_linux(wruntime_config_path, config_path, sizeof(config_path));
    lsw_hostfxr_init_params_linux_t linux_params = {0};
    if (win_params && win_params->size >= sizeof(*win_params)) {
        fxr_wpath_to_linux(win_params->host_path,   host_path,   sizeof(host_path));
        fxr_wpath_to_linux(win_params->dotnet_root, dotnet_root, sizeof(dotnet_root));
    }
    if (g_linux_dotnet_root[0]) snprintf(dotnet_root, sizeof(dotnet_root), "%s", g_linux_dotnet_root);
    linux_params.size        = sizeof(linux_params);
    linux_params.host_path   = host_path[0]   ? host_path   : NULL;
    linux_params.dotnet_root = dotnet_root[0] ? dotnet_root : NULL;
    LSW_LOG_INFO("  config=%s dotnet_root=%s", config_path, dotnet_root);

    int rc = fn(config_path, &linux_params, out_handle);
    LSW_LOG_INFO("hostfxr_initialize_for_runtime_config: rc=%d handle=%p", rc, out_handle ? *out_handle : NULL);
    return rc;
}

/*
 * hostfxr_run_app — run the app using a handle from initialize_for_command_line
 */
int __attribute__((ms_abi)) lsw_hostfxr_run_app(void* handle) {
    LSW_LOG_INFO("hostfxr_run_app: handle=%p", handle);
    typedef int (*fn_t)(void*);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_run_app");
    if (!fn) return -1;
    int rc = fn(handle);
    LSW_LOG_INFO("hostfxr_run_app: returned %d", rc);
    return rc;
}

/*
 * hostfxr_get_runtime_delegate — get a runtime function pointer
 * hostfxr_delegate_type is an int enum; same values on Win/Linux.
 */
int __attribute__((ms_abi)) lsw_hostfxr_get_runtime_delegate(void* handle, int type, void** out) {
    LSW_LOG_INFO("hostfxr_get_runtime_delegate: type=%d", type);
    typedef int (*fn_t)(void*, int, void**);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_get_runtime_delegate");
    if (!fn) return -1;
    return fn(handle, type, out);
}

/*
 * hostfxr_close — release a handle
 */
int __attribute__((ms_abi)) lsw_hostfxr_close(void* handle) {
    typedef int (*fn_t)(void*);
    fn_t fn = (fn_t)lsw_hostfxr_fn("hostfxr_close");
    return fn ? fn(handle) : 0;
}

/*
 * hostfxr_get_runtime_property_value
 * hostfxr_set_runtime_property_value
 * hostfxr_get_runtime_properties
 */
int __attribute__((ms_abi)) lsw_hostfxr_get_runtime_property_value(
        void* handle, const uint16_t* wname, const uint16_t** wout) {
    (void)handle; (void)wname; (void)wout;
    LSW_LOG_WARN("hostfxr_get_runtime_property_value: stub");
    return -1;
}
int __attribute__((ms_abi)) lsw_hostfxr_set_runtime_property_value(
        void* handle, const uint16_t* wname, const uint16_t* wvalue) {
    (void)handle; (void)wname; (void)wvalue;
    LSW_LOG_WARN("hostfxr_set_runtime_property_value: stub");
    return -1;
}
int __attribute__((ms_abi)) lsw_hostfxr_get_runtime_properties(
        void* handle, size_t* count, uint16_t** wkeys, uint16_t** wvals) {
    (void)handle; (void)count; (void)wkeys; (void)wvals;
    if (count) *count = 0;
    LSW_LOG_WARN("hostfxr_get_runtime_properties: stub");
    return -1;
}

/*
 * hostfxr_get_native_search_directories — returns semicolon-separated search paths
 */
int __attribute__((ms_abi)) lsw_hostfxr_get_native_search_directories(
        int argc, const uint16_t** wargv, uint16_t* wout, int32_t out_sz, int32_t* required) {
    (void)argc; (void)wargv; (void)wout; (void)out_sz;
    /* Return the Linux shared lib path */
    if (required) {
        char path[512];
        snprintf(path, sizeof(path), "%s/shared/Microsoft.NETCore.App/%s;", g_linux_dotnet_root, g_fxr_version);
        *required = (int32_t)strlen(path);
    }
    return 0;
}

/*
 * hostfxr_get_dotnet_environment_info — reports installed SDKs and runtimes
 * Returns 0 immediately (optional API; not required for app launch).
 */
int __attribute__((ms_abi)) lsw_hostfxr_get_dotnet_environment_info(
        const uint16_t* wdotnet_root, void* reserved,
        void* result_fn, void* result_fn_ctx) {
    (void)wdotnet_root; (void)reserved; (void)result_fn; (void)result_fn_ctx;
    LSW_LOG_INFO("hostfxr_get_dotnet_environment_info: stub");
    return 0;
}

/*
 * hostfxr_resolve_sdk / hostfxr_resolve_sdk2 — SDK resolution
 * Used by build tools, not runtime apps. Return "not found" gracefully.
 */
int __attribute__((ms_abi)) lsw_hostfxr_resolve_sdk(
        const uint16_t* wexe_dir, const uint16_t* wworking_dir, uint16_t* wout, int32_t out_sz) {
    (void)wexe_dir; (void)wworking_dir; (void)wout; (void)out_sz;
    return 0;
}
int __attribute__((ms_abi)) lsw_hostfxr_resolve_sdk2(
        const uint16_t* wexe_dir, const uint16_t* wworking_dir,
        int32_t flags, void* result_fn, void* result_fn_ctx) {
    (void)wexe_dir; (void)wworking_dir; (void)flags; (void)result_fn; (void)result_fn_ctx;
    return 0;
}

/*
 * hostfxr_get_available_sdks — returns list of installed SDKs
 */
int __attribute__((ms_abi)) lsw_hostfxr_get_available_sdks(
        const uint16_t* wexe_dir, void* result_fn, void* result_fn_ctx) {
    (void)wexe_dir; (void)result_fn; (void)result_fn_ctx;
    return 0;
}

/* ---- nethost.dll: get_hostfxr_path ---- */
/*
 * get_hostfxr_path — called by apps using nethost to discover hostfxr
 *
 * Windows: int get_hostfxr_path(wchar_t* buffer, size_t* buffer_size,
 *                                const get_hostfxr_parameters* params)
 * Returns the path to hostfxr.dll — we return the bridge path so
 * LoadLibraryW will be called with a path whose basename is hostfxr.dll.
 */
int __attribute__((ms_abi)) lsw_get_hostfxr_path(
        uint16_t* wbuf, size_t* buf_sz,
        const void* params) {
    (void)params;
    if (g_dotnet_detected != 1) {
        LSW_LOG_WARN("get_hostfxr_path: .NET not detected");
        return -1;  /* HostApiBufferTooSmall = some error */
    }

    /* Return the bridge path: C:\Program Files\dotnet\host\fxr\<ver>\hostfxr.dll */
    char bridge_path[512];
    snprintf(bridge_path, sizeof(bridge_path),
             "C:\\Program Files\\dotnet\\host\\fxr\\%s\\hostfxr.dll", g_fxr_version);

    /* Count wide chars needed */
    size_t needed = strlen(bridge_path) + 1;
    if (wbuf && buf_sz && *buf_sz >= needed) {
        u8_to_u16(bridge_path, wbuf, needed);
        *buf_sz = needed;
        LSW_LOG_INFO("get_hostfxr_path: returning %s", bridge_path);
        return 0;  /* Success */
    }
    if (buf_sz) *buf_sz = needed;
    return (int)0x80008098; /* HostApiBufferTooSmall if buf is too small */
}

/* ---- Mapping table ---- */

const win32_api_mapping_t win32_api_dotnet_mappings[] = {
    {"hostfxr.dll", "hostfxr_set_error_writer",                      (void*)lsw_hostfxr_set_error_writer},
    {"hostfxr.dll", "hostfxr_main",                                   (void*)lsw_hostfxr_main},
    {"hostfxr.dll", "hostfxr_main_startupinfo",                       (void*)lsw_hostfxr_main_startupinfo},
    {"hostfxr.dll", "hostfxr_main_bundle_startupinfo",                (void*)lsw_hostfxr_main_bundle_startupinfo},
    {"hostfxr.dll", "hostfxr_initialize_for_dotnet_command_line",     (void*)lsw_hostfxr_initialize_for_dotnet_command_line},
    {"hostfxr.dll", "hostfxr_initialize_for_runtime_config",          (void*)lsw_hostfxr_initialize_for_runtime_config},
    {"hostfxr.dll", "hostfxr_run_app",                                (void*)lsw_hostfxr_run_app},
    {"hostfxr.dll", "hostfxr_get_runtime_delegate",                   (void*)lsw_hostfxr_get_runtime_delegate},
    {"hostfxr.dll", "hostfxr_close",                                  (void*)lsw_hostfxr_close},
    {"hostfxr.dll", "hostfxr_get_runtime_property_value",             (void*)lsw_hostfxr_get_runtime_property_value},
    {"hostfxr.dll", "hostfxr_set_runtime_property_value",             (void*)lsw_hostfxr_set_runtime_property_value},
    {"hostfxr.dll", "hostfxr_get_runtime_properties",                 (void*)lsw_hostfxr_get_runtime_properties},
    {"hostfxr.dll", "hostfxr_get_native_search_directories",          (void*)lsw_hostfxr_get_native_search_directories},
    {"hostfxr.dll", "hostfxr_get_dotnet_environment_info",            (void*)lsw_hostfxr_get_dotnet_environment_info},
    {"hostfxr.dll", "hostfxr_resolve_sdk",                            (void*)lsw_hostfxr_resolve_sdk},
    {"hostfxr.dll", "hostfxr_resolve_sdk2",                           (void*)lsw_hostfxr_resolve_sdk2},
    {"hostfxr.dll", "hostfxr_get_available_sdks",                     (void*)lsw_hostfxr_get_available_sdks},
    {"nethost.dll", "get_hostfxr_path",                               (void*)lsw_get_hostfxr_path},
};
const size_t win32_api_dotnet_mappings_count =
    sizeof(win32_api_dotnet_mappings) / sizeof(win32_api_dotnet_mappings[0]);
