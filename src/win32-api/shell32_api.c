#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <ctype.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <limits.h>

#define BOOL int
#define DWORD uint32_t
#define HANDLE void*
#define HINSTANCE void*
#define HMODULE void*
#define LPCWSTR const uint16_t*
#define LPCSTR const char*
#define LPWSTR uint16_t*
#define LPSTR char*
#define UINT uint32_t
#define INT int
#define LONG long
#define LONGLONG int64_t
#define ULONGLONG uint64_t
#define HRESULT int32_t
#define S_OK 0
#define S_FALSE 1
#define E_FAIL ((int32_t)0x80004005)
#define E_NOTIMPL ((int32_t)0x80004001)
#define E_INVALIDARG ((int32_t)0x80070057)
#define TRUE 1
#define FALSE 0
#define MAX_PATH 4096

#define CSIDL_DESKTOPDIRECTORY 0
#define CSIDL_PERSONAL 5
#define CSIDL_APPDATA 26
#define CSIDL_LOCAL_APPDATA 28
#define CSIDL_COMMON_APPDATA 35
#define CSIDL_WINDOWS 36
#define CSIDL_SYSTEM 37
#define CSIDL_PROGRAM_FILES 38
#define CSIDL_MYPICTURES 39
#define CSIDL_PROFILE 40

static size_t u16_strlen(LPCWSTR s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static char* dup_narrow(LPCSTR s) {
    size_t len;
    char* out;
    if (!s) return NULL;
    len = strlen(s);
    out = (char*)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len + 1);
    return out;
}

static LPWSTR utf8_to_u16_dup(LPCSTR src) {
    size_t len, i;
    LPWSTR out;
    if (!src) return NULL;
    len = strlen(src);
    out = (LPWSTR)malloc((len + 1) * sizeof(uint16_t));
    if (!out) return NULL;
    for (i = 0; i < len; i++) out[i] = (uint16_t)(unsigned char)src[i];
    out[len] = 0;
    return out;
}

static void utf8_to_u16_buf(LPCSTR src, LPWSTR dst, size_t cap) {
    size_t i = 0;
    if (!dst || cap == 0) return;
    if (!src) {
        dst[0] = 0;
        return;
    }
    while (src[i] && i + 1 < cap) {
        dst[i] = (uint16_t)(unsigned char)src[i];
        i++;
    }
    dst[i] = 0;
}

static char* u16_to_utf8(LPCWSTR src) {
    size_t len, i;
    char* out;
    if (!src) return NULL;
    len = u16_strlen(src);
    out = (char*)malloc(len + 1);
    if (!out) return NULL;
    for (i = 0; i < len; i++) out[i] = (src[i] <= 0x7f) ? (char)src[i] : '?';
    out[len] = 0;
    return out;
}

static const char* home_dir(void) {
    const char* home = getenv("HOME");
    return (home && home[0]) ? home : ".";
}

static const char* resolve_csidl_path_a(int csidl) {
    static char buf[MAX_PATH];
    const char* home = home_dir();
    switch (csidl) {
        case CSIDL_PERSONAL:
            snprintf(buf, sizeof(buf), "%s/Documents", home);
            return buf;
        case CSIDL_DESKTOPDIRECTORY:
            snprintf(buf, sizeof(buf), "%s/Desktop", home);
            return buf;
        case CSIDL_APPDATA:
            snprintf(buf, sizeof(buf), "%s/.config", home);
            return buf;
        case CSIDL_LOCAL_APPDATA:
            snprintf(buf, sizeof(buf), "%s/.local/share", home);
            return buf;
        case CSIDL_COMMON_APPDATA:
            return "/etc";
        case CSIDL_WINDOWS:
            return "C:\\Windows";
        case CSIDL_SYSTEM:
            return "C:\\Windows\\System32";
        case CSIDL_PROGRAM_FILES:
            return "C:\\Program Files";
        case CSIDL_MYPICTURES:
            snprintf(buf, sizeof(buf), "%s/Pictures", home);
            return buf;
        case CSIDL_PROFILE:
            return home;
        default:
            snprintf(buf, sizeof(buf), "%s/.", home);
            return buf;
    }
}

static const char* resolve_known_folder_a(const void* rfid) {
    const unsigned char* id = (const unsigned char*)rfid;
    const char* home = home_dir();
    static char buf[MAX_PATH];
    if (!rfid) return home;
    switch (id[0]) {
        case 0x3A:
            snprintf(buf, sizeof(buf), "%s/Desktop", home);
            return buf;
        case 0xD0:
            snprintf(buf, sizeof(buf), "%s/Documents", home);
            return buf;
        case 0x24:
            snprintf(buf, sizeof(buf), "%s/Pictures", home);
            return buf;
        case 0x8F:
            return home;
        default:
            return home;
    }
}

static int mkdir_p_a(LPCSTR path) {
    char tmp[MAX_PATH];
    size_t i, len;
    struct stat st;
    if (!path || !path[0]) return -1;
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    len = strlen(tmp);
    if (len == 0) return -1;
    for (i = 1; i < len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char saved = tmp[i];
            tmp[i] = 0;
            if (tmp[0] && stat(tmp, &st) != 0 && mkdir(tmp, 0777) != 0 && errno != EEXIST) return -1;
            tmp[i] = saved;
        }
    }
    if (stat(tmp, &st) != 0 && mkdir(tmp, 0777) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int copy_file_a(LPCSTR src, LPCSTR dst) {
    FILE* in;
    FILE* out;
    char buf[8192];
    size_t n;
    if (!src || !dst) return -1;
    in = fopen(src, "rb");
    if (!in) return -1;
    out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

static int split_command_line_a(LPCSTR cmd, char*** argv_out) {
    char** argv = NULL;
    int argc = 0;
    int cap = 0;
    size_t i = 0;
    if (!cmd || !argv_out) return 0;
    while (cmd[i]) {
        char token[MAX_PATH];
        size_t tlen = 0;
        int quoted = 0;
        while (cmd[i] && isspace((unsigned char)cmd[i])) i++;
        if (!cmd[i]) break;
        while (cmd[i]) {
            if (cmd[i] == '"') {
                quoted = !quoted;
                i++;
                continue;
            }
            if (!quoted && isspace((unsigned char)cmd[i])) break;
            if (tlen + 1 < sizeof(token)) token[tlen++] = cmd[i];
            i++;
        }
        token[tlen] = 0;
        if (argc == cap) {
            int new_cap = cap ? cap * 2 : 4;
            char** new_argv = (char**)realloc(argv, (size_t)new_cap * sizeof(char*));
            if (!new_argv) break;
            argv = new_argv;
            cap = new_cap;
        }
        argv[argc++] = dup_narrow(token);
        while (cmd[i] && isspace((unsigned char)cmd[i])) i++;
    }
    *argv_out = argv;
    return argc;
}

HRESULT __attribute__((ms_abi)) SHGetFolderPathW(void* hwnd, int csidl, void* hToken, uint32_t dwFlags, uint16_t* pszPath) {
    (void)hwnd; (void)hToken; (void)dwFlags;
    if (!pszPath) return E_INVALIDARG;
    utf8_to_u16_buf(resolve_csidl_path_a(csidl), pszPath, MAX_PATH);
    return 0;
}

HRESULT __attribute__((ms_abi)) SHGetFolderPathA(void* hwnd, int csidl, void* hToken, uint32_t dwFlags, char* pszPath) {
    (void)hwnd; (void)hToken; (void)dwFlags;
    if (!pszPath) return E_INVALIDARG;
    strncpy(pszPath, resolve_csidl_path_a(csidl), MAX_PATH - 1);
    pszPath[MAX_PATH - 1] = 0;
    return 0;
}

BOOL __attribute__((ms_abi)) SHGetSpecialFolderPathW(void* hwndOwner, uint16_t* pszPath, int csidl, int fCreate) {
    (void)fCreate;
    return SHGetFolderPathW(hwndOwner, csidl, NULL, 0, pszPath) == 0;
}

BOOL __attribute__((ms_abi)) SHGetSpecialFolderPathA(void* hwndOwner, char* pszPath, int csidl, int fCreate) {
    (void)fCreate;
    return SHGetFolderPathA(hwndOwner, csidl, NULL, 0, pszPath) == 0;
}

HRESULT __attribute__((ms_abi)) SHGetKnownFolderPath(void* rfid, uint32_t dwFlags, void* hToken, uint16_t** ppszPath) {
    (void)dwFlags; (void)hToken;
    if (!ppszPath) return E_INVALIDARG;
    *ppszPath = utf8_to_u16_dup(resolve_known_folder_a(rfid));
    return *ppszPath ? 0 : E_FAIL;
}

HRESULT __attribute__((ms_abi)) SHGetFolderLocation(void* hwnd, int csidl, void* hToken, uint32_t dwReserved, void** ppidl) {
    (void)hwnd; (void)csidl; (void)hToken; (void)dwReserved;
    if (!ppidl) return E_INVALIDARG;
    *ppidl = calloc(1, 8);
    return *ppidl ? 0 : E_FAIL;
}

HRESULT __attribute__((ms_abi)) SHGetDesktopFolder(void** ppshf) { if (ppshf) *ppshf = NULL; return E_NOTIMPL; }
BOOL __attribute__((ms_abi)) SHGetPathFromIDListW(void* pidl, uint16_t* pszPath) { (void)pidl; if (pszPath) pszPath[0] = 0; return 0; }
BOOL __attribute__((ms_abi)) SHGetPathFromIDListA(void* pidl, char* pszPath) { (void)pidl; if (pszPath) pszPath[0] = 0; return 0; }

void* __attribute__((ms_abi)) ShellExecuteW(void* hwnd, const uint16_t* lpOperation, const uint16_t* lpFile, const uint16_t* lpParameters, const uint16_t* lpDirectory, int nShowCmd) {
    char* op = u16_to_utf8(lpOperation);
    char* file = u16_to_utf8(lpFile);
    char* params = u16_to_utf8(lpParameters);
    char* dir = u16_to_utf8(lpDirectory);
    (void)hwnd; (void)nShowCmd;
    LSW_LOG_INFO("ShellExecuteW op=%s file=%s params=%s dir=%s", op ? op : "", file ? file : "", params ? params : "", dir ? dir : "");
    free(op); free(file); free(params); free(dir);
    return (void*)42;
}

void* __attribute__((ms_abi)) ShellExecuteA(void* hwnd, const char* lpOperation, const char* lpFile, const char* lpParameters, const char* lpDirectory, int nShowCmd) {
    (void)hwnd; (void)lpOperation; (void)lpFile; (void)lpParameters; (void)lpDirectory; (void)nShowCmd;
    return (void*)42;
}

BOOL __attribute__((ms_abi)) ShellExecuteExW(void* pExecInfo) { (void)pExecInfo; return 1; }
BOOL __attribute__((ms_abi)) ShellExecuteExA(void* pExecInfo) { (void)pExecInfo; return 1; }

int __attribute__((ms_abi)) SHFileOperationW(void* lpFileOp) { (void)lpFileOp; return 1; }
int __attribute__((ms_abi)) SHFileOperationA(void* lpFileOp) { (void)lpFileOp; return 1; }
uintptr_t __attribute__((ms_abi)) SHGetFileInfoW(const uint16_t* pszPath, uint32_t dwFileAttributes, void* psfi, uint32_t cbFileInfo, uint32_t uFlags) { (void)pszPath; (void)dwFileAttributes; (void)psfi; (void)cbFileInfo; (void)uFlags; return 1; }
uintptr_t __attribute__((ms_abi)) SHGetFileInfoA(const char* pszPath, uint32_t dwFileAttributes, void* psfi, uint32_t cbFileInfo, uint32_t uFlags) { (void)pszPath; (void)dwFileAttributes; (void)psfi; (void)cbFileInfo; (void)uFlags; return 1; }
int __attribute__((ms_abi)) SHCopyFileW(void* hwnd, const uint16_t* pszSrcFile, const uint16_t* pszDestFile, int fNoConfirmation) {
    char* src = u16_to_utf8(pszSrcFile);
    char* dst = u16_to_utf8(pszDestFile);
    int rc;
    (void)hwnd; (void)fNoConfirmation;
    rc = copy_file_a(src, dst);
    free(src); free(dst);
    return rc == 0 ? 0 : 1;
}

void* __attribute__((ms_abi)) SHBrowseForFolderW(void* lpbi) { (void)lpbi; return NULL; }
void* __attribute__((ms_abi)) SHBrowseForFolderA(void* lpbi) { (void)lpbi; return NULL; }

void __attribute__((ms_abi)) SHChangeNotify(long wEventId, uint32_t uFlags, const void* dwItem1, const void* dwItem2) { (void)wEventId; (void)uFlags; (void)dwItem1; (void)dwItem2; }
BOOL __attribute__((ms_abi)) Shell_NotifyIconW(uint32_t dwMessage, void* lpData) { (void)dwMessage; (void)lpData; return 0; }
BOOL __attribute__((ms_abi)) Shell_NotifyIconA(uint32_t dwMessage, void* lpData) { (void)dwMessage; (void)lpData; return 0; }

void __attribute__((ms_abi)) DragAcceptFiles(void* hWnd, int fAccept) { (void)hWnd; (void)fAccept; }
uint32_t __attribute__((ms_abi)) DragQueryFileW(void* hDrop, uint32_t iFile, uint16_t* lpszFile, uint32_t cch) { (void)hDrop; (void)iFile; if (lpszFile && cch) lpszFile[0] = 0; return 0; }
uint32_t __attribute__((ms_abi)) DragQueryFileA(void* hDrop, uint32_t iFile, char* lpszFile, uint32_t cch) { (void)hDrop; (void)iFile; if (lpszFile && cch) lpszFile[0] = 0; return 0; }
void __attribute__((ms_abi)) DragFinish(void* hDrop) { (void)hDrop; }
BOOL __attribute__((ms_abi)) DragQueryPoint(void* hDrop, void* lppt) { (void)hDrop; (void)lppt; return 0; }

void* __attribute__((ms_abi)) ExtractIconW(void* hInst, const uint16_t* lpszExeFileName, uint32_t nIconIndex) { (void)hInst; (void)lpszExeFileName; (void)nIconIndex; return NULL; }
void* __attribute__((ms_abi)) ExtractIconA(void* hInst, const char* lpszExeFileName, uint32_t nIconIndex) { (void)hInst; (void)lpszExeFileName; (void)nIconIndex; return NULL; }
uint32_t __attribute__((ms_abi)) ExtractIconExW(const uint16_t* lpszFile, int nIconIndex, void** phiconLarge, void** phiconSmall, uint32_t nIcons) { (void)lpszFile; (void)nIconIndex; (void)phiconLarge; (void)phiconSmall; (void)nIcons; return 0; }
BOOL __attribute__((ms_abi)) DestroyIcon(void* hIcon) { (void)hIcon; return 1; }
void* __attribute__((ms_abi)) LoadIconW(void* hInstance, const uint16_t* lpIconName) { (void)hInstance; (void)lpIconName; return (void*)0x6001; }
void* __attribute__((ms_abi)) LoadIconA(void* hInstance, const char* lpIconName) { (void)hInstance; (void)lpIconName; return (void*)0x6001; }

uintptr_t __attribute__((ms_abi)) SHAppBarMessage(uint32_t dwMessage, void* pData) { (void)dwMessage; (void)pData; return 0; }
int __attribute__((ms_abi)) SHQueryRecycleBinW(const uint16_t* pszRootPath, void* pSHQueryRBInfo) { (void)pszRootPath; (void)pSHQueryRBInfo; return 0; }
int __attribute__((ms_abi)) SHEmptyRecycleBinW(void* hwnd, const uint16_t* pszRootPath, uint32_t dwFlags) { (void)hwnd; (void)pszRootPath; (void)dwFlags; return 0; }

uint16_t** __attribute__((ms_abi)) CommandLineToArgvW(const uint16_t* lpCmdLine, int* pNumArgs) {
    char* cmd = u16_to_utf8(lpCmdLine);
    char** argv = NULL;
    uint16_t** out = NULL;
    int argc = 0;
    int i;
    if (pNumArgs) *pNumArgs = 0;
    if (!cmd) return NULL;
    argc = split_command_line_a(cmd, &argv);
    free(cmd);
    out = (uint16_t**)calloc((size_t)(argc > 0 ? argc : 1), sizeof(uint16_t*));
    if (!out) {
        if (argv) {
            for (i = 0; i < argc; i++) free(argv[i]);
            free(argv);
        }
        return NULL;
    }
    for (i = 0; i < argc; i++) {
        out[i] = utf8_to_u16_dup(argv[i]);
        free(argv[i]);
    }
    free(argv);
    if (pNumArgs) *pNumArgs = argc;
    return out;
}

int __attribute__((ms_abi)) SHCreateDirectoryExW(void* hwnd, const uint16_t* pszPath, void* psa) {
    char* path = u16_to_utf8(pszPath);
    int rc;
    (void)hwnd; (void)psa;
    rc = mkdir_p_a(path);
    free(path);
    return rc == 0 ? 0 : 1;
}

int __attribute__((ms_abi)) SHCreateDirectoryExA(void* hwnd, const char* pszPath, void* psa) {
    (void)hwnd; (void)psa;
    return mkdir_p_a(pszPath) == 0 ? 0 : 1;
}

BOOL __attribute__((ms_abi)) SHGetDiskFreeSpaceExW(const uint16_t* pszDirectoryName, void* lpFreeBytesAvailableToCaller, void* lpTotalNumberOfBytes, void* lpTotalNumberOfFreeBytes) {
    char* path = u16_to_utf8(pszDirectoryName);
    struct statvfs vfs;
    int rc = statvfs((path && path[0]) ? path : "/", &vfs);
    free(path);
    if (rc != 0) return 0;
    if (lpFreeBytesAvailableToCaller) *(ULONGLONG*)lpFreeBytesAvailableToCaller = (ULONGLONG)vfs.f_bavail * vfs.f_frsize;
    if (lpTotalNumberOfBytes) *(ULONGLONG*)lpTotalNumberOfBytes = (ULONGLONG)vfs.f_blocks * vfs.f_frsize;
    if (lpTotalNumberOfFreeBytes) *(ULONGLONG*)lpTotalNumberOfFreeBytes = (ULONGLONG)vfs.f_bfree * vfs.f_frsize;
    return 1;
}

BOOL __attribute__((ms_abi)) SHGetDiskFreeSpaceExA(const char* pszDirectoryName, void* lpFreeBytesAvailableToCaller, void* lpTotalNumberOfBytes, void* lpTotalNumberOfFreeBytes) {
    struct statvfs vfs;
    if (statvfs((pszDirectoryName && pszDirectoryName[0]) ? pszDirectoryName : "/", &vfs) != 0) return 0;
    if (lpFreeBytesAvailableToCaller) *(ULONGLONG*)lpFreeBytesAvailableToCaller = (ULONGLONG)vfs.f_bavail * vfs.f_frsize;
    if (lpTotalNumberOfBytes) *(ULONGLONG*)lpTotalNumberOfBytes = (ULONGLONG)vfs.f_blocks * vfs.f_frsize;
    if (lpTotalNumberOfFreeBytes) *(ULONGLONG*)lpTotalNumberOfFreeBytes = (ULONGLONG)vfs.f_bfree * vfs.f_frsize;
    return 1;
}

BOOL __attribute__((ms_abi)) IsUserAnAdmin(void) { return 0; }
DWORD __attribute__((ms_abi)) SHRestricted(uint32_t rest) { (void)rest; return 0; }
HRESULT __attribute__((ms_abi)) SHGetStockIconInfo(uint32_t siid, uint32_t uFlags, void* psii) { (void)siid; (void)uFlags; (void)psii; return E_NOTIMPL; }
HRESULT __attribute__((ms_abi)) SHCreateItemFromParsingName(const uint16_t* pszPath, void* pbc, void* riid, void** ppv) { (void)pszPath; (void)pbc; (void)riid; if (ppv) *ppv = NULL; return E_NOTIMPL; }
HRESULT __attribute__((ms_abi)) SHGetNameFromIDList(void* pidl, int sigdnName, uint16_t** ppszName) { (void)pidl; (void)sigdnName; if (ppszName) *ppszName = NULL; return E_NOTIMPL; }
void __attribute__((ms_abi)) ILFree(void* pidl) { if (pidl) free(pidl); }
void* __attribute__((ms_abi)) ILClone(void* pidl) { return pidl ? malloc(8) : NULL; }
void* __attribute__((ms_abi)) FindExecutableW(const uint16_t* lpFile, const uint16_t* lpDirectory, uint16_t* lpResult) { (void)lpFile; (void)lpDirectory; if (lpResult) lpResult[0] = 0; return (void*)42; }
void* __attribute__((ms_abi)) FindExecutableA(const char* lpFile, const char* lpDirectory, char* lpResult) { (void)lpFile; (void)lpDirectory; if (lpResult) lpResult[0] = 0; return (void*)42; }
int __attribute__((ms_abi)) SHGetIconOverlayIndexW(const uint16_t* pszIconPath, int iIconIndex) { (void)pszIconPath; (void)iIconIndex; return -1; }
int __attribute__((ms_abi)) SHGetIconOverlayIndexA(const char* pszIconPath, int iIconIndex) { (void)pszIconPath; (void)iIconIndex; return -1; }

#define MAP(fn) {"shell32.dll", #fn, (void*)fn}

const win32_api_mapping_t win32_api_shell32_mappings[] = {
    MAP(SHGetFolderPathW), MAP(SHGetFolderPathA), MAP(SHGetSpecialFolderPathW), MAP(SHGetSpecialFolderPathA),
    MAP(SHGetKnownFolderPath), MAP(SHGetFolderLocation), MAP(SHGetDesktopFolder), MAP(SHGetPathFromIDListW), MAP(SHGetPathFromIDListA),
    MAP(ShellExecuteW), MAP(ShellExecuteA), MAP(ShellExecuteExW), MAP(ShellExecuteExA),
    MAP(SHFileOperationW), MAP(SHFileOperationA), MAP(SHGetFileInfoW), MAP(SHGetFileInfoA), MAP(SHCopyFileW),
    MAP(SHBrowseForFolderW), MAP(SHBrowseForFolderA),
    MAP(SHChangeNotify), MAP(Shell_NotifyIconW), MAP(Shell_NotifyIconA),
    MAP(DragAcceptFiles), MAP(DragQueryFileW), MAP(DragQueryFileA), MAP(DragFinish), MAP(DragQueryPoint),
    MAP(ExtractIconW), MAP(ExtractIconA), MAP(ExtractIconExW), MAP(DestroyIcon), MAP(LoadIconW), MAP(LoadIconA),
    MAP(SHAppBarMessage), MAP(SHQueryRecycleBinW), MAP(SHEmptyRecycleBinW),
    MAP(CommandLineToArgvW), MAP(SHCreateDirectoryExW), MAP(SHCreateDirectoryExA),
    MAP(SHGetDiskFreeSpaceExW), MAP(SHGetDiskFreeSpaceExA), MAP(IsUserAnAdmin), MAP(SHRestricted),
    MAP(SHGetStockIconInfo), MAP(SHCreateItemFromParsingName), MAP(SHGetNameFromIDList), MAP(ILFree), MAP(ILClone),
    MAP(FindExecutableW), MAP(FindExecutableA), MAP(SHGetIconOverlayIndexW), MAP(SHGetIconOverlayIndexA),
    {NULL, NULL, NULL}
};

const size_t win32_api_shell32_mappings_count =
    (sizeof(win32_api_shell32_mappings) / sizeof(win32_api_shell32_mappings[0])) - 1;
