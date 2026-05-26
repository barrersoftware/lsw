#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <ctype.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

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
#define WORD uint16_t
#define BYTE uint8_t
#define MAX_PATH 4096

static size_t u16_strlen(LPCWSTR s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static LPWSTR u16_end(LPWSTR s) { return s ? s + u16_strlen(s) : NULL; }

static uint16_t u16_tolower(uint16_t ch) {
    return (ch >= 'A' && ch <= 'Z') ? (uint16_t)(ch - 'A' + 'a') : ch;
}

static uint16_t u16_toupper(uint16_t ch) {
    return (ch >= 'a' && ch <= 'z') ? (uint16_t)(ch - 'a' + 'A') : ch;
}

static LPWSTR u16_copy(LPWSTR dst, LPCWSTR src) {
    size_t i = 0;
    if (!dst) return NULL;
    if (!src) {
        dst[0] = 0;
        return dst;
    }
    while (src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
    return dst;
}

static LPWSTR u16_ncopy(LPWSTR dst, LPCWSTR src, size_t count) {
    size_t i = 0;
    if (!dst || count == 0) return dst;
    if (!src) {
        dst[0] = 0;
        return dst;
    }
    while (i + 1 < count && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
    return dst;
}

static LPWSTR u16_cat(LPWSTR dst, LPCWSTR src) {
    if (!dst) return NULL;
    return u16_copy(u16_end(dst), src);
}

static int u16_cmp(LPCWSTR a, LPCWSTR b) {
    size_t i = 0;
    while (a && b && a[i] && b[i] && a[i] == b[i]) i++;
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    return (int)a[i] - (int)b[i];
}

static int u16_ncmp(LPCWSTR a, LPCWSTR b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        uint16_t ca = a && a[i] ? a[i] : 0;
        uint16_t cb = b && b[i] ? b[i] : 0;
        if (ca != cb || ca == 0 || cb == 0) return (int)ca - (int)cb;
    }
    return 0;
}

static int u16_icmp(LPCWSTR a, LPCWSTR b) {
    size_t i = 0;
    while (a && b && a[i] && b[i] && u16_tolower(a[i]) == u16_tolower(b[i])) i++;
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    return (int)u16_tolower(a[i]) - (int)u16_tolower(b[i]);
}

static int u16_nicmp(LPCWSTR a, LPCWSTR b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        uint16_t ca = a && a[i] ? u16_tolower(a[i]) : 0;
        uint16_t cb = b && b[i] ? u16_tolower(b[i]) : 0;
        if (ca != cb || ca == 0 || cb == 0) return (int)ca - (int)cb;
    }
    return 0;
}

static LPWSTR u16_chr(LPCWSTR s, uint16_t ch) {
    size_t i;
    if (!s) return NULL;
    for (i = 0; ; i++) {
        if (s[i] == ch) return (LPWSTR)(uintptr_t)(s + i);
        if (s[i] == 0) return NULL;
    }
}

static LPWSTR u16_rchr(LPCWSTR s, uint16_t ch) {
    LPWSTR found = NULL;
    size_t i;
    if (!s) return NULL;
    for (i = 0; ; i++) {
        if (s[i] == ch) found = (LPWSTR)(uintptr_t)(s + i);
        if (s[i] == 0) return found;
    }
}

static size_t u16_spn(LPCWSTR s, LPCWSTR accept) {
    size_t i, j;
    if (!s || !accept) return 0;
    for (i = 0; s[i]; i++) {
        for (j = 0; accept[j] && accept[j] != s[i]; j++) {}
        if (!accept[j]) break;
    }
    return i;
}

static size_t u16_cspn(LPCWSTR s, LPCWSTR reject, int ignore_case) {
    size_t i, j;
    if (!s) return 0;
    if (!reject) return u16_strlen(s);
    for (i = 0; s[i]; i++) {
        uint16_t sc = ignore_case ? u16_tolower(s[i]) : s[i];
        for (j = 0; reject[j]; j++) {
            uint16_t rc = ignore_case ? u16_tolower(reject[j]) : reject[j];
            if (sc == rc) return i;
        }
    }
    return i;
}

static int u16_has_space(LPCWSTR s) {
    size_t i;
    if (!s) return 0;
    for (i = 0; s[i]; i++) {
        if (s[i] == ' ' || s[i] == '\t') return 1;
    }
    return 0;
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

static LPWSTR u16_dup(LPCWSTR s) {
    size_t len;
    LPWSTR out;
    if (!s) return NULL;
    len = u16_strlen(s);
    out = (LPWSTR)malloc((len + 1) * sizeof(uint16_t));
    if (!out) return NULL;
    memcpy(out, s, (len + 1) * sizeof(uint16_t));
    return out;
}

static char* u16_to_utf8(LPCWSTR s) {
    size_t i, len;
    char* out;
    if (!s) return NULL;
    len = u16_strlen(s);
    out = (char*)malloc(len + 1);
    if (!out) return NULL;
    for (i = 0; i < len; i++) out[i] = (s[i] <= 0x7f) ? (char)s[i] : '?';
    out[len] = '\0';
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

static int has_sep_a(LPCSTR s) {
    return s && (strchr(s, '\\') || strchr(s, '/'));
}

static int has_ext_a(LPCSTR s) {
    const char* slash;
    const char* dot;
    if (!s) return 0;
    slash = strrchr(s, '\\');
    if (!slash) slash = strrchr(s, '/');
    dot = strrchr(s, '.');
    return dot && (!slash || dot > slash);
}

static int is_absolute_a(LPCSTR s) {
    if (!s || !s[0]) return 0;
    if ((isalpha((unsigned char)s[0]) && s[1] == ':') || s[0] == '\\' || s[0] == '/') return 1;
    return 0;
}

static char* find_filename_a(LPCSTR path) {
    char* p;
    if (!path) return NULL;
    p = strrchr(path, '\\');
    if (!p) p = strrchr(path, '/');
    return p ? p + 1 : (char*)(uintptr_t)path;
}

static char* find_extension_a(LPCSTR path) {
    const char* dot;
    const char* slash;
    if (!path) return NULL;
    dot = strrchr(path, '.');
    slash = strrchr(path, '\\');
    if (!slash) slash = strrchr(path, '/');
    if (dot && (!slash || dot > slash)) return (char*)(uintptr_t)dot;
    return (char*)(uintptr_t)(path + strlen(path));
}

static int is_root_a(LPCSTR path) {
    size_t len;
    if (!path || !path[0]) return 0;
    len = strlen(path);
    if ((strcmp(path, "\\") == 0) || (strcmp(path, "/") == 0)) return 1;
    if (len == 3 && isalpha((unsigned char)path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) return 1;
    return 0;
}

static BOOL path_combine_a(LPSTR dst, LPCSTR dir, LPCSTR file) {
    size_t len;
    if (!dst) return FALSE;
    if ((!dir || !dir[0]) && (!file || !file[0])) return FALSE;
    if (!dir || !dir[0]) {
        strcpy(dst, file ? file : "");
        return TRUE;
    }
    if (!file || !file[0]) {
        strcpy(dst, dir);
        return TRUE;
    }
    if (is_absolute_a(file)) {
        strcpy(dst, file);
        return TRUE;
    }
    strcpy(dst, dir);
    len = strlen(dst);
    if (len && dst[len - 1] != '\\' && dst[len - 1] != '/') {
        dst[len++] = '\\';
        dst[len] = '\0';
    }
    strcat(dst, file);
    return TRUE;
}

static BOOL path_canonicalize_a(LPSTR dst, LPCSTR src) {
    char* temp;
    char* tokens[256];
    size_t count = 0;
    size_t i = 0;
    char prefix[8] = "";
    size_t prefix_len = 0;
    int leading_sep = 0;
    if (!dst || !src) return FALSE;
    temp = dup_narrow(src);
    if (!temp) return FALSE;
    for (i = 0; temp[i]; i++) {
        if (temp[i] == '/') temp[i] = '\\';
    }
    if (isalpha((unsigned char)temp[0]) && temp[1] == ':') {
        prefix[0] = temp[0];
        prefix[1] = ':';
        prefix[2] = '\0';
        prefix_len = 2;
        i = (temp[2] == '\\') ? 3 : 2;
        leading_sep = 1;
    } else if (temp[0] == '\\' && temp[1] == '\\') {
        prefix[0] = '\\';
        prefix[1] = '\\';
        prefix[2] = '\0';
        prefix_len = 2;
        i = 2;
        leading_sep = 1;
    } else if (temp[0] == '\\') {
        prefix[0] = '\\';
        prefix[1] = '\0';
        prefix_len = 1;
        i = 1;
        leading_sep = 1;
    }
    while (temp[i]) {
        char* seg = temp + i;
        while (temp[i] && temp[i] != '\\') i++;
        if (temp[i]) temp[i++] = '\0';
        if (seg[0] == '\0' || strcmp(seg, ".") == 0) continue;
        if (strcmp(seg, "..") == 0) {
            if (count > 0) count--;
            continue;
        }
        tokens[count++] = seg;
    }
    dst[0] = '\0';
    if (prefix_len) strcat(dst, prefix);
    if (leading_sep && prefix_len == 2 && prefix[1] == ':' && count > 0) strcat(dst, "\\");
    for (i = 0; i < count; i++) {
        if (dst[0] && dst[strlen(dst) - 1] != '\\') strcat(dst, "\\");
        strcat(dst, tokens[i]);
    }
    if (dst[0] == '\0' && leading_sep) strcpy(dst, prefix_len ? prefix : "\\");
    free(temp);
    return TRUE;
}

static BOOL wildcard_match_a(LPCSTR str, LPCSTR pat) {
    while (*pat) {
        if (*pat == '*') {
            pat++;
            if (!*pat) return TRUE;
            while (*str) {
                if (wildcard_match_a(str, pat)) return TRUE;
                str++;
            }
            return FALSE;
        }
        if (*pat == '?') {
            if (!*str) return FALSE;
            str++;
            pat++;
            continue;
        }
        if (tolower((unsigned char)*str) != tolower((unsigned char)*pat)) return FALSE;
        str++;
        pat++;
    }
    return *str == '\0';
}

static BOOL wildcard_match_w(LPCWSTR str, LPCWSTR pat) {
    while (*pat) {
        if (*pat == '*') {
            pat++;
            if (!*pat) return TRUE;
            while (*str) {
                if (wildcard_match_w(str, pat)) return TRUE;
                str++;
            }
            return FALSE;
        }
        if (*pat == '?') {
            if (!*str) return FALSE;
            str++;
            pat++;
            continue;
        }
        if (u16_tolower(*str) != u16_tolower(*pat)) return FALSE;
        str++;
        pat++;
    }
    return *str == 0;
}

static int trim_char_a(char ch, LPCSTR trim) {
    return trim ? strchr(trim, ch) != NULL : isspace((unsigned char)ch);
}

static int trim_char_w(uint16_t ch, LPCWSTR trim) {
    size_t i;
    if (!trim) return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
    for (i = 0; trim[i]; i++) if (trim[i] == ch) return 1;
    return 0;
}

static void format_bytes_a(LONGLONG bytes, char* buf, size_t size) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double value = (double)bytes;
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < sizeof(units) / sizeof(units[0])) {
        value /= 1024.0;
        unit++;
    }
    if (unit == 0) snprintf(buf, size, "%lld %s", (long long)bytes, units[unit]);
    else snprintf(buf, size, "%.2f %s", value, units[unit]);
}

LPWSTR __attribute__((ms_abi)) PathCombineW(LPWSTR pszDest, LPCWSTR pszDir, LPCWSTR pszFile) {
    char dir[MAX_PATH], file[MAX_PATH], out[MAX_PATH];
    if (!pszDest) return NULL;
    pszDest[0] = 0;
    if (pszDir) {
        char* tmp = u16_to_utf8(pszDir);
        if (!tmp) return NULL;
        strncpy(dir, tmp, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = 0;
        free(tmp);
    } else dir[0] = 0;
    if (pszFile) {
        char* tmp = u16_to_utf8(pszFile);
        if (!tmp) return NULL;
        strncpy(file, tmp, sizeof(file) - 1);
        file[sizeof(file) - 1] = 0;
        free(tmp);
    } else file[0] = 0;
    if (!path_combine_a(out, dir, file)) return NULL;
    utf8_to_u16_buf(out, pszDest, MAX_PATH);
    return pszDest;
}

LPSTR __attribute__((ms_abi)) PathCombineA(LPSTR pszDest, LPCSTR pszDir, LPCSTR pszFile) {
    return path_combine_a(pszDest, pszDir, pszFile) ? pszDest : NULL;
}

BOOL __attribute__((ms_abi)) PathFileExistsW(LPCWSTR pszPath) {
    char* path = u16_to_utf8(pszPath);
    int rc;
    if (!path) return FALSE;
    rc = access(path, F_OK);
    free(path);
    return rc == 0;
}

BOOL __attribute__((ms_abi)) PathFileExistsA(LPCSTR pszPath) { return pszPath && access(pszPath, F_OK) == 0; }

LPWSTR __attribute__((ms_abi)) PathFindFileNameW(LPCWSTR pszPath) {
    LPWSTR a = u16_rchr(pszPath, '\\');
    LPWSTR b = u16_rchr(pszPath, '/');
    LPWSTR p = (a && b) ? (a > b ? a : b) : (a ? a : b);
    return p ? p + 1 : (LPWSTR)(uintptr_t)pszPath;
}

LPSTR __attribute__((ms_abi)) PathFindFileNameA(LPCSTR pszPath) { return find_filename_a(pszPath); }

LPWSTR __attribute__((ms_abi)) PathFindExtensionW(LPCWSTR pszPath) {
    LPWSTR dot = u16_rchr(pszPath, '.');
    LPWSTR slash = u16_rchr(pszPath, '\\');
    LPWSTR slash2 = u16_rchr(pszPath, '/');
    LPWSTR last = (slash && slash2) ? (slash > slash2 ? slash : slash2) : (slash ? slash : slash2);
    if (dot && (!last || dot > last)) return dot;
    return (LPWSTR)(uintptr_t)(pszPath + u16_strlen(pszPath));
}

LPSTR __attribute__((ms_abi)) PathFindExtensionA(LPCSTR pszPath) { return find_extension_a(pszPath); }

void __attribute__((ms_abi)) PathStripPathW(LPWSTR pszPath) {
    LPWSTR file = PathFindFileNameW(pszPath);
    if (pszPath && file && file != pszPath) memmove(pszPath, file, (u16_strlen(file) + 1) * sizeof(uint16_t));
}

void __attribute__((ms_abi)) PathStripPathA(LPSTR pszPath) {
    char* file = find_filename_a(pszPath);
    if (pszPath && file && file != pszPath) memmove(pszPath, file, strlen(file) + 1);
}

BOOL __attribute__((ms_abi)) PathRemoveFileSpecW(LPWSTR pszPath) {
    LPWSTR a = u16_rchr(pszPath, '\\');
    LPWSTR b = u16_rchr(pszPath, '/');
    LPWSTR p = (a && b) ? (a > b ? a : b) : (a ? a : b);
    if (!pszPath || !p) return FALSE;
    *p = 0;
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathRemoveFileSpecA(LPSTR pszPath) {
    char* p = strrchr(pszPath, '\\');
    char* q = strrchr(pszPath, '/');
    char* last = (p && q) ? (p > q ? p : q) : (p ? p : q);
    if (!pszPath || !last) return FALSE;
    *last = 0;
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathAddExtensionW(LPWSTR pszPath, LPCWSTR pszExt) {
    if (!pszPath || !pszExt) return FALSE;
    if (*PathFindExtensionW(pszPath)) return FALSE;
    u16_cat(pszPath, pszExt);
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathAddExtensionA(LPSTR pszPath, LPCSTR pszExt) {
    if (!pszPath || !pszExt) return FALSE;
    if (*find_extension_a(pszPath)) return FALSE;
    strcat(pszPath, pszExt);
    return TRUE;
}

void __attribute__((ms_abi)) PathRemoveExtensionW(LPWSTR pszPath) {
    LPWSTR dot = PathFindExtensionW(pszPath);
    if (dot) *dot = 0;
}

void __attribute__((ms_abi)) PathRemoveExtensionA(LPSTR pszPath) {
    char* dot = find_extension_a(pszPath);
    if (dot) *dot = 0;
}

int __attribute__((ms_abi)) PathGetDriveNumberW(LPCWSTR pszPath) {
    if (pszPath && pszPath[1] == ':') return (int)(u16_toupper(pszPath[0]) - 'A');
    return -1;
}

int __attribute__((ms_abi)) PathGetDriveNumberA(LPCSTR pszPath) {
    if (pszPath && pszPath[1] == ':') return toupper((unsigned char)pszPath[0]) - 'A';
    return -1;
}

BOOL __attribute__((ms_abi)) PathIsRelativeW(LPCWSTR pszPath) {
    if (!pszPath || !pszPath[0]) return TRUE;
    return !(pszPath[0] == '\\' || pszPath[0] == '/' || pszPath[1] == ':');
}

BOOL __attribute__((ms_abi)) PathIsRelativeA(LPCSTR pszPath) {
    if (!pszPath || !pszPath[0]) return TRUE;
    return !(pszPath[0] == '\\' || pszPath[0] == '/' || pszPath[1] == ':');
}

BOOL __attribute__((ms_abi)) PathIsRootW(LPCWSTR pszPath) {
    size_t len = u16_strlen(pszPath);
    if (!pszPath || !pszPath[0]) return FALSE;
    if ((len == 1 && (pszPath[0] == '\\' || pszPath[0] == '/')) ||
        (len == 3 && pszPath[1] == ':' && (pszPath[2] == '\\' || pszPath[2] == '/'))) return TRUE;
    return FALSE;
}

BOOL __attribute__((ms_abi)) PathIsRootA(LPCSTR pszPath) { return is_root_a(pszPath); }

BOOL __attribute__((ms_abi)) PathIsDirectoryW(LPCWSTR pszPath) {
    char* path = u16_to_utf8(pszPath);
    struct stat st;
    int rc;
    if (!path) return FALSE;
    rc = stat(path, &st);
    free(path);
    return rc == 0 && S_ISDIR(st.st_mode);
}

BOOL __attribute__((ms_abi)) PathIsDirectoryA(LPCSTR pszPath) {
    struct stat st;
    return pszPath && stat(pszPath, &st) == 0 && S_ISDIR(st.st_mode);
}

BOOL __attribute__((ms_abi)) PathIsFileSpecW(LPCWSTR pszPath) { return pszPath && !u16_chr(pszPath, '\\') && !u16_chr(pszPath, '/'); }
BOOL __attribute__((ms_abi)) PathIsFileSpecA(LPCSTR pszPath) { return pszPath && !strchr(pszPath, '\\') && !strchr(pszPath, '/'); }
BOOL __attribute__((ms_abi)) PathIsUNCW(LPCWSTR pszPath) { return pszPath && pszPath[0] == '\\' && pszPath[1] == '\\'; }
BOOL __attribute__((ms_abi)) PathIsUNCA(LPCSTR pszPath) { return pszPath && pszPath[0] == '\\' && pszPath[1] == '\\'; }

BOOL __attribute__((ms_abi)) PathCanonicalizeW(LPWSTR pszBuf, LPCWSTR pszPath) {
    char* src = u16_to_utf8(pszPath);
    char out[MAX_PATH];
    BOOL ok;
    if (!src) return FALSE;
    ok = path_canonicalize_a(out, src);
    free(src);
    if (!ok) return FALSE;
    utf8_to_u16_buf(out, pszBuf, MAX_PATH);
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathCanonicalizeA(LPSTR pszBuf, LPCSTR pszPath) { return path_canonicalize_a(pszBuf, pszPath); }

void __attribute__((ms_abi)) PathQuoteSpacesW(LPWSTR pszPath) {
    size_t len;
    if (!pszPath || !u16_has_space(pszPath)) return;
    len = u16_strlen(pszPath);
    memmove(pszPath + 1, pszPath, (len + 1) * sizeof(uint16_t));
    pszPath[0] = '"';
    pszPath[len + 1] = '"';
    pszPath[len + 2] = 0;
}

void __attribute__((ms_abi)) PathQuoteSpacesA(LPSTR pszPath) {
    size_t len;
    if (!pszPath || !strchr(pszPath, ' ')) return;
    len = strlen(pszPath);
    memmove(pszPath + 1, pszPath, len + 1);
    pszPath[0] = '"';
    pszPath[len + 1] = '"';
    pszPath[len + 2] = 0;
}

void __attribute__((ms_abi)) PathUnquoteSpacesW(LPWSTR pszPath) {
    size_t len;
    if (!pszPath) return;
    len = u16_strlen(pszPath);
    if (len >= 2 && pszPath[0] == '"' && pszPath[len - 1] == '"') {
        memmove(pszPath, pszPath + 1, (len - 1) * sizeof(uint16_t));
        pszPath[len - 2] = 0;
    }
}

void __attribute__((ms_abi)) PathUnquoteSpacesA(LPSTR pszPath) {
    size_t len;
    if (!pszPath) return;
    len = strlen(pszPath);
    if (len >= 2 && pszPath[0] == '"' && pszPath[len - 1] == '"') {
        memmove(pszPath, pszPath + 1, len - 1);
        pszPath[len - 2] = 0;
    }
}

LPWSTR __attribute__((ms_abi)) PathGetArgsW(LPCWSTR pszPath) {
    int quoted = 0;
    size_t i;
    if (!pszPath) return NULL;
    for (i = 0; pszPath[i]; i++) {
        if (pszPath[i] == '"') quoted = !quoted;
        else if (!quoted && (pszPath[i] == ' ' || pszPath[i] == '\t')) {
            while (pszPath[i] == ' ' || pszPath[i] == '\t') i++;
            return (LPWSTR)(uintptr_t)(pszPath + i);
        }
    }
    return (LPWSTR)(uintptr_t)(pszPath + u16_strlen(pszPath));
}

LPSTR __attribute__((ms_abi)) PathGetArgsA(LPCSTR pszPath) {
    int quoted = 0;
    size_t i;
    if (!pszPath) return NULL;
    for (i = 0; pszPath[i]; i++) {
        if (pszPath[i] == '"') quoted = !quoted;
        else if (!quoted && isspace((unsigned char)pszPath[i])) {
            while (pszPath[i] && isspace((unsigned char)pszPath[i])) i++;
            return (LPSTR)(uintptr_t)(pszPath + i);
        }
    }
    return (LPSTR)(uintptr_t)(pszPath + strlen(pszPath));
}

LPWSTR __attribute__((ms_abi)) PathSkipRootW(LPCWSTR pszPath) {
    size_t i = 0;
    if (!pszPath) return NULL;
    if (pszPath[1] == ':' && (pszPath[2] == '\\' || pszPath[2] == '/')) return (LPWSTR)(uintptr_t)(pszPath + 3);
    if (pszPath[0] == '\\' && pszPath[1] == '\\') {
        i = 2;
        while (pszPath[i] && pszPath[i] != '\\' && pszPath[i] != '/') i++;
        while (pszPath[i] == '\\' || pszPath[i] == '/') i++;
        while (pszPath[i] && pszPath[i] != '\\' && pszPath[i] != '/') i++;
        while (pszPath[i] == '\\' || pszPath[i] == '/') i++;
        return (LPWSTR)(uintptr_t)(pszPath + i);
    }
    if (pszPath[0] == '\\' || pszPath[0] == '/') return (LPWSTR)(uintptr_t)(pszPath + 1);
    return (LPWSTR)(uintptr_t)pszPath;
}

LPSTR __attribute__((ms_abi)) PathSkipRootA(LPCSTR pszPath) {
    size_t i = 0;
    if (!pszPath) return NULL;
    if (pszPath[1] == ':' && (pszPath[2] == '\\' || pszPath[2] == '/')) return (LPSTR)(uintptr_t)(pszPath + 3);
    if (pszPath[0] == '\\' && pszPath[1] == '\\') {
        i = 2;
        while (pszPath[i] && pszPath[i] != '\\' && pszPath[i] != '/') i++;
        while (pszPath[i] == '\\' || pszPath[i] == '/') i++;
        while (pszPath[i] && pszPath[i] != '\\' && pszPath[i] != '/') i++;
        while (pszPath[i] == '\\' || pszPath[i] == '/') i++;
        return (LPSTR)(uintptr_t)(pszPath + i);
    }
    if (pszPath[0] == '\\' || pszPath[0] == '/') return (LPSTR)(uintptr_t)(pszPath + 1);
    return (LPSTR)(uintptr_t)pszPath;
}

BOOL __attribute__((ms_abi)) PathRenameExtensionW(LPWSTR pszPath, LPCWSTR pszExt) {
    if (!pszPath || !pszExt) return FALSE;
    PathRemoveExtensionW(pszPath);
    return PathAddExtensionW(pszPath, pszExt);
}

BOOL __attribute__((ms_abi)) PathRenameExtensionA(LPSTR pszPath, LPCSTR pszExt) {
    if (!pszPath || !pszExt) return FALSE;
    PathRemoveExtensionA(pszPath);
    return PathAddExtensionA(pszPath, pszExt);
}

BOOL __attribute__((ms_abi)) PathAppendW(LPWSTR pszPath, LPCWSTR pszMore) {
    char* base = u16_to_utf8(pszPath);
    char* more = u16_to_utf8(pszMore);
    char out[MAX_PATH];
    BOOL ok;
    if (!base || !more) {
        free(base);
        free(more);
        return FALSE;
    }
    ok = path_combine_a(out, base, more);
    free(base);
    free(more);
    if (!ok) return FALSE;
    utf8_to_u16_buf(out, pszPath, MAX_PATH);
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathAppendA(LPSTR pszPath, LPCSTR pszMore) {
    char out[MAX_PATH];
    if (!path_combine_a(out, pszPath, pszMore)) return FALSE;
    strcpy(pszPath, out);
    return TRUE;
}

LPWSTR __attribute__((ms_abi)) PathBuildRootW(LPWSTR pszRoot, INT drive) {
    if (!pszRoot || drive < 0 || drive > 25) return NULL;
    pszRoot[0] = (uint16_t)('A' + drive);
    pszRoot[1] = ':';
    pszRoot[2] = '\\';
    pszRoot[3] = 0;
    return pszRoot;
}

LPSTR __attribute__((ms_abi)) PathBuildRootA(LPSTR pszRoot, INT drive) {
    if (!pszRoot || drive < 0 || drive > 25) return NULL;
    pszRoot[0] = (char)('A' + drive);
    pszRoot[1] = ':';
    pszRoot[2] = '\\';
    pszRoot[3] = 0;
    return pszRoot;
}

BOOL __attribute__((ms_abi)) PathCompactW(LPWSTR pszPath, UINT cchMax) {
    if (!pszPath || cchMax == 0) return FALSE;
    if (u16_strlen(pszPath) >= cchMax) pszPath[cchMax - 1] = 0;
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathCompactA(LPSTR pszPath, UINT cchMax) {
    if (!pszPath || cchMax == 0) return FALSE;
    if (strlen(pszPath) >= cchMax) pszPath[cchMax - 1] = 0;
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathCompactPathExW(LPWSTR pszOut, LPCWSTR pszSrc, UINT cchMax, DWORD dwFlags) {
    (void)dwFlags;
    if (!pszOut || !pszSrc || cchMax == 0) return FALSE;
    u16_ncopy(pszOut, pszSrc, cchMax);
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathCompactPathExA(LPSTR pszOut, LPCSTR pszSrc, UINT cchMax, DWORD dwFlags) {
    (void)dwFlags;
    if (!pszOut || !pszSrc || cchMax == 0) return FALSE;
    strncpy(pszOut, pszSrc, cchMax - 1);
    pszOut[cchMax - 1] = 0;
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathMatchSpecW(LPCWSTR pszFile, LPCWSTR pszSpec) { return pszFile && pszSpec && wildcard_match_w(pszFile, pszSpec); }
BOOL __attribute__((ms_abi)) PathMatchSpecA(LPCSTR pszFile, LPCSTR pszSpec) { return pszFile && pszSpec && wildcard_match_a(pszFile, pszSpec); }

BOOL __attribute__((ms_abi)) PathMakeAbsoluteW(LPWSTR pszOut, LPCWSTR pszPath, DWORD cchMax) {
    char cwd[MAX_PATH], src[MAX_PATH], out[MAX_PATH];
    char* tmp;
    if (!pszOut || !pszPath || cchMax == 0) return FALSE;
    tmp = u16_to_utf8(pszPath);
    if (!tmp) return FALSE;
    strncpy(src, tmp, sizeof(src) - 1);
    src[sizeof(src) - 1] = 0;
    free(tmp);
    if (!is_absolute_a(src)) {
        if (!getcwd(cwd, sizeof(cwd))) return FALSE;
        path_combine_a(out, cwd, src);
    } else {
        strncpy(out, src, sizeof(out) - 1);
        out[sizeof(out) - 1] = 0;
    }
    path_canonicalize_a(src, out);
    utf8_to_u16_buf(src, pszOut, cchMax);
    return TRUE;
}

BOOL __attribute__((ms_abi)) PathMakeAbsoluteA(LPSTR pszOut, LPCSTR pszPath, DWORD cchMax) {
    char cwd[MAX_PATH];
    if (!pszOut || !pszPath || cchMax == 0) return FALSE;
    if (!is_absolute_a(pszPath)) {
        if (!getcwd(cwd, sizeof(cwd))) return FALSE;
        path_combine_a(pszOut, cwd, pszPath);
    } else {
        strncpy(pszOut, pszPath, cchMax - 1);
        pszOut[cchMax - 1] = 0;
    }
    return path_canonicalize_a(pszOut, pszOut);
}

void __attribute__((ms_abi)) PathSetDlgItemPathW(void* hDlg, int id, LPCWSTR pszPath) { (void)hDlg; (void)id; (void)pszPath; }
void __attribute__((ms_abi)) PathSetDlgItemPathA(void* hDlg, int id, LPCSTR pszPath) { (void)hDlg; (void)id; (void)pszPath; }

LPSTR __attribute__((ms_abi)) StrStrIA(LPCSTR haystack, LPCSTR needle) {
    size_t i, nlen;
    if (!haystack || !needle) return NULL;
    nlen = strlen(needle);
    if (!nlen) return (LPSTR)(uintptr_t)haystack;
    for (i = 0; haystack[i]; i++) if (strncasecmp(haystack + i, needle, nlen) == 0) return (LPSTR)(uintptr_t)(haystack + i);
    return NULL;
}

LPWSTR __attribute__((ms_abi)) StrStrIW(LPCWSTR haystack, LPCWSTR needle) {
    size_t i, nlen;
    if (!haystack || !needle) return NULL;
    nlen = u16_strlen(needle);
    if (!nlen) return (LPWSTR)(uintptr_t)haystack;
    for (i = 0; haystack[i]; i++) if (u16_nicmp(haystack + i, needle, nlen) == 0) return (LPWSTR)(uintptr_t)(haystack + i);
    return NULL;
}

LPWSTR __attribute__((ms_abi)) StrStrW(LPCWSTR haystack, LPCWSTR needle) {
    size_t i, nlen;
    if (!haystack || !needle) return NULL;
    nlen = u16_strlen(needle);
    if (!nlen) return (LPWSTR)(uintptr_t)haystack;
    for (i = 0; haystack[i]; i++) if (u16_ncmp(haystack + i, needle, nlen) == 0) return (LPWSTR)(uintptr_t)(haystack + i);
    return NULL;
}

LPSTR __attribute__((ms_abi)) StrStrA(LPCSTR haystack, LPCSTR needle) { return needle ? strstr(haystack, needle) : NULL; }
int __attribute__((ms_abi)) StrCmpIA(LPCSTR a, LPCSTR b) { return strcasecmp(a ? a : "", b ? b : ""); }
int __attribute__((ms_abi)) StrCmpIW(LPCWSTR a, LPCWSTR b) {
    static const uint16_t empty_u16[] = {0};
    return u16_icmp(a ? a : empty_u16, b ? b : empty_u16);
}
int __attribute__((ms_abi)) StrCmpNIA(LPCSTR a, LPCSTR b, int n) { return strncasecmp(a ? a : "", b ? b : "", (size_t)(n < 0 ? 0 : n)); }
int __attribute__((ms_abi)) StrCmpNIW(LPCWSTR a, LPCWSTR b, int n) { return u16_nicmp(a, b, (size_t)(n < 0 ? 0 : n)); }
int __attribute__((ms_abi)) StrCmpW(LPCWSTR a, LPCWSTR b) { return u16_cmp(a, b); }
int __attribute__((ms_abi)) StrCmpA(LPCSTR a, LPCSTR b) { return strcmp(a ? a : "", b ? b : ""); }
int __attribute__((ms_abi)) StrCmpNW(LPCWSTR a, LPCWSTR b, int n) { return u16_ncmp(a, b, (size_t)(n < 0 ? 0 : n)); }
int __attribute__((ms_abi)) StrCmpNA(LPCSTR a, LPCSTR b, int n) { return strncmp(a ? a : "", b ? b : "", (size_t)(n < 0 ? 0 : n)); }
LPWSTR __attribute__((ms_abi)) StrCatW(LPWSTR dst, LPCWSTR src) { return u16_cat(dst, src); }
LPSTR __attribute__((ms_abi)) StrCatA(LPSTR dst, LPCSTR src) { return strcat(dst, src); }
LPWSTR __attribute__((ms_abi)) StrCpyW(LPWSTR dst, LPCWSTR src) { return u16_copy(dst, src); }
LPSTR __attribute__((ms_abi)) StrCpyA(LPSTR dst, LPCSTR src) { return strcpy(dst, src ? src : ""); }
LPWSTR __attribute__((ms_abi)) StrCpyNW(LPWSTR dst, LPCWSTR src, int cchMax) { return u16_ncopy(dst, src, (size_t)(cchMax < 0 ? 0 : cchMax)); }
LPSTR __attribute__((ms_abi)) StrCpyNA(LPSTR dst, LPCSTR src, int cchMax) {
    size_t n = (size_t)(cchMax < 0 ? 0 : cchMax);
    if (!dst || n == 0) return dst;
    strncpy(dst, src ? src : "", n - 1);
    dst[n - 1] = 0;
    return dst;
}

LPWSTR __attribute__((ms_abi)) StrCatBuffW(LPWSTR dst, LPCWSTR src, int cchMax) {
    size_t len;
    if (!dst || cchMax <= 0) return dst;
    len = u16_strlen(dst);
    if ((size_t)cchMax <= len) return dst;
    u16_ncopy(dst + len, src, (size_t)cchMax - len);
    return dst;
}

LPSTR __attribute__((ms_abi)) StrCatBuffA(LPSTR dst, LPCSTR src, int cchMax) {
    size_t len;
    if (!dst || cchMax <= 0) return dst;
    len = strlen(dst);
    if ((size_t)cchMax <= len) return dst;
    strncat(dst, src ? src : "", (size_t)cchMax - len - 1);
    return dst;
}

LPWSTR __attribute__((ms_abi)) StrFormatByteSizeW(LONGLONG qdw, LPWSTR pszBuf, UINT cchBuf) {
    char tmp[64];
    format_bytes_a(qdw, tmp, sizeof(tmp));
    utf8_to_u16_buf(tmp, pszBuf, cchBuf);
    return pszBuf;
}

LPSTR __attribute__((ms_abi)) StrFormatByteSizeA(LONGLONG qdw, LPSTR pszBuf, UINT cchBuf) {
    format_bytes_a(qdw, pszBuf, cchBuf);
    return pszBuf;
}

int __attribute__((ms_abi)) StrToIntW(LPCWSTR pszSrc) {
    char* s = u16_to_utf8(pszSrc);
    long v = s ? strtol(s, NULL, 10) : 0;
    free(s);
    return (int)v;
}

int __attribute__((ms_abi)) StrToIntA(LPCSTR pszSrc) { return pszSrc ? atoi(pszSrc) : 0; }

BOOL __attribute__((ms_abi)) StrToInt64ExW(LPCWSTR pszSrc, DWORD dwFlags, LONGLONG* pllRet) {
    char* s = u16_to_utf8(pszSrc);
    char* end = NULL;
    long long v;
    (void)dwFlags;
    if (!s || !pllRet) {
        free(s);
        return FALSE;
    }
    v = strtoll(s, &end, 0);
    free(s);
    if (end == s) return FALSE;
    *pllRet = (LONGLONG)v;
    return TRUE;
}

BOOL __attribute__((ms_abi)) StrToInt64ExA(LPCSTR pszSrc, DWORD dwFlags, LONGLONG* pllRet) {
    char* end = NULL;
    (void)dwFlags;
    if (!pszSrc || !pllRet) return FALSE;
    *pllRet = (LONGLONG)strtoll(pszSrc, &end, 0);
    return end != pszSrc;
}

BOOL __attribute__((ms_abi)) StrTrimW(LPWSTR psz, LPCWSTR pszTrimChars) {
    size_t start = 0, end, len;
    if (!psz) return FALSE;
    len = u16_strlen(psz);
    end = len;
    while (start < len && trim_char_w(psz[start], pszTrimChars)) start++;
    while (end > start && trim_char_w(psz[end - 1], pszTrimChars)) end--;
    if (start > 0) memmove(psz, psz + start, (end - start) * sizeof(uint16_t));
    psz[end - start] = 0;
    return TRUE;
}

BOOL __attribute__((ms_abi)) StrTrimA(LPSTR psz, LPCSTR pszTrimChars) {
    size_t start = 0, end, len;
    if (!psz) return FALSE;
    len = strlen(psz);
    end = len;
    while (start < len && trim_char_a(psz[start], pszTrimChars)) start++;
    while (end > start && trim_char_a(psz[end - 1], pszTrimChars)) end--;
    if (start > 0) memmove(psz, psz + start, end - start);
    psz[end - start] = 0;
    return TRUE;
}

BOOL __attribute__((ms_abi)) StrToIntExW(LPCWSTR pszSrc, DWORD dwFlags, INT* piRet) {
    LONGLONG v = 0;
    if (!piRet || !StrToInt64ExW(pszSrc, dwFlags, &v)) return FALSE;
    *piRet = (INT)v;
    return TRUE;
}

BOOL __attribute__((ms_abi)) StrToIntExA(LPCSTR pszSrc, DWORD dwFlags, INT* piRet) {
    LONGLONG v = 0;
    if (!piRet || !StrToInt64ExA(pszSrc, dwFlags, &v)) return FALSE;
    *piRet = (INT)v;
    return TRUE;
}

LPSTR __attribute__((ms_abi)) StrDupA(LPCSTR pszSrc) { return dup_narrow(pszSrc); }
LPWSTR __attribute__((ms_abi)) StrDupW(LPCWSTR pszSrc) { return u16_dup(pszSrc); }
int __attribute__((ms_abi)) StrSpnA(LPCSTR psz, LPCSTR mask) { return (int)strspn(psz ? psz : "", mask ? mask : ""); }
int __attribute__((ms_abi)) StrSpnW(LPCWSTR psz, LPCWSTR mask) { return (int)u16_spn(psz, mask); }
int __attribute__((ms_abi)) StrCSpnA(LPCSTR psz, LPCSTR mask) { return (int)strcspn(psz ? psz : "", mask ? mask : ""); }
int __attribute__((ms_abi)) StrCSpnW(LPCWSTR psz, LPCWSTR mask) { return (int)u16_cspn(psz, mask, 0); }
int __attribute__((ms_abi)) StrCSpnIA(LPCSTR psz, LPCSTR mask) {
    size_t i, j;
    if (!psz) return 0;
    if (!mask) return (int)strlen(psz);
    for (i = 0; psz[i]; i++) for (j = 0; mask[j]; j++) if (tolower((unsigned char)psz[i]) == tolower((unsigned char)mask[j])) return (int)i;
    return (int)strlen(psz);
}
int __attribute__((ms_abi)) StrCSpnIW(LPCWSTR psz, LPCWSTR mask) { return (int)u16_cspn(psz, mask, 1); }
LPSTR __attribute__((ms_abi)) StrRChrA(LPCSTR pszStart, LPCSTR pszEnd, WORD wMatch) {
    const char* end = pszEnd ? pszEnd : pszStart + strlen(pszStart ? pszStart : "");
    const char* p;
    if (!pszStart) return NULL;
    for (p = end; p >= pszStart; p--) if (*p == (char)wMatch) return (LPSTR)(uintptr_t)p;
    return NULL;
}

LPWSTR __attribute__((ms_abi)) StrRChrW(LPCWSTR pszStart, LPCWSTR pszEnd, WORD wMatch) {
    LPCWSTR end = pszEnd ? pszEnd : pszStart + u16_strlen(pszStart);
    LPCWSTR p;
    if (!pszStart) return NULL;
    for (p = end; p >= pszStart; p--) if (*p == (uint16_t)wMatch) return (LPWSTR)(uintptr_t)p;
    return NULL;
}

LPSTR __attribute__((ms_abi)) StrChrA(LPCSTR pszStart, WORD wMatch) { return pszStart ? strchr(pszStart, (char)wMatch) : NULL; }
LPWSTR __attribute__((ms_abi)) StrChrW(LPCWSTR pszStart, WORD wMatch) { return pszStart ? u16_chr(pszStart, (uint16_t)wMatch) : NULL; }
LPSTR __attribute__((ms_abi)) StrChrIA(LPCSTR pszStart, WORD wMatch) {
    size_t i;
    if (!pszStart) return NULL;
    for (i = 0; pszStart[i]; i++) if (tolower((unsigned char)pszStart[i]) == tolower((unsigned char)wMatch)) return (LPSTR)(uintptr_t)(pszStart + i);
    return NULL;
}

LPWSTR __attribute__((ms_abi)) StrChrIW(LPCWSTR pszStart, WORD wMatch) {
    size_t i;
    uint16_t match = u16_tolower((uint16_t)wMatch);
    if (!pszStart) return NULL;
    for (i = 0; pszStart[i]; i++) if (u16_tolower(pszStart[i]) == match) return (LPWSTR)(uintptr_t)(pszStart + i);
    return NULL;
}

LPSTR __attribute__((ms_abi)) StrPBrkA(LPCSTR psz, LPCSTR set) { return psz && set ? strpbrk(psz, set) : NULL; }
LPWSTR __attribute__((ms_abi)) StrPBrkW(LPCWSTR psz, LPCWSTR set) {
    size_t i, j;
    if (!psz || !set) return NULL;
    for (i = 0; psz[i]; i++) for (j = 0; set[j]; j++) if (psz[i] == set[j]) return (LPWSTR)(uintptr_t)(psz + i);
    return NULL;
}

HRESULT __attribute__((ms_abi)) UrlCombineW(LPCWSTR pszBase, LPCWSTR pszRelative, LPWSTR pszCombined, UINT* pcchCombined, DWORD dwFlags) {
    (void)pszRelative; (void)dwFlags;
    if (!pszCombined || !pcchCombined) return E_INVALIDARG;
    u16_ncopy(pszCombined, pszBase, *pcchCombined);
    *pcchCombined = (UINT)u16_strlen(pszCombined);
    return S_OK;
}

HRESULT __attribute__((ms_abi)) UrlCombineA(LPCSTR pszBase, LPCSTR pszRelative, LPSTR pszCombined, UINT* pcchCombined, DWORD dwFlags) {
    (void)pszRelative; (void)dwFlags;
    if (!pszCombined || !pcchCombined) return E_INVALIDARG;
    strncpy(pszCombined, pszBase ? pszBase : "", *pcchCombined ? *pcchCombined - 1 : 0);
    if (*pcchCombined) pszCombined[*pcchCombined - 1] = 0;
    *pcchCombined = (UINT)strlen(pszCombined);
    return S_OK;
}

HRESULT __attribute__((ms_abi)) UrlCreateFromPathW(LPCWSTR pszPath, LPWSTR pszUrl, UINT* pcchUrl, DWORD dwFlags) {
    char* path = u16_to_utf8(pszPath);
    char out[MAX_PATH + 16];
    (void)dwFlags;
    if (!path || !pszUrl || !pcchUrl) {
        free(path);
        return E_INVALIDARG;
    }
    snprintf(out, sizeof(out), "file://%s", path);
    free(path);
    utf8_to_u16_buf(out, pszUrl, *pcchUrl);
    *pcchUrl = (UINT)u16_strlen(pszUrl);
    return S_OK;
}

HRESULT __attribute__((ms_abi)) UrlCreateFromPathA(LPCSTR pszPath, LPSTR pszUrl, UINT* pcchUrl, DWORD dwFlags) {
    (void)dwFlags;
    if (!pszPath || !pszUrl || !pcchUrl) return E_INVALIDARG;
    snprintf(pszUrl, *pcchUrl, "file://%s", pszPath);
    *pcchUrl = (UINT)strlen(pszUrl);
    return S_OK;
}

HRESULT __attribute__((ms_abi)) UrlGetPartW(LPCWSTR pszIn, LPWSTR pszOut, DWORD* pcchOut, DWORD dwPart, DWORD dwFlags) { (void)pszIn; (void)pszOut; (void)pcchOut; (void)dwPart; (void)dwFlags; return S_FALSE; }
HRESULT __attribute__((ms_abi)) UrlGetPartA(LPCSTR pszIn, LPSTR pszOut, DWORD* pcchOut, DWORD dwPart, DWORD dwFlags) { (void)pszIn; (void)pszOut; (void)pcchOut; (void)dwPart; (void)dwFlags; return S_FALSE; }
BOOL __attribute__((ms_abi)) UrlIsW(LPCWSTR pszUrl, DWORD urlIs) { (void)pszUrl; (void)urlIs; return 0; }
BOOL __attribute__((ms_abi)) UrlIsA(LPCSTR pszUrl, DWORD urlIs) { (void)pszUrl; (void)urlIs; return 0; }

HRESULT __attribute__((ms_abi)) UrlCanonicalizeW(LPCWSTR pszUrl, LPWSTR pszCanonicalized, DWORD* pcchCanonicalized, DWORD dwFlags) {
    (void)dwFlags;
    if (!pszCanonicalized || !pcchCanonicalized) return E_INVALIDARG;
    u16_ncopy(pszCanonicalized, pszUrl, *pcchCanonicalized);
    *pcchCanonicalized = (DWORD)u16_strlen(pszCanonicalized);
    return S_OK;
}

HRESULT __attribute__((ms_abi)) UrlCanonicalizeA(LPCSTR pszUrl, LPSTR pszCanonicalized, DWORD* pcchCanonicalized, DWORD dwFlags) {
    (void)dwFlags;
    if (!pszCanonicalized || !pcchCanonicalized) return E_INVALIDARG;
    strncpy(pszCanonicalized, pszUrl ? pszUrl : "", *pcchCanonicalized ? *pcchCanonicalized - 1 : 0);
    if (*pcchCanonicalized) pszCanonicalized[*pcchCanonicalized - 1] = 0;
    *pcchCanonicalized = (DWORD)strlen(pszCanonicalized);
    return S_OK;
}

HRESULT __attribute__((ms_abi)) UrlEscapeW(LPCWSTR pszUrl, LPWSTR pszEscaped, DWORD* pcchEscaped, DWORD dwFlags) { return UrlCanonicalizeW(pszUrl, pszEscaped, pcchEscaped, dwFlags); }
HRESULT __attribute__((ms_abi)) UrlEscapeA(LPCSTR pszUrl, LPSTR pszEscaped, DWORD* pcchEscaped, DWORD dwFlags) { return UrlCanonicalizeA(pszUrl, pszEscaped, pcchEscaped, dwFlags); }
HRESULT __attribute__((ms_abi)) UrlUnescapeW(LPWSTR pszUrl, LPWSTR pszUnescaped, DWORD* pcchUnescaped, DWORD dwFlags) { return UrlCanonicalizeW(pszUrl, pszUnescaped, pcchUnescaped, dwFlags); }
HRESULT __attribute__((ms_abi)) UrlUnescapeA(LPSTR pszUrl, LPSTR pszUnescaped, DWORD* pcchUnescaped, DWORD dwFlags) { return UrlCanonicalizeA(pszUrl, pszUnescaped, pcchUnescaped, dwFlags); }

HRESULT __attribute__((ms_abi)) HashData(const uint8_t* pbData, uint32_t cbData, uint8_t* piet, uint32_t cbDest) {
    uint8_t acc = 0;
    uint32_t i;
    if (!piet || cbDest == 0) return E_INVALIDARG;
    for (i = 0; i < cbData; i++) acc ^= pbData[i];
    for (i = 0; i < cbDest; i++) piet[i] = (uint8_t)(acc ^ (uint8_t)i);
    return S_OK;
}

LONG __attribute__((ms_abi)) SHDeleteKeyW(HANDLE hKey, LPCWSTR pszSubKey) { (void)hKey; (void)pszSubKey; return 0; }
LONG __attribute__((ms_abi)) SHDeleteKeyA(HANDLE hKey, LPCSTR pszSubKey) { (void)hKey; (void)pszSubKey; return 0; }
LONG __attribute__((ms_abi)) SHDeleteValueW(HANDLE hKey, LPCWSTR pszSubKey, LPCWSTR pszValue) { (void)hKey; (void)pszSubKey; (void)pszValue; return 0; }
LONG __attribute__((ms_abi)) SHDeleteValueA(HANDLE hKey, LPCSTR pszSubKey, LPCSTR pszValue) { (void)hKey; (void)pszSubKey; (void)pszValue; return 0; }
LONG __attribute__((ms_abi)) SHRegGetValueW(HANDLE hKey, LPCWSTR pszSubKey, LPCWSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData) { (void)hKey; (void)pszSubKey; (void)pszValue; (void)pdwType; (void)pvData; (void)pcbData; return 1; }
LONG __attribute__((ms_abi)) SHRegGetValueA(HANDLE hKey, LPCSTR pszSubKey, LPCSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData) { (void)hKey; (void)pszSubKey; (void)pszValue; (void)pdwType; (void)pvData; (void)pcbData; return 1; }
HRESULT __attribute__((ms_abi)) SHRegCreateUSKeyW(LPCWSTR pszPath, DWORD samDesired, HANDLE hRelativeUSKey, HANDLE* phNewUSKey, DWORD dwFlags) { (void)pszPath; (void)samDesired; (void)hRelativeUSKey; (void)dwFlags; if (phNewUSKey) *phNewUSKey = NULL; return S_OK; }
HRESULT __attribute__((ms_abi)) SHRegCreateUSKeyA(LPCSTR pszPath, DWORD samDesired, HANDLE hRelativeUSKey, HANDLE* phNewUSKey, DWORD dwFlags) { (void)pszPath; (void)samDesired; (void)hRelativeUSKey; (void)dwFlags; if (phNewUSKey) *phNewUSKey = NULL; return S_OK; }
HRESULT __attribute__((ms_abi)) SHRegSetUSValueW(LPCWSTR pszSubKey, LPCWSTR pszValue, DWORD dwType, const void* pvData, DWORD cbData, DWORD dwFlags) { (void)pszSubKey; (void)pszValue; (void)dwType; (void)pvData; (void)cbData; (void)dwFlags; return S_OK; }
HRESULT __attribute__((ms_abi)) SHRegSetUSValueA(LPCSTR pszSubKey, LPCSTR pszValue, DWORD dwType, const void* pvData, DWORD cbData, DWORD dwFlags) { (void)pszSubKey; (void)pszValue; (void)dwType; (void)pvData; (void)cbData; (void)dwFlags; return S_OK; }
HRESULT __attribute__((ms_abi)) SHRegQueryUSValueW(LPCWSTR pszSubKey, LPCWSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData, BOOL fIgnoreHKCU, void* pvDefaultData, DWORD dwDefaultDataSize) { (void)pszSubKey; (void)pszValue; (void)pdwType; (void)pvData; (void)pcbData; (void)fIgnoreHKCU; (void)pvDefaultData; (void)dwDefaultDataSize; return S_OK; }
HRESULT __attribute__((ms_abi)) SHRegQueryUSValueA(LPCSTR pszSubKey, LPCSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData, BOOL fIgnoreHKCU, void* pvDefaultData, DWORD dwDefaultDataSize) { (void)pszSubKey; (void)pszValue; (void)pdwType; (void)pvData; (void)pcbData; (void)fIgnoreHKCU; (void)pvDefaultData; (void)dwDefaultDataSize; return S_OK; }
LONG __attribute__((ms_abi)) SHRegCloseUSKey(void* hUSKey) { (void)hUSKey; return 0; }
LONG __attribute__((ms_abi)) SHSetValueW(HANDLE hKey, LPCWSTR pszSubKey, LPCWSTR pszValue, DWORD dwType, const void* pvData, DWORD cbData) { (void)hKey; (void)pszSubKey; (void)pszValue; (void)dwType; (void)pvData; (void)cbData; return 0; }
LONG __attribute__((ms_abi)) SHSetValueA(HANDLE hKey, LPCSTR pszSubKey, LPCSTR pszValue, DWORD dwType, const void* pvData, DWORD cbData) { (void)hKey; (void)pszSubKey; (void)pszValue; (void)dwType; (void)pvData; (void)cbData; return 0; }
LONG __attribute__((ms_abi)) SHGetValueW(HANDLE hKey, LPCWSTR pszSubKey, LPCWSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData) { (void)hKey; (void)pszSubKey; (void)pszValue; (void)pdwType; (void)pvData; (void)pcbData; return 1; }
LONG __attribute__((ms_abi)) SHGetValueA(HANDLE hKey, LPCSTR pszSubKey, LPCSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData) { (void)hKey; (void)pszSubKey; (void)pszValue; (void)pdwType; (void)pvData; (void)pcbData; return 1; }
HRESULT __attribute__((ms_abi)) AssocQueryStringW(DWORD flags, DWORD str, LPCWSTR pszAssoc, LPCWSTR pszExtra, LPWSTR pszOut, DWORD* pcchOut) { (void)flags; (void)str; (void)pszAssoc; (void)pszExtra; (void)pszOut; (void)pcchOut; return S_FALSE; }
HRESULT __attribute__((ms_abi)) AssocQueryStringA(DWORD flags, DWORD str, LPCSTR pszAssoc, LPCSTR pszExtra, LPSTR pszOut, DWORD* pcchOut) { (void)flags; (void)str; (void)pszAssoc; (void)pszExtra; (void)pszOut; (void)pcchOut; return S_FALSE; }
HRESULT __attribute__((ms_abi)) AssocCreate(DWORD clsid, DWORD riid, void** ppv) { (void)clsid; (void)riid; if (ppv) *ppv = NULL; return E_NOTIMPL; }
HRESULT __attribute__((ms_abi)) StrRetToStrW(const void* pstr, const void* pidl, LPWSTR* ppszName) { (void)pstr; (void)pidl; if (ppszName) *ppszName = utf8_to_u16_dup(""); return S_OK; }
HRESULT __attribute__((ms_abi)) StrRetToStrA(const void* pstr, const void* pidl, LPSTR* ppszName) { (void)pstr; (void)pidl; if (ppszName) *ppszName = dup_narrow(""); return S_OK; }

#define MAP(fn) {"shlwapi.dll", #fn, (void*)fn}

const win32_api_mapping_t win32_api_shlwapi_mappings[] = {
    MAP(PathCombineW), MAP(PathCombineA),
    MAP(PathFileExistsW), MAP(PathFileExistsA),
    MAP(PathFindFileNameW), MAP(PathFindFileNameA),
    MAP(PathFindExtensionW), MAP(PathFindExtensionA),
    MAP(PathStripPathW), MAP(PathStripPathA),
    MAP(PathRemoveFileSpecW), MAP(PathRemoveFileSpecA),
    MAP(PathAddExtensionW), MAP(PathAddExtensionA),
    MAP(PathRemoveExtensionW), MAP(PathRemoveExtensionA),
    MAP(PathGetDriveNumberW), MAP(PathGetDriveNumberA),
    MAP(PathIsRelativeW), MAP(PathIsRelativeA),
    MAP(PathIsRootW), MAP(PathIsRootA),
    MAP(PathIsDirectoryW), MAP(PathIsDirectoryA),
    MAP(PathIsFileSpecW), MAP(PathIsFileSpecA),
    MAP(PathIsUNCW), MAP(PathIsUNCA),
    MAP(PathCanonicalizeW), MAP(PathCanonicalizeA),
    MAP(PathQuoteSpacesW), MAP(PathQuoteSpacesA),
    MAP(PathUnquoteSpacesW), MAP(PathUnquoteSpacesA),
    MAP(PathGetArgsW), MAP(PathGetArgsA),
    MAP(PathSkipRootW), MAP(PathSkipRootA),
    MAP(PathRenameExtensionW), MAP(PathRenameExtensionA),
    MAP(PathAppendW), MAP(PathAppendA),
    MAP(PathBuildRootW), MAP(PathBuildRootA),
    MAP(PathCompactW), MAP(PathCompactA),
    MAP(PathCompactPathExW), MAP(PathCompactPathExA),
    MAP(PathMatchSpecW), MAP(PathMatchSpecA),
    MAP(PathMakeAbsoluteW), MAP(PathMakeAbsoluteA),
    MAP(PathSetDlgItemPathW), MAP(PathSetDlgItemPathA),
    MAP(StrStrIA), MAP(StrStrIW), MAP(StrStrW), MAP(StrStrA),
    MAP(StrCmpIA), MAP(StrCmpIW), MAP(StrCmpNIA), MAP(StrCmpNIW),
    MAP(StrCmpW), MAP(StrCmpA), MAP(StrCmpNW), MAP(StrCmpNA),
    MAP(StrCatW), MAP(StrCatA), MAP(StrCpyW), MAP(StrCpyA),
    MAP(StrCpyNW), MAP(StrCpyNA), MAP(StrCatBuffW), MAP(StrCatBuffA),
    MAP(StrFormatByteSizeW), MAP(StrFormatByteSizeA),
    MAP(StrToIntW), MAP(StrToIntA), MAP(StrToInt64ExW), MAP(StrToInt64ExA),
    MAP(StrTrimW), MAP(StrTrimA), MAP(StrToIntExW), MAP(StrToIntExA),
    MAP(StrDupA), MAP(StrDupW), MAP(StrSpnA), MAP(StrSpnW),
    MAP(StrCSpnA), MAP(StrCSpnW), MAP(StrCSpnIA), MAP(StrCSpnIW),
    MAP(StrRChrA), MAP(StrRChrW), MAP(StrChrA), MAP(StrChrW),
    MAP(StrChrIA), MAP(StrChrIW), MAP(StrPBrkA), MAP(StrPBrkW),
    MAP(UrlCombineW), MAP(UrlCombineA), MAP(UrlCreateFromPathW), MAP(UrlCreateFromPathA),
    MAP(UrlGetPartW), MAP(UrlGetPartA), MAP(UrlIsW), MAP(UrlIsA),
    MAP(UrlCanonicalizeW), MAP(UrlCanonicalizeA), MAP(UrlEscapeW), MAP(UrlEscapeA),
    MAP(UrlUnescapeW), MAP(UrlUnescapeA), MAP(HashData),
    MAP(SHDeleteKeyW), MAP(SHDeleteKeyA), MAP(SHDeleteValueW), MAP(SHDeleteValueA),
    MAP(SHRegGetValueW), MAP(SHRegGetValueA), MAP(SHRegCreateUSKeyW), MAP(SHRegCreateUSKeyA),
    MAP(SHRegSetUSValueW), MAP(SHRegSetUSValueA), MAP(SHRegQueryUSValueW), MAP(SHRegQueryUSValueA),
    MAP(SHRegCloseUSKey), MAP(SHSetValueW), MAP(SHSetValueA), MAP(SHGetValueW), MAP(SHGetValueA),
    MAP(AssocQueryStringW), MAP(AssocQueryStringA), MAP(AssocCreate), MAP(StrRetToStrW), MAP(StrRetToStrA),
    {NULL, NULL, NULL}
};

const size_t win32_api_shlwapi_mappings_count =
    (sizeof(win32_api_shlwapi_mappings) / sizeof(win32_api_shlwapi_mappings[0])) - 1;
