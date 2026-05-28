#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>
#include <time.h>
#include <arpa/inet.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"

/* Forward declaration for SetLastError in win32_api.c */
extern void __attribute__((ms_abi)) lsw_SetLastError(uint32_t code);

/* ---- UTF-16LE → UTF-8 path conversion ---- */
static void vi_u16_to_u8(const uint16_t *src, char *dst, int maxbytes) {
    int n = 0;
    for (; *src && n < maxbytes - 4; src++) {
        uint32_t c = *src;
        if (c < 0x80) {
            dst[n++] = (char)c;
        } else if (c < 0x800) {
            dst[n++] = (char)(0xC0 | (c >> 6));
            dst[n++] = (char)(0x80 | (c & 0x3F));
        } else {
            dst[n++] = (char)(0xE0 | (c >> 12));
            dst[n++] = (char)(0x80 | ((c >> 6) & 0x3F));
            dst[n++] = (char)(0x80 | (c & 0x3F));
        }
    }
    dst[n] = '\0';
}

/* ---- Little-endian helpers for PE/version-info parsing ---- */
static uint16_t vi_r16(const uint8_t *p, uint32_t off) {
    return (uint16_t)(p[off] | ((uint16_t)p[off + 1] << 8));
}
static uint32_t vi_r32(const uint8_t *p, uint32_t off) {
    return (uint32_t)(p[off] | ((uint32_t)p[off+1]<<8) |
                     ((uint32_t)p[off+2]<<16) | ((uint32_t)p[off+3]<<24));
}

/* ---- PE .rsrc RT_VERSION reader ---- */

/* Read the RT_VERSION resource from a PE file.
 * Returns a malloc'd copy of the VS_VERSION_INFO data on success.
 * Sets *out_size to the data length.
 * Returns NULL on failure (file not found, no resource, etc.). */
static uint8_t *pe_read_version_resource(const char *path, uint32_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz <= 0 || fsz > 64 * 1024 * 1024) { fclose(f); return NULL; }

    uint8_t *raw = (uint8_t *)malloc((size_t)fsz);
    if (!raw) { fclose(f); return NULL; }
    if ((long)fread(raw, 1, (size_t)fsz, f) != fsz) { free(raw); fclose(f); return NULL; }
    fclose(f);

#define PE_SAFE(x) do { if ((uint32_t)(x) > (uint32_t)fsz) goto pe_fail; } while(0)

    PE_SAFE(0x40);
    if (vi_r16(raw, 0) != 0x5A4D) goto pe_fail; /* MZ */
    uint32_t pe_off = vi_r32(raw, 0x3C);
    PE_SAFE(pe_off + 4 + 20 + 2); /* at least coff header */
    if (vi_r32(raw, pe_off) != 0x00004550) goto pe_fail; /* PE\0\0 */

    uint16_t nsections = vi_r16(raw, pe_off + 6);
    uint16_t opt_size  = vi_r16(raw, pe_off + 20);
    uint32_t opt_off   = pe_off + 4 + 20; /* optional header start */
    PE_SAFE(opt_off + 2);

    uint16_t magic = vi_r16(raw, opt_off);
    uint32_t rsrc_dd_off;
    if      (magic == 0x020B) rsrc_dd_off = opt_off + 128; /* PE32+: DataDir[2] at +128 */
    else if (magic == 0x010B) rsrc_dd_off = opt_off + 112; /* PE32:  DataDir[2] at +112 */
    else goto pe_fail;

    PE_SAFE(rsrc_dd_off + 8);
    uint32_t rsrc_rva  = vi_r32(raw, rsrc_dd_off);
    uint32_t rsrc_sz   = vi_r32(raw, rsrc_dd_off + 4);
    if (!rsrc_rva || !rsrc_sz) goto pe_fail;

    /* Locate section containing rsrc_rva */
    uint32_t sec_tbl = opt_off + opt_size;
    uint32_t rsrc_raw_off = 0;
    for (uint16_t i = 0; i < nsections; i++) {
        uint32_t s = sec_tbl + (uint32_t)i * 40;
        PE_SAFE(s + 40);
        uint32_t s_vaddr = vi_r32(raw, s + 12);
        uint32_t s_vsz   = vi_r32(raw, s + 16);
        uint32_t s_raw   = vi_r32(raw, s + 20);
        if (rsrc_rva >= s_vaddr && rsrc_rva < s_vaddr + s_vsz) {
            rsrc_raw_off = s_raw + (rsrc_rva - s_vaddr);
            break;
        }
    }
    if (!rsrc_raw_off) goto pe_fail;
    PE_SAFE(rsrc_raw_off + rsrc_sz);

    uint8_t *rsrc = raw + rsrc_raw_off;

    /* Level 1: root directory — find type 16 (RT_VERSION) subdir */
    uint16_t n_named = vi_r16(rsrc, 12);
    uint16_t n_id    = vi_r16(rsrc, 14);
    uint32_t type_dir = 0;
    for (uint16_t i = n_named; i < (uint16_t)(n_named + n_id); i++) {
        uint32_t e = 16 + (uint32_t)i * 8;
        PE_SAFE(rsrc_raw_off + e + 8);
        uint32_t eid = vi_r32(rsrc, e) & 0x7FFFFFFFu;
        uint32_t eval = vi_r32(rsrc, e + 4);
        if (eid == 16 && (eval & 0x80000000u)) {
            type_dir = eval & 0x7FFFFFFFu;
            break;
        }
    }
    if (!type_dir) goto pe_fail;

    /* Level 2: name directory — take first entry (subdir) */
    PE_SAFE(rsrc_raw_off + type_dir + 16 + 8);
    uint32_t name_entry = type_dir + 16;
    uint32_t v2 = vi_r32(rsrc, name_entry + 4);
    if (!(v2 & 0x80000000u)) goto pe_fail;
    uint32_t lang_dir = v2 & 0x7FFFFFFFu;

    /* Level 3: language directory — take first entry (data leaf) */
    PE_SAFE(rsrc_raw_off + lang_dir + 16 + 8);
    uint32_t lang_entry = lang_dir + 16;
    uint32_t v3 = vi_r32(rsrc, lang_entry + 4);
    if (v3 & 0x80000000u) goto pe_fail; /* must be leaf */

    /* IMAGE_RESOURCE_DATA_ENTRY: RVA, Size, CodePage, Reserved */
    PE_SAFE(rsrc_raw_off + v3 + 16);
    uint32_t data_rva  = vi_r32(rsrc, v3);
    uint32_t data_size = vi_r32(rsrc, v3 + 4);
    if (!data_size) goto pe_fail;

    /* Convert data_rva to raw file offset */
    uint32_t data_raw = 0;
    for (uint16_t i = 0; i < nsections; i++) {
        uint32_t s = sec_tbl + (uint32_t)i * 40;
        uint32_t sv = vi_r32(raw, s + 12);
        uint32_t ss = vi_r32(raw, s + 16);
        uint32_t sr = vi_r32(raw, s + 20);
        if (data_rva >= sv && data_rva < sv + ss) {
            data_raw = sr + (data_rva - sv);
            break;
        }
    }
    if (!data_raw) goto pe_fail;
    PE_SAFE(data_raw + data_size);

    uint8_t *result = (uint8_t *)malloc(data_size);
    if (!result) goto pe_fail;
    memcpy(result, raw + data_raw, data_size);
    *out_size = data_size;
    free(raw);
    return result;

pe_fail:
    free(raw);
    return NULL;
#undef PE_SAFE
}

/* ---- Single-slot version info cache ---- */
static struct {
    char    path[512];
    uint8_t *data;
    uint32_t size;
} s_vi_cache;

/* Ensure cache is populated for the given path. Returns 1 on success, 0 on failure. */
static int vi_ensure_cached(const char *path) {
    if (s_vi_cache.data && strcmp(s_vi_cache.path, path) == 0)
        return 1;
    uint32_t sz = 0;
    uint8_t *d = pe_read_version_resource(path, &sz);
    if (!d) return 0;
    free(s_vi_cache.data);
    strncpy(s_vi_cache.path, path, sizeof(s_vi_cache.path) - 1);
    s_vi_cache.path[sizeof(s_vi_cache.path) - 1] = '\0';
    s_vi_cache.data = d;
    s_vi_cache.size = sz;
    return 1;
}

/* ---- VS_VERSION_INFO block navigator ---- */

/* Find a child block by UTF-16LE name inside a VS_VERSION_INFO block.
 * block/block_size: the parent block
 * name: null-terminated UTF-16LE name to search for (case-insensitive)
 * Returns pointer to child block on success, sets *child_len, else NULL. */
static const uint8_t *vi_find_child(const uint8_t *block, uint32_t block_size,
                                     const uint16_t *name, uint32_t *child_len) {
    if (block_size < 6) return NULL;
    uint16_t wLen = vi_r16(block, 0);
    if (wLen > block_size) wLen = (uint16_t)block_size;

    uint16_t wValLen = vi_r16(block, 2);

    /* Skip header (6 bytes) + key string (null-terminated UTF-16LE) + DWORD padding */
    uint32_t off = 6;
    while (off + 2 <= wLen && vi_r16(block, off) != 0) off += 2;
    off += 2; /* null terminator */
    off = (off + 3) & ~3u; /* align to DWORD */

    /* Skip binary value (if any) + DWORD padding */
    if (wValLen > 0) {
        off += wValLen;
        off = (off + 3) & ~3u;
    }

    /* Iterate child blocks */
    while (off + 6 <= wLen) {
        uint16_t cLen = vi_r16(block, off);
        if (cLen < 6 || off + cLen > wLen) break;

        /* Compare child key name (case-insensitive UTF-16LE) */
        uint32_t key_off = off + 6;
        const uint16_t *n = name;
        int match = 1;
        for (;;) {
            if (key_off + 2 > off + cLen) { match = 0; break; }
            uint16_t c1 = vi_r16(block, key_off);
            uint16_t c2 = *n;
            uint16_t u1 = (c1 >= 'a' && c1 <= 'z') ? (uint16_t)(c1 - 32) : c1;
            uint16_t u2 = (c2 >= 'a' && c2 <= 'z') ? (uint16_t)(c2 - 32) : c2;
            if (u1 != u2) { match = 0; break; }
            if (c1 == 0) break; /* both null-terminated → matched */
            key_off += 2;
            n++;
        }
        if (match) {
            *child_len = cLen;
            return block + off;
        }
        /* Advance to next child, DWORD-aligned */
        uint32_t next = off + cLen;
        off = (next + 3) & ~3u;
    }
    return NULL;
}

typedef int BOOL;
typedef uint32_t DWORD;
typedef void* HANDLE;
typedef void* HWND;
typedef void* HINSTANCE;
typedef void* HIMAGELIST;
typedef void* HICON;
typedef void* HBITMAP;
typedef int32_t HRESULT;
#define TRUE 1
#define FALSE 0
#define S_OK 0
#define E_NOTIMPL ((int32_t)0x80004001)
#define E_INVALIDARG ((int32_t)0x80070057)
#define E_OUTOFMEMORY ((int32_t)0x8007000E)

#define LSW_MSABI __attribute__((ms_abi))
#define MAP(dll, name, fn) {dll, name, (void*)fn}

void* LSW_MSABI lsw_OpenThemeData(void* hwnd, const uint16_t* pszClassList) {
    (void)hwnd; (void)pszClassList;
    return (void*)0x8001;
}

void* LSW_MSABI lsw_OpenThemeDataEx(void* hwnd, const uint16_t* pszClassIdList, uint32_t dwFlags) {
    (void)hwnd; (void)pszClassIdList; (void)dwFlags;
    return (void*)0x8001;
}

int32_t LSW_MSABI lsw_CloseThemeData(void* hTheme) { (void)hTheme; return S_OK; }
int32_t LSW_MSABI lsw_DrawThemeBackground(void* hTheme, void* hdc, int iPartId, int iStateId, const void* pRect, const void* pClipRect) { (void)hTheme; (void)hdc; (void)iPartId; (void)iStateId; (void)pRect; (void)pClipRect; return S_OK; }
int32_t LSW_MSABI lsw_DrawThemeBackgroundEx(void* hTheme, void* hdc, int iPartId, int iStateId, const void* pRect, const void* pOptions) { (void)hTheme; (void)hdc; (void)iPartId; (void)iStateId; (void)pRect; (void)pOptions; return S_OK; }
int32_t LSW_MSABI lsw_DrawThemeText(void* hTheme, void* hdc, int iPartId, int iStateId, const uint16_t* pszText, int cchText, uint32_t dwTextFlags, uint32_t dwTextFlags2, const void* pRect) { (void)hTheme; (void)hdc; (void)iPartId; (void)iStateId; (void)pszText; (void)cchText; (void)dwTextFlags; (void)dwTextFlags2; (void)pRect; return S_OK; }
int32_t LSW_MSABI lsw_DrawThemeTextEx(void* hTheme, void* hdc, int iPartId, int iStateId, const uint16_t* pszText, int iCharCount, uint32_t dwFlags, void* pRect, const void* pOptions) { (void)hTheme; (void)hdc; (void)iPartId; (void)iStateId; (void)pszText; (void)iCharCount; (void)dwFlags; (void)pRect; (void)pOptions; return S_OK; }
int32_t LSW_MSABI lsw_GetThemeColor(void* hTheme, int iPartId, int iStateId, int iPropId, uint32_t* pColor) { (void)hTheme; (void)iPartId; (void)iStateId; (void)iPropId; if (pColor) *pColor = 0xFFFFFFu; return S_OK; }
uint32_t LSW_MSABI lsw_GetThemeSysColor(void* hTheme, int iColorId) { (void)hTheme; (void)iColorId; return 0xFFFFFFu; }
void* LSW_MSABI lsw_GetThemeSysColorBrush(void* hTheme, int iColorId) { (void)hTheme; (void)iColorId; return NULL; }
int32_t LSW_MSABI lsw_GetThemeSysFont(void* hTheme, int iFontId, void* plf) { (void)hTheme; (void)iFontId; (void)plf; return S_OK; }
int LSW_MSABI lsw_GetThemeSysSize(void* hTheme, int iSizeId) { (void)hTheme; (void)iSizeId; return 16; }
int LSW_MSABI lsw_GetThemeSysBool(void* hTheme, int iBoolId) { (void)hTheme; (void)iBoolId; return 1; }
int32_t LSW_MSABI lsw_GetThemeSysString(void* hTheme, int iStringId, uint16_t* pszStringBuff, int cchMaxStringChars) { (void)hTheme; (void)iStringId; if (pszStringBuff && cchMaxStringChars > 0) pszStringBuff[0] = 0; return S_OK; }
int32_t LSW_MSABI lsw_GetThemePartSize(void* hTheme, void* hdc, int iPartId, int iStateId, const void* prc, int eSize, void* psz) { (void)hTheme; (void)hdc; (void)iPartId; (void)iStateId; (void)prc; (void)eSize; (void)psz; return S_OK; }
int32_t LSW_MSABI lsw_GetThemePosition(void* hTheme, int iPartId, int iStateId, int iPropId, void* pPoint) { (void)hTheme; (void)iPartId; (void)iStateId; (void)iPropId; (void)pPoint; return S_OK; }
int32_t LSW_MSABI lsw_GetThemeMargins(void* hTheme, void* hdc, int iPartId, int iStateId, int iPropId, const void* prc, void* pMargins) { (void)hTheme; (void)hdc; (void)iPartId; (void)iStateId; (void)iPropId; (void)prc; if (pMargins) memset(pMargins, 0, 16); return S_OK; }
int32_t LSW_MSABI lsw_GetThemeRect(void* hTheme, int iPartId, int iStateId, int iPropId, void* pRect) { (void)hTheme; (void)iPartId; (void)iStateId; (void)iPropId; (void)pRect; return S_OK; }
int32_t LSW_MSABI lsw_GetThemeMetric(void* hTheme, void* hdc, int iPartId, int iStateId, int iPropId, int* piVal) { (void)hTheme; (void)hdc; (void)iPartId; (void)iStateId; (void)iPropId; if (piVal) *piVal = 0; return S_OK; }
int LSW_MSABI lsw_IsThemeActive(void) { return 0; }
int LSW_MSABI lsw_IsAppThemed(void) { return 0; }
int LSW_MSABI lsw_IsCompositionActive(void) { return 0; }
int LSW_MSABI lsw_IsThemeBackgroundPartiallyTransparent(void* hTheme, int iPartId, int iStateId) { (void)hTheme; (void)iPartId; (void)iStateId; return 0; }
int LSW_MSABI lsw_IsThemePartDefined(void* hTheme, int iPartId, int iStateId) { (void)hTheme; (void)iPartId; (void)iStateId; return 0; }
int32_t LSW_MSABI lsw_EnableTheming(int fEnable) { (void)fEnable; return S_OK; }
int32_t LSW_MSABI lsw_SetWindowTheme(void* hwnd, const uint16_t* pszSubAppName, const uint16_t* pszSubIdList) { (void)hwnd; (void)pszSubAppName; (void)pszSubIdList; return S_OK; }
int32_t LSW_MSABI lsw_SetWindowThemeAttribute(void* hwnd, int eAttribute, void* pvAttribute, uint32_t cbAttribute) { (void)hwnd; (void)eAttribute; (void)pvAttribute; (void)cbAttribute; return S_OK; }
int32_t LSW_MSABI lsw_GetCurrentThemeName(uint16_t* pszThemeFileName, int cchMaxNameChars, uint16_t* pszColorBuff, int cchMaxColorChars, uint16_t* pszSizeBuff, int cchMaxSizeChars) { if (pszThemeFileName && cchMaxNameChars > 0) pszThemeFileName[0] = 0; if (pszColorBuff && cchMaxColorChars > 0) pszColorBuff[0] = 0; if (pszSizeBuff && cchMaxSizeChars > 0) pszSizeBuff[0] = 0; return S_OK; }
uint32_t LSW_MSABI lsw_GetThemeAppProperties(void) { return 0; }
void LSW_MSABI lsw_SetThemeAppProperties(uint32_t dwFlags) { (void)dwFlags; }
int32_t LSW_MSABI lsw_GetThemeDocumentationProperty(const uint16_t* pszThemeName, const uint16_t* pszPropertyName, uint16_t* pszValueBuff, int cchMaxValChars) { (void)pszThemeName; (void)pszPropertyName; if (pszValueBuff && cchMaxValChars > 0) pszValueBuff[0] = 0; return S_OK; }
int32_t LSW_MSABI lsw_DrawThemeParentBackground(void* hwnd, void* hdc, const void* prc) { (void)hwnd; (void)hdc; (void)prc; return S_OK; }
int32_t LSW_MSABI lsw_DrawThemeParentBackgroundEx(void* hwnd, void* hdc, uint32_t dwFlags, const void* prc) { (void)hwnd; (void)hdc; (void)dwFlags; (void)prc; return S_OK; }
int32_t LSW_MSABI lsw_BufferedPaintInit(void) { return S_OK; }
int32_t LSW_MSABI lsw_BufferedPaintUnInit(void) { return S_OK; }
void* LSW_MSABI lsw_BeginBufferedPaint(void* hdcTarget, const void* prcTarget, int dxbp, void* pPaintParams, void** phdc) { (void)prcTarget; (void)dxbp; (void)pPaintParams; if (phdc) *phdc = hdcTarget; return (void*)0x8002; }
int32_t LSW_MSABI lsw_EndBufferedPaint(void* hBufferedPaint, int fUpdateTarget) { (void)hBufferedPaint; (void)fUpdateTarget; return S_OK; }
int32_t LSW_MSABI lsw_BufferedPaintClear(void* hBufferedPaint, const void* prc) { (void)hBufferedPaint; (void)prc; return S_OK; }
void* LSW_MSABI lsw_GetBufferedPaintDC(void* hBufferedPaint) { (void)hBufferedPaint; return NULL; }
void* LSW_MSABI lsw_GetBufferedPaintTargetDC(void* hBufferedPaint) { (void)hBufferedPaint; return NULL; }
int32_t LSW_MSABI lsw_GetBufferedPaintTargetRect(void* hBufferedPaint, void* prc) { (void)hBufferedPaint; (void)prc; return S_OK; }

void* LSW_MSABI lsw_ImmGetContext(void* hWnd) { (void)hWnd; return NULL; }
int LSW_MSABI lsw_ImmReleaseContext(void* hWnd, void* hIMC) { (void)hWnd; (void)hIMC; return 1; }
int32_t LSW_MSABI lsw_ImmGetCompositionStringW(void* hIMC, uint32_t dwIndex, void* lpBuf, uint32_t dwBufLen) { (void)hIMC; (void)dwIndex; (void)lpBuf; (void)dwBufLen; return 0; }
int32_t LSW_MSABI lsw_ImmGetCompositionStringA(void* hIMC, uint32_t dwIndex, void* lpBuf, uint32_t dwBufLen) { (void)hIMC; (void)dwIndex; (void)lpBuf; (void)dwBufLen; return 0; }
int LSW_MSABI lsw_ImmSetCompositionWindow(void* hIMC, void* lpCompForm) { (void)hIMC; (void)lpCompForm; return 1; }
int LSW_MSABI lsw_ImmSetCompositionStringW(void* hIMC, uint32_t dwIndex, void* lpComp, uint32_t dwCompLen, void* lpRead, uint32_t dwReadLen) { (void)hIMC; (void)dwIndex; (void)lpComp; (void)dwCompLen; (void)lpRead; (void)dwReadLen; return 1; }
void* LSW_MSABI lsw_ImmAssociateContext(void* hWnd, void* hIMC) { (void)hWnd; (void)hIMC; return NULL; }
int LSW_MSABI lsw_ImmAssociateContextEx(void* hWnd, void* hIMC, uint32_t dwFlags) { (void)hWnd; (void)hIMC; (void)dwFlags; return 1; }
int LSW_MSABI lsw_ImmNotifyIME(void* hIMC, uint32_t dwAction, uint32_t dwIndex, uint32_t dwValue) { (void)hIMC; (void)dwAction; (void)dwIndex; (void)dwValue; return 1; }
int LSW_MSABI lsw_ImmSetOpenStatus(void* hIMC, int fOpen) { (void)hIMC; (void)fOpen; return 1; }
int LSW_MSABI lsw_ImmGetOpenStatus(void* hIMC) { (void)hIMC; return 0; }
void* LSW_MSABI lsw_ImmGetDefaultIMEWnd(void* hWnd) { (void)hWnd; return NULL; }
void* LSW_MSABI lsw_ImmCreateContext(void) { return (void*)0x9001; }
int LSW_MSABI lsw_ImmDestroyContext(void* hIMC) { (void)hIMC; return 1; }
int LSW_MSABI lsw_ImmGetCandidateWindow(void* hIMC, uint32_t dwIndex, void* lpCandidate) { (void)hIMC; (void)dwIndex; (void)lpCandidate; return 0; }
int LSW_MSABI lsw_ImmSetCandidateWindow(void* hIMC, void* lpCandidate) { (void)hIMC; (void)lpCandidate; return 1; }
int LSW_MSABI lsw_ImmGetConversionStatus(void* hIMC, uint32_t* lpfdwConversion, uint32_t* lpfdwSentence) { (void)hIMC; if (lpfdwConversion) *lpfdwConversion = 0; if (lpfdwSentence) *lpfdwSentence = 0; return 1; }
int LSW_MSABI lsw_ImmSetConversionStatus(void* hIMC, uint32_t fdwConversion, uint32_t fdwSentence) { (void)hIMC; (void)fdwConversion; (void)fdwSentence; return 1; }
int LSW_MSABI lsw_ImmConfigureIMEW(void* hKL, void* hWnd, uint32_t dwMode, void* lpData) { (void)hKL; (void)hWnd; (void)dwMode; (void)lpData; return 0; }
void* LSW_MSABI lsw_ImmInstallIMEW(const uint16_t* lpszIMEFileName, const uint16_t* lpszLayoutText) { (void)lpszIMEFileName; (void)lpszLayoutText; return NULL; }
int LSW_MSABI lsw_ImmIsIME(void* hKL) { (void)hKL; return 0; }
uint32_t LSW_MSABI lsw_ImmGetIMEFileNameW(void* hKL, uint16_t* lpszFileName, uint32_t uBufLen) { (void)hKL; if (lpszFileName && uBufLen > 0) lpszFileName[0] = 0; return 0; }
uint32_t LSW_MSABI lsw_ImmGetVirtualKey(void* hWnd) { (void)hWnd; return 0; }
int LSW_MSABI lsw_ImmRegisterWordW(void* hKL, const uint16_t* lpszReading, uint32_t dwStyle, const uint16_t* lpszRegister) { (void)hKL; (void)lpszReading; (void)dwStyle; (void)lpszRegister; return 0; }
uint32_t LSW_MSABI lsw_ImmEnumRegisterWordW(void* hKL, void* lpfnEnumProc, const uint16_t* lpszReading, uint32_t dwStyle, const uint16_t* lpszRegister, void* lpData) { (void)hKL; (void)lpfnEnumProc; (void)lpszReading; (void)dwStyle; (void)lpszRegister; (void)lpData; return 0; }
uint32_t LSW_MSABI lsw_ImmGetRegisterWordStyleW(void* hKL, uint32_t nItem, void* lpStyleBuf) { (void)hKL; (void)nItem; (void)lpStyleBuf; return 0; }

/* ---- VERSION.dll implementation ---- */

uint32_t LSW_MSABI lsw_GetFileVersionInfoSizeExW(uint32_t dwFlags,
                                                   const uint16_t *lpwstrFilename,
                                                   uint32_t *lpdwHandle) {
    (void)dwFlags;
    if (lpdwHandle) *lpdwHandle = 0;
    if (!lpwstrFilename) { lsw_SetLastError(87); return 0; }

    char path[512];
    vi_u16_to_u8(lpwstrFilename, path, sizeof(path));

    if (!vi_ensure_cached(path)) {
        /* ERROR_RESOURCE_TYPE_NOT_FOUND = 1813 */
        lsw_SetLastError(1813);
        LSW_LOG_INFO("GetFileVersionInfoSizeExW(%s) -> 0 (resource not found)", path);
        return 0;
    }
    LSW_LOG_INFO("GetFileVersionInfoSizeExW(%s) -> %u", path, s_vi_cache.size);
    return s_vi_cache.size;
}

uint32_t LSW_MSABI lsw_GetFileVersionInfoSizeW(const uint16_t *lptstrFilename,
                                                uint32_t *lpdwHandle) {
    return lsw_GetFileVersionInfoSizeExW(0, lptstrFilename, lpdwHandle);
}

uint32_t LSW_MSABI lsw_GetFileVersionInfoSizeA(const char *lptstrFilename,
                                                uint32_t *lpdwHandle) {
    (void)lptstrFilename;
    if (lpdwHandle) *lpdwHandle = 0;
    lsw_SetLastError(1813);
    return 0;
}

int LSW_MSABI lsw_GetFileVersionInfoExW(uint32_t dwFlags,
                                         const uint16_t *lpwstrFilename,
                                         uint32_t dwHandle, uint32_t dwLen,
                                         void *lpData) {
    (void)dwFlags; (void)dwHandle;
    if (!lpwstrFilename || !lpData || !dwLen) { lsw_SetLastError(87); return 0; }

    char path[512];
    vi_u16_to_u8(lpwstrFilename, path, sizeof(path));

    if (!vi_ensure_cached(path)) { lsw_SetLastError(1813); return 0; }

    uint32_t copy = (dwLen < s_vi_cache.size) ? dwLen : s_vi_cache.size;
    memcpy(lpData, s_vi_cache.data, copy);
    LSW_LOG_INFO("GetFileVersionInfoExW(%s, len=%u) -> 1", path, dwLen);
    return 1;
}

int LSW_MSABI lsw_GetFileVersionInfoW(const uint16_t *lptstrFilename,
                                       uint32_t dwHandle, uint32_t dwLen,
                                       void *lpData) {
    return lsw_GetFileVersionInfoExW(0, lptstrFilename, dwHandle, dwLen, lpData);
}

int LSW_MSABI lsw_GetFileVersionInfoA(const char *lptstrFilename,
                                       uint32_t dwHandle, uint32_t dwLen,
                                       void *lpData) {
    (void)lptstrFilename; (void)dwHandle; (void)dwLen; (void)lpData;
    lsw_SetLastError(1813);
    return 0;
}

int LSW_MSABI lsw_VerQueryValueW(const void *pBlock, const uint16_t *lpSubBlock,
                                  void **lplpBuffer, uint32_t *puLen) {
    if (!pBlock || !lpSubBlock || !lplpBuffer || !puLen) return 0;
    *lplpBuffer = NULL;
    *puLen = 0;

    /* Log sub-block query for debugging */
    {
        char sub_utf8[256];
        vi_u16_to_u8(lpSubBlock, sub_utf8, sizeof(sub_utf8));
        LSW_LOG_INFO("VerQueryValueW(sub='%s')", sub_utf8);
    }

    const uint8_t *b = (const uint8_t *)pBlock;
    uint16_t wLen = vi_r16(b, 0);
    const uint16_t *sub = lpSubBlock;

    if (sub[0] != (uint16_t)'\\') return 0;
    sub++;

    if (sub[0] == 0) {
        /* Root query "\\" → return VS_FIXEDFILEINFO */
        uint16_t wValLen = vi_r16(b, 2);
        if (wValLen == 0) return 0;
        uint32_t off = 6;
        while (off + 2 <= wLen && vi_r16(b, off) != 0) off += 2;
        off += 2;
        off = (off + 3) & ~3u;
        if (off + wValLen > wLen) return 0;
        *lplpBuffer = (void *)(b + off);
        *puLen = wValLen;
        return 1;
    }

    /* Walk the path components: e.g. "VarFileInfo\Translation" */
    const uint8_t *cur = b;
    uint32_t cur_sz = wLen;

    while (sub[0] != 0) {
        /* Extract component name up to next '\\' or end */
        uint16_t comp[128];
        int clen = 0;
        while (sub[clen] != 0 && sub[clen] != (uint16_t)'\\' && clen < 127) {
            comp[clen] = sub[clen];
            clen++;
        }
        comp[clen] = 0;

        uint32_t child_len = 0;
        const uint8_t *child = vi_find_child(cur, cur_sz, comp, &child_len);
        if (!child) return 0;

        sub += clen;
        if (sub[0] == (uint16_t)'\\') sub++;

        if (sub[0] == 0) {
            /* Reached the target block — return its value or block itself */
            uint16_t child_val_len = vi_r16(child, 2);
            if (child_val_len > 0) {
                /* Navigate to value within child */
                uint32_t off = 6;
                uint32_t cl = child_len;
                while (off + 2 <= cl && vi_r16(child, off) != 0) off += 2;
                off += 2;
                off = (off + 3) & ~3u;
                if (off + child_val_len > cl) return 0;
                *lplpBuffer = (void *)(child + off);
                *puLen = child_val_len;
                {
                    const uint8_t *vp = (const uint8_t *)*lplpBuffer;
                    LSW_LOG_DEBUG("VerQueryValueW -> ptr=%p off_in_block=%u len=%u bytes=[%02x %02x %02x %02x %02x %02x %02x %02x]",
                        *lplpBuffer, (unsigned)(child + off - b),
                        child_val_len,
                        vp[0], vp[1],
                        child_val_len > 2 ? vp[2] : 0, child_val_len > 3 ? vp[3] : 0,
                        child_val_len > 4 ? vp[4] : 0, child_val_len > 5 ? vp[5] : 0,
                        child_val_len > 6 ? vp[6] : 0, child_val_len > 7 ? vp[7] : 0);
                }
            } else {
                *lplpBuffer = (void *)child;
                *puLen = child_len;
                LSW_LOG_INFO("VerQueryValueW -> block ptr=%p off=%u len=%u", *lplpBuffer, (unsigned)(child - b), child_len);
            }
            return 1;
        }
        cur    = child;
        cur_sz = child_len;
    }
    return 0;
}

int LSW_MSABI lsw_VerQueryValueA(const void *pBlock, const char *lpSubBlock,
                                  void **lplpBuffer, uint32_t *puLen) {
    (void)pBlock; (void)lpSubBlock;
    if (lplpBuffer) *lplpBuffer = NULL;
    if (puLen) *puLen = 0;
    return 0;
}
uint32_t LSW_MSABI lsw_VerFindFileW(uint32_t uFlags, const uint16_t* szFileName, const uint16_t* szWinDir, const uint16_t* szAppDir, uint16_t* szCurDir, uint32_t* lpuCurDirLen, uint16_t* szDestDir, uint32_t* lpuDestDirLen) { (void)uFlags; (void)szFileName; (void)szWinDir; (void)szAppDir; (void)szCurDir; (void)lpuCurDirLen; (void)szDestDir; (void)lpuDestDirLen; return 0; }
uint32_t LSW_MSABI lsw_VerInstallFileW(uint32_t uFlags, const uint16_t* szSrcFileName, const uint16_t* szDestFileName, const uint16_t* szSrcDir, const uint16_t* szDestDir, const uint16_t* szCurDir, uint16_t* szTmpFile, uint32_t* lpuTmpFileLen) { (void)uFlags; (void)szSrcFileName; (void)szDestFileName; (void)szSrcDir; (void)szDestDir; (void)szCurDir; (void)szTmpFile; (void)lpuTmpFileLen; return 0; }

uint32_t LSW_MSABI lsw_timeGetTime(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint32_t)(ts.tv_sec * 1000u + (uint32_t)(ts.tv_nsec / 1000000u));
}

uint32_t LSW_MSABI lsw_timeBeginPeriod(uint32_t uPeriod) { (void)uPeriod; return 0; }
uint32_t LSW_MSABI lsw_timeEndPeriod(uint32_t uPeriod) { (void)uPeriod; return 0; }
uint32_t LSW_MSABI lsw_timeGetDevCaps(void* ptc, uint32_t cbtc) { (void)ptc; (void)cbtc; return 0; }
uint32_t LSW_MSABI lsw_timeSetEvent(uint32_t uDelay, uint32_t uResolution, void* lpTimeProc, uint32_t dwUser, uint32_t fuEvent) { (void)uDelay; (void)uResolution; (void)lpTimeProc; (void)dwUser; (void)fuEvent; return 1; }
uint32_t LSW_MSABI lsw_timeKillEvent(uint32_t uTimerID) { (void)uTimerID; return 0; }
uint32_t LSW_MSABI lsw_waveOutOpen(void** phwo, uint32_t uDeviceID, void* pwfx, uint64_t dwCallback, uint64_t dwInstance, uint32_t fdwOpen) { (void)uDeviceID; (void)pwfx; (void)dwCallback; (void)dwInstance; (void)fdwOpen; if (phwo) *phwo = (void*)0xA001; return 0; }
uint32_t LSW_MSABI lsw_waveOutClose(void* hwo) { (void)hwo; return 0; }
uint32_t LSW_MSABI lsw_waveOutWrite(void* hwo, void* pwh, uint32_t cbwh) { (void)hwo; (void)pwh; (void)cbwh; return 0; }
uint32_t LSW_MSABI lsw_waveOutPrepareHeader(void* hwo, void* pwh, uint32_t cbwh) { (void)hwo; (void)pwh; (void)cbwh; return 0; }
uint32_t LSW_MSABI lsw_waveOutUnprepareHeader(void* hwo, void* pwh, uint32_t cbwh) { (void)hwo; (void)pwh; (void)cbwh; return 0; }
uint32_t LSW_MSABI lsw_waveOutGetNumDevs(void) { return 0; }
uint32_t LSW_MSABI lsw_waveOutGetDevCapsW(uint64_t uDeviceID, void* pwoc, uint32_t cbwoc) { (void)uDeviceID; (void)pwoc; (void)cbwoc; return 1; }
uint32_t LSW_MSABI lsw_waveOutGetVolume(void* hwo, uint32_t* pdwVolume) { (void)hwo; if (pdwVolume) *pdwVolume = 0xFFFFFFFFu; return 0; }
uint32_t LSW_MSABI lsw_waveOutSetVolume(void* hwo, uint32_t dwVolume) { (void)hwo; (void)dwVolume; return 0; }
uint32_t LSW_MSABI lsw_waveOutPause(void* hwo) { (void)hwo; return 0; }
uint32_t LSW_MSABI lsw_waveOutRestart(void* hwo) { (void)hwo; return 0; }
uint32_t LSW_MSABI lsw_waveOutReset(void* hwo) { (void)hwo; return 0; }
uint32_t LSW_MSABI lsw_waveOutGetPosition(void* hwo, void* pmmt, uint32_t cbmmt) { (void)hwo; (void)pmmt; (void)cbmmt; return 0; }
uint32_t LSW_MSABI lsw_mciSendStringW(const uint16_t* lpstrCommand, uint16_t* lpstrReturnString, uint32_t uReturnLength, void* hwndCallback) { (void)lpstrCommand; (void)lpstrReturnString; (void)uReturnLength; (void)hwndCallback; return 1; }
uint32_t LSW_MSABI lsw_mciSendStringA(const char* lpstrCommand, char* lpstrReturnString, uint32_t uReturnLength, void* hwndCallback) { (void)lpstrCommand; (void)lpstrReturnString; (void)uReturnLength; (void)hwndCallback; return 1; }
uint32_t LSW_MSABI lsw_mciSendCommandW(uint32_t mciId, uint32_t uMsg, uint64_t dwParam1, uint64_t dwParam2) { (void)mciId; (void)uMsg; (void)dwParam1; (void)dwParam2; return 1; }
uint32_t LSW_MSABI lsw_mixerGetNumDevs(void) { return 0; }
int LSW_MSABI lsw_PlaySoundW(const uint16_t* pszSound, void* hmod, uint32_t fdwSound) { (void)pszSound; (void)hmod; (void)fdwSound; return 0; }
int LSW_MSABI lsw_PlaySoundA(const char* pszSound, void* hmod, uint32_t fdwSound) { (void)pszSound; (void)hmod; (void)fdwSound; return 0; }
int LSW_MSABI lsw_sndPlaySoundW(const uint16_t* pszSound, uint32_t fuSound) { (void)pszSound; (void)fuSound; return 0; }
int LSW_MSABI lsw_sndPlaySoundA(const char* pszSound, uint32_t fuSound) { (void)pszSound; (void)fuSound; return 0; }
uint32_t LSW_MSABI lsw_joyGetNumDevs(void) { return 0; }
uint32_t LSW_MSABI lsw_joyGetPos(uint32_t uJoyID, void* pji) { (void)uJoyID; (void)pji; return 1; }
uint32_t LSW_MSABI lsw_joyGetPosEx(uint32_t uJoyID, void* pji) { (void)uJoyID; (void)pji; return 1; }
uint32_t LSW_MSABI lsw_joyGetDevCapsW(uint64_t uJoyID, void* pjc, uint32_t cbjc) { (void)uJoyID; (void)pjc; (void)cbjc; return 1; }

static void LSW_MSABI lsw_msvcp_noop(void) { }
static void* LSW_MSABI lsw_msvcp_nullptr(void) { return NULL; }
static int32_t __attribute__((unused)) LSW_MSABI lsw_msvcp_s_ok(void) { return 0; }

int LSW_MSABI lsw_GetProcessMemoryInfo(void* Process, void* ppsmemCounters, uint32_t cb) { (void)Process; if (ppsmemCounters) memset(ppsmemCounters, 0, cb); return 1; }
int LSW_MSABI lsw_EnumProcesses(uint32_t* pProcessIds, uint32_t cb, uint32_t* pBytesReturned) { (void)pProcessIds; (void)cb; if (pBytesReturned) *pBytesReturned = 0; return 1; }
int LSW_MSABI lsw_EnumProcessModules(void* hProcess, void** lphModule, uint32_t cb, uint32_t* lpcbNeeded) { (void)hProcess; (void)lphModule; (void)cb; if (lpcbNeeded) *lpcbNeeded = 0; return 1; }
uint32_t LSW_MSABI lsw_GetModuleBaseNameW(void* hProcess, void* hModule, uint16_t* lpBaseName, uint32_t nSize) { (void)hProcess; (void)hModule; if (lpBaseName && nSize > 0) lpBaseName[0] = 0; return 0; }
uint32_t LSW_MSABI lsw_GetModuleFileNameExW(void* hProcess, void* hModule, uint16_t* lpFilename, uint32_t nSize) { (void)hProcess; (void)hModule; if (lpFilename && nSize > 0) lpFilename[0] = 0; return 0; }

int LSW_MSABI lsw_GetUserProfileDirectoryW(void* hToken, uint16_t* lpProfileDir, uint32_t* lpcchSize) { (void)hToken; (void)lpProfileDir; (void)lpcchSize; return 0; }
int LSW_MSABI lsw_CreateEnvironmentBlock(void** lpEnvironment, void* hToken, int bInherit) { (void)hToken; (void)bInherit; if (lpEnvironment) *lpEnvironment = NULL; return 0; }
int LSW_MSABI lsw_DestroyEnvironmentBlock(void* lpEnvironment) { (void)lpEnvironment; return 1; }
int LSW_MSABI lsw_LoadUserProfileW(void* hToken, void* lpProfileInfo) { (void)hToken; (void)lpProfileInfo; return 0; }
int LSW_MSABI lsw_UnloadUserProfile(void* hToken, void* hProfile) { (void)hToken; (void)hProfile; return 1; }

void* LSW_MSABI lsw_WTSOpenServerW(uint16_t* pServerName) { (void)pServerName; return NULL; }
void LSW_MSABI lsw_WTSCloseServer(void* hServer) { (void)hServer; }
int LSW_MSABI lsw_WTSQuerySessionInformationW(void* hServer, uint32_t SessionId, int WTSInfoClass, uint16_t** ppBuffer, uint32_t* pBytesReturned) { (void)hServer; (void)SessionId; (void)WTSInfoClass; if (ppBuffer) *ppBuffer = NULL; if (pBytesReturned) *pBytesReturned = 0; return 0; }
void LSW_MSABI lsw_WTSFreeMemory(void* pMemory) { if (pMemory) free(pMemory); }
uint32_t LSW_MSABI lsw_WTSGetActiveConsoleSessionId(void) { return 0; }
int LSW_MSABI lsw_WTSSendMessageW(void* hServer, uint32_t SessionId, uint16_t* pTitle, uint32_t TitleLength, uint16_t* pMessage, uint32_t MessageLength, uint32_t Style, uint32_t Timeout, uint32_t* pResponse, int bWait) { (void)hServer; (void)SessionId; (void)pTitle; (void)TitleLength; (void)pMessage; (void)MessageLength; (void)Style; (void)Timeout; (void)bWait; if (pResponse) *pResponse = 0; return 0; }
int LSW_MSABI lsw_ProcessIdToSessionId(uint32_t dwProcessId, uint32_t* pSessionId) { (void)dwProcessId; if (pSessionId) *pSessionId = 0; return 1; }

uint32_t LSW_MSABI lsw_GetAdaptersInfo(void* pAdapterInfo, uint32_t* pOutBufLen) { (void)pAdapterInfo; if (pOutBufLen) *pOutBufLen = 0; return 111; }
/* GetAdaptersAddresses: forward to win32_api.c real implementation */
extern uint32_t __attribute__((ms_abi)) lsw_GetAdaptersAddresses_real(uint32_t Family, uint32_t Flags, void* Reserved, uint8_t* AdapterAddresses, uint32_t* SizePointer);
uint32_t LSW_MSABI lsw_GetAdaptersAddresses(uint32_t Family, uint32_t Flags, void* Reserved, void* AdapterAddresses, uint32_t* SizePointer) {
    return lsw_GetAdaptersAddresses_real(Family, Flags, Reserved, (uint8_t*)AdapterAddresses, SizePointer);
}

/* --- IPHLPAPI: interface conversion stubs --- */
static int lsw_misc_ascii_to_u16(const char* src, uint16_t* dst, int maxchars) {
    int n = 0;
    while (*src && n < maxchars - 1) dst[n++] = (uint16_t)(unsigned char)*src++;
    if (n < maxchars) dst[n] = 0;
    return n;
}
uint32_t LSW_MSABI lsw_ConvertLengthToIpv4Mask(uint32_t maskLen, uint32_t* mask) {
    if (maskLen > 32) { if (mask) *mask = 0xffffffff; return 87; }
    uint32_t m = maskLen == 0 ? 0 : (~0u << (32 - maskLen));
    if (mask) *mask = htonl(m);
    return 0;
}
uint32_t LSW_MSABI lsw_GetCurrentThreadCompartmentId(void) { return 0; }
uint32_t LSW_MSABI lsw_SetCurrentThreadCompartmentId(uint32_t id) { (void)id; return 0; }
uint32_t LSW_MSABI lsw_ConvertInterfaceIndexToLuid(uint32_t idx, void* luid) {
    if (luid) { memset(luid, 0, 8); *(uint32_t*)((uint8_t*)luid + 4) = idx; } return 0;
}
uint32_t LSW_MSABI lsw_ConvertInterfaceLuidToGuid(const void* luid, void* guid) {
    (void)luid; if (guid) memset(guid, 0, 16); return 0;
}
uint32_t LSW_MSABI lsw_ConvertInterfaceLuidToNameW(const void* luid, wchar_t* ifname, size_t len) {
    (void)luid;
    if (ifname && len > 0) lsw_misc_ascii_to_u16("eth0", (uint16_t*)ifname, (int)len);
    return 0;
}
uint32_t LSW_MSABI lsw_ConvertGuidToStringW(const void* guid, wchar_t* buf, uint32_t len) {
    (void)guid;
    if (buf && len > 0) lsw_misc_ascii_to_u16("{00000000-0000-0000-0000-000000000000}", (uint16_t*)buf, (int)len);
    return 0;
}
uint32_t LSW_MSABI lsw_GetInterfaceDnsSettings(void* adapter, void* settings) {
    (void)adapter; (void)settings; return 0;
}
void LSW_MSABI lsw_FreeInterfaceDnsSettings(void* settings) { (void)settings; }

/* --- NSI (Network Store Interface) stubs — Windows internal --- */
#define LSW_NSI_NOT_SUPPORTED 50
uint32_t LSW_MSABI lsw_NsiAllocateAndGetTable(uint32_t a, void* b, void* c, uint32_t d,
    void* e, uint32_t f, void* g, uint32_t h, void* i, uint32_t j, uint32_t* k, uint32_t l) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)l;
    if (k) *k = 0; return LSW_NSI_NOT_SUPPORTED;
}
uint32_t LSW_MSABI lsw_NsiFreeTable(void* a, void* b, void* c, void* d) { (void)a;(void)b;(void)c;(void)d; return 0; }
uint32_t LSW_MSABI lsw_NsiGetAllParameters(uint32_t a, void* b, uint32_t c, void* d,
    uint32_t e, void* f, uint32_t g, void* h, uint32_t i) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i; return LSW_NSI_NOT_SUPPORTED;
}
uint32_t LSW_MSABI lsw_NsiSetAllParameters(uint32_t a, uint32_t b, void* c, uint32_t d,
    void* e, uint32_t f, void* g, uint32_t h) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h; return LSW_NSI_NOT_SUPPORTED;
}

/* --- DNSAPI stubs --- */
void* LSW_MSABI lsw_DnsQueryConfigAllocEx(uint32_t cfg, uint32_t* sz, void* ctx) {
    (void)cfg; if (sz) *sz = 0; (void)ctx; return NULL;
}
void LSW_MSABI lsw_DnsFree(void* ptr, uint32_t type) { (void)ptr; (void)type; }
void* LSW_MSABI lsw_DnsGetCacheRecords(void) { return NULL; }
uint32_t LSW_MSABI lsw_DnsFlushResolverCache(void) { return 1; }
uint32_t LSW_MSABI lsw_DnsResolverOp(uint32_t a, void* b, void* c) {
    (void)a;(void)b;(void)c; return LSW_NSI_NOT_SUPPORTED;
}
void* LSW_MSABI lsw_DnsGetDdrInfo(void* a, uint32_t b, uint32_t* c) {
    (void)a;(void)b; if (c) *c = 0; return NULL;
}
void LSW_MSABI lsw_DnsFreeConfigStructure(void* p, uint32_t t) { (void)p;(void)t; }

/* --- DHCP stubs --- */
uint32_t LSW_MSABI lsw_DhcpAcquireParameters(void* a) { (void)a; return LSW_NSI_NOT_SUPPORTED; }
uint32_t LSW_MSABI lsw_DhcpReleaseParameters(void* a) { (void)a; return LSW_NSI_NOT_SUPPORTED; }
uint32_t LSW_MSABI lsw_DhcpHandlePnPEvent(uint32_t a, uint32_t b, void* c, uint32_t d, void* e) {
    (void)a;(void)b;(void)c;(void)d;(void)e; return LSW_NSI_NOT_SUPPORTED;
}
uint32_t LSW_MSABI lsw_DhcpEnumClasses(uint32_t a, uint32_t b, void* c) {
    (void)a;(void)b;(void)c; return LSW_NSI_NOT_SUPPORTED;
}
uint32_t LSW_MSABI lsw_Dhcpv6AcquireParameters(void* a, void* b, void* c) {
    (void)a;(void)b;(void)c; return LSW_NSI_NOT_SUPPORTED;
}
uint32_t LSW_MSABI lsw_Dhcpv6ReleaseParameters(void* a) { (void)a; return LSW_NSI_NOT_SUPPORTED; }
uint32_t LSW_MSABI lsw_Dhcpv6IsEnabled(uint32_t a) { (void)a; return 0; }
uint32_t LSW_MSABI lsw_Dhcpv6GetUserClasses(void* a, void* b) { (void)a;(void)b; return LSW_NSI_NOT_SUPPORTED; }
uint32_t LSW_MSABI lsw_Dhcpv6SetUserClass(void* a, void* b, void* c) { (void)a;(void)b;(void)c; return LSW_NSI_NOT_SUPPORTED; }
uint32_t LSW_MSABI lsw_GetIfTable(void* pIfTable, uint32_t* pdwSize, int bOrder) { (void)pIfTable; (void)bOrder; if (pdwSize) *pdwSize = 0; return 122; }
uint32_t LSW_MSABI lsw_GetIpAddrTable(void* pIpAddrTable, uint32_t* pdwSize, int bOrder) { (void)pIpAddrTable; (void)bOrder; if (pdwSize) *pdwSize = 0; return 122; }
uint32_t LSW_MSABI lsw_GetIpForwardTable(void* pIpForwardTable, uint32_t* pdwSize, int bOrder) { (void)pIpForwardTable; (void)bOrder; if (pdwSize) *pdwSize = 0; return 122; }

/* InternalGetBound*EndpointTable — used by netstat to list connections.
 * We return an empty (but valid) dummy hash table so that
 * RtlEnumerateEntryHashTable returns NULL (no connections) without crashing.
 * The allocated block is freed by RtlDeleteHashTable. */
uint32_t LSW_MSABI lsw_InternalGetBoundTcpEndpointTable(void** ppTable, void* heap, uint32_t flags) {
    (void)heap; (void)flags;
    if (!ppTable) return 2;
    void* t = calloc(1, 256); /* dummy empty hash-table token */
    if (!t) return 8;
    *ppTable = t;
    return 0; /* NO_ERROR */
}
uint32_t LSW_MSABI lsw_InternalGetBoundTcp6EndpointTable(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetBoundTcpEndpointTable(ppTable, heap, flags);
}
/* InternalGetTcpTable / InternalGetUdpTable variants — return NO_ERROR with
 * an empty MIB table (NumEntries = 0) so callers don't deref NULL. */
uint32_t LSW_MSABI lsw_InternalGetTcpTable(void** ppTable, void* heap, uint32_t flags) {
    (void)heap; (void)flags;
    if (!ppTable) return 2;
    uint32_t* t = calloc(1, 256); /* first uint32 = NumEntries = 0 */
    if (!t) return 8;
    *ppTable = t;
    return 0;
}
uint32_t LSW_MSABI lsw_InternalGetTcpTableEx(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetTcpTable2(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetTcpTableWithOwnerModule(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetTcp6Table2(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetTcp6TableWithOwnerModule(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetUdpTable(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetUdpTable2(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetUdp6Table2(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
/* Statistics functions — return ERROR_NO_DATA (232) */
uint32_t LSW_MSABI lsw_GetTcpStatisticsEx(void* stats, uint32_t family) { (void)stats; (void)family; return 232; }
uint32_t LSW_MSABI lsw_GetUdpStatistics(void* stats) { (void)stats; return 232; }
uint32_t LSW_MSABI lsw_GetUdpStatisticsEx(void* stats, uint32_t family) { (void)stats; (void)family; return 232; }
uint32_t LSW_MSABI lsw_GetIpStatistics(void* stats) { (void)stats; return 232; }
uint32_t LSW_MSABI lsw_GetIpStatisticsEx(void* stats, uint32_t family) { (void)stats; (void)family; return 232; }
uint32_t LSW_MSABI lsw_GetIcmpStatistics(void* stats) { (void)stats; return 232; }
uint32_t LSW_MSABI lsw_GetIcmpStatisticsEx(void* stats, uint32_t family) { (void)stats; (void)family; return 232; }
/* Internal If/IpAddr/IpForward/IpNet tables — return empty */
uint32_t LSW_MSABI lsw_InternalGetIfTable(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetIpAddrTable(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetIpForwardTable(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
uint32_t LSW_MSABI lsw_InternalGetIpNetTable(void** ppTable, void* heap, uint32_t flags) {
    return lsw_InternalGetTcpTable(ppTable, heap, flags);
}
/* ConvertInterfaceLuidToNameA */
uint32_t LSW_MSABI lsw_ConvertInterfaceLuidToNameA(void* luid, char* name, uint32_t len) {
    (void)luid;
    if (name && len > 0) name[0] = '\0';
    return 1; /* ERROR_GEN_FAILURE */
}

void* LSW_MSABI lsw_IcmpCreateFile(void) { return (void*)0xB001; }
int LSW_MSABI lsw_IcmpCloseHandle(void* IcmpHandle) { (void)IcmpHandle; return 1; }
/* lsw_IcmpSendEcho implemented in win32_api.c (full ICMP socket implementation) */
extern uint32_t __attribute__((ms_abi)) lsw_IcmpSendEcho(void*, uint32_t, void*, uint16_t, void*, void*, uint32_t, uint32_t);
uint32_t LSW_MSABI lsw_GetNetworkParams(void* pFixedInfo, uint32_t* pOutBufLen) { (void)pFixedInfo; if (pOutBufLen) *pOutBufLen = 256; return 111; }
uint32_t LSW_MSABI lsw_NotifyAddrChange(void* Handle, void* overlapped) { (void)Handle; (void)overlapped; return 0; }
int LSW_MSABI lsw_CancelIPChangeNotify(void* overlapped) { (void)overlapped; return 1; }

// ---- DirectX stubs -------------------------------------------------------
// d3d9
void* LSW_MSABI lsw_Direct3DCreate9(uint32_t sdk_version) { (void)sdk_version; return NULL; }
int32_t LSW_MSABI lsw_Direct3DCreate9Ex(uint32_t sdk_version, void** ppD3D) { (void)sdk_version; if (ppD3D) *ppD3D = NULL; return E_NOTIMPL; }
void* LSW_MSABI lsw_Direct3DCreate8(uint32_t sdk_version) { (void)sdk_version; return NULL; }

// d3d11
int32_t LSW_MSABI lsw_D3D11CreateDevice(void* adapter, int driver_type, void* sw, uint32_t flags,
    const void* feature_levels, uint32_t num_fl, uint32_t sdk_version, void** device, void* fl_out, void** ctx) {
    (void)adapter; (void)driver_type; (void)sw; (void)flags;
    (void)feature_levels; (void)num_fl; (void)sdk_version;
    if (device) *device = NULL; if (ctx) *ctx = NULL;
    return E_NOTIMPL;
}
int32_t LSW_MSABI lsw_D3D11CreateDeviceAndSwapChain(void* adapter, int driver_type, void* sw,
    uint32_t flags, const void* feature_levels, uint32_t num_fl, uint32_t sdk_version,
    const void* swap_chain_desc, void** swap_chain, void** device, void* fl_out, void** ctx) {
    (void)adapter; (void)driver_type; (void)sw; (void)flags;
    (void)feature_levels; (void)num_fl; (void)sdk_version; (void)swap_chain_desc;
    if (swap_chain) *swap_chain = NULL; if (device) *device = NULL; if (ctx) *ctx = NULL;
    return E_NOTIMPL;
}

// d3d12
int32_t LSW_MSABI lsw_D3D12CreateDevice(void* adapter, int minimum_fl, const void* riid, void** ppDevice) {
    (void)adapter; (void)minimum_fl; (void)riid; if (ppDevice) *ppDevice = NULL; return E_NOTIMPL;
}
int32_t LSW_MSABI lsw_D3D12GetDebugInterface(const void* riid, void** ppDebug) { (void)riid; if (ppDebug) *ppDebug = NULL; return E_NOTIMPL; }
int32_t LSW_MSABI lsw_D3D12SerializeRootSignature(const void* pRootSignature, int Version, void** ppBlob, void** ppError) {
    (void)pRootSignature; (void)Version; if (ppBlob) *ppBlob = NULL; if (ppError) *ppError = NULL; return E_NOTIMPL;
}
int32_t LSW_MSABI lsw_D3D12EnableExperimentalFeatures(uint32_t numFeatures, const void* pIIDs, void* pConfigurations, uint32_t* pConfigurationSizes) {
    (void)numFeatures; (void)pIIDs; (void)pConfigurations; (void)pConfigurationSizes; return E_NOTIMPL;
}

// dxgi
int32_t LSW_MSABI lsw_CreateDXGIFactory(const void* riid, void** ppFactory)  { (void)riid; if (ppFactory) *ppFactory = NULL; return E_NOTIMPL; }
int32_t LSW_MSABI lsw_CreateDXGIFactory1(const void* riid, void** ppFactory) { (void)riid; if (ppFactory) *ppFactory = NULL; return E_NOTIMPL; }
int32_t LSW_MSABI lsw_CreateDXGIFactory2(uint32_t flags, const void* riid, void** ppFactory) { (void)flags; (void)riid; if (ppFactory) *ppFactory = NULL; return E_NOTIMPL; }
int32_t LSW_MSABI lsw_DXGIDeclareAdapterRemovalSupport(void) { return E_NOTIMPL; }
int32_t LSW_MSABI lsw_DXGIGetDebugInterface1(uint32_t flags, const void* riid, void** pDebug) { (void)flags; (void)riid; if (pDebug) *pDebug = NULL; return E_NOTIMPL; }

// d3dcompiler_47
int32_t LSW_MSABI lsw_D3DCompile(const void* pSrcData, size_t SrcDataSize, const char* pSourceName,
    const void* pDefines, void* pInclude, const char* pEntrypoint, const char* pTarget,
    uint32_t Flags1, uint32_t Flags2, void** ppCode, void** ppErrors) {
    (void)pSrcData; (void)SrcDataSize; (void)pSourceName; (void)pDefines; (void)pInclude;
    (void)pEntrypoint; (void)pTarget; (void)Flags1; (void)Flags2;
    if (ppCode) *ppCode = NULL; if (ppErrors) *ppErrors = NULL; return E_NOTIMPL;
}
int32_t LSW_MSABI lsw_D3DReflect(const void* pSrcData, size_t SrcDataSize, const void* pInterface, void** ppReflector) {
    (void)pSrcData; (void)SrcDataSize; (void)pInterface; if (ppReflector) *ppReflector = NULL; return E_NOTIMPL;
}
int32_t LSW_MSABI lsw_D3DDisassemble(const void* pSrcData, size_t SrcDataSize, uint32_t Flags,
    const char* szComments, void** ppDisassembly) {
    (void)pSrcData; (void)SrcDataSize; (void)Flags; (void)szComments; if (ppDisassembly) *ppDisassembly = NULL; return E_NOTIMPL;
}

// XInput
int32_t LSW_MSABI lsw_XInputGetState(uint32_t userIndex, void* pState) { (void)userIndex; if (pState) memset(pState, 0, 32); return 0x48F /*ERROR_DEVICE_NOT_CONNECTED*/; }
int32_t LSW_MSABI lsw_XInputSetState(uint32_t userIndex, void* pVibration) { (void)userIndex; (void)pVibration; return 0x48F; }
int32_t LSW_MSABI lsw_XInputGetCapabilities(uint32_t userIndex, uint32_t flags, void* pCapabilities) { (void)userIndex; (void)flags; (void)pCapabilities; return 0x48F; }
void    LSW_MSABI lsw_XInputEnable(int enable) { (void)enable; }

// dsound
int32_t LSW_MSABI lsw_DirectSoundCreate(const void* lpGuid, void** ppDS, void* pUnkOuter) { (void)lpGuid; if (ppDS) *ppDS = NULL; (void)pUnkOuter; return E_NOTIMPL; }
int32_t LSW_MSABI lsw_DirectSoundCreate8(const void* lpGuid, void** ppDS, void* pUnkOuter) { (void)lpGuid; if (ppDS) *ppDS = NULL; (void)pUnkOuter; return E_NOTIMPL; }
int32_t LSW_MSABI lsw_DirectSoundEnumerateW(void* pDSEnumCallback, void* pContext) { (void)pDSEnumCallback; (void)pContext; return E_NOTIMPL; }
int32_t LSW_MSABI lsw_DirectSoundCaptureCreate8(const void* lpGuid, void** ppDSC, void* pUnkOuter) { (void)lpGuid; if (ppDSC) *ppDSC = NULL; (void)pUnkOuter; return E_NOTIMPL; }

const win32_api_mapping_t win32_api_misc_mappings[] = {
    MAP("uxtheme.dll", "OpenThemeData", lsw_OpenThemeData),
    MAP("uxtheme.dll", "OpenThemeDataEx", lsw_OpenThemeDataEx),
    MAP("uxtheme.dll", "CloseThemeData", lsw_CloseThemeData),
    MAP("uxtheme.dll", "DrawThemeBackground", lsw_DrawThemeBackground),
    MAP("uxtheme.dll", "DrawThemeBackgroundEx", lsw_DrawThemeBackgroundEx),
    MAP("uxtheme.dll", "DrawThemeText", lsw_DrawThemeText),
    MAP("uxtheme.dll", "DrawThemeTextEx", lsw_DrawThemeTextEx),
    MAP("uxtheme.dll", "GetThemeColor", lsw_GetThemeColor),
    MAP("uxtheme.dll", "GetThemeSysColor", lsw_GetThemeSysColor),
    MAP("uxtheme.dll", "GetThemeSysColorBrush", lsw_GetThemeSysColorBrush),
    MAP("uxtheme.dll", "GetThemeSysFont", lsw_GetThemeSysFont),
    MAP("uxtheme.dll", "GetThemeSysSize", lsw_GetThemeSysSize),
    MAP("uxtheme.dll", "GetThemeSysBool", lsw_GetThemeSysBool),
    MAP("uxtheme.dll", "GetThemeSysString", lsw_GetThemeSysString),
    MAP("uxtheme.dll", "GetThemePartSize", lsw_GetThemePartSize),
    MAP("uxtheme.dll", "GetThemePosition", lsw_GetThemePosition),
    MAP("uxtheme.dll", "GetThemeMargins", lsw_GetThemeMargins),
    MAP("uxtheme.dll", "GetThemeRect", lsw_GetThemeRect),
    MAP("uxtheme.dll", "GetThemeMetric", lsw_GetThemeMetric),
    MAP("uxtheme.dll", "IsThemeActive", lsw_IsThemeActive),
    MAP("uxtheme.dll", "IsAppThemed", lsw_IsAppThemed),
    MAP("uxtheme.dll", "IsCompositionActive", lsw_IsCompositionActive),
    MAP("uxtheme.dll", "IsThemeBackgroundPartiallyTransparent", lsw_IsThemeBackgroundPartiallyTransparent),
    MAP("uxtheme.dll", "IsThemePartDefined", lsw_IsThemePartDefined),
    MAP("uxtheme.dll", "EnableTheming", lsw_EnableTheming),
    MAP("uxtheme.dll", "SetWindowTheme", lsw_SetWindowTheme),
    MAP("uxtheme.dll", "SetWindowThemeAttribute", lsw_SetWindowThemeAttribute),
    MAP("uxtheme.dll", "GetCurrentThemeName", lsw_GetCurrentThemeName),
    MAP("uxtheme.dll", "GetThemeAppProperties", lsw_GetThemeAppProperties),
    MAP("uxtheme.dll", "SetThemeAppProperties", lsw_SetThemeAppProperties),
    MAP("uxtheme.dll", "GetThemeDocumentationProperty", lsw_GetThemeDocumentationProperty),
    MAP("uxtheme.dll", "DrawThemeParentBackground", lsw_DrawThemeParentBackground),
    MAP("uxtheme.dll", "DrawThemeParentBackgroundEx", lsw_DrawThemeParentBackgroundEx),
    MAP("uxtheme.dll", "BufferedPaintInit", lsw_BufferedPaintInit),
    MAP("uxtheme.dll", "BufferedPaintUnInit", lsw_BufferedPaintUnInit),
    MAP("uxtheme.dll", "BeginBufferedPaint", lsw_BeginBufferedPaint),
    MAP("uxtheme.dll", "EndBufferedPaint", lsw_EndBufferedPaint),
    MAP("uxtheme.dll", "BufferedPaintClear", lsw_BufferedPaintClear),
    MAP("uxtheme.dll", "GetBufferedPaintDC", lsw_GetBufferedPaintDC),
    MAP("uxtheme.dll", "GetBufferedPaintTargetDC", lsw_GetBufferedPaintTargetDC),
    MAP("uxtheme.dll", "GetBufferedPaintTargetRect", lsw_GetBufferedPaintTargetRect),
    MAP("imm32.dll", "ImmGetContext", lsw_ImmGetContext),
    MAP("imm32.dll", "ImmReleaseContext", lsw_ImmReleaseContext),
    MAP("imm32.dll", "ImmGetCompositionStringW", lsw_ImmGetCompositionStringW),
    MAP("imm32.dll", "ImmGetCompositionStringA", lsw_ImmGetCompositionStringA),
    MAP("imm32.dll", "ImmSetCompositionWindow", lsw_ImmSetCompositionWindow),
    MAP("imm32.dll", "ImmSetCompositionStringW", lsw_ImmSetCompositionStringW),
    MAP("imm32.dll", "ImmAssociateContext", lsw_ImmAssociateContext),
    MAP("imm32.dll", "ImmAssociateContextEx", lsw_ImmAssociateContextEx),
    MAP("imm32.dll", "ImmNotifyIME", lsw_ImmNotifyIME),
    MAP("imm32.dll", "ImmSetOpenStatus", lsw_ImmSetOpenStatus),
    MAP("imm32.dll", "ImmGetOpenStatus", lsw_ImmGetOpenStatus),
    MAP("imm32.dll", "ImmGetDefaultIMEWnd", lsw_ImmGetDefaultIMEWnd),
    MAP("imm32.dll", "ImmCreateContext", lsw_ImmCreateContext),
    MAP("imm32.dll", "ImmDestroyContext", lsw_ImmDestroyContext),
    MAP("imm32.dll", "ImmGetCandidateWindow", lsw_ImmGetCandidateWindow),
    MAP("imm32.dll", "ImmSetCandidateWindow", lsw_ImmSetCandidateWindow),
    MAP("imm32.dll", "ImmGetConversionStatus", lsw_ImmGetConversionStatus),
    MAP("imm32.dll", "ImmSetConversionStatus", lsw_ImmSetConversionStatus),
    MAP("imm32.dll", "ImmConfigureIMEW", lsw_ImmConfigureIMEW),
    MAP("imm32.dll", "ImmInstallIMEW", lsw_ImmInstallIMEW),
    MAP("imm32.dll", "ImmIsIME", lsw_ImmIsIME),
    MAP("imm32.dll", "ImmGetIMEFileNameW", lsw_ImmGetIMEFileNameW),
    MAP("imm32.dll", "ImmGetVirtualKey", lsw_ImmGetVirtualKey),
    MAP("imm32.dll", "ImmRegisterWordW", lsw_ImmRegisterWordW),
    MAP("imm32.dll", "ImmEnumRegisterWordW", lsw_ImmEnumRegisterWordW),
    MAP("imm32.dll", "ImmGetRegisterWordStyleW", lsw_ImmGetRegisterWordStyleW),
    MAP("version.dll", "GetFileVersionInfoSizeW", lsw_GetFileVersionInfoSizeW),
    MAP("version.dll", "GetFileVersionInfoSizeA", lsw_GetFileVersionInfoSizeA),
    MAP("version.dll", "GetFileVersionInfoW", lsw_GetFileVersionInfoW),
    MAP("version.dll", "GetFileVersionInfoA", lsw_GetFileVersionInfoA),
    MAP("version.dll", "VerQueryValueW", lsw_VerQueryValueW),
    MAP("version.dll", "VerQueryValueA", lsw_VerQueryValueA),
    MAP("version.dll", "GetFileVersionInfoExW", lsw_GetFileVersionInfoExW),
    MAP("version.dll", "GetFileVersionInfoSizeExW", lsw_GetFileVersionInfoSizeExW),
    MAP("version.dll", "VerFindFileW", lsw_VerFindFileW),
    MAP("version.dll", "VerInstallFileW", lsw_VerInstallFileW),
    MAP("winmm.dll", "timeGetTime", lsw_timeGetTime),
    MAP("winmm.dll", "timeBeginPeriod", lsw_timeBeginPeriod),
    MAP("winmm.dll", "timeEndPeriod", lsw_timeEndPeriod),
    MAP("winmm.dll", "timeGetDevCaps", lsw_timeGetDevCaps),
    MAP("winmm.dll", "timeSetEvent", lsw_timeSetEvent),
    MAP("winmm.dll", "timeKillEvent", lsw_timeKillEvent),
    MAP("winmm.dll", "waveOutOpen", lsw_waveOutOpen),
    MAP("winmm.dll", "waveOutClose", lsw_waveOutClose),
    MAP("winmm.dll", "waveOutWrite", lsw_waveOutWrite),
    MAP("winmm.dll", "waveOutPrepareHeader", lsw_waveOutPrepareHeader),
    MAP("winmm.dll", "waveOutUnprepareHeader", lsw_waveOutUnprepareHeader),
    MAP("winmm.dll", "waveOutGetNumDevs", lsw_waveOutGetNumDevs),
    MAP("winmm.dll", "waveOutGetDevCapsW", lsw_waveOutGetDevCapsW),
    MAP("winmm.dll", "waveOutGetVolume", lsw_waveOutGetVolume),
    MAP("winmm.dll", "waveOutSetVolume", lsw_waveOutSetVolume),
    MAP("winmm.dll", "waveOutPause", lsw_waveOutPause),
    MAP("winmm.dll", "waveOutRestart", lsw_waveOutRestart),
    MAP("winmm.dll", "waveOutReset", lsw_waveOutReset),
    MAP("winmm.dll", "waveOutGetPosition", lsw_waveOutGetPosition),
    MAP("winmm.dll", "mciSendStringW", lsw_mciSendStringW),
    MAP("winmm.dll", "mciSendStringA", lsw_mciSendStringA),
    MAP("winmm.dll", "mciSendCommandW", lsw_mciSendCommandW),
    MAP("winmm.dll", "mixerGetNumDevs", lsw_mixerGetNumDevs),
    MAP("winmm.dll", "PlaySoundW", lsw_PlaySoundW),
    MAP("winmm.dll", "PlaySoundA", lsw_PlaySoundA),
    MAP("winmm.dll", "sndPlaySoundW", lsw_sndPlaySoundW),
    MAP("winmm.dll", "sndPlaySoundA", lsw_sndPlaySoundA),
    MAP("winmm.dll", "joyGetNumDevs", lsw_joyGetNumDevs),
    MAP("winmm.dll", "joyGetPos", lsw_joyGetPos),
    MAP("winmm.dll", "joyGetPosEx", lsw_joyGetPosEx),
    MAP("winmm.dll", "joyGetDevCapsW", lsw_joyGetDevCapsW),
    MAP("msvcp140.dll", "??0exception@@QEAA@AEBQEBD@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "??0exception@@QEAA@AEBV0@@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "??1exception@@UEAA@XZ", lsw_msvcp_noop),
    MAP("msvcp140.dll", "??_7exception@@6B@", lsw_msvcp_nullptr),
    MAP("msvcp140.dll", "?what@exception@@UEBAPEBDXZ", lsw_msvcp_nullptr),
    MAP("msvcp140.dll", "??0bad_alloc@std@@QEAA@AEBQEBD@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "??0bad_alloc@std@@QEAA@AEBV01@@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "??1bad_alloc@std@@UEAA@XZ", lsw_msvcp_noop),
    MAP("msvcp140.dll", "??_7bad_alloc@std@@6B@", lsw_msvcp_nullptr),
    MAP("msvcp140.dll", "??0logic_error@std@@QEAA@AEBQEBD@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "??0runtime_error@std@@QEAA@AEBQEBD@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "?_Xbad_alloc@std@@YAXXZ", lsw_msvcp_noop),
    MAP("msvcp140.dll", "?_Xlength_error@std@@YAXPEBD@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "?_Xout_of_range@std@@YAXPEBD@Z", lsw_msvcp_noop),
    MAP("msvcp140.dll", "_Lock_shared_ptr_spin_lock", lsw_msvcp_noop),
    MAP("msvcp140.dll", "_Unlock_shared_ptr_spin_lock", lsw_msvcp_noop),
    MAP("msvcp140.dll", "?_Allocate@?$allocator@D@std@@QEAAPEADXZ", lsw_msvcp_nullptr),
    MAP("msvcp140.dll", "__std_exception_copy", lsw_msvcp_noop),
    MAP("msvcp140.dll", "__std_exception_destroy", lsw_msvcp_noop),
    MAP("psapi.dll", "GetProcessMemoryInfo", lsw_GetProcessMemoryInfo),
    MAP("psapi.dll", "EnumProcesses", lsw_EnumProcesses),
    MAP("psapi.dll", "EnumProcessModules", lsw_EnumProcessModules),
    MAP("psapi.dll", "GetModuleBaseNameW", lsw_GetModuleBaseNameW),
    MAP("psapi.dll", "GetModuleFileNameExW", lsw_GetModuleFileNameExW),
    MAP("userenv.dll", "GetUserProfileDirectoryW", lsw_GetUserProfileDirectoryW),
    MAP("userenv.dll", "CreateEnvironmentBlock", lsw_CreateEnvironmentBlock),
    MAP("userenv.dll", "DestroyEnvironmentBlock", lsw_DestroyEnvironmentBlock),
    MAP("userenv.dll", "LoadUserProfileW", lsw_LoadUserProfileW),
    MAP("userenv.dll", "UnloadUserProfile", lsw_UnloadUserProfile),
    MAP("wtsapi32.dll", "WTSOpenServerW", lsw_WTSOpenServerW),
    MAP("wtsapi32.dll", "WTSCloseServer", lsw_WTSCloseServer),
    MAP("wtsapi32.dll", "WTSQuerySessionInformationW", lsw_WTSQuerySessionInformationW),
    MAP("wtsapi32.dll", "WTSFreeMemory", lsw_WTSFreeMemory),
    MAP("wtsapi32.dll", "WTSGetActiveConsoleSessionId", lsw_WTSGetActiveConsoleSessionId),
    MAP("wtsapi32.dll", "WTSSendMessageW", lsw_WTSSendMessageW),
    MAP("wtsapi32.dll", "ProcessIdToSessionId", lsw_ProcessIdToSessionId),
    MAP("iphlpapi.dll", "GetAdaptersInfo", lsw_GetAdaptersInfo),
    MAP("iphlpapi.dll", "GetAdaptersAddresses", lsw_GetAdaptersAddresses),
    MAP("iphlpapi.dll", "GetIfTable", lsw_GetIfTable),
    MAP("iphlpapi.dll", "GetIpAddrTable", lsw_GetIpAddrTable),
    MAP("iphlpapi.dll", "GetIpForwardTable", lsw_GetIpForwardTable),
    MAP("iphlpapi.dll", "IcmpCreateFile", lsw_IcmpCreateFile),
    MAP("iphlpapi.dll", "IcmpCloseHandle", lsw_IcmpCloseHandle),
    MAP("iphlpapi.dll", "IcmpSendEcho", lsw_IcmpSendEcho),
    MAP("iphlpapi.dll", "GetNetworkParams", lsw_GetNetworkParams),
    MAP("iphlpapi.dll", "NotifyAddrChange", lsw_NotifyAddrChange),
    MAP("iphlpapi.dll", "CancelIPChangeNotify", lsw_CancelIPChangeNotify),
    MAP("iphlpapi.dll", "ConvertLengthToIpv4Mask", lsw_ConvertLengthToIpv4Mask),
    MAP("iphlpapi.dll", "ConvertInterfaceIndexToLuid", lsw_ConvertInterfaceIndexToLuid),
    MAP("iphlpapi.dll", "ConvertInterfaceLuidToGuid", lsw_ConvertInterfaceLuidToGuid),
    MAP("iphlpapi.dll", "ConvertInterfaceLuidToNameW", lsw_ConvertInterfaceLuidToNameW),
    MAP("iphlpapi.dll", "ConvertGuidToStringW", lsw_ConvertGuidToStringW),
    MAP("iphlpapi.dll", "GetCurrentThreadCompartmentId", lsw_GetCurrentThreadCompartmentId),
    MAP("iphlpapi.dll", "SetCurrentThreadCompartmentId", lsw_SetCurrentThreadCompartmentId),
    MAP("iphlpapi.dll", "GetInterfaceDnsSettings", lsw_GetInterfaceDnsSettings),
    MAP("iphlpapi.dll", "FreeInterfaceDnsSettings", lsw_FreeInterfaceDnsSettings),
    /* Internal endpoint/connection table stubs (used by netstat, tasklist, etc.) */
    MAP("iphlpapi.dll", "InternalGetBoundTcpEndpointTable",           lsw_InternalGetBoundTcpEndpointTable),
    MAP("iphlpapi.dll", "InternalGetBoundTcp6EndpointTable",          lsw_InternalGetBoundTcp6EndpointTable),
    MAP("iphlpapi.dll", "InternalGetTcpTable",                        lsw_InternalGetTcpTable),
    MAP("iphlpapi.dll", "InternalGetTcpTableEx",                      lsw_InternalGetTcpTableEx),
    MAP("iphlpapi.dll", "InternalGetTcpTable2",                       lsw_InternalGetTcpTable2),
    MAP("iphlpapi.dll", "InternalGetTcpTableWithOwnerModule",         lsw_InternalGetTcpTableWithOwnerModule),
    MAP("iphlpapi.dll", "InternalGetTcp6Table2",                      lsw_InternalGetTcp6Table2),
    MAP("iphlpapi.dll", "InternalGetTcp6TableWithOwnerModule",        lsw_InternalGetTcp6TableWithOwnerModule),
    MAP("iphlpapi.dll", "InternalGetUdpTable",                        lsw_InternalGetUdpTable),
    MAP("iphlpapi.dll", "InternalGetUdpTable2",                       lsw_InternalGetUdpTable2),
    MAP("iphlpapi.dll", "InternalGetUdp6Table2",                      lsw_InternalGetUdp6Table2),
    MAP("iphlpapi.dll", "InternalGetIfTable",                         lsw_InternalGetIfTable),
    MAP("iphlpapi.dll", "InternalGetIpAddrTable",                     lsw_InternalGetIpAddrTable),
    MAP("iphlpapi.dll", "InternalGetIpForwardTable",                  lsw_InternalGetIpForwardTable),
    MAP("iphlpapi.dll", "InternalGetIpNetTable",                      lsw_InternalGetIpNetTable),
    /* Network statistics stubs */
    MAP("iphlpapi.dll", "GetTcpStatisticsEx",                         lsw_GetTcpStatisticsEx),
    MAP("iphlpapi.dll", "GetUdpStatistics",                           lsw_GetUdpStatistics),
    MAP("iphlpapi.dll", "GetUdpStatisticsEx",                         lsw_GetUdpStatisticsEx),
    MAP("iphlpapi.dll", "GetIpStatistics",                            lsw_GetIpStatistics),
    MAP("iphlpapi.dll", "GetIpStatisticsEx",                          lsw_GetIpStatisticsEx),
    MAP("iphlpapi.dll", "GetIcmpStatistics",                          lsw_GetIcmpStatistics),
    MAP("iphlpapi.dll", "GetIcmpStatisticsEx",                        lsw_GetIcmpStatisticsEx),
    MAP("iphlpapi.dll", "ConvertInterfaceLuidToNameA",                lsw_ConvertInterfaceLuidToNameA),
    /* NSI.dll */
    MAP("nsi.dll", "NsiAllocateAndGetTable", lsw_NsiAllocateAndGetTable),
    MAP("nsi.dll", "NsiFreeTable", lsw_NsiFreeTable),
    MAP("nsi.dll", "NsiGetAllParameters", lsw_NsiGetAllParameters),
    MAP("nsi.dll", "NsiSetAllParameters", lsw_NsiSetAllParameters),
    /* DNSAPI.dll */
    MAP("dnsapi.dll", "DnsQueryConfigAllocEx", lsw_DnsQueryConfigAllocEx),
    MAP("dnsapi.dll", "DnsFree", lsw_DnsFree),
    MAP("dnsapi.dll", "DnsGetCacheRecords", lsw_DnsGetCacheRecords),
    MAP("dnsapi.dll", "DnsFlushResolverCache", lsw_DnsFlushResolverCache),
    MAP("dnsapi.dll", "DnsResolverOp", lsw_DnsResolverOp),
    MAP("dnsapi.dll", "DnsGetDdrInfo", lsw_DnsGetDdrInfo),
    MAP("dnsapi.dll", "DnsFreeConfigStructure", lsw_DnsFreeConfigStructure),
    /* DHCPCSVC.dll / DHCPCSVC6.dll */
    MAP("dhcpcsvc.dll",  "DhcpAcquireParameters",  lsw_DhcpAcquireParameters),
    MAP("dhcpcsvc.dll",  "DhcpReleaseParameters",  lsw_DhcpReleaseParameters),
    MAP("dhcpcsvc.dll",  "DhcpHandlePnPEvent",     lsw_DhcpHandlePnPEvent),
    MAP("dhcpcsvc.dll",  "DhcpEnumClasses",         lsw_DhcpEnumClasses),
    MAP("dhcpcsvc6.dll", "Dhcpv6AcquireParameters", lsw_Dhcpv6AcquireParameters),
    MAP("dhcpcsvc6.dll", "Dhcpv6ReleaseParameters", lsw_Dhcpv6ReleaseParameters),
    MAP("dhcpcsvc6.dll", "Dhcpv6IsEnabled",         lsw_Dhcpv6IsEnabled),
    MAP("dhcpcsvc6.dll", "Dhcpv6GetUserClasses",    lsw_Dhcpv6GetUserClasses),
    MAP("dhcpcsvc6.dll", "Dhcpv6SetUserClass",      lsw_Dhcpv6SetUserClass),
    /* DirectX */
    MAP("d3d9.dll",     "Direct3DCreate9",              lsw_Direct3DCreate9),
    MAP("d3d9.dll",     "Direct3DCreate9Ex",             lsw_Direct3DCreate9Ex),
    MAP("d3d8.dll",     "Direct3DCreate8",               lsw_Direct3DCreate8),
    MAP("d3d11.dll",    "D3D11CreateDevice",             lsw_D3D11CreateDevice),
    MAP("d3d11.dll",    "D3D11CreateDeviceAndSwapChain", lsw_D3D11CreateDeviceAndSwapChain),
    MAP("d3d12.dll",    "D3D12CreateDevice",             lsw_D3D12CreateDevice),
    MAP("d3d12.dll",    "D3D12GetDebugInterface",        lsw_D3D12GetDebugInterface),
    MAP("d3d12.dll",    "D3D12SerializeRootSignature",   lsw_D3D12SerializeRootSignature),
    MAP("d3d12.dll",    "D3D12EnableExperimentalFeatures", lsw_D3D12EnableExperimentalFeatures),
    MAP("dxgi.dll",     "CreateDXGIFactory",             lsw_CreateDXGIFactory),
    MAP("dxgi.dll",     "CreateDXGIFactory1",            lsw_CreateDXGIFactory1),
    MAP("dxgi.dll",     "CreateDXGIFactory2",            lsw_CreateDXGIFactory2),
    MAP("dxgi.dll",     "DXGIDeclareAdapterRemovalSupport", lsw_DXGIDeclareAdapterRemovalSupport),
    MAP("dxgi.dll",     "DXGIGetDebugInterface1",        lsw_DXGIGetDebugInterface1),
    MAP("d3dcompiler_47.dll", "D3DCompile",              lsw_D3DCompile),
    MAP("d3dcompiler_47.dll", "D3DReflect",              lsw_D3DReflect),
    MAP("d3dcompiler_47.dll", "D3DDisassemble",          lsw_D3DDisassemble),
    MAP("d3dcompiler_46.dll", "D3DCompile",              lsw_D3DCompile),
    MAP("d3dcompiler_43.dll", "D3DCompile",              lsw_D3DCompile),
    /* XInput */
    MAP("xinput1_4.dll",    "XInputGetState",       lsw_XInputGetState),
    MAP("xinput1_4.dll",    "XInputSetState",       lsw_XInputSetState),
    MAP("xinput1_4.dll",    "XInputGetCapabilities", lsw_XInputGetCapabilities),
    MAP("xinput1_4.dll",    "XInputEnable",         lsw_XInputEnable),
    MAP("xinput1_3.dll",    "XInputGetState",       lsw_XInputGetState),
    MAP("xinput1_3.dll",    "XInputSetState",       lsw_XInputSetState),
    MAP("xinput1_3.dll",    "XInputGetCapabilities", lsw_XInputGetCapabilities),
    MAP("xinput1_3.dll",    "XInputEnable",         lsw_XInputEnable),
    MAP("xinput9_1_0.dll",  "XInputGetState",       lsw_XInputGetState),
    MAP("xinput9_1_0.dll",  "XInputSetState",       lsw_XInputSetState),
    /* DirectSound */
    MAP("dsound.dll",   "DirectSoundCreate",         lsw_DirectSoundCreate),
    MAP("dsound.dll",   "DirectSoundCreate8",        lsw_DirectSoundCreate8),
    MAP("dsound.dll",   "DirectSoundEnumerateW",     lsw_DirectSoundEnumerateW),
    MAP("dsound.dll",   "DirectSoundCaptureCreate8", lsw_DirectSoundCaptureCreate8),
    {NULL, NULL, NULL}
};

const size_t win32_api_misc_mappings_count =
    (sizeof(win32_api_misc_mappings) / sizeof(win32_api_misc_mappings[0])) - 1;
