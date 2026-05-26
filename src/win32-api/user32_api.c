/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 *
 * USER32.dll + GDI32.dll Compatibility Layer
 *
 * Provides stub implementations for the most commonly imported USER32 and
 * GDI32 functions.  The stubs are sufficient for:
 *  - Console applications that link USER32 but don't open windows
 *  - Applications that call MessageBox() for error dialogs
 *  - Applications whose startup code queries system metrics / capabilities
 *
 * Window creation and message-loop functions are present but return
 * failure/NULL — real GUI support would require an X11 or Wayland backend.
 *
 * All functions carry __attribute__((ms_abi)).
 */

#include "win32_api.h"
#include "lsw_log.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>

/* Windows type aliases used in signatures */
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t  BYTE;
typedef int32_t  BOOL;
typedef void*    HANDLE;
typedef void*    HWND;
typedef void*    HINSTANCE;
typedef void*    HDC;
typedef void*    HGDIOBJ;
typedef void*    HBITMAP;
typedef void*    HBRUSH;
typedef void*    HFONT;
typedef void*    HPEN;
typedef void*    HRGN;
typedef void*    HICON;
typedef void*    HCURSOR;
typedef void*    HMENU;
typedef void*    HMONITOR;
typedef uint64_t WPARAM;
typedef int64_t  LPARAM;
typedef int64_t  LRESULT;
typedef uint32_t COLORREF;
typedef LRESULT (__attribute__((ms_abi)) *WNDPROC)(HWND, uint32_t, WPARAM, LPARAM);
typedef int      UINT;
typedef int      INT;

/* MessageBox button IDs */
#define IDOK     1
#define IDCANCEL 2
#define IDYES    6
#define IDNO     7

/* ShowWindow commands */
#define SW_HIDE       0
#define SW_SHOWNORMAL 1
#define SW_SHOW       5

/* System metrics */
#define SM_CXSCREEN  0
#define SM_CYSCREEN  1
#define SM_CXFULLSCREEN 16
#define SM_CYFULLSCREEN 17

/* ============================================================
 * MessageBox
 * ============================================================ */
int __attribute__((ms_abi)) lsw_MessageBoxA(HWND hwnd, const char* text, const char* caption, UINT type) {
    (void)hwnd; (void)type;
    fprintf(stderr, "\n[MessageBox] %s: %s\n", caption ? caption : "Message", text ? text : "");
    return IDOK;
}

int __attribute__((ms_abi)) lsw_MessageBoxW(HWND hwnd, const uint16_t* text, const uint16_t* caption, UINT type) {
    (void)hwnd; (void)type; (void)text; (void)caption;
    LSW_LOG_WARN("MessageBoxW called (wide strings not displayed — use MessageBoxA)");
    return IDOK;
}

int __attribute__((ms_abi)) lsw_MessageBoxExA(HWND hwnd, const char* text, const char* cap, UINT type, WORD lang_id) {
    (void)lang_id;
    return lsw_MessageBoxA(hwnd, text, cap, type);
}

/* ============================================================
 * System Metrics / Capabilities
 * ============================================================ */
int __attribute__((ms_abi)) lsw_GetSystemMetrics(int index) {
    switch (index) {
        case SM_CXSCREEN:      return 1920;
        case SM_CYSCREEN:      return 1080;
        case SM_CXFULLSCREEN:  return 1920;
        case SM_CYFULLSCREEN:  return 1080;
        default:               return 0;
    }
}

int __attribute__((ms_abi)) lsw_GetSystemMetricsForDpi(int index, UINT dpi) {
    (void)dpi;
    return lsw_GetSystemMetrics(index);
}

/* ============================================================
 * Window management — stubs returning NULL/0
 * Real window creation requires an X11/Wayland backend.
 * ============================================================ */
HWND __attribute__((ms_abi)) lsw_CreateWindowExA(
    DWORD ex_style, const char* class_name, const char* wnd_name,
    DWORD style, int x, int y, int w, int h,
    HWND parent, HMENU menu, HINSTANCE inst, void* param)
{
    (void)ex_style; (void)class_name; (void)wnd_name; (void)style;
    (void)x; (void)y; (void)w; (void)h; (void)parent; (void)menu; (void)inst; (void)param;
    LSW_LOG_WARN("CreateWindowExA: GUI not supported — returning NULL");
    return NULL;
}

HWND __attribute__((ms_abi)) lsw_CreateWindowExW(
    DWORD ex_style, const uint16_t* class_name, const uint16_t* wnd_name,
    DWORD style, int x, int y, int w, int h,
    HWND parent, HMENU menu, HINSTANCE inst, void* param)
{
    (void)ex_style; (void)class_name; (void)wnd_name; (void)style;
    (void)x; (void)y; (void)w; (void)h; (void)parent; (void)menu; (void)inst; (void)param;
    LSW_LOG_WARN("CreateWindowExW: GUI not supported — returning NULL");
    return NULL;
}

BOOL __attribute__((ms_abi)) lsw_DestroyWindow(HWND hwnd) { (void)hwnd; return 1; }
BOOL __attribute__((ms_abi)) lsw_ShowWindow(HWND hwnd, int cmd) { (void)hwnd; (void)cmd; return 0; }
BOOL __attribute__((ms_abi)) lsw_UpdateWindow(HWND hwnd) { (void)hwnd; return 1; }
BOOL __attribute__((ms_abi)) lsw_InvalidateRect(HWND hwnd, const void* rect, BOOL erase) {
    (void)hwnd; (void)rect; (void)erase; return 1;
}

LRESULT __attribute__((ms_abi)) lsw_DefWindowProcA(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    (void)hwnd; (void)msg; (void)wp; (void)lp; return 0;
}
LRESULT __attribute__((ms_abi)) lsw_DefWindowProcW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    (void)hwnd; (void)msg; (void)wp; (void)lp; return 0;
}
HWND __attribute__((ms_abi)) lsw_GetDesktopWindow(void) { return NULL; }
HWND __attribute__((ms_abi)) lsw_GetForegroundWindow(void) { return NULL; }
HWND __attribute__((ms_abi)) lsw_GetActiveWindow(void) { return NULL; }
HWND __attribute__((ms_abi)) lsw_SetFocus(HWND hwnd) { (void)hwnd; return NULL; }
HWND __attribute__((ms_abi)) lsw_GetFocus(void) { return NULL; }
BOOL __attribute__((ms_abi)) lsw_SetForegroundWindow(HWND hwnd) { (void)hwnd; return 1; }

/* ============================================================
 * Window class registration
 * ============================================================ */
typedef struct {
    UINT      cbSize;
    UINT      style;
    WNDPROC   lpfnWndProc;
    int       cbClsExtra;
    int       cbWndExtra;
    HINSTANCE hInstance;
    HICON     hIcon;
    HCURSOR   hCursor;
    HBRUSH    hbrBackground;
    const char* lpszMenuName;
    const char* lpszClassName;
    HICON     hIconSm;
} WNDCLASSEXA;

typedef struct {
    UINT        cbSize;
    UINT        style;
    WNDPROC     lpfnWndProc;
    int         cbClsExtra;
    int         cbWndExtra;
    HINSTANCE   hInstance;
    HICON       hIcon;
    HCURSOR     hCursor;
    HBRUSH      hbrBackground;
    const uint16_t* lpszMenuName;
    const uint16_t* lpszClassName;
    HICON       hIconSm;
} WNDCLASSEXW;

uint16_t __attribute__((ms_abi)) lsw_RegisterClassExA(const WNDCLASSEXA* wc) {
    (void)wc;
    LSW_LOG_DEBUG("RegisterClassExA: stub — returning fake atom 0x1");
    return 1; /* non-zero = success */
}
uint16_t __attribute__((ms_abi)) lsw_RegisterClassExW(const WNDCLASSEXW* wc) {
    (void)wc;
    return 1;
}
uint16_t __attribute__((ms_abi)) lsw_RegisterClassA(const void* wc) { (void)wc; return 1; }
uint16_t __attribute__((ms_abi)) lsw_RegisterClassW(const void* wc) { (void)wc; return 1; }
BOOL __attribute__((ms_abi)) lsw_UnregisterClassA(const char* name, HINSTANCE inst) {
    (void)name; (void)inst; return 1;
}
BOOL __attribute__((ms_abi)) lsw_UnregisterClassW(const uint16_t* name, HINSTANCE inst) {
    (void)name; (void)inst; return 1;
}

/* ============================================================
 * Message loop — minimal stubs
 * ============================================================ */
typedef struct {
    HWND   hwnd;
    UINT   message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD  time;
    int    pt_x, pt_y;
} lsw_MSG;

BOOL __attribute__((ms_abi)) lsw_GetMessageA(lsw_MSG* msg, HWND hwnd, UINT min, UINT max) {
    (void)hwnd; (void)min; (void)max;
    if (msg) memset(msg, 0, sizeof(*msg));
    return 0; /* WM_QUIT immediately */
}
BOOL __attribute__((ms_abi)) lsw_GetMessageW(lsw_MSG* msg, HWND hwnd, UINT min, UINT max) {
    return lsw_GetMessageA(msg, hwnd, min, max);
}
BOOL __attribute__((ms_abi)) lsw_PeekMessageA(lsw_MSG* msg, HWND hwnd, UINT min, UINT max, UINT remove) {
    (void)hwnd; (void)min; (void)max; (void)remove;
    if (msg) memset(msg, 0, sizeof(*msg));
    return 0;
}
BOOL __attribute__((ms_abi)) lsw_PeekMessageW(lsw_MSG* msg, HWND hwnd, UINT min, UINT max, UINT remove) {
    return lsw_PeekMessageA(msg, hwnd, min, max, remove);
}
BOOL __attribute__((ms_abi)) lsw_TranslateMessage(const lsw_MSG* msg) { (void)msg; return 0; }
LRESULT __attribute__((ms_abi)) lsw_DispatchMessageA(const lsw_MSG* msg) { (void)msg; return 0; }
LRESULT __attribute__((ms_abi)) lsw_DispatchMessageW(const lsw_MSG* msg) { (void)msg; return 0; }
void __attribute__((ms_abi)) lsw_PostQuitMessage(int exit_code) { (void)exit_code; }
BOOL __attribute__((ms_abi)) lsw_PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
    (void)h; (void)m; (void)w; (void)l; return 1;
}
BOOL __attribute__((ms_abi)) lsw_PostMessageW(HWND h, UINT m, WPARAM w, LPARAM l) {
    return lsw_PostMessageA(h, m, w, l);
}
LRESULT __attribute__((ms_abi)) lsw_SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
    (void)h; (void)m; (void)w; (void)l; return 0;
}
LRESULT __attribute__((ms_abi)) lsw_SendMessageW(HWND h, UINT m, WPARAM w, LPARAM l) {
    return lsw_SendMessageA(h, m, w, l);
}

/* ============================================================
 * Resources / Icons / Cursors
 * ============================================================ */
HICON   __attribute__((ms_abi)) lsw_LoadIconA(HINSTANCE inst, const char* name)      { (void)inst; (void)name; return NULL; }
HICON   __attribute__((ms_abi)) lsw_LoadIconW(HINSTANCE inst, const uint16_t* name)  { (void)inst; (void)name; return NULL; }
HCURSOR __attribute__((ms_abi)) lsw_LoadCursorA(HINSTANCE inst, const char* name)    { (void)inst; (void)name; return NULL; }
HCURSOR __attribute__((ms_abi)) lsw_LoadCursorW(HINSTANCE inst, const uint16_t* name){ (void)inst; (void)name; return NULL; }
HCURSOR __attribute__((ms_abi)) lsw_SetCursor(HCURSOR cur)                            { (void)cur; return NULL; }
BOOL    __attribute__((ms_abi)) lsw_SetCursorPos(int x, int y)                        { (void)x; (void)y; return 1; }
BOOL    __attribute__((ms_abi)) lsw_GetCursorPos(void* pt)                            { if (pt) memset(pt, 0, 8); return 1; }
int     __attribute__((ms_abi)) lsw_ShowCursor(BOOL show)                             { (void)show; return 0; }
void*   __attribute__((ms_abi)) lsw_LoadImageA(HINSTANCE inst, const char* name, UINT type, int cx, int cy, UINT lr) {
    (void)inst; (void)name; (void)type; (void)cx; (void)cy; (void)lr; return NULL;
}
void*   __attribute__((ms_abi)) lsw_LoadImageW(HINSTANCE inst, const uint16_t* name, UINT type, int cx, int cy, UINT lr) {
    (void)inst; (void)name; (void)type; (void)cx; (void)cy; (void)lr; return NULL;
}

/* ============================================================
 * Window title / text
 * ============================================================ */
BOOL __attribute__((ms_abi)) lsw_SetWindowTextA(HWND hwnd, const char* text) {
    (void)hwnd;
    if (text) LSW_LOG_DEBUG("SetWindowTextA: \"%s\"", text);
    return 1;
}
BOOL __attribute__((ms_abi)) lsw_SetWindowTextW(HWND hwnd, const uint16_t* text) {
    (void)hwnd; (void)text; return 1;
}
int __attribute__((ms_abi)) lsw_GetWindowTextA(HWND hwnd, char* buf, int max) {
    (void)hwnd; if (buf && max > 0) buf[0] = 0; return 0;
}
int __attribute__((ms_abi)) lsw_GetWindowTextW(HWND hwnd, uint16_t* buf, int max) {
    (void)hwnd; if (buf && max > 0) buf[0] = 0; return 0;
}

/* ============================================================
 * Window geometry
 * ============================================================ */
typedef struct { int32_t left, top, right, bottom; } lsw_RECT;
typedef struct { int32_t x, y; } lsw_POINT;
typedef struct { lsw_POINT pt; int32_t cx, cy; } lsw_SIZE;

BOOL __attribute__((ms_abi)) lsw_GetWindowRect(HWND hwnd, lsw_RECT* r) {
    (void)hwnd; if (r) memset(r, 0, sizeof(*r)); return 1;
}
BOOL __attribute__((ms_abi)) lsw_GetClientRect(HWND hwnd, lsw_RECT* r) {
    (void)hwnd;
    if (r) { r->left=0; r->top=0; r->right=1920; r->bottom=1080; }
    return 1;
}
BOOL __attribute__((ms_abi)) lsw_MoveWindow(HWND hwnd, int x, int y, int w, int h, BOOL repaint) {
    (void)hwnd; (void)x; (void)y; (void)w; (void)h; (void)repaint; return 1;
}
BOOL __attribute__((ms_abi)) lsw_SetWindowPos(
    HWND hwnd, HWND after, int x, int y, int cx, int cy, UINT flags) {
    (void)hwnd; (void)after; (void)x; (void)y; (void)cx; (void)cy; (void)flags; return 1;
}
BOOL __attribute__((ms_abi)) lsw_ScreenToClient(HWND hwnd, lsw_POINT* pt) {
    (void)hwnd; (void)pt; return 1;
}
BOOL __attribute__((ms_abi)) lsw_ClientToScreen(HWND hwnd, lsw_POINT* pt) {
    (void)hwnd; (void)pt; return 1;
}

/* ============================================================
 * Enable / visibility
 * ============================================================ */
BOOL __attribute__((ms_abi)) lsw_EnableWindow(HWND hwnd, BOOL enable) { (void)hwnd; (void)enable; return 0; }
BOOL __attribute__((ms_abi)) lsw_IsWindowVisible(HWND hwnd)           { (void)hwnd; return 0; }
BOOL __attribute__((ms_abi)) lsw_IsWindow(HWND hwnd)                  { (void)hwnd; return 0; }
BOOL __attribute__((ms_abi)) lsw_IsWindowEnabled(HWND hwnd)           { (void)hwnd; return 0; }

/* ============================================================
 * Dialog stubs
 * ============================================================ */
HWND __attribute__((ms_abi)) lsw_CreateDialogParamA(
    HINSTANCE inst, const char* name, HWND parent, void* dlg_proc, LPARAM init)
{
    (void)inst; (void)name; (void)parent; (void)dlg_proc; (void)init;
    LSW_LOG_WARN("CreateDialogParamA: GUI not supported");
    return NULL;
}
HWND __attribute__((ms_abi)) lsw_CreateDialogParamW(
    HINSTANCE inst, const uint16_t* name, HWND parent, void* dlg_proc, LPARAM init)
{
    (void)inst; (void)name; (void)parent; (void)dlg_proc; (void)init;
    return NULL;
}
int __attribute__((ms_abi)) lsw_DialogBoxParamA(
    HINSTANCE inst, const char* name, HWND parent, void* dlg_proc, LPARAM init)
{
    (void)inst; (void)name; (void)parent; (void)dlg_proc; (void)init;
    return -1;
}
int __attribute__((ms_abi)) lsw_DialogBoxParamW(
    HINSTANCE inst, const uint16_t* name, HWND parent, void* dlg_proc, LPARAM init)
{
    (void)inst; (void)name; (void)parent; (void)dlg_proc; (void)init;
    return -1;
}
BOOL __attribute__((ms_abi)) lsw_EndDialog(HWND hwnd, INT result) { (void)hwnd; (void)result; return 1; }
HWND __attribute__((ms_abi)) lsw_GetDlgItem(HWND hwnd, int id) { (void)hwnd; (void)id; return NULL; }
UINT __attribute__((ms_abi)) lsw_GetDlgItemTextA(HWND hwnd, int id, char* buf, int max) {
    (void)hwnd; (void)id; if (buf && max > 0) buf[0] = 0; return 0;
}
BOOL __attribute__((ms_abi)) lsw_SetDlgItemTextA(HWND hwnd, int id, const char* s) {
    (void)hwnd; (void)id; (void)s; return 1;
}
UINT __attribute__((ms_abi)) lsw_GetDlgItemInt(HWND hwnd, int id, BOOL* ok, BOOL sign) {
    (void)hwnd; (void)id; (void)sign; if (ok) *ok = 0; return 0;
}
BOOL __attribute__((ms_abi)) lsw_SetDlgItemInt(HWND hwnd, int id, UINT val, BOOL sign) {
    (void)hwnd; (void)id; (void)val; (void)sign; return 1;
}
BOOL __attribute__((ms_abi)) lsw_CheckDlgButton(HWND hwnd, int id, UINT check) {
    (void)hwnd; (void)id; (void)check; return 1;
}
UINT __attribute__((ms_abi)) lsw_IsDlgButtonChecked(HWND hwnd, int id) {
    (void)hwnd; (void)id; return 0;
}

/* ============================================================
 * Miscellaneous USER32
 * ============================================================ */
int  __attribute__((ms_abi)) lsw_MessageBeep(UINT type)              { (void)type; return 1; }
BOOL __attribute__((ms_abi)) lsw_FlashWindow(HWND hwnd, BOOL invert) { (void)hwnd; (void)invert; return 0; }
void __attribute__((ms_abi)) lsw_keybd_event(BYTE vk, BYTE scan, DWORD flags, uintptr_t extra) {
    (void)vk; (void)scan; (void)flags; (void)extra;
}
void __attribute__((ms_abi)) lsw_mouse_event(DWORD flags, DWORD dx, DWORD dy, DWORD data, uintptr_t extra) {
    (void)flags; (void)dx; (void)dy; (void)data; (void)extra;
}
int __attribute__((ms_abi)) lsw_GetKeyState(int vk) { (void)vk; return 0; }
int __attribute__((ms_abi)) lsw_GetAsyncKeyState(int vk) { (void)vk; return 0; }

HWND __attribute__((ms_abi)) lsw_FindWindowA(const char* cls, const char* wnd) {
    (void)cls; (void)wnd; return NULL;
}
HWND __attribute__((ms_abi)) lsw_FindWindowW(const uint16_t* cls, const uint16_t* wnd) {
    (void)cls; (void)wnd; return NULL;
}

BOOL __attribute__((ms_abi)) lsw_SetWindowLongPtrA(HWND hwnd, int idx, intptr_t new_val) {
    (void)hwnd; (void)idx; (void)new_val; return 0;
}
intptr_t __attribute__((ms_abi)) lsw_GetWindowLongPtrA(HWND hwnd, int idx) {
    (void)hwnd; (void)idx; return 0;
}
BOOL __attribute__((ms_abi)) lsw_SetWindowLongA(HWND hwnd, int idx, int32_t v) {
    (void)hwnd; (void)idx; (void)v; return 0;
}
int32_t __attribute__((ms_abi)) lsw_GetWindowLongA(HWND hwnd, int idx) {
    (void)hwnd; (void)idx; return 0;
}
uint32_t __attribute__((ms_abi)) lsw_GetWindowThreadProcessId(HWND hwnd, uint32_t* pid) {
    (void)hwnd; if (pid) *pid = 0; return 0;
}

BOOL __attribute__((ms_abi)) lsw_AdjustWindowRect(lsw_RECT* r, DWORD style, BOOL menu) {
    (void)r; (void)style; (void)menu; return 1;
}
BOOL __attribute__((ms_abi)) lsw_AdjustWindowRectEx(lsw_RECT* r, DWORD style, BOOL menu, DWORD ex) {
    (void)r; (void)style; (void)menu; (void)ex; return 1;
}

int __attribute__((ms_abi)) lsw_wsprintfA(char* buf, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf, 1024, fmt, ap);
    va_end(ap);
    return r;
}
int __attribute__((ms_abi)) lsw_wsprintfW(uint16_t* buf, const uint16_t* fmt, ...) {
    (void)buf; (void)fmt;
    return 0;
}
int __attribute__((ms_abi)) lsw_wvsprintfA(char* buf, const char* fmt, va_list ap) {
    return vsnprintf(buf, 1024, fmt, ap);
}

HMENU __attribute__((ms_abi)) lsw_CreateMenu(void) { return NULL; }
HMENU __attribute__((ms_abi)) lsw_CreatePopupMenu(void) { return NULL; }
BOOL  __attribute__((ms_abi)) lsw_DestroyMenu(HMENU m) { (void)m; return 1; }
BOOL  __attribute__((ms_abi)) lsw_AppendMenuA(HMENU m, UINT f, uintptr_t id, const char* s) {
    (void)m; (void)f; (void)id; (void)s; return 1;
}

HMONITOR __attribute__((ms_abi)) lsw_MonitorFromWindow(HWND hwnd, DWORD flags) {
    (void)hwnd; (void)flags;
    return (HMONITOR)1; /* non-NULL fake monitor */
}
BOOL __attribute__((ms_abi)) lsw_GetMonitorInfoA(HMONITOR mon, void* info) {
    (void)mon; (void)info; return 0;
}

uint32_t __attribute__((ms_abi)) lsw_GetSysColor(int index) { (void)index; return 0x00FFFFFF; }

uint32_t __attribute__((ms_abi)) lsw_RegisterWindowMessageA(const char* msg) {
    (void)msg; return 0xC000; /* WM_APP + custom range */
}
uint32_t __attribute__((ms_abi)) lsw_RegisterWindowMessageW(const uint16_t* msg) {
    (void)msg; return 0xC000;
}

/* ============================================================
 * GDI32 stubs
 * ============================================================ */

HDC  __attribute__((ms_abi)) lsw_GetDC(HWND hwnd)         { (void)hwnd; return NULL; }
HDC  __attribute__((ms_abi)) lsw_GetWindowDC(HWND hwnd)   { (void)hwnd; return NULL; }
int  __attribute__((ms_abi)) lsw_ReleaseDC(HWND hwnd, HDC dc) { (void)hwnd; (void)dc; return 1; }
HDC  __attribute__((ms_abi)) lsw_CreateCompatibleDC(HDC dc) { (void)dc; return NULL; }
BOOL __attribute__((ms_abi)) lsw_DeleteDC(HDC dc)          { (void)dc; return 1; }

HGDIOBJ __attribute__((ms_abi)) lsw_GetStockObject(int idx) { (void)idx; return NULL; }
HGDIOBJ __attribute__((ms_abi)) lsw_SelectObject(HDC dc, HGDIOBJ obj) { (void)dc; (void)obj; return NULL; }
BOOL    __attribute__((ms_abi)) lsw_DeleteObject(HGDIOBJ obj) { (void)obj; return 1; }

HBITMAP __attribute__((ms_abi)) lsw_CreateCompatibleBitmap(HDC dc, int w, int h) {
    (void)dc; (void)w; (void)h; return NULL;
}
HBITMAP __attribute__((ms_abi)) lsw_CreateBitmap(int w, int h, UINT planes, UINT bits, const void* bits_ptr) {
    (void)w; (void)h; (void)planes; (void)bits; (void)bits_ptr; return NULL;
}

BOOL __attribute__((ms_abi)) lsw_BitBlt(HDC dst, int x, int y, int w, int h,
    HDC src, int sx, int sy, DWORD rop) {
    (void)dst; (void)x; (void)y; (void)w; (void)h; (void)src; (void)sx; (void)sy; (void)rop;
    return 0;
}
BOOL __attribute__((ms_abi)) lsw_StretchBlt(HDC dst, int dx, int dy, int dw, int dh,
    HDC src, int sx, int sy, int sw, int sh, DWORD rop) {
    (void)dst; (void)dx; (void)dy; (void)dw; (void)dh;
    (void)src; (void)sx; (void)sy; (void)sw; (void)sh; (void)rop;
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_TextOutA(HDC dc, int x, int y, const char* s, int len) {
    (void)dc; (void)x; (void)y;
    if (s && len > 0) fwrite(s, 1, (size_t)len, stdout);
    return 1;
}
BOOL __attribute__((ms_abi)) lsw_TextOutW(HDC dc, int x, int y, const uint16_t* s, int len) {
    (void)dc; (void)x; (void)y; (void)s; (void)len; return 0;
}
BOOL __attribute__((ms_abi)) lsw_ExtTextOutA(HDC dc, int x, int y, UINT opts,
    const lsw_RECT* r, const char* s, UINT cnt, const int* dx) {
    (void)dc; (void)x; (void)y; (void)opts; (void)r; (void)dx;
    if (s && cnt) fwrite(s, 1, cnt, stdout);
    return 1;
}

COLORREF __attribute__((ms_abi)) lsw_SetTextColor(HDC dc, COLORREF c) { (void)dc; (void)c; return 0; }
COLORREF __attribute__((ms_abi)) lsw_GetTextColor(HDC dc)             { (void)dc; return 0; }
COLORREF __attribute__((ms_abi)) lsw_SetBkColor(HDC dc, COLORREF c)   { (void)dc; (void)c; return 0; }
int      __attribute__((ms_abi)) lsw_SetBkMode(HDC dc, int mode)       { (void)dc; (void)mode; return 0; }
BOOL     __attribute__((ms_abi)) lsw_Rectangle(HDC dc, int l, int t, int r, int b) {
    (void)dc; (void)l; (void)t; (void)r; (void)b; return 0;
}
BOOL __attribute__((ms_abi)) lsw_FillRect(HDC dc, const lsw_RECT* r, HBRUSH br) {
    (void)dc; (void)r; (void)br; return 0;
}
BOOL __attribute__((ms_abi)) lsw_DrawFocusRect(HDC dc, const lsw_RECT* r) {
    (void)dc; (void)r; return 0;
}
BOOL __attribute__((ms_abi)) lsw_DrawText(HDC dc, const char* s, int cnt,
    lsw_RECT* r, UINT fmt) {
    (void)dc; (void)s; (void)cnt; (void)r; (void)fmt; return 0;
}

int __attribute__((ms_abi)) lsw_GetDeviceCaps(HDC dc, int idx) {
    (void)dc;
    switch (idx) {
        case 8:  return 96;  /* LOGPIXELSX */
        case 10: return 96;  /* LOGPIXELSY */
        case 88: return 32;  /* BITSPIXEL */
        case 14: return 1920; /* HORZRES */
        case 16: return 1080; /* VERTRES */
        default: return 0;
    }
}

HFONT __attribute__((ms_abi)) lsw_CreateFontA(
    int h, int w, int esc, int ori, int weight, DWORD italic, DWORD underline,
    DWORD strike, DWORD charset, DWORD outprecision, DWORD clipprecision,
    DWORD quality, DWORD pitch, const char* face)
{
    (void)h; (void)w; (void)esc; (void)ori; (void)weight; (void)italic;
    (void)underline; (void)strike; (void)charset; (void)outprecision;
    (void)clipprecision; (void)quality; (void)pitch; (void)face;
    return NULL;
}
HFONT __attribute__((ms_abi)) lsw_CreateFontW(
    int h, int w, int esc, int ori, int weight, DWORD italic, DWORD underline,
    DWORD strike, DWORD charset, DWORD outprecision, DWORD clipprecision,
    DWORD quality, DWORD pitch, const uint16_t* face)
{
    (void)h; (void)w; (void)esc; (void)ori; (void)weight; (void)italic;
    (void)underline; (void)strike; (void)charset; (void)outprecision;
    (void)clipprecision; (void)quality; (void)pitch; (void)face;
    return NULL;
}
HFONT __attribute__((ms_abi)) lsw_CreateFontIndirectA(const void* lf) { (void)lf; return NULL; }
HFONT __attribute__((ms_abi)) lsw_CreateFontIndirectW(const void* lf) { (void)lf; return NULL; }
BOOL  __attribute__((ms_abi)) lsw_GetTextMetricsA(HDC dc, void* tm) {
    (void)dc; if (tm) memset(tm, 0, 56); return 0;
}
BOOL  __attribute__((ms_abi)) lsw_GetTextMetricsW(HDC dc, void* tm) {
    (void)dc; if (tm) memset(tm, 0, 56); return 0;
}
BOOL  __attribute__((ms_abi)) lsw_GetTextExtentPoint32A(HDC dc, const char* s, int cnt, lsw_SIZE* sz) {
    (void)dc;
    if (sz) { sz->pt.x = cnt * 8; sz->pt.y = 16; }
    return 1;
}

HPEN __attribute__((ms_abi)) lsw_CreatePen(int style, int width, COLORREF color) {
    (void)style; (void)width; (void)color; return NULL;
}
HBRUSH __attribute__((ms_abi)) lsw_CreateSolidBrush(COLORREF color) { (void)color; return NULL; }
HBRUSH __attribute__((ms_abi)) lsw_CreateHatchBrush(int style, COLORREF color) {
    (void)style; (void)color; return NULL;
}
BOOL __attribute__((ms_abi)) lsw_MoveToEx(HDC dc, int x, int y, lsw_POINT* prev) {
    (void)dc; (void)x; (void)y; (void)prev; return 0;
}
BOOL __attribute__((ms_abi)) lsw_LineTo(HDC dc, int x, int y) {
    (void)dc; (void)x; (void)y; return 0;
}
BOOL __attribute__((ms_abi)) lsw_Ellipse(HDC dc, int l, int t, int r, int b) {
    (void)dc; (void)l; (void)t; (void)r; (void)b; return 0;
}
BOOL __attribute__((ms_abi)) lsw_Polygon(HDC dc, const lsw_POINT* pts, int cnt) {
    (void)dc; (void)pts; (void)cnt; return 0;
}
BOOL __attribute__((ms_abi)) lsw_Polyline(HDC dc, const lsw_POINT* pts, int cnt) {
    (void)dc; (void)pts; (void)cnt; return 0;
}
int __attribute__((ms_abi)) lsw_SetROP2(HDC dc, int rop) { (void)dc; (void)rop; return 0; }
int __attribute__((ms_abi)) lsw_GetROP2(HDC dc)          { (void)dc; return 0; }
COLORREF __attribute__((ms_abi)) lsw_GetPixel(HDC dc, int x, int y) {
    (void)dc; (void)x; (void)y; return 0;
}
COLORREF __attribute__((ms_abi)) lsw_SetPixel(HDC dc, int x, int y, COLORREF c) {
    (void)dc; (void)x; (void)y; (void)c; return 0;
}

HDC __attribute__((ms_abi)) lsw_BeginPaint(HWND hwnd, void* ps) {
    (void)hwnd; (void)ps; return NULL;
}
BOOL __attribute__((ms_abi)) lsw_EndPaint(HWND hwnd, const void* ps) {
    (void)hwnd; (void)ps; return 1;
}

/* ============================================================
 * Scrollbar
 * ============================================================ */
int  __attribute__((ms_abi)) lsw_SetScrollPos(HWND hwnd, int bar, int pos, BOOL redraw) {
    (void)hwnd; (void)bar; (void)pos; (void)redraw; return 0;
}
int  __attribute__((ms_abi)) lsw_GetScrollPos(HWND hwnd, int bar) { (void)hwnd; (void)bar; return 0; }
BOOL __attribute__((ms_abi)) lsw_SetScrollRange(HWND hwnd, int bar, int min, int max, BOOL redraw) {
    (void)hwnd; (void)bar; (void)min; (void)max; (void)redraw; return 1;
}
void __attribute__((ms_abi)) lsw_ShowScrollBar(HWND hwnd, int bar, BOOL show) {
    (void)hwnd; (void)bar; (void)show;
}

/* ============================================================
 * Clipboard (stub)
 * ============================================================ */
BOOL __attribute__((ms_abi)) lsw_OpenClipboard(HWND hwnd)  { (void)hwnd; return 0; }
BOOL __attribute__((ms_abi)) lsw_CloseClipboard(void)       { return 1; }
BOOL __attribute__((ms_abi)) lsw_EmptyClipboard(void)       { return 1; }
HANDLE __attribute__((ms_abi)) lsw_SetClipboardData(UINT fmt, HANDLE data) {
    (void)fmt; (void)data; return NULL;
}
HANDLE __attribute__((ms_abi)) lsw_GetClipboardData(UINT fmt) { (void)fmt; return NULL; }
BOOL   __attribute__((ms_abi)) lsw_IsClipboardFormatAvailable(UINT fmt) { (void)fmt; return 0; }

/* ============================================================
 * API Mapping tables — automatically picked up by Makefile wildcard
 * ============================================================ */
const win32_api_mapping_t win32_api_user32_mappings[] = {
    /* MessageBox */
    {"USER32.dll", "MessageBoxA",        (void*)lsw_MessageBoxA},
    {"USER32.dll", "MessageBoxW",        (void*)lsw_MessageBoxW},
    {"USER32.dll", "MessageBoxExA",      (void*)lsw_MessageBoxExA},
    {"user32.dll", "MessageBoxA",        (void*)lsw_MessageBoxA},
    {"user32.dll", "MessageBoxW",        (void*)lsw_MessageBoxW},
    /* System metrics */
    {"USER32.dll", "GetSystemMetrics",   (void*)lsw_GetSystemMetrics},
    {"USER32.dll", "GetSystemMetricsForDpi", (void*)lsw_GetSystemMetricsForDpi},
    /* Window creation */
    {"USER32.dll", "CreateWindowExA",    (void*)lsw_CreateWindowExA},
    {"USER32.dll", "CreateWindowExW",    (void*)lsw_CreateWindowExW},
    {"USER32.dll", "DestroyWindow",      (void*)lsw_DestroyWindow},
    {"USER32.dll", "ShowWindow",         (void*)lsw_ShowWindow},
    {"USER32.dll", "UpdateWindow",       (void*)lsw_UpdateWindow},
    {"USER32.dll", "InvalidateRect",     (void*)lsw_InvalidateRect},
    {"USER32.dll", "DefWindowProcA",     (void*)lsw_DefWindowProcA},
    {"USER32.dll", "DefWindowProcW",     (void*)lsw_DefWindowProcW},
    {"USER32.dll", "GetDesktopWindow",   (void*)lsw_GetDesktopWindow},
    {"USER32.dll", "GetForegroundWindow",(void*)lsw_GetForegroundWindow},
    {"USER32.dll", "GetActiveWindow",    (void*)lsw_GetActiveWindow},
    {"USER32.dll", "SetFocus",           (void*)lsw_SetFocus},
    {"USER32.dll", "GetFocus",           (void*)lsw_GetFocus},
    {"USER32.dll", "SetForegroundWindow",(void*)lsw_SetForegroundWindow},
    /* Class registration */
    {"USER32.dll", "RegisterClassExA",   (void*)lsw_RegisterClassExA},
    {"USER32.dll", "RegisterClassExW",   (void*)lsw_RegisterClassExW},
    {"USER32.dll", "RegisterClassA",     (void*)lsw_RegisterClassA},
    {"USER32.dll", "RegisterClassW",     (void*)lsw_RegisterClassW},
    {"USER32.dll", "UnregisterClassA",   (void*)lsw_UnregisterClassA},
    {"USER32.dll", "UnregisterClassW",   (void*)lsw_UnregisterClassW},
    /* Message loop */
    {"USER32.dll", "GetMessageA",        (void*)lsw_GetMessageA},
    {"USER32.dll", "GetMessageW",        (void*)lsw_GetMessageW},
    {"USER32.dll", "PeekMessageA",       (void*)lsw_PeekMessageA},
    {"USER32.dll", "PeekMessageW",       (void*)lsw_PeekMessageW},
    {"USER32.dll", "TranslateMessage",   (void*)lsw_TranslateMessage},
    {"USER32.dll", "DispatchMessageA",   (void*)lsw_DispatchMessageA},
    {"USER32.dll", "DispatchMessageW",   (void*)lsw_DispatchMessageW},
    {"USER32.dll", "PostQuitMessage",    (void*)lsw_PostQuitMessage},
    {"USER32.dll", "PostMessageA",       (void*)lsw_PostMessageA},
    {"USER32.dll", "PostMessageW",       (void*)lsw_PostMessageW},
    {"USER32.dll", "SendMessageA",       (void*)lsw_SendMessageA},
    {"USER32.dll", "SendMessageW",       (void*)lsw_SendMessageW},
    /* Resources */
    {"USER32.dll", "LoadIconA",          (void*)lsw_LoadIconA},
    {"USER32.dll", "LoadIconW",          (void*)lsw_LoadIconW},
    {"USER32.dll", "LoadCursorA",        (void*)lsw_LoadCursorA},
    {"USER32.dll", "LoadCursorW",        (void*)lsw_LoadCursorW},
    {"USER32.dll", "SetCursor",          (void*)lsw_SetCursor},
    {"USER32.dll", "SetCursorPos",       (void*)lsw_SetCursorPos},
    {"USER32.dll", "GetCursorPos",       (void*)lsw_GetCursorPos},
    {"USER32.dll", "ShowCursor",         (void*)lsw_ShowCursor},
    {"USER32.dll", "LoadImageA",         (void*)lsw_LoadImageA},
    {"USER32.dll", "LoadImageW",         (void*)lsw_LoadImageW},
    /* Title / text */
    {"USER32.dll", "SetWindowTextA",     (void*)lsw_SetWindowTextA},
    {"USER32.dll", "SetWindowTextW",     (void*)lsw_SetWindowTextW},
    {"USER32.dll", "GetWindowTextA",     (void*)lsw_GetWindowTextA},
    {"USER32.dll", "GetWindowTextW",     (void*)lsw_GetWindowTextW},
    /* Geometry */
    {"USER32.dll", "GetWindowRect",      (void*)lsw_GetWindowRect},
    {"USER32.dll", "GetClientRect",      (void*)lsw_GetClientRect},
    {"USER32.dll", "MoveWindow",         (void*)lsw_MoveWindow},
    {"USER32.dll", "SetWindowPos",       (void*)lsw_SetWindowPos},
    {"USER32.dll", "ScreenToClient",     (void*)lsw_ScreenToClient},
    {"USER32.dll", "ClientToScreen",     (void*)lsw_ClientToScreen},
    {"USER32.dll", "AdjustWindowRect",   (void*)lsw_AdjustWindowRect},
    {"USER32.dll", "AdjustWindowRectEx", (void*)lsw_AdjustWindowRectEx},
    /* Enable / visible */
    {"USER32.dll", "EnableWindow",       (void*)lsw_EnableWindow},
    {"USER32.dll", "IsWindowVisible",    (void*)lsw_IsWindowVisible},
    {"USER32.dll", "IsWindow",           (void*)lsw_IsWindow},
    {"USER32.dll", "IsWindowEnabled",    (void*)lsw_IsWindowEnabled},
    /* Dialogs */
    {"USER32.dll", "CreateDialogParamA", (void*)lsw_CreateDialogParamA},
    {"USER32.dll", "CreateDialogParamW", (void*)lsw_CreateDialogParamW},
    {"USER32.dll", "DialogBoxParamA",    (void*)lsw_DialogBoxParamA},
    {"USER32.dll", "DialogBoxParamW",    (void*)lsw_DialogBoxParamW},
    {"USER32.dll", "EndDialog",          (void*)lsw_EndDialog},
    {"USER32.dll", "GetDlgItem",         (void*)lsw_GetDlgItem},
    {"USER32.dll", "GetDlgItemTextA",    (void*)lsw_GetDlgItemTextA},
    {"USER32.dll", "SetDlgItemTextA",    (void*)lsw_SetDlgItemTextA},
    {"USER32.dll", "GetDlgItemInt",      (void*)lsw_GetDlgItemInt},
    {"USER32.dll", "SetDlgItemInt",      (void*)lsw_SetDlgItemInt},
    {"USER32.dll", "CheckDlgButton",     (void*)lsw_CheckDlgButton},
    {"USER32.dll", "IsDlgButtonChecked", (void*)lsw_IsDlgButtonChecked},
    /* Misc */
    {"USER32.dll", "MessageBeep",        (void*)lsw_MessageBeep},
    {"USER32.dll", "FlashWindow",        (void*)lsw_FlashWindow},
    {"USER32.dll", "keybd_event",        (void*)lsw_keybd_event},
    {"USER32.dll", "mouse_event",        (void*)lsw_mouse_event},
    {"USER32.dll", "GetKeyState",        (void*)lsw_GetKeyState},
    {"USER32.dll", "GetAsyncKeyState",   (void*)lsw_GetAsyncKeyState},
    {"USER32.dll", "FindWindowA",        (void*)lsw_FindWindowA},
    {"USER32.dll", "FindWindowW",        (void*)lsw_FindWindowW},
    {"USER32.dll", "SetWindowLongPtrA",  (void*)lsw_SetWindowLongPtrA},
    {"USER32.dll", "GetWindowLongPtrA",  (void*)lsw_GetWindowLongPtrA},
    {"USER32.dll", "SetWindowLongA",     (void*)lsw_SetWindowLongA},
    {"USER32.dll", "GetWindowLongA",     (void*)lsw_GetWindowLongA},
    {"USER32.dll", "GetWindowThreadProcessId", (void*)lsw_GetWindowThreadProcessId},
    {"USER32.dll", "wsprintfA",          (void*)lsw_wsprintfA},
    {"USER32.dll", "wsprintfW",          (void*)lsw_wsprintfW},
    {"USER32.dll", "wvsprintfA",         (void*)lsw_wvsprintfA},
    {"USER32.dll", "CreateMenu",         (void*)lsw_CreateMenu},
    {"USER32.dll", "CreatePopupMenu",    (void*)lsw_CreatePopupMenu},
    {"USER32.dll", "DestroyMenu",        (void*)lsw_DestroyMenu},
    {"USER32.dll", "AppendMenuA",        (void*)lsw_AppendMenuA},
    {"USER32.dll", "MonitorFromWindow",  (void*)lsw_MonitorFromWindow},
    {"USER32.dll", "GetMonitorInfoA",    (void*)lsw_GetMonitorInfoA},
    {"USER32.dll", "GetSysColor",        (void*)lsw_GetSysColor},
    {"USER32.dll", "RegisterWindowMessageA", (void*)lsw_RegisterWindowMessageA},
    {"USER32.dll", "RegisterWindowMessageW", (void*)lsw_RegisterWindowMessageW},
    /* Scrollbar */
    {"USER32.dll", "SetScrollPos",       (void*)lsw_SetScrollPos},
    {"USER32.dll", "GetScrollPos",       (void*)lsw_GetScrollPos},
    {"USER32.dll", "SetScrollRange",     (void*)lsw_SetScrollRange},
    {"USER32.dll", "ShowScrollBar",      (void*)lsw_ShowScrollBar},
    /* Clipboard */
    {"USER32.dll", "OpenClipboard",      (void*)lsw_OpenClipboard},
    {"USER32.dll", "CloseClipboard",     (void*)lsw_CloseClipboard},
    {"USER32.dll", "EmptyClipboard",     (void*)lsw_EmptyClipboard},
    {"USER32.dll", "SetClipboardData",   (void*)lsw_SetClipboardData},
    {"USER32.dll", "GetClipboardData",   (void*)lsw_GetClipboardData},
    {"USER32.dll", "IsClipboardFormatAvailable", (void*)lsw_IsClipboardFormatAvailable},
    /* GDI32 */
    {"GDI32.dll",  "GetDC",              (void*)lsw_GetDC},
    {"gdi32.dll",  "GetDC",              (void*)lsw_GetDC},
    {"GDI32.dll",  "GetWindowDC",        (void*)lsw_GetWindowDC},
    {"GDI32.dll",  "ReleaseDC",          (void*)lsw_ReleaseDC},
    {"GDI32.dll",  "CreateCompatibleDC", (void*)lsw_CreateCompatibleDC},
    {"GDI32.dll",  "DeleteDC",           (void*)lsw_DeleteDC},
    {"GDI32.dll",  "GetStockObject",     (void*)lsw_GetStockObject},
    {"GDI32.dll",  "SelectObject",       (void*)lsw_SelectObject},
    {"GDI32.dll",  "DeleteObject",       (void*)lsw_DeleteObject},
    {"GDI32.dll",  "CreateCompatibleBitmap", (void*)lsw_CreateCompatibleBitmap},
    {"GDI32.dll",  "CreateBitmap",       (void*)lsw_CreateBitmap},
    {"GDI32.dll",  "BitBlt",             (void*)lsw_BitBlt},
    {"GDI32.dll",  "StretchBlt",         (void*)lsw_StretchBlt},
    {"GDI32.dll",  "TextOutA",           (void*)lsw_TextOutA},
    {"GDI32.dll",  "TextOutW",           (void*)lsw_TextOutW},
    {"GDI32.dll",  "ExtTextOutA",        (void*)lsw_ExtTextOutA},
    {"GDI32.dll",  "SetTextColor",       (void*)lsw_SetTextColor},
    {"GDI32.dll",  "GetTextColor",       (void*)lsw_GetTextColor},
    {"GDI32.dll",  "SetBkColor",         (void*)lsw_SetBkColor},
    {"GDI32.dll",  "SetBkMode",          (void*)lsw_SetBkMode},
    {"GDI32.dll",  "Rectangle",          (void*)lsw_Rectangle},
    {"GDI32.dll",  "FillRect",           (void*)lsw_FillRect},
    {"GDI32.dll",  "DrawFocusRect",      (void*)lsw_DrawFocusRect},
    {"GDI32.dll",  "DrawText",           (void*)lsw_DrawText},
    {"GDI32.dll",  "GetDeviceCaps",      (void*)lsw_GetDeviceCaps},
    {"GDI32.dll",  "CreateFontA",        (void*)lsw_CreateFontA},
    {"GDI32.dll",  "CreateFontW",        (void*)lsw_CreateFontW},
    {"GDI32.dll",  "CreateFontIndirectA",(void*)lsw_CreateFontIndirectA},
    {"GDI32.dll",  "CreateFontIndirectW",(void*)lsw_CreateFontIndirectW},
    {"GDI32.dll",  "GetTextMetricsA",    (void*)lsw_GetTextMetricsA},
    {"GDI32.dll",  "GetTextMetricsW",    (void*)lsw_GetTextMetricsW},
    {"GDI32.dll",  "GetTextExtentPoint32A", (void*)lsw_GetTextExtentPoint32A},
    {"GDI32.dll",  "CreatePen",          (void*)lsw_CreatePen},
    {"GDI32.dll",  "CreateSolidBrush",   (void*)lsw_CreateSolidBrush},
    {"GDI32.dll",  "CreateHatchBrush",   (void*)lsw_CreateHatchBrush},
    {"GDI32.dll",  "MoveToEx",           (void*)lsw_MoveToEx},
    {"GDI32.dll",  "LineTo",             (void*)lsw_LineTo},
    {"GDI32.dll",  "Ellipse",            (void*)lsw_Ellipse},
    {"GDI32.dll",  "Polygon",            (void*)lsw_Polygon},
    {"GDI32.dll",  "Polyline",           (void*)lsw_Polyline},
    {"GDI32.dll",  "SetROP2",            (void*)lsw_SetROP2},
    {"GDI32.dll",  "GetROP2",            (void*)lsw_GetROP2},
    {"GDI32.dll",  "GetPixel",           (void*)lsw_GetPixel},
    {"GDI32.dll",  "SetPixel",           (void*)lsw_SetPixel},
    {"GDI32.dll",  "BeginPaint",         (void*)lsw_BeginPaint},
    {"GDI32.dll",  "EndPaint",           (void*)lsw_EndPaint},
    /* Sentinel */
    {NULL, NULL, NULL}
};

const size_t win32_api_user32_mappings_count =
    (sizeof(win32_api_user32_mappings) / sizeof(win32_api_user32_mappings[0])) - 1;
