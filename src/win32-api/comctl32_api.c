#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"

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

#define LSW_MSABI __attribute__((ms_abi))
#define MAP(fn) {"comctl32.dll", #fn, (void*)lsw_##fn}

void LSW_MSABI lsw_InitCommonControls(void) {
    LSW_LOG_DEBUG("InitCommonControls");
}

int LSW_MSABI lsw_InitCommonControlsEx(void* lpInitCtrls) {
    (void)lpInitCtrls;
    return 1;
}

void* LSW_MSABI lsw_ImageList_Create(int cx, int cy, uint32_t flags, int cInitial, int cGrow) {
    (void)cx; (void)cy; (void)flags; (void)cInitial; (void)cGrow;
    return calloc(1, 64);
}

int LSW_MSABI lsw_ImageList_Destroy(void* himl) {
    if (himl) free(himl);
    return 1;
}

int LSW_MSABI lsw_ImageList_Add(void* himl, void* hbmImage, void* hbmMask) {
    (void)himl; (void)hbmImage; (void)hbmMask;
    return 0;
}

int LSW_MSABI lsw_ImageList_AddIcon(void* himl, void* hicon) {
    (void)himl; (void)hicon;
    return 0;
}

int LSW_MSABI lsw_ImageList_AddMasked(void* himl, void* hbmImage, uint32_t crMask) {
    (void)himl; (void)hbmImage; (void)crMask;
    return 0;
}

int LSW_MSABI lsw_ImageList_Remove(void* himl, int i) {
    (void)himl; (void)i;
    return 1;
}

void* LSW_MSABI lsw_ImageList_GetIcon(void* himl, int i, uint32_t flags) {
    (void)himl; (void)i; (void)flags;
    return NULL;
}

int LSW_MSABI lsw_ImageList_GetImageCount(void* himl) {
    (void)himl;
    return 0;
}

int LSW_MSABI lsw_ImageList_SetImageCount(void* himl, uint32_t uNewCount) {
    (void)himl; (void)uNewCount;
    return 1;
}

int LSW_MSABI lsw_ImageList_Replace(void* himl, int i, void* hbmImage, void* hbmMask) {
    (void)himl; (void)i; (void)hbmImage; (void)hbmMask;
    return 1;
}

int LSW_MSABI lsw_ImageList_ReplaceIcon(void* himl, int i, void* hicon) {
    (void)himl; (void)i; (void)hicon;
    return 0;
}

int LSW_MSABI lsw_ImageList_Draw(void* himl, int i, void* hdcDst, int x, int y, uint32_t fStyle) {
    (void)himl; (void)i; (void)hdcDst; (void)x; (void)y; (void)fStyle;
    return 1;
}

int LSW_MSABI lsw_ImageList_DrawEx(void* himl, int i, void* hdc, int x, int y, int dx, int dy, uint32_t rgbBk, uint32_t rgbFg, uint32_t fStyle) {
    (void)himl; (void)i; (void)hdc; (void)x; (void)y; (void)dx; (void)dy; (void)rgbBk; (void)rgbFg; (void)fStyle;
    return 1;
}

int LSW_MSABI lsw_ImageList_DrawIndirect(void* pimldp) {
    (void)pimldp;
    return 1;
}

uint32_t LSW_MSABI lsw_ImageList_GetBkColor(void* himl) {
    (void)himl;
    return 0xFFFFFFFFu;
}

uint32_t LSW_MSABI lsw_ImageList_SetBkColor(void* himl, uint32_t clrBk) {
    (void)himl; (void)clrBk;
    return 0xFFFFFFFFu;
}

int LSW_MSABI lsw_ImageList_GetImageInfo(void* himl, int i, void* pImageInfo) {
    (void)himl; (void)i; (void)pImageInfo;
    return 0;
}

int LSW_MSABI lsw_ImageList_Copy(void* himlDst, int iDst, void* himlSrc, int iSrc, uint32_t uFlags) {
    (void)himlDst; (void)iDst; (void)himlSrc; (void)iSrc; (void)uFlags;
    return 1;
}

void* LSW_MSABI lsw_ImageList_Merge(void* himl1, int i1, void* himl2, int i2, int dx, int dy) {
    (void)himl1; (void)i1; (void)himl2; (void)i2; (void)dx; (void)dy;
    return calloc(1, 64);
}

void* LSW_MSABI lsw_ImageList_Duplicate(void* himl) {
    (void)himl;
    return calloc(1, 64);
}

int LSW_MSABI lsw_ImageList_BeginDrag(void* himlTrack, int iTrack, int dxHotspot, int dyHotspot) {
    (void)himlTrack; (void)iTrack; (void)dxHotspot; (void)dyHotspot;
    return 1;
}

void LSW_MSABI lsw_ImageList_EndDrag(void) {
}

int LSW_MSABI lsw_ImageList_DragEnter(void* hwndLock, int x, int y) {
    (void)hwndLock; (void)x; (void)y;
    return 1;
}

int LSW_MSABI lsw_ImageList_DragLeave(void* hwndLock) {
    (void)hwndLock;
    return 1;
}

int LSW_MSABI lsw_ImageList_DragMove(int x, int y) {
    (void)x; (void)y;
    return 1;
}

int LSW_MSABI lsw_ImageList_DragShowNolock(int fShow) {
    (void)fShow;
    return 1;
}

void* LSW_MSABI lsw_ImageList_GetDragImage(void* ppt, void* pptHotspot) {
    (void)ppt; (void)pptHotspot;
    return NULL;
}

void* LSW_MSABI lsw_ImageList_Read(void* pstm) {
    (void)pstm;
    return NULL;
}

int LSW_MSABI lsw_ImageList_Write(void* himl, void* pstm) {
    (void)himl; (void)pstm;
    return 1;
}

int32_t LSW_MSABI lsw_ImageList_ReadEx(uint32_t dwFlags, void* pstm, const void* riid, void** ppv) {
    (void)dwFlags; (void)pstm; (void)riid;
    if (ppv) *ppv = NULL;
    return E_NOTIMPL;
}

int32_t LSW_MSABI lsw_ImageList_WriteEx(void* himl, uint32_t dwFlags, void* pstm) {
    (void)himl; (void)dwFlags; (void)pstm;
    return S_OK;
}

void* LSW_MSABI lsw_ImageList_LoadImageW(void* hi, const uint16_t* lpbmp, int cx, int cGrow, uint32_t crMask, uint32_t uType, uint32_t uFlags) {
    (void)hi; (void)lpbmp; (void)cx; (void)cGrow; (void)crMask; (void)uType; (void)uFlags;
    return calloc(1, 64);
}

void* LSW_MSABI lsw_ImageList_LoadImageA(void* hi, const char* lpbmp, int cx, int cGrow, uint32_t crMask, uint32_t uType, uint32_t uFlags) {
    (void)hi; (void)lpbmp; (void)cx; (void)cGrow; (void)crMask; (void)uType; (void)uFlags;
    return calloc(1, 64);
}

int32_t LSW_MSABI lsw_PropertySheetW(void* lppsh) {
    (void)lppsh;
    return 0;
}

int32_t LSW_MSABI lsw_PropertySheetA(void* lppsh) {
    (void)lppsh;
    return 0;
}

void* LSW_MSABI lsw_CreatePropertySheetPageW(void* lppsp) {
    (void)lppsp;
    return (void*)0x7001;
}

void* LSW_MSABI lsw_CreatePropertySheetPageA(void* lppsp) {
    (void)lppsp;
    return (void*)0x7002;
}

int LSW_MSABI lsw_DestroyPropertySheetPage(void* hPSPage) {
    (void)hPSPage;
    return 1;
}

void* LSW_MSABI lsw_CreateToolbarEx(void* hwnd, uint32_t ws, uint32_t wID, int nBitmaps, void* hBMInst, uint32_t wBMID, void* lpButtons, int iNumButtons, int dxButton, int dyButton, int dxBitmap, int dyBitmap, uint32_t uStructSize) {
    (void)hwnd; (void)ws; (void)wID; (void)nBitmaps; (void)hBMInst; (void)wBMID; (void)lpButtons; (void)iNumButtons; (void)dxButton; (void)dyButton; (void)dxBitmap; (void)dyBitmap; (void)uStructSize;
    return NULL;
}

void* LSW_MSABI lsw_CreateMappedBitmap(void* hInstance, int32_t idBitmap, uint32_t wFlags, void* lpColorMap, int iNumMaps) {
    (void)hInstance; (void)idBitmap; (void)wFlags; (void)lpColorMap; (void)iNumMaps;
    return NULL;
}

void* LSW_MSABI lsw_CreateUpDownControl(uint32_t dwStyle, int x, int y, int cx, int cy, void* hParent, int nID, void* hInst, void* hBuddy, int nUpper, int nLower, int nPos) {
    (void)dwStyle; (void)x; (void)y; (void)cx; (void)cy; (void)hParent; (void)nID; (void)hInst; (void)hBuddy; (void)nUpper; (void)nLower; (void)nPos;
    return NULL;
}

int32_t LSW_MSABI lsw_TaskDialog(void* hwndOwner, void* hInstance, const uint16_t* pszWindowTitle, const uint16_t* pszMainInstruction, const uint16_t* pszContent, uint32_t dwCommonButtons, const uint16_t* pszIcon, int* pnButton) {
    (void)hwndOwner; (void)hInstance; (void)pszWindowTitle; (void)pszMainInstruction; (void)pszContent; (void)dwCommonButtons; (void)pszIcon;
    if (pnButton) *pnButton = 1;
    return S_OK;
}

int32_t LSW_MSABI lsw_TaskDialogIndirect(void* pTaskConfig, int* pnButton, int* pnRadioButton, int* pfVerificationFlagChecked) {
    (void)pTaskConfig; (void)pnRadioButton; (void)pfVerificationFlagChecked;
    if (pnButton) *pnButton = 1;
    return S_OK;
}

int32_t LSW_MSABI lsw_LoadIconWithScaleDown(void* hinst, const uint16_t* pszName, int cx, int cy, void** phico) {
    (void)hinst; (void)pszName; (void)cx; (void)cy;
    if (phico) *phico = NULL;
    return E_NOTIMPL;
}

int LSW_MSABI lsw_DrawShadowText(void* hdc, const uint16_t* pszText, uint32_t cch, void* prc, uint32_t dwFlags, uint32_t crText, uint32_t crShadow, int ixOffset, int iyOffset) {
    (void)hdc; (void)pszText; (void)cch; (void)prc; (void)dwFlags; (void)crText; (void)crShadow; (void)ixOffset; (void)iyOffset;
    return 0;
}

int LSW_MSABI lsw_FlatSB_EnableScrollBar(void* hWnd, int wSBflags, uint32_t wArrows) {
    (void)hWnd; (void)wSBflags; (void)wArrows;
    return 0;
}

int LSW_MSABI lsw_FlatSB_GetScrollInfo(void* hWnd, int fnBar, void* lpsi) {
    (void)hWnd; (void)fnBar; (void)lpsi;
    return 0;
}

int LSW_MSABI lsw_FlatSB_GetScrollPos(void* hWnd, int nBar) {
    (void)hWnd; (void)nBar;
    return 0;
}

int LSW_MSABI lsw_FlatSB_GetScrollProp(void* hWnd, int propIndex, int32_t* pValue) {
    (void)hWnd; (void)propIndex; (void)pValue;
    return 0;
}

int LSW_MSABI lsw_FlatSB_GetScrollRange(void* hWnd, int nBar, int32_t* lpMinPos, int32_t* lpMaxPos) {
    (void)hWnd; (void)nBar;
    if (lpMinPos) *lpMinPos = 0;
    if (lpMaxPos) *lpMaxPos = 100;
    return 0;
}

int LSW_MSABI lsw_FlatSB_SetScrollInfo(void* hWnd, int fnBar, void* lpsi, int fRedraw) {
    (void)hWnd; (void)fnBar; (void)lpsi; (void)fRedraw;
    return 0;
}

int LSW_MSABI lsw_FlatSB_SetScrollPos(void* hWnd, int nBar, int nPos, int fRedraw) {
    (void)hWnd; (void)nBar; (void)fRedraw;
    return nPos;
}

int LSW_MSABI lsw_FlatSB_SetScrollProp(uint32_t id, uint32_t index, int32_t newValue, int fRedraw) {
    (void)id; (void)index; (void)newValue; (void)fRedraw;
    return 1;
}

int LSW_MSABI lsw_FlatSB_SetScrollRange(void* hWnd, int nBar, int nMinPos, int nMaxPos, int fRedraw) {
    (void)hWnd; (void)nBar; (void)nMinPos; (void)nMaxPos; (void)fRedraw;
    return 1;
}

int LSW_MSABI lsw_FlatSB_ShowScrollBar(void* hWnd, int wBar, int fShow) {
    (void)hWnd; (void)wBar; (void)fShow;
    return 1;
}

int LSW_MSABI lsw_InitializeFlatSB(void* hWnd) {
    (void)hWnd;
    return S_OK;
}

int32_t LSW_MSABI lsw_UninitializeFlatSB(void* hWnd) {
    (void)hWnd;
    return S_OK;
}

int LSW_MSABI lsw__TrackMouseEvent(void* lpEventTrack) {
    (void)lpEventTrack;
    return 1;
}

int LSW_MSABI lsw_ShowHideMenuCtl(void* hWnd, uint32_t uFlags, int32_t* lpInfo) {
    (void)hWnd; (void)uFlags; (void)lpInfo;
    return 1;
}

void LSW_MSABI lsw_GetEffectiveClientRect(void* hWnd, void* lprc, const int32_t* lpInfo) {
    (void)hWnd; (void)lprc; (void)lpInfo;
}

void LSW_MSABI lsw_MenuHelp(uint32_t uMsg, uint64_t wParam, int64_t lParam, void* hMainMenu, void* hInst, void* hwndStatus, uint32_t* lpwIDs) {
    (void)uMsg; (void)wParam; (void)lParam; (void)hMainMenu; (void)hInst; (void)hwndStatus; (void)lpwIDs;
}

void LSW_MSABI lsw_DrawStatusTextW(void* hDC, void* lprc, const uint16_t* pszText, uint32_t uFlags) {
    (void)hDC; (void)lprc; (void)pszText; (void)uFlags;
}

void LSW_MSABI lsw_DrawStatusTextA(void* hDC, void* lprc, const char* pszText, uint32_t uFlags) {
    (void)hDC; (void)lprc; (void)pszText; (void)uFlags;
}

void* LSW_MSABI lsw_CreateStatusWindowW(int32_t style, const uint16_t* lpszText, void* hwndParent, uint32_t wID) {
    (void)style; (void)lpszText; (void)hwndParent; (void)wID;
    return NULL;
}

void* LSW_MSABI lsw_CreateStatusWindowA(int32_t style, const char* lpszText, void* hwndParent, uint32_t wID) {
    (void)style; (void)lpszText; (void)hwndParent; (void)wID;
    return NULL;
}

const win32_api_mapping_t win32_api_comctl32_mappings[] = {
    MAP(InitCommonControls),
    MAP(InitCommonControlsEx),
    MAP(ImageList_Create),
    MAP(ImageList_Destroy),
    MAP(ImageList_Add),
    MAP(ImageList_AddIcon),
    MAP(ImageList_AddMasked),
    MAP(ImageList_Remove),
    MAP(ImageList_GetIcon),
    MAP(ImageList_GetImageCount),
    MAP(ImageList_SetImageCount),
    MAP(ImageList_Replace),
    MAP(ImageList_ReplaceIcon),
    MAP(ImageList_Draw),
    MAP(ImageList_DrawEx),
    MAP(ImageList_DrawIndirect),
    MAP(ImageList_GetBkColor),
    MAP(ImageList_SetBkColor),
    MAP(ImageList_GetImageInfo),
    MAP(ImageList_Copy),
    MAP(ImageList_Merge),
    MAP(ImageList_Duplicate),
    MAP(ImageList_BeginDrag),
    MAP(ImageList_EndDrag),
    MAP(ImageList_DragEnter),
    MAP(ImageList_DragLeave),
    MAP(ImageList_DragMove),
    MAP(ImageList_DragShowNolock),
    MAP(ImageList_GetDragImage),
    MAP(ImageList_Read),
    MAP(ImageList_Write),
    MAP(ImageList_ReadEx),
    MAP(ImageList_WriteEx),
    MAP(ImageList_LoadImageW),
    MAP(ImageList_LoadImageA),
    MAP(PropertySheetW),
    MAP(PropertySheetA),
    MAP(CreatePropertySheetPageW),
    MAP(CreatePropertySheetPageA),
    MAP(DestroyPropertySheetPage),
    MAP(CreateToolbarEx),
    MAP(CreateMappedBitmap),
    MAP(CreateUpDownControl),
    MAP(TaskDialog),
    MAP(TaskDialogIndirect),
    MAP(LoadIconWithScaleDown),
    MAP(DrawShadowText),
    MAP(FlatSB_EnableScrollBar),
    MAP(FlatSB_GetScrollInfo),
    MAP(FlatSB_GetScrollPos),
    MAP(FlatSB_GetScrollProp),
    MAP(FlatSB_GetScrollRange),
    MAP(FlatSB_SetScrollInfo),
    MAP(FlatSB_SetScrollPos),
    MAP(FlatSB_SetScrollProp),
    MAP(FlatSB_SetScrollRange),
    MAP(FlatSB_ShowScrollBar),
    MAP(InitializeFlatSB),
    MAP(UninitializeFlatSB),
    MAP(_TrackMouseEvent),
    MAP(ShowHideMenuCtl),
    MAP(GetEffectiveClientRect),
    MAP(MenuHelp),
    MAP(DrawStatusTextW),
    MAP(DrawStatusTextA),
    MAP(CreateStatusWindowW),
    MAP(CreateStatusWindowA),
    {NULL, NULL, NULL}
};

const size_t win32_api_comctl32_mappings_count =
    (sizeof(win32_api_comctl32_mappings) / sizeof(win32_api_comctl32_mappings[0])) - 1;
