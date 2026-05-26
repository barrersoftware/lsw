#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
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

uint32_t LSW_MSABI lsw_GetFileVersionInfoSizeW(const uint16_t* lptstrFilename, uint32_t* lpdwHandle) { (void)lptstrFilename; if (lpdwHandle) *lpdwHandle = 0; return 0; }
uint32_t LSW_MSABI lsw_GetFileVersionInfoSizeA(const char* lptstrFilename, uint32_t* lpdwHandle) { (void)lptstrFilename; if (lpdwHandle) *lpdwHandle = 0; return 0; }
int LSW_MSABI lsw_GetFileVersionInfoW(const uint16_t* lptstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData) { (void)lptstrFilename; (void)dwHandle; (void)dwLen; (void)lpData; return 0; }
int LSW_MSABI lsw_GetFileVersionInfoA(const char* lptstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData) { (void)lptstrFilename; (void)dwHandle; (void)dwLen; (void)lpData; return 0; }
int LSW_MSABI lsw_VerQueryValueW(const void* pBlock, const uint16_t* lpSubBlock, void** lplpBuffer, uint32_t* puLen) { (void)pBlock; (void)lpSubBlock; if (lplpBuffer) *lplpBuffer = NULL; if (puLen) *puLen = 0; return 0; }
int LSW_MSABI lsw_VerQueryValueA(const void* pBlock, const char* lpSubBlock, void** lplpBuffer, uint32_t* puLen) { (void)pBlock; (void)lpSubBlock; if (lplpBuffer) *lplpBuffer = NULL; if (puLen) *puLen = 0; return 0; }
int LSW_MSABI lsw_GetFileVersionInfoExW(uint32_t dwFlags, const uint16_t* lpwstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData) { (void)dwFlags; (void)lpwstrFilename; (void)dwHandle; (void)dwLen; (void)lpData; return 0; }
uint32_t LSW_MSABI lsw_GetFileVersionInfoSizeExW(uint32_t dwFlags, const uint16_t* lpwstrFilename, uint32_t* lpdwHandle) { (void)dwFlags; (void)lpwstrFilename; if (lpdwHandle) *lpdwHandle = 0; return 0; }
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
uint32_t LSW_MSABI lsw_GetAdaptersAddresses(uint32_t Family, uint32_t Flags, void* Reserved, void* AdapterAddresses, uint32_t* SizePointer) { (void)Family; (void)Flags; (void)Reserved; (void)AdapterAddresses; if (SizePointer) *SizePointer = 0; return 111; }
uint32_t LSW_MSABI lsw_GetIfTable(void* pIfTable, uint32_t* pdwSize, int bOrder) { (void)pIfTable; (void)bOrder; if (pdwSize) *pdwSize = 0; return 122; }
uint32_t LSW_MSABI lsw_GetIpAddrTable(void* pIpAddrTable, uint32_t* pdwSize, int bOrder) { (void)pIpAddrTable; (void)bOrder; if (pdwSize) *pdwSize = 0; return 122; }
uint32_t LSW_MSABI lsw_GetIpForwardTable(void* pIpForwardTable, uint32_t* pdwSize, int bOrder) { (void)pIpForwardTable; (void)bOrder; if (pdwSize) *pdwSize = 0; return 122; }
void* LSW_MSABI lsw_IcmpCreateFile(void) { return (void*)0xB001; }
int LSW_MSABI lsw_IcmpCloseHandle(void* IcmpHandle) { (void)IcmpHandle; return 1; }
uint32_t LSW_MSABI lsw_IcmpSendEcho(void* IcmpHandle, uint32_t DestinationAddress, void* RequestData, uint16_t RequestSize, void* RequestOptions, void* ReplyBuffer, uint32_t ReplySize, uint32_t Timeout) { (void)IcmpHandle; (void)DestinationAddress; (void)RequestData; (void)RequestSize; (void)RequestOptions; (void)ReplyBuffer; (void)ReplySize; (void)Timeout; return 0; }
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
