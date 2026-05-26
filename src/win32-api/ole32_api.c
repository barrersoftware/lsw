#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <pthread.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"

typedef int32_t HRESULT;
typedef void* LPVOID;
typedef uint32_t DWORD;
typedef int BOOL;
#define S_OK 0
#define S_FALSE 1
#define E_FAIL ((int32_t)0x80004005)
#define E_NOTIMPL ((int32_t)0x80004001)
#define E_INVALIDARG ((int32_t)0x80070057)
#define E_OUTOFMEMORY ((int32_t)0x8007000E)
#define CO_E_NOTINITIALIZED ((int32_t)0x800401F0)
#define COINIT_MULTITHREADED 0x0
#define COINIT_APARTMENTTHREADED 0x2
#define TRUE 1
#define FALSE 0

typedef struct { uint32_t Data1; uint16_t Data2; uint16_t Data3; uint8_t Data4[8]; } GUID;
typedef GUID IID;
typedef GUID CLSID;

static _Thread_local int s_com_initialized = 0;
static _Thread_local int s_com_apartment = 0;

#define LSW_UNUSED(x) ((void)(x))

extern int getpid(void);

static void lsw_utf16_to_ascii(const uint16_t* src, char* dst, size_t dst_size) {
    size_t i = 0;

    if (!dst || dst_size == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    while (i + 1 < dst_size && src[i]) {
        dst[i] = (char)(src[i] & 0xFF);
        i++;
    }
    dst[i] = '\0';
}

static size_t lsw_ascii_to_utf16(const char* src, uint16_t* dst, size_t dst_size) {
    size_t i = 0;

    if (!src || !dst || dst_size == 0) {
        return 0;
    }

    while (src[i] && i + 1 < dst_size) {
        dst[i] = (uint16_t)(unsigned char)src[i];
        i++;
    }
    dst[i] = 0;
    return i + 1;
}

int32_t __attribute__((ms_abi)) lsw_CoInitialize(void* pvReserved) {
    LSW_UNUSED(pvReserved);
    s_com_initialized = 1;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoInitializeEx(void* pvReserved, uint32_t dwCoInit) {
    LSW_UNUSED(pvReserved);
    s_com_initialized = 1;
    s_com_apartment = (int)dwCoInit;
    return S_OK;
}

void __attribute__((ms_abi)) lsw_CoUninitialize(void) {
    s_com_initialized = 0;
    s_com_apartment = 0;
}

int32_t __attribute__((ms_abi)) lsw_CoCreateInstance(const GUID* rclsid, void* pUnkOuter, uint32_t dwClsContext, const GUID* riid, void** ppv) {
    LSW_UNUSED(rclsid);
    LSW_UNUSED(pUnkOuter);
    LSW_UNUSED(dwClsContext);
    LSW_UNUSED(riid);
    if (ppv) {
        *ppv = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CoCreateInstanceEx(const GUID* Clsid, void* punkOuter, uint32_t dwClsCtx, void* pServerInfo, uint32_t dwCount, void* pResults) {
    LSW_UNUSED(Clsid);
    LSW_UNUSED(punkOuter);
    LSW_UNUSED(dwClsCtx);
    LSW_UNUSED(pServerInfo);
    LSW_UNUSED(dwCount);
    LSW_UNUSED(pResults);
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CoGetClassObject(const GUID* rclsid, uint32_t dwClsContext, void* pvReserved, const GUID* riid, void** ppv) {
    LSW_UNUSED(rclsid);
    LSW_UNUSED(dwClsContext);
    LSW_UNUSED(pvReserved);
    LSW_UNUSED(riid);
    if (ppv) {
        *ppv = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CoRegisterClassObject(const GUID* rclsid, void* pUnk, uint32_t dwClsContext, uint32_t flags, uint32_t* lpdwRegister) {
    LSW_UNUSED(rclsid);
    LSW_UNUSED(pUnk);
    LSW_UNUSED(dwClsContext);
    LSW_UNUSED(flags);
    if (lpdwRegister) {
        *lpdwRegister = 1;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoRevokeClassObject(uint32_t dwRegister) {
    LSW_UNUSED(dwRegister);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoCreateGuid(GUID* pguid) {
    size_t i;

    if (!pguid) {
        return E_INVALIDARG;
    }

    pguid->Data1 = (uint32_t)rand();
    pguid->Data2 = (uint16_t)(rand() & 0xFFFF);
    pguid->Data3 = (uint16_t)((rand() & 0x0FFF) | 0x4000);
    pguid->Data4[0] = (uint8_t)((rand() & 0x3F) | 0x80);
    for (i = 1; i < sizeof(pguid->Data4); i++) {
        pguid->Data4[i] = (uint8_t)(rand() & 0xFF);
    }

    return S_OK;
}

void* __attribute__((ms_abi)) lsw_CoTaskMemAlloc(size_t cb) {
    return malloc(cb);
}

void __attribute__((ms_abi)) lsw_CoTaskMemFree(void* pv) {
    if (pv) {
        free(pv);
    }
}

void* __attribute__((ms_abi)) lsw_CoTaskMemRealloc(void* pv, size_t cb) {
    return realloc(pv, cb);
}

int __attribute__((ms_abi)) lsw_StringFromGUID2(const GUID* rguid, uint16_t* lpsz, int cchMax) {
    char buffer[39];
    int written;

    if (!rguid || !lpsz || cchMax < 39) {
        return 0;
    }

    written = snprintf(
        buffer,
        sizeof(buffer),
        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        rguid->Data1,
        rguid->Data2,
        rguid->Data3,
        rguid->Data4[0],
        rguid->Data4[1],
        rguid->Data4[2],
        rguid->Data4[3],
        rguid->Data4[4],
        rguid->Data4[5],
        rguid->Data4[6],
        rguid->Data4[7]
    );
    if (written != 38) {
        return 0;
    }

    if (lsw_ascii_to_utf16(buffer, lpsz, (size_t)cchMax) == 0) {
        return 0;
    }

    return written + 1;
}

int32_t __attribute__((ms_abi)) lsw_StringFromCLSID(const GUID* rclsid, uint16_t** lplpsz) {
    uint16_t* text;

    if (!rclsid || !lplpsz) {
        return E_INVALIDARG;
    }

    text = (uint16_t*)lsw_CoTaskMemAlloc(39u * sizeof(uint16_t));
    if (!text) {
        return E_OUTOFMEMORY;
    }

    if (lsw_StringFromGUID2(rclsid, text, 39) == 0) {
        lsw_CoTaskMemFree(text);
        return E_FAIL;
    }

    *lplpsz = text;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_StringFromIID(const GUID* rclsid, uint16_t** lplpsz) {
    return lsw_StringFromCLSID(rclsid, lplpsz);
}

int32_t __attribute__((ms_abi)) lsw_CLSIDFromString(const uint16_t* lpsz, GUID* pclsid) {
    char buffer[64];
    unsigned int data1;
    unsigned int data2;
    unsigned int data3;
    unsigned int data4[8];
    int parsed;

    if (!lpsz || !pclsid) {
        return E_INVALIDARG;
    }

    lsw_utf16_to_ascii(lpsz, buffer, sizeof(buffer));
    parsed = sscanf(
        buffer,
        "{%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}",
        &data1,
        &data2,
        &data3,
        &data4[0],
        &data4[1],
        &data4[2],
        &data4[3],
        &data4[4],
        &data4[5],
        &data4[6],
        &data4[7]
    );
    if (parsed != 11) {
        return E_INVALIDARG;
    }

    pclsid->Data1 = data1;
    pclsid->Data2 = (uint16_t)data2;
    pclsid->Data3 = (uint16_t)data3;
    pclsid->Data4[0] = (uint8_t)data4[0];
    pclsid->Data4[1] = (uint8_t)data4[1];
    pclsid->Data4[2] = (uint8_t)data4[2];
    pclsid->Data4[3] = (uint8_t)data4[3];
    pclsid->Data4[4] = (uint8_t)data4[4];
    pclsid->Data4[5] = (uint8_t)data4[5];
    pclsid->Data4[6] = (uint8_t)data4[6];
    pclsid->Data4[7] = (uint8_t)data4[7];
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_IIDFromString(const uint16_t* lpsz, GUID* lpiid) {
    return lsw_CLSIDFromString(lpsz, lpiid);
}

int32_t __attribute__((ms_abi)) lsw_CLSIDFromProgID(const uint16_t* lpszProgID, GUID* lpclsid) {
    LSW_UNUSED(lpszProgID);
    if (lpclsid) {
        memset(lpclsid, 0, sizeof(*lpclsid));
    }
    return E_INVALIDARG;
}

int32_t __attribute__((ms_abi)) lsw_ProgIDFromCLSID(const GUID* clsid, uint16_t** lplpszProgID) {
    LSW_UNUSED(clsid);
    if (lplpszProgID) {
        *lplpszProgID = NULL;
    }
    return E_INVALIDARG;
}

int __attribute__((ms_abi)) lsw_IsEqualGUID(const GUID* rguid1, const GUID* rguid2) {
    if (!rguid1 || !rguid2) {
        return FALSE;
    }
    return memcmp(rguid1, rguid2, sizeof(GUID)) == 0;
}

int __attribute__((ms_abi)) lsw_IsEqualIID(const GUID* rguid1, const GUID* rguid2) {
    return lsw_IsEqualGUID(rguid1, rguid2);
}

int __attribute__((ms_abi)) lsw_IsEqualCLSID(const GUID* rguid1, const GUID* rguid2) {
    return lsw_IsEqualGUID(rguid1, rguid2);
}

int32_t __attribute__((ms_abi)) lsw_OleInitialize(void* pvReserved) {
    LSW_UNUSED(pvReserved);
    lsw_CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    return S_OK;
}

void __attribute__((ms_abi)) lsw_OleUninitialize(void) {
    lsw_CoUninitialize();
}

int32_t __attribute__((ms_abi)) lsw_OleRun(void* pUnknown) {
    LSW_UNUSED(pUnknown);
    return S_OK;
}

int __attribute__((ms_abi)) lsw_OleIsRunning(void* pObject) {
    LSW_UNUSED(pObject);
    return 0;
}

int32_t __attribute__((ms_abi)) lsw_OleFlushClipboard(void) {
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_OleGetClipboard(void** ppDataObj) {
    if (ppDataObj) {
        *ppDataObj = NULL;
    }
    return E_FAIL;
}

int32_t __attribute__((ms_abi)) lsw_OleSetClipboard(void* pDataObj) {
    LSW_UNUSED(pDataObj);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_OleCreateDefaultHandler(const GUID* clsid, void* pUnkOuter, const GUID* riid, void** ppvObj) {
    LSW_UNUSED(clsid);
    LSW_UNUSED(pUnkOuter);
    LSW_UNUSED(riid);
    if (ppvObj) {
        *ppvObj = NULL;
    }
    return E_NOTIMPL;
}

void* __attribute__((ms_abi)) lsw_OleDuplicateData(void* hSrc, uint32_t cfFormat, uint32_t uiFlags) {
    LSW_UNUSED(hSrc);
    LSW_UNUSED(cfFormat);
    LSW_UNUSED(uiFlags);
    return NULL;
}

int32_t __attribute__((ms_abi)) lsw_CreateStreamOnHGlobal(void* hGlobal, int fDeleteOnRelease, void** ppstm) {
    LSW_UNUSED(hGlobal);
    LSW_UNUSED(fDeleteOnRelease);
    if (ppstm) {
        *ppstm = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_GetHGlobalFromStream(void* pstm, void** phglobal) {
    LSW_UNUSED(pstm);
    if (phglobal) {
        *phglobal = NULL;
    }
    return E_INVALIDARG;
}

int32_t __attribute__((ms_abi)) lsw_CreateBindCtx(uint32_t reserved, void** ppbc) {
    LSW_UNUSED(reserved);
    if (ppbc) {
        *ppbc = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_MkParseDisplayName(void* pbc, const uint16_t* szUserName, uint32_t* pchEaten, void** ppmk) {
    LSW_UNUSED(pbc);
    LSW_UNUSED(szUserName);
    if (pchEaten) {
        *pchEaten = 0;
    }
    if (ppmk) {
        *ppmk = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CoGetMalloc(uint32_t dwMemContext, void** ppMalloc) {
    LSW_UNUSED(dwMemContext);
    if (ppMalloc) {
        *ppMalloc = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CoMarshalInterface(void* pStm, const GUID* riid, void* pUnk, uint32_t dwDestContext, void* pvDestContext, uint32_t mshlflags) {
    LSW_UNUSED(pStm);
    LSW_UNUSED(riid);
    LSW_UNUSED(pUnk);
    LSW_UNUSED(dwDestContext);
    LSW_UNUSED(pvDestContext);
    LSW_UNUSED(mshlflags);
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CoUnmarshalInterface(void* pStm, const GUID* riid, void** ppv) {
    LSW_UNUSED(pStm);
    LSW_UNUSED(riid);
    if (ppv) {
        *ppv = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CoReleaseMarshalData(void* pStm) {
    LSW_UNUSED(pStm);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoDisconnectObject(void* pUnk, uint32_t dwReserved) {
    LSW_UNUSED(pUnk);
    LSW_UNUSED(dwReserved);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoLockObjectExternal(void* pUnk, int fLock, int fLastUnlockReleases) {
    LSW_UNUSED(pUnk);
    LSW_UNUSED(fLock);
    LSW_UNUSED(fLastUnlockReleases);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoGetStandardMarshal(const GUID* riid, void* pUnk, uint32_t dwDestContext, void* pvDestContext, uint32_t mshlflags, void** ppMarshal) {
    LSW_UNUSED(riid);
    LSW_UNUSED(pUnk);
    LSW_UNUSED(dwDestContext);
    LSW_UNUSED(pvDestContext);
    LSW_UNUSED(mshlflags);
    if (ppMarshal) {
        *ppMarshal = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_RegisterDragDrop(void* hwnd, void* pDropTarget) {
    LSW_UNUSED(hwnd);
    LSW_UNUSED(pDropTarget);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_RevokeDragDrop(void* hwnd) {
    LSW_UNUSED(hwnd);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_DoDragDrop(void* pDataObj, void* pDropSource, uint32_t dwOKEffects, uint32_t* pdwEffect) {
    LSW_UNUSED(pDataObj);
    LSW_UNUSED(pDropSource);
    LSW_UNUSED(dwOKEffects);
    if (pdwEffect) {
        *pdwEffect = 0;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoWaitForMultipleHandles(uint32_t dwFlags, uint32_t dwTimeout, uint32_t cHandles, void** pHandles, uint32_t* lpdwindex) {
    LSW_UNUSED(dwFlags);
    LSW_UNUSED(dwTimeout);
    LSW_UNUSED(cHandles);
    LSW_UNUSED(pHandles);
    if (lpdwindex) {
        *lpdwindex = 0;
    }
    return S_OK;
}

uint32_t __attribute__((ms_abi)) lsw_CoGetCurrentProcess(void) {
    return (uint32_t)getpid();
}

int32_t __attribute__((ms_abi)) lsw_CoGetCurrentLogicalThreadId(GUID* pguid) {
    if (pguid) {
        memset(pguid, 0, sizeof(*pguid));
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoSwitchCallContext(void* pNewObject, void** ppOldObject) {
    LSW_UNUSED(pNewObject);
    if (ppOldObject) {
        *ppOldObject = NULL;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoSetProxyBlanket(void* pProxy, uint32_t dwAuthnSvc, uint32_t dwAuthzSvc, uint16_t* pServerPrincName, uint32_t dwAuthnLevel, uint32_t dwImpLevel, void* pAuthInfo, uint32_t dwCapabilities) {
    LSW_UNUSED(pProxy);
    LSW_UNUSED(dwAuthnSvc);
    LSW_UNUSED(dwAuthzSvc);
    LSW_UNUSED(pServerPrincName);
    LSW_UNUSED(dwAuthnLevel);
    LSW_UNUSED(dwImpLevel);
    LSW_UNUSED(pAuthInfo);
    LSW_UNUSED(dwCapabilities);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoQueryProxyBlanket(void* pProxy, uint32_t* pwAuthnSvc, uint32_t* pAuthzSvc, uint16_t** pServerPrincName, uint32_t* pAuthnLevel, uint32_t* pImpLevel, void** pAuthInfo, uint32_t* pCapabilities) {
    LSW_UNUSED(pProxy);
    if (pwAuthnSvc) {
        *pwAuthnSvc = 0;
    }
    if (pAuthzSvc) {
        *pAuthzSvc = 0;
    }
    if (pServerPrincName) {
        *pServerPrincName = NULL;
    }
    if (pAuthnLevel) {
        *pAuthnLevel = 0;
    }
    if (pImpLevel) {
        *pImpLevel = 0;
    }
    if (pAuthInfo) {
        *pAuthInfo = NULL;
    }
    if (pCapabilities) {
        *pCapabilities = 0;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoCopyProxy(void* pProxy, void** ppCopy) {
    if (ppCopy) {
        *ppCopy = pProxy;
    }
    return S_OK;
}

void* __attribute__((ms_abi)) lsw_CoLoadLibrary(const uint16_t* lpszLibName, int bAutoFree) {
    LSW_UNUSED(lpszLibName);
    LSW_UNUSED(bAutoFree);
    return NULL;
}

void __attribute__((ms_abi)) lsw_CoFreeLibrary(void* hInst) {
    LSW_UNUSED(hInst);
}

void __attribute__((ms_abi)) lsw_CoFreeAllLibraries(void) {
}

int32_t __attribute__((ms_abi)) lsw_CoGetTreatAsClass(const GUID* clsidOld, GUID* pClsidNew) {
    if (!pClsidNew) {
        return E_INVALIDARG;
    }
    if (clsidOld) {
        memcpy(pClsidNew, clsidOld, sizeof(*pClsidNew));
    } else {
        memset(pClsidNew, 0, sizeof(*pClsidNew));
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CoTreatAsClass(const GUID* clsidOld, const GUID* clsidNew) {
    LSW_UNUSED(clsidOld);
    LSW_UNUSED(clsidNew);
    return S_OK;
}

const win32_api_mapping_t win32_api_ole32_mappings[] = {
    {"ole32.dll", "CoInitialize", (void*)lsw_CoInitialize},
    {"ole32.dll", "CoInitializeEx", (void*)lsw_CoInitializeEx},
    {"ole32.dll", "CoUninitialize", (void*)lsw_CoUninitialize},
    {"ole32.dll", "CoCreateInstance", (void*)lsw_CoCreateInstance},
    {"ole32.dll", "CoCreateInstanceEx", (void*)lsw_CoCreateInstanceEx},
    {"ole32.dll", "CoGetClassObject", (void*)lsw_CoGetClassObject},
    {"ole32.dll", "CoRegisterClassObject", (void*)lsw_CoRegisterClassObject},
    {"ole32.dll", "CoRevokeClassObject", (void*)lsw_CoRevokeClassObject},
    {"ole32.dll", "CoCreateGuid", (void*)lsw_CoCreateGuid},
    {"ole32.dll", "CoTaskMemAlloc", (void*)lsw_CoTaskMemAlloc},
    {"ole32.dll", "CoTaskMemFree", (void*)lsw_CoTaskMemFree},
    {"ole32.dll", "CoTaskMemRealloc", (void*)lsw_CoTaskMemRealloc},
    {"ole32.dll", "StringFromGUID2", (void*)lsw_StringFromGUID2},
    {"ole32.dll", "StringFromCLSID", (void*)lsw_StringFromCLSID},
    {"ole32.dll", "StringFromIID", (void*)lsw_StringFromIID},
    {"ole32.dll", "CLSIDFromString", (void*)lsw_CLSIDFromString},
    {"ole32.dll", "IIDFromString", (void*)lsw_IIDFromString},
    {"ole32.dll", "CLSIDFromProgID", (void*)lsw_CLSIDFromProgID},
    {"ole32.dll", "ProgIDFromCLSID", (void*)lsw_ProgIDFromCLSID},
    {"ole32.dll", "IsEqualGUID", (void*)lsw_IsEqualGUID},
    {"ole32.dll", "IsEqualIID", (void*)lsw_IsEqualIID},
    {"ole32.dll", "IsEqualCLSID", (void*)lsw_IsEqualCLSID},
    {"ole32.dll", "OleInitialize", (void*)lsw_OleInitialize},
    {"ole32.dll", "OleUninitialize", (void*)lsw_OleUninitialize},
    {"ole32.dll", "OleRun", (void*)lsw_OleRun},
    {"ole32.dll", "OleIsRunning", (void*)lsw_OleIsRunning},
    {"ole32.dll", "OleFlushClipboard", (void*)lsw_OleFlushClipboard},
    {"ole32.dll", "OleGetClipboard", (void*)lsw_OleGetClipboard},
    {"ole32.dll", "OleSetClipboard", (void*)lsw_OleSetClipboard},
    {"ole32.dll", "OleCreateDefaultHandler", (void*)lsw_OleCreateDefaultHandler},
    {"ole32.dll", "OleDuplicateData", (void*)lsw_OleDuplicateData},
    {"ole32.dll", "CreateStreamOnHGlobal", (void*)lsw_CreateStreamOnHGlobal},
    {"ole32.dll", "GetHGlobalFromStream", (void*)lsw_GetHGlobalFromStream},
    {"ole32.dll", "CreateBindCtx", (void*)lsw_CreateBindCtx},
    {"ole32.dll", "MkParseDisplayName", (void*)lsw_MkParseDisplayName},
    {"ole32.dll", "CoGetMalloc", (void*)lsw_CoGetMalloc},
    {"ole32.dll", "CoMarshalInterface", (void*)lsw_CoMarshalInterface},
    {"ole32.dll", "CoUnmarshalInterface", (void*)lsw_CoUnmarshalInterface},
    {"ole32.dll", "CoReleaseMarshalData", (void*)lsw_CoReleaseMarshalData},
    {"ole32.dll", "CoDisconnectObject", (void*)lsw_CoDisconnectObject},
    {"ole32.dll", "CoLockObjectExternal", (void*)lsw_CoLockObjectExternal},
    {"ole32.dll", "CoGetStandardMarshal", (void*)lsw_CoGetStandardMarshal},
    {"ole32.dll", "RegisterDragDrop", (void*)lsw_RegisterDragDrop},
    {"ole32.dll", "RevokeDragDrop", (void*)lsw_RevokeDragDrop},
    {"ole32.dll", "DoDragDrop", (void*)lsw_DoDragDrop},
    {"ole32.dll", "CoWaitForMultipleHandles", (void*)lsw_CoWaitForMultipleHandles},
    {"ole32.dll", "CoGetCurrentProcess", (void*)lsw_CoGetCurrentProcess},
    {"ole32.dll", "CoGetCurrentLogicalThreadId", (void*)lsw_CoGetCurrentLogicalThreadId},
    {"ole32.dll", "CoSwitchCallContext", (void*)lsw_CoSwitchCallContext},
    {"ole32.dll", "CoSetProxyBlanket", (void*)lsw_CoSetProxyBlanket},
    {"ole32.dll", "CoQueryProxyBlanket", (void*)lsw_CoQueryProxyBlanket},
    {"ole32.dll", "CoCopyProxy", (void*)lsw_CoCopyProxy},
    {"ole32.dll", "CoLoadLibrary", (void*)lsw_CoLoadLibrary},
    {"ole32.dll", "CoFreeLibrary", (void*)lsw_CoFreeLibrary},
    {"ole32.dll", "CoFreeAllLibraries", (void*)lsw_CoFreeAllLibraries},
    {"ole32.dll", "CoGetTreatAsClass", (void*)lsw_CoGetTreatAsClass},
    {"ole32.dll", "CoTreatAsClass", (void*)lsw_CoTreatAsClass},
    {NULL, NULL, NULL}
};

const size_t win32_api_ole32_mappings_count =
    (sizeof(win32_api_ole32_mappings) / sizeof(win32_api_ole32_mappings[0])) - 1;
