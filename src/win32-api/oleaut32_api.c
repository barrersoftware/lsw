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

#define VT_EMPTY 0
#define VT_NULL 1
#define VT_I2 2
#define VT_I4 3
#define VT_R4 4
#define VT_R8 5
#define VT_CY 6
#define VT_DATE 7
#define VT_BSTR 8
#define VT_DISPATCH 9
#define VT_ERROR 10
#define VT_BOOL 11
#define VT_VARIANT 12
#define VT_UNKNOWN 13
#define VT_DECIMAL 14
#define VT_I1 16
#define VT_UI1 17
#define VT_UI2 18
#define VT_UI4 19
#define VT_I8 20
#define VT_UI8 21
#define VT_INT 22
#define VT_UINT 23
#define VT_VOID 24
#define VT_HRESULT 25
#define VT_PTR 26
#define VT_SAFEARRAY 27
#define VT_ARRAY 0x2000
#define VT_BYREF 0x4000

typedef struct {
    uint16_t vt;
    uint16_t wReserved1;
    uint16_t wReserved2;
    uint16_t wReserved3;
    union {
        int64_t llVal;
        int32_t lVal;
        int16_t iVal;
        float fltVal;
        double dblVal;
        int16_t boolVal;
        int32_t scode;
        void* pdispVal;
        void* punkVal;
        uint8_t bVal;
        uint16_t uiVal;
        uint32_t ulVal;
        uint64_t ullVal;
        uint16_t* bstrVal;
        void* parray;
        void* byref;
    };
} VARIANT;

typedef struct {
    uint32_t cElements;
    int32_t lLbound;
} SAFEARRAYBOUND;

typedef struct {
    uint16_t cDims;
    uint16_t fFeatures;
    uint32_t cbElements;
    uint32_t cLocks;
    void* pvData;
    SAFEARRAYBOUND rgsabound[1];
} SAFEARRAY;

#define VARCMP_LT 0
#define VARCMP_EQ 1
#define VARCMP_GT 2
#define LSW_UNUSED(x) ((void)(x))

static const uint16_t lsw_empty_u16[] = {0};

static void lsw_u16_to_ascii(const uint16_t* src, char* dst, size_t dst_size) {
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

static uint16_t* lsw_ascii_to_bstr(const char* src) {
    uint32_t len = 0;
    uint8_t* buf;
    uint32_t i;

    if (!src) {
        return NULL;
    }

    while (src[len]) {
        len++;
    }

    buf = (uint8_t*)malloc((len * 2u) + 6u);
    if (!buf) {
        return NULL;
    }

    *(uint32_t*)buf = len * 2u;
    for (i = 0; i < len; i++) {
        ((uint16_t*)(buf + 4))[i] = (uint16_t)(unsigned char)src[i];
    }
    ((uint16_t*)(buf + 4))[len] = 0;
    return (uint16_t*)(buf + 4);
}

static int lsw_u16_casecmp_ascii(const uint16_t* value, const char* ascii) {
    size_t i = 0;
    char a;
    char b;

    if (!value || !ascii) {
        return -1;
    }

    while (value[i] || ascii[i]) {
        a = (char)(value[i] & 0xFF);
        b = ascii[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return (unsigned char)a - (unsigned char)b;
        }
        if (!a || !b) {
            break;
        }
        i++;
    }

    return 0;
}

static uint32_t lsw_vartype_size(uint16_t vt) {
    switch (vt) {
        case VT_I1:
        case VT_UI1:
            return 1;
        case VT_I2:
        case VT_UI2:
        case VT_BOOL:
            return 2;
        case VT_I4:
        case VT_UI4:
        case VT_INT:
        case VT_UINT:
        case VT_HRESULT:
        case VT_R4:
        case VT_ERROR:
            return 4;
        case VT_I8:
        case VT_UI8:
        case VT_R8:
        case VT_DATE:
        case VT_BSTR:
        case VT_DISPATCH:
        case VT_UNKNOWN:
        case VT_PTR:
        case VT_SAFEARRAY:
            return (uint32_t)sizeof(void*);
        case VT_VARIANT:
            return (uint32_t)sizeof(VARIANT);
        default:
            return 1;
    }
}

static size_t lsw_safearray_total_elements(const SAFEARRAY* psa) {
    size_t total = 1;
    uint16_t i;

    if (!psa || psa->cDims == 0) {
        return 0;
    }

    for (i = 0; i < psa->cDims; i++) {
        total *= psa->rgsabound[i].cElements;
    }
    return total;
}

static int lsw_safearray_offset(const SAFEARRAY* psa, const int32_t* rgIndices, size_t* offset_out) {
    size_t offset = 0;
    size_t stride = 1;
    uint16_t i;

    if (!psa || !rgIndices || !offset_out) {
        return 0;
    }

    for (i = 0; i < psa->cDims; i++) {
        int32_t relative = rgIndices[i] - psa->rgsabound[i].lLbound;
        if (relative < 0 || (uint32_t)relative >= psa->rgsabound[i].cElements) {
            return 0;
        }
        offset += (size_t)relative * stride;
        stride *= psa->rgsabound[i].cElements;
    }

    *offset_out = offset;
    return 1;
}

uint16_t* __attribute__((ms_abi)) lsw_SysAllocString(const uint16_t* psz) {
    uint32_t len = 0;
    uint32_t byteLen;
    uint8_t* buf;

    if (!psz) {
        return NULL;
    }

    while (psz[len]) {
        len++;
    }
    byteLen = len * 2u;
    buf = (uint8_t*)malloc(byteLen + 6u);
    if (!buf) {
        return NULL;
    }
    *(uint32_t*)buf = byteLen;
    memcpy(buf + 4, psz, byteLen);
    buf[byteLen + 4] = 0;
    buf[byteLen + 5] = 0;
    return (uint16_t*)(buf + 4);
}

uint16_t* __attribute__((ms_abi)) lsw_SysAllocStringLen(const uint16_t* strIn, uint32_t ui) {
    uint8_t* buf = (uint8_t*)malloc((ui * 2u) + 6u);
    if (!buf) {
        return NULL;
    }
    *(uint32_t*)buf = ui * 2u;
    if (strIn) {
        memcpy(buf + 4, strIn, ui * 2u);
    } else {
        memset(buf + 4, 0, ui * 2u);
    }
    buf[(ui * 2u) + 4u] = 0;
    buf[(ui * 2u) + 5u] = 0;
    return (uint16_t*)(buf + 4);
}

uint16_t* __attribute__((ms_abi)) lsw_SysAllocStringByteLen(const char* psz, uint32_t len) {
    uint8_t* buf = (uint8_t*)malloc(len + 6u);
    if (!buf) {
        return NULL;
    }
    *(uint32_t*)buf = len;
    if (psz && len) {
        memcpy(buf + 4, psz, len);
    } else if (len) {
        memset(buf + 4, 0, len);
    }
    buf[len + 4u] = 0;
    buf[len + 5u] = 0;
    return (uint16_t*)(buf + 4);
}

void __attribute__((ms_abi)) lsw_SysFreeString(uint16_t* bstrString) {
    if (!bstrString) {
        return;
    }
    free((uint8_t*)bstrString - 4);
}

int __attribute__((ms_abi)) lsw_SysReAllocString(uint16_t** pbstr, const uint16_t* psz) {
    if (!pbstr) {
        return 0;
    }
    lsw_SysFreeString(*pbstr);
    *pbstr = lsw_SysAllocString(psz);
    return *pbstr != NULL ? 1 : 0;
}

int __attribute__((ms_abi)) lsw_SysReAllocStringLen(uint16_t** pbstr, const uint16_t* psz, uint32_t len) {
    if (!pbstr) {
        return 0;
    }
    lsw_SysFreeString(*pbstr);
    *pbstr = lsw_SysAllocStringLen(psz, len);
    return *pbstr != NULL ? 1 : 0;
}

uint32_t __attribute__((ms_abi)) lsw_SysStringLen(uint16_t* bstrString) {
    if (!bstrString) {
        return 0;
    }
    return *(uint32_t*)((uint8_t*)bstrString - 4) / 2u;
}

uint32_t __attribute__((ms_abi)) lsw_SysStringByteLen(uint16_t* bstrString) {
    if (!bstrString) {
        return 0;
    }
    return *(uint32_t*)((uint8_t*)bstrString - 4);
}

int32_t __attribute__((ms_abi)) lsw_SysAddRefString(uint16_t* bstrString) {
    LSW_UNUSED(bstrString);
    return S_OK;
}

void __attribute__((ms_abi)) lsw_SysReleaseString(uint16_t* bstrString) {
    LSW_UNUSED(bstrString);
}

void __attribute__((ms_abi)) lsw_VariantInit(VARIANT* pvarg) {
    if (pvarg) {
        memset(pvarg, 0, sizeof(VARIANT));
    }
}

int32_t __attribute__((ms_abi)) lsw_VariantClear(VARIANT* pvarg) {
    if (!pvarg) {
        return E_INVALIDARG;
    }
    if (pvarg->vt == VT_BSTR) {
        lsw_SysFreeString(pvarg->bstrVal);
    }
    if ((pvarg->vt == VT_DISPATCH || pvarg->vt == VT_UNKNOWN) && pvarg->punkVal != NULL) {
        LSW_LOG_DEBUG("VariantClear releasing interface stub %p", pvarg->punkVal);
    }
    memset(pvarg, 0, sizeof(VARIANT));
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VariantCopy(VARIANT* pvargDest, const VARIANT* pvargSrc) {
    if (!pvargDest || !pvargSrc) {
        return E_INVALIDARG;
    }

    if (pvargDest == pvargSrc) {
        return S_OK;
    }

    lsw_VariantClear(pvargDest);
    memcpy(pvargDest, pvargSrc, sizeof(VARIANT));

    if (pvargSrc->vt == VT_BSTR && pvargSrc->bstrVal) {
        pvargDest->bstrVal = lsw_SysAllocStringLen(pvargSrc->bstrVal, lsw_SysStringLen(pvargSrc->bstrVal));
        if (!pvargDest->bstrVal) {
            memset(pvargDest, 0, sizeof(VARIANT));
            return E_OUTOFMEMORY;
        }
    }

    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VariantCopyInd(VARIANT* pvarDest, const VARIANT* pvargSrc) {
    return lsw_VariantCopy(pvarDest, pvargSrc);
}

int32_t __attribute__((ms_abi)) lsw_VariantChangeType(VARIANT* pvargDest, VARIANT* pvarSrc, uint16_t wFlags, uint16_t vt) {
    LSW_UNUSED(wFlags);
    if (!pvargDest || !pvarSrc) {
        return E_INVALIDARG;
    }
    if (pvargDest != pvarSrc) {
        int32_t hr = lsw_VariantCopy(pvargDest, pvarSrc);
        if (hr != S_OK) {
            return hr;
        }
    }
    pvargDest->vt = vt;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VariantChangeTypeEx(VARIANT* pvargDest, VARIANT* pvarSrc, uint32_t lcid, uint16_t wFlags, uint16_t vt) {
    LSW_UNUSED(lcid);
    return lsw_VariantChangeType(pvargDest, pvarSrc, wFlags, vt);
}

int32_t __attribute__((ms_abi)) lsw_VarBstrFromI4(int32_t lIn, uint32_t lcid, uint32_t dwFlags, uint16_t** pbstrOut) {
    char buffer[32];
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    if (!pbstrOut) {
        return E_INVALIDARG;
    }
    snprintf(buffer, sizeof(buffer), "%d", lIn);
    *pbstrOut = lsw_ascii_to_bstr(buffer);
    return *pbstrOut ? S_OK : E_OUTOFMEMORY;
}

int32_t __attribute__((ms_abi)) lsw_VarBstrFromR8(double dblIn, uint32_t lcid, uint32_t dwFlags, uint16_t** pbstrOut) {
    char buffer[64];
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    if (!pbstrOut) {
        return E_INVALIDARG;
    }
    snprintf(buffer, sizeof(buffer), "%.15g", dblIn);
    *pbstrOut = lsw_ascii_to_bstr(buffer);
    return *pbstrOut ? S_OK : E_OUTOFMEMORY;
}

int32_t __attribute__((ms_abi)) lsw_VarBstrFromBool(int16_t boolIn, uint32_t lcid, uint32_t dwFlags, uint16_t** pbstrOut) {
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    if (!pbstrOut) {
        return E_INVALIDARG;
    }
    *pbstrOut = lsw_ascii_to_bstr(boolIn ? "True" : "False");
    return *pbstrOut ? S_OK : E_OUTOFMEMORY;
}

int32_t __attribute__((ms_abi)) lsw_VarI4FromStr(const uint16_t* strIn, uint32_t lcid, uint32_t dwFlags, int32_t* plOut) {
    char buffer[64];
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    if (!plOut) {
        return E_INVALIDARG;
    }
    lsw_u16_to_ascii(strIn, buffer, sizeof(buffer));
    *plOut = (int32_t)strtol(buffer, NULL, 10);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VarR8FromStr(const uint16_t* strIn, uint32_t lcid, uint32_t dwFlags, double* pdblOut) {
    char buffer[64];
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    if (!pdblOut) {
        return E_INVALIDARG;
    }
    lsw_u16_to_ascii(strIn, buffer, sizeof(buffer));
    *pdblOut = strtod(buffer, NULL);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VarBoolFromStr(const uint16_t* strIn, uint32_t lcid, uint32_t dwFlags, int16_t* pboolOut) {
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    if (!pboolOut) {
        return E_INVALIDARG;
    }
    *pboolOut = (strIn && (lsw_u16_casecmp_ascii(strIn, "true") == 0 || lsw_u16_casecmp_ascii(strIn, "1") == 0)) ? (int16_t)-1 : 0;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VarI4FromR8(double dblIn, int32_t* plOut) {
    if (!plOut) {
        return E_INVALIDARG;
    }
    *plOut = (int32_t)dblIn;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VarR8FromI4(int32_t lIn, double* pdblOut) {
    if (!pdblOut) {
        return E_INVALIDARG;
    }
    *pdblOut = (double)lIn;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VarDateFromStr(const uint16_t* strIn, uint32_t lcid, uint32_t dwFlags, double* pdateOut) {
    LSW_UNUSED(strIn);
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    if (!pdateOut) {
        return E_INVALIDARG;
    }
    *pdateOut = 0;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VarFormat(VARIANT* pvarIn, uint16_t* pstrFormat, int iFirstDay, int iFirstWeek, uint32_t dwFlags, uint16_t** pbstrOut) {
    LSW_UNUSED(pvarIn);
    LSW_UNUSED(iFirstDay);
    LSW_UNUSED(iFirstWeek);
    LSW_UNUSED(dwFlags);
    if (!pbstrOut) {
        return E_INVALIDARG;
    }
    *pbstrOut = lsw_SysAllocString(pstrFormat ? pstrFormat : lsw_empty_u16);
    return *pbstrOut ? S_OK : E_OUTOFMEMORY;
}

int32_t __attribute__((ms_abi)) lsw_VarCmp(VARIANT* pvarLeft, VARIANT* pvarRight, uint32_t lcid, uint32_t dwFlags) {
    LSW_UNUSED(pvarLeft);
    LSW_UNUSED(pvarRight);
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);
    return VARCMP_EQ;
}

SAFEARRAY* __attribute__((ms_abi)) lsw_SafeArrayCreate(uint16_t vt, uint32_t cDims, SAFEARRAYBOUND* rgsabound) {
    SAFEARRAY* psa;
    size_t descriptor_size;
    size_t total_elements = 1;
    uint32_t i;

    if (cDims == 0 || !rgsabound) {
        return NULL;
    }

    descriptor_size = sizeof(SAFEARRAY) + ((size_t)cDims - 1u) * sizeof(SAFEARRAYBOUND);
    psa = (SAFEARRAY*)calloc(1, descriptor_size);
    if (!psa) {
        return NULL;
    }

    psa->cDims = (uint16_t)cDims;
    psa->fFeatures = vt;
    psa->cbElements = lsw_vartype_size(vt);
    for (i = 0; i < cDims; i++) {
        psa->rgsabound[i] = rgsabound[i];
        total_elements *= rgsabound[i].cElements;
    }

    if (total_elements > 0 && psa->cbElements > 0) {
        psa->pvData = calloc(total_elements, psa->cbElements);
        if (!psa->pvData) {
            free(psa);
            return NULL;
        }
    }

    return psa;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayDestroy(SAFEARRAY* psa) {
    if (psa) {
        free(psa->pvData);
        free(psa);
    }
    return S_OK;
}

uint32_t __attribute__((ms_abi)) lsw_SafeArrayGetDim(SAFEARRAY* psa) {
    return psa ? psa->cDims : 0;
}

uint32_t __attribute__((ms_abi)) lsw_SafeArrayGetElemsize(SAFEARRAY* psa) {
    return psa ? psa->cbElements : 0;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayGetLBound(SAFEARRAY* psa, uint32_t nDim, int32_t* plLbound) {
    if (psa && plLbound && nDim >= 1 && nDim <= psa->cDims) {
        *plLbound = psa->rgsabound[nDim - 1u].lLbound;
        return S_OK;
    }
    return E_INVALIDARG;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayGetUBound(SAFEARRAY* psa, uint32_t nDim, int32_t* plUbound) {
    if (psa && plUbound && nDim >= 1 && nDim <= psa->cDims) {
        SAFEARRAYBOUND* bound = &psa->rgsabound[nDim - 1u];
        *plUbound = bound->lLbound + (int32_t)bound->cElements - 1;
        return S_OK;
    }
    return E_INVALIDARG;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayAccessData(SAFEARRAY* psa, void** ppvData) {
    if (psa && ppvData) {
        *ppvData = psa->pvData;
        psa->cLocks++;
        return S_OK;
    }
    return E_INVALIDARG;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayUnaccessData(SAFEARRAY* psa) {
    if (psa && psa->cLocks > 0) {
        psa->cLocks--;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayLock(SAFEARRAY* psa) {
    if (psa) {
        psa->cLocks++;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayUnlock(SAFEARRAY* psa) {
    if (psa && psa->cLocks > 0) {
        psa->cLocks--;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayPutElement(SAFEARRAY* psa, int32_t* rgIndices, void* pv) {
    size_t offset;
    if (!psa || !pv || !psa->pvData || !lsw_safearray_offset(psa, rgIndices, &offset)) {
        return E_INVALIDARG;
    }
    memcpy((uint8_t*)psa->pvData + (offset * psa->cbElements), pv, psa->cbElements);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayGetElement(SAFEARRAY* psa, int32_t* rgIndices, void* pv) {
    size_t offset;
    if (!psa || !pv || !psa->pvData || !lsw_safearray_offset(psa, rgIndices, &offset)) {
        return E_INVALIDARG;
    }
    memcpy(pv, (uint8_t*)psa->pvData + (offset * psa->cbElements), psa->cbElements);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayCopy(SAFEARRAY* psa, SAFEARRAY** ppsaOut) {
    SAFEARRAY* copy;
    size_t bytes;

    if (!psa || !ppsaOut) {
        return E_INVALIDARG;
    }

    copy = lsw_SafeArrayCreate(psa->fFeatures, psa->cDims, psa->rgsabound);
    if (!copy) {
        return E_OUTOFMEMORY;
    }

    bytes = lsw_safearray_total_elements(psa) * psa->cbElements;
    if (bytes && psa->pvData && copy->pvData) {
        memcpy(copy->pvData, psa->pvData, bytes);
    }

    *ppsaOut = copy;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayRedim(SAFEARRAY* psa, SAFEARRAYBOUND* psaboundNew) {
    size_t old_total;
    size_t new_total;
    void* new_data;

    if (!psa || !psaboundNew) {
        return E_INVALIDARG;
    }

    old_total = lsw_safearray_total_elements(psa);
    new_total = (psa->rgsabound[0].cElements == 0) ? 0 : (old_total / psa->rgsabound[0].cElements) * psaboundNew->cElements;
    if (psa->cDims == 1) {
        new_total = psaboundNew->cElements;
    }

    new_data = realloc(psa->pvData, new_total * psa->cbElements);
    if (new_total > 0 && !new_data) {
        return E_OUTOFMEMORY;
    }

    if (new_total > old_total) {
        memset((uint8_t*)new_data + (old_total * psa->cbElements), 0, (new_total - old_total) * psa->cbElements);
    }

    psa->pvData = new_data;
    psa->rgsabound[0] = *psaboundNew;
    return S_OK;
}

SAFEARRAY* __attribute__((ms_abi)) lsw_SafeArrayCreateVector(uint16_t vt, int32_t lLbound, uint32_t cElements) {
    SAFEARRAYBOUND bound;
    bound.cElements = cElements;
    bound.lLbound = lLbound;
    return lsw_SafeArrayCreate(vt, 1, &bound);
}

SAFEARRAY* __attribute__((ms_abi)) lsw_SafeArrayCreateVectorEx(uint16_t vt, int32_t lLbound, uint32_t cElements, void* pvExtra) {
    LSW_UNUSED(pvExtra);
    return lsw_SafeArrayCreateVector(vt, lLbound, cElements);
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayDestroyData(SAFEARRAY* psa) {
    if (psa && psa->pvData) {
        free(psa->pvData);
        psa->pvData = NULL;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayDestroyDescriptor(SAFEARRAY* psa) {
    if (psa) {
        free(psa);
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayAllocDescriptor(uint32_t cDims, SAFEARRAY** ppsaOut) {
    size_t descriptor_size;
    SAFEARRAY* psa;

    if (!ppsaOut || cDims == 0) {
        return E_INVALIDARG;
    }

    descriptor_size = sizeof(SAFEARRAY) + ((size_t)cDims - 1u) * sizeof(SAFEARRAYBOUND);
    psa = (SAFEARRAY*)calloc(1, descriptor_size);
    if (!psa) {
        return E_OUTOFMEMORY;
    }

    psa->cDims = (uint16_t)cDims;
    psa->cbElements = 1;
    *ppsaOut = psa;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayAllocData(SAFEARRAY* psa) {
    size_t total;

    if (!psa) {
        return E_INVALIDARG;
    }

    free(psa->pvData);
    total = lsw_safearray_total_elements(psa);
    if (total == 0 || psa->cbElements == 0) {
        psa->pvData = NULL;
        return S_OK;
    }

    psa->pvData = calloc(total, psa->cbElements);
    return psa->pvData ? S_OK : E_OUTOFMEMORY;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayPtrOfIndex(SAFEARRAY* psa, int32_t* rgIndices, void** ppvData) {
    LSW_UNUSED(psa);
    LSW_UNUSED(rgIndices);
    if (ppvData) {
        *ppvData = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_SafeArraySetRecordInfo(SAFEARRAY* psa, void* prinfo) {
    LSW_UNUSED(psa);
    LSW_UNUSED(prinfo);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayGetRecordInfo(SAFEARRAY* psa, void** prinfo) {
    LSW_UNUSED(psa);
    if (prinfo) {
        *prinfo = NULL;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArraySetIID(SAFEARRAY* psa, const GUID* guid) {
    LSW_UNUSED(psa);
    LSW_UNUSED(guid);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayGetIID(SAFEARRAY* psa, GUID* pguid) {
    LSW_UNUSED(psa);
    if (pguid) {
        memset(pguid, 0, sizeof(*pguid));
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_SafeArrayGetVartype(SAFEARRAY* psa, uint16_t* pvt) {
    if (pvt) {
        *pvt = psa ? psa->fFeatures : VT_EMPTY;
    }
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_LoadTypeLib(const uint16_t* szFile, void** pptlib) {
    LSW_UNUSED(szFile);
    if (pptlib) {
        *pptlib = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_LoadTypeLibEx(const uint16_t* szFile, uint32_t regkind, void** pptlib) {
    LSW_UNUSED(szFile);
    LSW_UNUSED(regkind);
    if (pptlib) {
        *pptlib = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_LoadRegTypeLib(const GUID* rguid, uint16_t wVerMajor, uint16_t wVerMinor, uint32_t lcid, void** pptlib) {
    LSW_UNUSED(rguid);
    LSW_UNUSED(wVerMajor);
    LSW_UNUSED(wVerMinor);
    LSW_UNUSED(lcid);
    if (pptlib) {
        *pptlib = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_QueryPathOfRegTypeLib(const GUID* guid, uint16_t wMaj, uint16_t wMin, uint32_t lcid, uint16_t** lpbstrPathName) {
    LSW_UNUSED(guid);
    LSW_UNUSED(wMaj);
    LSW_UNUSED(wMin);
    LSW_UNUSED(lcid);
    if (lpbstrPathName) {
        *lpbstrPathName = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_RegisterTypeLib(void* ptlib, const uint16_t* szFullPath, const uint16_t* szHelpDir) {
    LSW_UNUSED(ptlib);
    LSW_UNUSED(szFullPath);
    LSW_UNUSED(szHelpDir);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_UnRegisterTypeLib(const GUID* libID, uint16_t wVerMajor, uint16_t wVerMinor, uint32_t lcid, int syskind) {
    LSW_UNUSED(libID);
    LSW_UNUSED(wVerMajor);
    LSW_UNUSED(wVerMinor);
    LSW_UNUSED(lcid);
    LSW_UNUSED(syskind);
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_CreateTypeLib2(int syskind, const uint16_t* szFile, void** ppctlib) {
    LSW_UNUSED(syskind);
    LSW_UNUSED(szFile);
    if (ppctlib) {
        *ppctlib = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_GetTypeInfoOfGuid(void* ptlib, const GUID* guid, void** pptinfo) {
    LSW_UNUSED(ptlib);
    LSW_UNUSED(guid);
    if (pptinfo) {
        *pptinfo = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_DispGetIDsOfNames(void* ptinfo, uint16_t** rgszNames, uint32_t cNames, int32_t* rgdispid) {
    LSW_UNUSED(ptinfo);
    LSW_UNUSED(rgszNames);
    LSW_UNUSED(cNames);
    LSW_UNUSED(rgdispid);
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_DispInvoke(void* _this, void* ptinfo, int32_t dispidMember, uint16_t wFlags, void* pparams, VARIANT* pvarResult, void* pexcepinfo, uint32_t* puArgErr) {
    LSW_UNUSED(_this);
    LSW_UNUSED(ptinfo);
    LSW_UNUSED(dispidMember);
    LSW_UNUSED(wFlags);
    LSW_UNUSED(pparams);
    LSW_UNUSED(pvarResult);
    LSW_UNUSED(pexcepinfo);
    LSW_UNUSED(puArgErr);
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CreateDispTypeInfo(void* pidata, uint32_t lcid, void** pptinfo) {
    LSW_UNUSED(pidata);
    LSW_UNUSED(lcid);
    if (pptinfo) {
        *pptinfo = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_CreateStdDispatch(void* punkOuter, void* pvThis, void* ptinfo, void** ppunkStdDisp) {
    LSW_UNUSED(punkOuter);
    LSW_UNUSED(pvThis);
    LSW_UNUSED(ptinfo);
    if (ppunkStdDisp) {
        *ppunkStdDisp = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_VarBstrCat(uint16_t* bstr1, uint16_t* bstr2, uint16_t** pbstrResult) {
    uint32_t len1;
    uint32_t len2;
    uint16_t* result;

    if (!pbstrResult) {
        return E_INVALIDARG;
    }

    len1 = lsw_SysStringLen(bstr1);
    len2 = lsw_SysStringLen(bstr2);
    result = lsw_SysAllocStringLen(NULL, len1 + len2);
    if (!result) {
        return E_OUTOFMEMORY;
    }
    if (bstr1 && len1) {
        memcpy(result, bstr1, len1 * sizeof(uint16_t));
    }
    if (bstr2 && len2) {
        memcpy(result + len1, bstr2, len2 * sizeof(uint16_t));
    }
    *pbstrResult = result;
    return S_OK;
}

int32_t __attribute__((ms_abi)) lsw_VarBstrCmp(uint16_t* bstrLeft, uint16_t* bstrRight, uint32_t lcid, uint32_t dwFlags) {
    uint32_t i = 0;
    LSW_UNUSED(lcid);
    LSW_UNUSED(dwFlags);

    while ((bstrLeft && bstrLeft[i]) || (bstrRight && bstrRight[i])) {
        uint16_t left = bstrLeft ? bstrLeft[i] : 0;
        uint16_t right = bstrRight ? bstrRight[i] : 0;
        if (left < right) {
            return VARCMP_LT;
        }
        if (left > right) {
            return VARCMP_GT;
        }
        i++;
    }

    return VARCMP_EQ;
}

int32_t __attribute__((ms_abi)) lsw_OleCreatePictureIndirect(void* lpPictDesc, const GUID* riid, int fOwn, void** lplpvObj) {
    LSW_UNUSED(lpPictDesc);
    LSW_UNUSED(riid);
    LSW_UNUSED(fOwn);
    if (lplpvObj) {
        *lplpvObj = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_OleLoadPicture(void* lpstream, int32_t lSize, int fRunmode, const GUID* riid, void** lplpvObj) {
    LSW_UNUSED(lpstream);
    LSW_UNUSED(lSize);
    LSW_UNUSED(fRunmode);
    LSW_UNUSED(riid);
    if (lplpvObj) {
        *lplpvObj = NULL;
    }
    return E_NOTIMPL;
}

int32_t __attribute__((ms_abi)) lsw_OleCreateFontIndirect(void* lpFontDesc, const GUID* riid, void** lplpvObj) {
    LSW_UNUSED(lpFontDesc);
    LSW_UNUSED(riid);
    if (lplpvObj) {
        *lplpvObj = NULL;
    }
    return E_NOTIMPL;
}

const win32_api_mapping_t win32_api_oleaut32_mappings[] = {
    {"oleaut32.dll", "SysAllocString", (void*)lsw_SysAllocString},
    {"oleaut32.dll", "SysAllocStringLen", (void*)lsw_SysAllocStringLen},
    {"oleaut32.dll", "SysAllocStringByteLen", (void*)lsw_SysAllocStringByteLen},
    {"oleaut32.dll", "SysFreeString", (void*)lsw_SysFreeString},
    {"oleaut32.dll", "SysReAllocString", (void*)lsw_SysReAllocString},
    {"oleaut32.dll", "SysReAllocStringLen", (void*)lsw_SysReAllocStringLen},
    {"oleaut32.dll", "SysStringLen", (void*)lsw_SysStringLen},
    {"oleaut32.dll", "SysStringByteLen", (void*)lsw_SysStringByteLen},
    {"oleaut32.dll", "SysAddRefString", (void*)lsw_SysAddRefString},
    {"oleaut32.dll", "SysReleaseString", (void*)lsw_SysReleaseString},
    {"oleaut32.dll", "VariantInit", (void*)lsw_VariantInit},
    {"oleaut32.dll", "VariantClear", (void*)lsw_VariantClear},
    {"oleaut32.dll", "VariantCopy", (void*)lsw_VariantCopy},
    {"oleaut32.dll", "VariantCopyInd", (void*)lsw_VariantCopyInd},
    {"oleaut32.dll", "VariantChangeType", (void*)lsw_VariantChangeType},
    {"oleaut32.dll", "VariantChangeTypeEx", (void*)lsw_VariantChangeTypeEx},
    {"oleaut32.dll", "VarBstrFromI4", (void*)lsw_VarBstrFromI4},
    {"oleaut32.dll", "VarBstrFromR8", (void*)lsw_VarBstrFromR8},
    {"oleaut32.dll", "VarBstrFromBool", (void*)lsw_VarBstrFromBool},
    {"oleaut32.dll", "VarI4FromStr", (void*)lsw_VarI4FromStr},
    {"oleaut32.dll", "VarR8FromStr", (void*)lsw_VarR8FromStr},
    {"oleaut32.dll", "VarBoolFromStr", (void*)lsw_VarBoolFromStr},
    {"oleaut32.dll", "VarI4FromR8", (void*)lsw_VarI4FromR8},
    {"oleaut32.dll", "VarR8FromI4", (void*)lsw_VarR8FromI4},
    {"oleaut32.dll", "VarDateFromStr", (void*)lsw_VarDateFromStr},
    {"oleaut32.dll", "VarFormat", (void*)lsw_VarFormat},
    {"oleaut32.dll", "VarCmp", (void*)lsw_VarCmp},
    {"oleaut32.dll", "SafeArrayCreate", (void*)lsw_SafeArrayCreate},
    {"oleaut32.dll", "SafeArrayDestroy", (void*)lsw_SafeArrayDestroy},
    {"oleaut32.dll", "SafeArrayGetDim", (void*)lsw_SafeArrayGetDim},
    {"oleaut32.dll", "SafeArrayGetElemsize", (void*)lsw_SafeArrayGetElemsize},
    {"oleaut32.dll", "SafeArrayGetLBound", (void*)lsw_SafeArrayGetLBound},
    {"oleaut32.dll", "SafeArrayGetUBound", (void*)lsw_SafeArrayGetUBound},
    {"oleaut32.dll", "SafeArrayAccessData", (void*)lsw_SafeArrayAccessData},
    {"oleaut32.dll", "SafeArrayUnaccessData", (void*)lsw_SafeArrayUnaccessData},
    {"oleaut32.dll", "SafeArrayLock", (void*)lsw_SafeArrayLock},
    {"oleaut32.dll", "SafeArrayUnlock", (void*)lsw_SafeArrayUnlock},
    {"oleaut32.dll", "SafeArrayPutElement", (void*)lsw_SafeArrayPutElement},
    {"oleaut32.dll", "SafeArrayGetElement", (void*)lsw_SafeArrayGetElement},
    {"oleaut32.dll", "SafeArrayCopy", (void*)lsw_SafeArrayCopy},
    {"oleaut32.dll", "SafeArrayRedim", (void*)lsw_SafeArrayRedim},
    {"oleaut32.dll", "SafeArrayCreateVector", (void*)lsw_SafeArrayCreateVector},
    {"oleaut32.dll", "SafeArrayCreateVectorEx", (void*)lsw_SafeArrayCreateVectorEx},
    {"oleaut32.dll", "SafeArrayDestroyData", (void*)lsw_SafeArrayDestroyData},
    {"oleaut32.dll", "SafeArrayDestroyDescriptor", (void*)lsw_SafeArrayDestroyDescriptor},
    {"oleaut32.dll", "SafeArrayAllocDescriptor", (void*)lsw_SafeArrayAllocDescriptor},
    {"oleaut32.dll", "SafeArrayAllocData", (void*)lsw_SafeArrayAllocData},
    {"oleaut32.dll", "SafeArrayPtrOfIndex", (void*)lsw_SafeArrayPtrOfIndex},
    {"oleaut32.dll", "SafeArraySetRecordInfo", (void*)lsw_SafeArraySetRecordInfo},
    {"oleaut32.dll", "SafeArrayGetRecordInfo", (void*)lsw_SafeArrayGetRecordInfo},
    {"oleaut32.dll", "SafeArraySetIID", (void*)lsw_SafeArraySetIID},
    {"oleaut32.dll", "SafeArrayGetIID", (void*)lsw_SafeArrayGetIID},
    {"oleaut32.dll", "SafeArrayGetVartype", (void*)lsw_SafeArrayGetVartype},
    {"oleaut32.dll", "LoadTypeLib", (void*)lsw_LoadTypeLib},
    {"oleaut32.dll", "LoadTypeLibEx", (void*)lsw_LoadTypeLibEx},
    {"oleaut32.dll", "LoadRegTypeLib", (void*)lsw_LoadRegTypeLib},
    {"oleaut32.dll", "QueryPathOfRegTypeLib", (void*)lsw_QueryPathOfRegTypeLib},
    {"oleaut32.dll", "RegisterTypeLib", (void*)lsw_RegisterTypeLib},
    {"oleaut32.dll", "UnRegisterTypeLib", (void*)lsw_UnRegisterTypeLib},
    {"oleaut32.dll", "CreateTypeLib2", (void*)lsw_CreateTypeLib2},
    {"oleaut32.dll", "GetTypeInfoOfGuid", (void*)lsw_GetTypeInfoOfGuid},
    {"oleaut32.dll", "DispGetIDsOfNames", (void*)lsw_DispGetIDsOfNames},
    {"oleaut32.dll", "DispInvoke", (void*)lsw_DispInvoke},
    {"oleaut32.dll", "CreateDispTypeInfo", (void*)lsw_CreateDispTypeInfo},
    {"oleaut32.dll", "CreateStdDispatch", (void*)lsw_CreateStdDispatch},
    {"oleaut32.dll", "VarBstrCat", (void*)lsw_VarBstrCat},
    {"oleaut32.dll", "VarBstrCmp", (void*)lsw_VarBstrCmp},
    {"oleaut32.dll", "OleCreatePictureIndirect", (void*)lsw_OleCreatePictureIndirect},
    {"oleaut32.dll", "OleLoadPicture", (void*)lsw_OleLoadPicture},
    {"oleaut32.dll", "OleCreateFontIndirect", (void*)lsw_OleCreateFontIndirect},
    {NULL, NULL, NULL}
};

const size_t win32_api_oleaut32_mappings_count =
    (sizeof(win32_api_oleaut32_mappings) / sizeof(win32_api_oleaut32_mappings[0])) - 1;
