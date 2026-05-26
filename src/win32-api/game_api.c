/*
 * game_api.c — Win32 stubs enabling game compatibility on LSW
 *
 * Covers:
 *   BCrypt (bcrypt.dll)          — real BCryptGenRandom via /dev/urandom
 *   XAudio2 (xaudio2_9/8/7.dll) — null audio device COM stub
 *   DirectInput8 (dinput8.dll)   — null device COM stub
 *   ETW (advapi32/ntdll)         — telemetry no-ops
 *   RawInput (user32)            — stub so games register but receive nothing
 *   D3DX9/D3DX11 (d3dx9_43.dll) — math/utility stubs
 *   Priority class / process mem — SetPriorityClass, ReadProcessMemory …
 *   Misc game-critical stubs     — GameInput, GameBar, etc.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sched.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"

#define MSABI __attribute__((ms_abi))
#define MAP(dll, sym, fn) {dll, sym, (void*)(fn)}

typedef int32_t  HRESULT;
typedef uint32_t DWORD;
typedef int      BOOL;
#define S_OK        ((HRESULT)0)
#define S_FALSE     ((HRESULT)1)
#define E_NOTIMPL   ((HRESULT)0x80004001)
#define E_NOINTERFACE ((HRESULT)0x80004002)
#define E_POINTER   ((HRESULT)0x80004003)
#define E_INVALIDARG ((HRESULT)0x80070057)
#define E_OUTOFMEMORY ((HRESULT)0x8007000E)
#define TRUE  1
#define FALSE 0

/* =========================================================================
 * BCrypt (bcrypt.dll)
 * ========================================================================= */

typedef struct {
    uint32_t magic;   /* 0xBC007400 */
    char     alg[64]; /* algorithm name */
} lsw_bcrypt_alg_t;
#define BCRYPT_ALG_MAGIC 0xBC007400u

typedef struct {
    uint32_t magic; /* 0xBC007401 */
    /* We don't actually hash — hash output is zeroed */
} lsw_bcrypt_hash_t;
#define BCRYPT_HASH_MAGIC 0xBC007401u

typedef struct {
    uint32_t magic; /* 0xBC007402 */
} lsw_bcrypt_key_t;
#define BCRYPT_KEY_MAGIC 0xBC007402u

/* STATUS_SUCCESS = 0, STATUS_INVALID_PARAMETER = 0xC000000D */
#define BCRYPT_OK    0
#define BCRYPT_EINVAL ((HRESULT)0xC000000D)
#define BCRYPT_ENOENT ((HRESULT)0xC0000034)

HRESULT MSABI lsw_BCryptOpenAlgorithmProvider(void** phAlgorithm, const uint16_t* pszAlgId,
                                               const uint16_t* pszImplementation, DWORD dwFlags) {
    (void)pszImplementation; (void)dwFlags;
    if (!phAlgorithm) return BCRYPT_EINVAL;
    lsw_bcrypt_alg_t* alg = calloc(1, sizeof(lsw_bcrypt_alg_t));
    alg->magic = BCRYPT_ALG_MAGIC;
    if (pszAlgId) {
        /* Copy wide string to narrow alg name */
        for (int i = 0; i < 63 && pszAlgId[i]; i++) alg->alg[i] = (char)pszAlgId[i];
    }
    *phAlgorithm = alg;
    LSW_LOG_INFO("BCryptOpenAlgorithmProvider: %s", alg->alg);
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptCloseAlgorithmProvider(void* hAlgorithm, DWORD dwFlags) {
    (void)dwFlags;
    if (!hAlgorithm) return BCRYPT_EINVAL;
    lsw_bcrypt_alg_t* alg = hAlgorithm;
    if (alg->magic == BCRYPT_ALG_MAGIC) { alg->magic = 0; free(alg); }
    return BCRYPT_OK;
}

/* Real random bytes from /dev/urandom — critical for DRM, session tokens */
HRESULT MSABI lsw_BCryptGenRandom(void* hAlgorithm, uint8_t* pbBuffer, DWORD cbBuffer, DWORD dwFlags) {
    (void)hAlgorithm; (void)dwFlags;
    if (!pbBuffer || cbBuffer == 0) return BCRYPT_EINVAL;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { memset(pbBuffer, 0xAB, cbBuffer); return BCRYPT_OK; }
    ssize_t got = 0, total = 0;
    while (total < (ssize_t)cbBuffer) {
        got = read(fd, pbBuffer + total, cbBuffer - total);
        if (got <= 0) break;
        total += got;
    }
    close(fd);
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptGetProperty(void* hObject, const uint16_t* pszProperty, uint8_t* pbOutput,
                                     DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags) {
    (void)hObject; (void)pszProperty; (void)dwFlags;
    /* Return a reasonable default: key/block size = 32 bytes, hash size = 32 bytes */
    DWORD val = 32;
    if (pcbResult) *pcbResult = sizeof(DWORD);
    if (pbOutput && cbOutput >= sizeof(DWORD)) memcpy(pbOutput, &val, sizeof(DWORD));
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptSetProperty(void* hObject, const uint16_t* pszProperty, uint8_t* pbInput,
                                     DWORD cbInput, DWORD dwFlags) {
    (void)hObject; (void)pszProperty; (void)pbInput; (void)cbInput; (void)dwFlags;
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptCreateHash(void* hAlgorithm, void** phHash, uint8_t* pbHashObject,
                                    DWORD cbHashObject, uint8_t* pbSecret, DWORD cbSecret, DWORD dwFlags) {
    (void)hAlgorithm; (void)pbHashObject; (void)cbHashObject; (void)pbSecret; (void)cbSecret; (void)dwFlags;
    if (!phHash) return BCRYPT_EINVAL;
    lsw_bcrypt_hash_t* h = calloc(1, sizeof(lsw_bcrypt_hash_t));
    h->magic = BCRYPT_HASH_MAGIC;
    *phHash = h;
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptHashData(void* hHash, uint8_t* pbInput, DWORD cbInput, DWORD dwFlags) {
    (void)hHash; (void)pbInput; (void)cbInput; (void)dwFlags;
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptFinishHash(void* hHash, uint8_t* pbOutput, DWORD cbOutput, DWORD dwFlags) {
    (void)hHash; (void)dwFlags;
    /* Return zero-hash so apps get a consistent non-crash result */
    if (pbOutput && cbOutput > 0) memset(pbOutput, 0, cbOutput);
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptDestroyHash(void* hHash) {
    if (!hHash) return BCRYPT_EINVAL;
    lsw_bcrypt_hash_t* h = hHash;
    if (h->magic == BCRYPT_HASH_MAGIC) { h->magic = 0; free(h); }
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptHash(void* hAlgorithm, uint8_t* pbSecret, DWORD cbSecret,
                              uint8_t* pbInput, DWORD cbInput, uint8_t* pbOutput, DWORD cbOutput) {
    (void)hAlgorithm; (void)pbSecret; (void)cbSecret; (void)pbInput; (void)cbInput;
    if (pbOutput && cbOutput > 0) memset(pbOutput, 0, cbOutput);
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptDeriveKey(void* hSharedSecret, const uint16_t* pwszKDF, void* pParameterList,
                                   uint8_t* pbDerivedKey, DWORD cbDerivedKey, DWORD* pcbResult, DWORD dwFlags) {
    (void)hSharedSecret; (void)pwszKDF; (void)pParameterList; (void)dwFlags;
    if (pcbResult) *pcbResult = cbDerivedKey;
    if (pbDerivedKey && cbDerivedKey > 0) {
        /* Use urandom so the key is valid-looking */
        lsw_BCryptGenRandom(NULL, pbDerivedKey, cbDerivedKey, 0);
    }
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptGenerateSymmetricKey(void* hAlgorithm, void** phKey, uint8_t* pbKeyObj,
                                              DWORD cbKeyObj, uint8_t* pbSecret, DWORD cbSecret, DWORD dwFlags) {
    (void)hAlgorithm; (void)pbKeyObj; (void)cbKeyObj; (void)pbSecret; (void)cbSecret; (void)dwFlags;
    if (!phKey) return BCRYPT_EINVAL;
    lsw_bcrypt_key_t* k = calloc(1, sizeof(lsw_bcrypt_key_t));
    k->magic = BCRYPT_KEY_MAGIC;
    *phKey = k;
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptDestroyKey(void* hKey) {
    if (!hKey) return BCRYPT_EINVAL;
    lsw_bcrypt_key_t* k = hKey;
    if (k->magic == BCRYPT_KEY_MAGIC) { k->magic = 0; free(k); }
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptEncrypt(void* hKey, uint8_t* pbInput, DWORD cbInput, void* pPaddingInfo,
                                 uint8_t* pbIV, DWORD cbIV, uint8_t* pbOutput, DWORD cbOutput,
                                 DWORD* pcbResult, DWORD dwFlags) {
    (void)hKey; (void)pPaddingInfo; (void)pbIV; (void)cbIV; (void)dwFlags;
    if (pcbResult) *pcbResult = cbInput;
    if (pbOutput && cbOutput >= cbInput) memcpy(pbOutput, pbInput, cbInput);
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptDecrypt(void* hKey, uint8_t* pbInput, DWORD cbInput, void* pPaddingInfo,
                                 uint8_t* pbIV, DWORD cbIV, uint8_t* pbOutput, DWORD cbOutput,
                                 DWORD* pcbResult, DWORD dwFlags) {
    (void)hKey; (void)pPaddingInfo; (void)pbIV; (void)cbIV; (void)dwFlags;
    if (pcbResult) *pcbResult = cbInput;
    if (pbOutput && cbOutput >= cbInput) memcpy(pbOutput, pbInput, cbInput);
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptImportKey(void* hAlgorithm, void* hImportKey, const uint16_t* pszBlobType,
                                   void** phKey, uint8_t* pbKeyObj, DWORD cbKeyObj,
                                   uint8_t* pbInput, DWORD cbInput, DWORD dwFlags) {
    (void)hAlgorithm; (void)hImportKey; (void)pszBlobType;
    (void)pbKeyObj; (void)cbKeyObj; (void)pbInput; (void)cbInput; (void)dwFlags;
    if (!phKey) return BCRYPT_EINVAL;
    lsw_bcrypt_key_t* k = calloc(1, sizeof(lsw_bcrypt_key_t));
    k->magic = BCRYPT_KEY_MAGIC;
    *phKey = k;
    return BCRYPT_OK;
}

HRESULT MSABI lsw_BCryptExportKey(void* hKey, void* hExportKey, const uint16_t* pszBlobType,
                                   uint8_t* pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags) {
    (void)hKey; (void)hExportKey; (void)pszBlobType; (void)dwFlags;
    if (pcbResult) *pcbResult = 0;
    if (pbOutput && cbOutput > 0) memset(pbOutput, 0, cbOutput);
    return BCRYPT_OK;
}

/* NCrypt stubs (ncrypt.dll) — same pattern */
HRESULT MSABI lsw_NCryptOpenStorageProvider(void** phProvider, const uint16_t* pszProviderName, DWORD dwFlags) {
    (void)pszProviderName; (void)dwFlags;
    if (!phProvider) return E_POINTER;
    *phProvider = (void*)(uintptr_t)0xC0FE;
    return S_OK;
}
HRESULT MSABI lsw_NCryptFreeObject(void* hObject) { (void)hObject; return S_OK; }
HRESULT MSABI lsw_NCryptEnumAlgorithms(void* hProvider, DWORD dwAlgOperations, DWORD* pdwAlgCount,
                                        void** ppAlgList, DWORD dwFlags) {
    (void)hProvider; (void)dwAlgOperations; (void)dwFlags;
    if (pdwAlgCount) *pdwAlgCount = 0;
    if (ppAlgList)   *ppAlgList   = NULL;
    return S_OK;
}
HRESULT MSABI lsw_NCryptGetProperty(void* hObject, const uint16_t* pszProperty, uint8_t* pbOutput,
                                     DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags) {
    (void)hObject; (void)pszProperty; (void)pbOutput; (void)cbOutput; (void)dwFlags;
    if (pcbResult) *pcbResult = 0;
    return S_OK;
}
HRESULT MSABI lsw_NCryptIsAlgSupported(void* hProvider, const uint16_t* pszAlgId, DWORD dwFlags) {
    (void)hProvider; (void)pszAlgId; (void)dwFlags; return S_FALSE; /* not supported */
}


/* =========================================================================
 * ETW — Event Tracing for Windows (advapi32/ntdll)
 * Games use ETW for telemetry. We stub it out so calls silently succeed.
 * ========================================================================= */

typedef uint64_t REGHANDLE;

HRESULT MSABI lsw_EventRegister(const void* ProviderId, void* EnableCallback,
                                  void* CallbackContext, REGHANDLE* RegHandle) {
    (void)ProviderId; (void)EnableCallback; (void)CallbackContext;
    if (RegHandle) *RegHandle = 0x1; /* fake handle */
    return S_OK;
}

HRESULT MSABI lsw_EventUnregister(REGHANDLE RegHandle) { (void)RegHandle; return S_OK; }

HRESULT MSABI lsw_EventWrite(REGHANDLE RegHandle, const void* EventDescriptor,
                               DWORD UserDataCount, void* UserData) {
    (void)RegHandle; (void)EventDescriptor; (void)UserDataCount; (void)UserData;
    return S_OK;
}

HRESULT MSABI lsw_EventWriteEx(REGHANDLE RegHandle, const void* EventDescriptor, uint64_t Filter,
                                 DWORD Flags, const void* ActivityId, const void* RelatedActivityId,
                                 DWORD UserDataCount, void* UserData) {
    (void)RegHandle; (void)EventDescriptor; (void)Filter; (void)Flags;
    (void)ActivityId; (void)RelatedActivityId; (void)UserDataCount; (void)UserData;
    return S_OK;
}

HRESULT MSABI lsw_EventWriteTransfer(REGHANDLE RegHandle, const void* EventDescriptor,
                                       const void* ActivityId, const void* RelatedActivityId,
                                       DWORD UserDataCount, void* UserData) {
    (void)RegHandle; (void)EventDescriptor; (void)ActivityId; (void)RelatedActivityId;
    (void)UserDataCount; (void)UserData;
    return S_OK;
}

HRESULT MSABI lsw_EventWriteString(REGHANDLE RegHandle, uint8_t Level, uint64_t Keyword,
                                    const uint16_t* String) {
    (void)RegHandle; (void)Level; (void)Keyword; (void)String; return S_OK;
}

BOOL    MSABI lsw_EventEnabled(REGHANDLE RegHandle, const void* EventDescriptor) {
    (void)RegHandle; (void)EventDescriptor; return FALSE; /* disable all ETW events */
}

BOOL    MSABI lsw_EventProviderEnabled(REGHANDLE RegHandle, uint8_t Level, uint64_t Keyword) {
    (void)RegHandle; (void)Level; (void)Keyword; return FALSE;
}

/* EtwEventRegister / EtwEventWrite (ntdll exports) */
HRESULT MSABI lsw_EtwEventRegister(const void* ProviderId, void* EnableCallback,
                                     void* CallbackContext, REGHANDLE* RegHandle) {
    return lsw_EventRegister(ProviderId, EnableCallback, CallbackContext, RegHandle);
}
HRESULT MSABI lsw_EtwEventWrite(REGHANDLE RegHandle, const void* EventDescriptor,
                                  DWORD UserDataCount, void* UserData) {
    return lsw_EventWrite(RegHandle, EventDescriptor, UserDataCount, UserData);
}
HRESULT MSABI lsw_EtwEventUnregister(REGHANDLE RegHandle) { return lsw_EventUnregister(RegHandle); }

/* TdhGetEventInformation / TdhLoadManifest stubs (tdh.dll) */
HRESULT MSABI lsw_TdhGetEventInformation(void* pEvent, DWORD TdhContextCount,
                                           void* pTdhContext, void* pBuffer, DWORD* pBufferSize) {
    (void)pEvent; (void)TdhContextCount; (void)pTdhContext; (void)pBuffer;
    if (pBufferSize) *pBufferSize = 0;
    return 0x80070002; /* ERROR_FILE_NOT_FOUND */
}
HRESULT MSABI lsw_TdhLoadManifest(const uint16_t* pManifestPath) { (void)pManifestPath; return S_OK; }


/* =========================================================================
 * RawInput — user32.dll
 * Games call RegisterRawInputDevices so that WM_INPUT messages arrive.
 * We accept the registration but never generate WM_INPUT messages.
 * ========================================================================= */

BOOL MSABI lsw_RegisterRawInputDevices(const void* pRawInputDevices, DWORD uiNumDevices, DWORD cbSize) {
    (void)pRawInputDevices; (void)uiNumDevices; (void)cbSize;
    return TRUE;
}

DWORD MSABI lsw_GetRawInputData(void* hRawInput, DWORD uiCommand, void* pData, DWORD* pcbSize, DWORD cbSizeHeader) {
    (void)hRawInput; (void)uiCommand; (void)pData; (void)cbSizeHeader;
    if (pcbSize) *pcbSize = 0;
    return 0;
}

DWORD MSABI lsw_GetRawInputBuffer(void* pData, DWORD* pcbSize, DWORD cbSizeHeader) {
    (void)pData; (void)cbSizeHeader;
    if (pcbSize) *pcbSize = 0;
    return 0;
}

DWORD MSABI lsw_GetRegisteredRawInputDevices(void* pRawInputDevices, DWORD* puiNumDevices, DWORD cbSize) {
    (void)pRawInputDevices; (void)cbSize;
    if (puiNumDevices) *puiNumDevices = 0;
    return 0;
}

DWORD MSABI lsw_GetRawInputDeviceList(void* pRawInputDeviceList, DWORD* puiNumDevices, DWORD cbSize) {
    (void)pRawInputDeviceList; (void)cbSize;
    if (puiNumDevices) *puiNumDevices = 0;
    return 0;
}

DWORD MSABI lsw_GetRawInputDeviceInfoW(void* hDevice, DWORD uiCommand, void* pData, DWORD* pcbSize) {
    (void)hDevice; (void)uiCommand; (void)pData;
    if (pcbSize) *pcbSize = 0;
    return 0;
}
DWORD MSABI lsw_GetRawInputDeviceInfoA(void* hDevice, DWORD uiCommand, void* pData, DWORD* pcbSize) {
    return lsw_GetRawInputDeviceInfoW(hDevice, uiCommand, pData, pcbSize);
}


/* =========================================================================
 * Process priority and affinity — KERNEL32.dll
 * ========================================================================= */

#define NORMAL_PRIORITY_CLASS       0x20
#define ABOVE_NORMAL_PRIORITY_CLASS 0x8000
#define HIGH_PRIORITY_CLASS         0x80
#define REALTIME_PRIORITY_CLASS     0x100

BOOL  MSABI lsw_SetPriorityClass(void* hProcess, DWORD dwPriorityClass) {
    (void)hProcess;
    int niceval = 0;
    if (dwPriorityClass == HIGH_PRIORITY_CLASS)  niceval = -10;
    if (dwPriorityClass == REALTIME_PRIORITY_CLASS) niceval = -20;
    if (dwPriorityClass == ABOVE_NORMAL_PRIORITY_CLASS) niceval = -5;
    setpriority(PRIO_PROCESS, 0, niceval);
    return TRUE;
}

DWORD MSABI lsw_GetPriorityClass(void* hProcess) {
    (void)hProcess; return NORMAL_PRIORITY_CLASS;
}

BOOL  MSABI lsw_GetProcessAffinityMask(void* hProcess, uint64_t* lpProcessAffinityMask,
                                         uint64_t* lpSystemAffinityMask) {
    (void)hProcess;
    /* Return all CPUs online */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0 || ncpu > 64) ncpu = 1;
    uint64_t mask = (ncpu == 64) ? ~(uint64_t)0 : ((uint64_t)1 << ncpu) - 1;
    if (lpProcessAffinityMask) *lpProcessAffinityMask = mask;
    if (lpSystemAffinityMask)  *lpSystemAffinityMask  = mask;
    return TRUE;
}

BOOL MSABI lsw_SetProcessAffinityMask(void* hProcess, uint64_t dwProcessAffinityMask) {
    (void)hProcess;
    cpu_set_t set;
    CPU_ZERO(&set);
    for (int i = 0; i < 64; i++)
        if (dwProcessAffinityMask & ((uint64_t)1 << i)) CPU_SET(i, &set);
    sched_setaffinity(0, sizeof(set), &set);
    return TRUE;
}

BOOL MSABI lsw_GetProcessHandleCount(void* hProcess, DWORD* pdwHandleCount) {
    (void)hProcess; if (pdwHandleCount) *pdwHandleCount = 10; return TRUE;
}


/* =========================================================================
 * ReadProcessMemory / WriteProcessMemory — KERNEL32.dll
 * For the current process (pseudo-handle), just do memcpy.
 * For other PIDs, try /proc/<pid>/mem.
 * ========================================================================= */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>

BOOL MSABI lsw_ReadProcessMemory(void* hProcess, const void* lpBaseAddress,
                                   void* lpBuffer, size_t nSize, size_t* lpNumberOfBytesRead) {
    if (!lpBuffer || nSize == 0) { if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0; return FALSE; }
    /* Pseudo-handle for current process */
    uintptr_t hp = (uintptr_t)hProcess;
    if (hp == 0xFFFFFFFFFFFFFFFFULL || hp == 0xFFFFFFFEULL || hp == (uintptr_t)-1) {
        memcpy(lpBuffer, lpBaseAddress, nSize);
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;
        return TRUE;
    }
    /* Try /proc/pid/mem for other processes */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)(uintptr_t)hProcess);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0; return FALSE; }
    ssize_t r = pread(fd, lpBuffer, nSize, (off_t)(uintptr_t)lpBaseAddress);
    close(fd);
    if (r < 0) { if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0; return FALSE; }
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (size_t)r;
    return TRUE;
}

BOOL MSABI lsw_WriteProcessMemory(void* hProcess, void* lpBaseAddress,
                                    const void* lpBuffer, size_t nSize, size_t* lpNumberOfBytesWritten) {
    if (!lpBuffer || nSize == 0) { if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0; return FALSE; }
    uintptr_t hp = (uintptr_t)hProcess;
    if (hp == 0xFFFFFFFFFFFFFFFFULL || hp == 0xFFFFFFFEULL || hp == (uintptr_t)-1) {
        memcpy(lpBaseAddress, lpBuffer, nSize);
        if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;
        return TRUE;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)(uintptr_t)hProcess);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) { if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0; return FALSE; }
    ssize_t r = pwrite(fd, lpBuffer, nSize, (off_t)(uintptr_t)lpBaseAddress);
    close(fd);
    if (r < 0) { if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0; return FALSE; }
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (size_t)r;
    return TRUE;
}


/* =========================================================================
 * VirtualAlloc2 / VirtualAllocFromApp / AddressWindowing (KERNEL32)
 * ========================================================================= */

#include <sys/mman.h>

void* MSABI lsw_VirtualAlloc2(void* Process, void* BaseAddress, size_t Size,
                                DWORD AllocationType, DWORD PageProtection,
                                void* ExtendedParameters, DWORD ParameterCount) {
    (void)Process; (void)ExtendedParameters; (void)ParameterCount;
    int prot = PROT_READ | PROT_WRITE;
    if (PageProtection & 0x10) prot = PROT_EXEC | PROT_READ;
    if (PageProtection & 0x20) prot = PROT_EXEC | PROT_READ;
    if (PageProtection & 0x40) prot = PROT_EXEC | PROT_READ | PROT_WRITE;
    (void)AllocationType;
    return mmap(BaseAddress, Size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void* MSABI lsw_VirtualAllocFromApp(void* BaseAddress, size_t Size, DWORD AllocationType, DWORD PageProtection) {
    return lsw_VirtualAlloc2(NULL, BaseAddress, Size, AllocationType, PageProtection, NULL, 0);
}


/* =========================================================================
 * XAudio2 — null audio device COM stub
 *
 * We implement a fake IXAudio2 COM object.  All voice operations succeed
 * (return S_OK) but produce no actual sound.  This lets games start and
 * run without audio hardware, instead of crashing on XAudio2Create.
 *
 * Two vtable layouts are provided:
 *   v28 (xaudio2_8/9.dll): no GetDeviceCount/GetDeviceDetails/Initialize
 *   v27 (xaudio2_7.dll):   includes the three legacy methods
 * ========================================================================= */

/* ---- IXAudio2Voice vtable (shared by mastering + source voices) ---- */
static HRESULT MSABI xa2voice_noop1(void* t, void* a) { (void)t; (void)a; return S_OK; }
static HRESULT MSABI xa2voice_noop2(void* t, void* a, void* b) { (void)t; (void)a; (void)b; return S_OK; }
static HRESULT MSABI xa2voice_noop3(void* t, void* a, void* b, void* c) { (void)t; (void)a; (void)b; (void)c; return S_OK; }
static HRESULT MSABI xa2voice_noop_i3(void* t, uint32_t a, uint32_t b, uint32_t c) { (void)t; (void)a; (void)b; (void)c; return S_OK; }
static HRESULT MSABI xa2voice_noop_iap(void* t, uint32_t a, void* b, uint32_t c) { (void)t; (void)a; (void)b; (void)c; return S_OK; }
static void    MSABI xa2voice_void_noop(void* t) { (void)t; }
static void    MSABI xa2voice_void_noop1(void* t, void* a) { (void)t; (void)a; }
static HRESULT MSABI xa2voice_get_vol(void* t, float* v) { if (v) *v = 1.0f; return S_OK; }
static HRESULT MSABI xa2voice_set_vol(void* t, float v, uint32_t op) { (void)t; (void)v; (void)op; return S_OK; }
static HRESULT MSABI xa2voice_get_details(void* t, void* d) { (void)t; if (d) memset(d, 0, 32); return S_OK; }
static HRESULT MSABI xa2voice_get_state(void* t, void* st, uint32_t fl) { (void)t; (void)fl; if (st) memset(st, 0, 32); return S_OK; }
static HRESULT MSABI xa2voice_submit(void* t, void* buf, uint32_t op) { (void)t; (void)buf; (void)op; return S_OK; }
static HRESULT MSABI xa2voice_start(void* t, uint32_t fl, uint32_t op) { (void)t; (void)fl; (void)op; return S_OK; }
static HRESULT MSABI xa2voice_stop(void* t, uint32_t fl, uint32_t op)  { (void)t; (void)fl; (void)op; return S_OK; }
static HRESULT MSABI xa2voice_freq(void* t, float r, void* cb, uint32_t op) { (void)t; (void)r; (void)cb; (void)op; return S_OK; }
static HRESULT MSABI xa2voice_getfreq(void* t, float* r) { if (r) *r = 1.0f; return S_OK; }
static HRESULT MSABI xa2voice_setsamplerate(void* t, uint32_t r, uint32_t op) { (void)t; (void)r; (void)op; return S_OK; }
static DWORD   MSABI xa2voice_getchanmask(void* t, DWORD* m) { if (m) *m = 3; return S_OK; }
static HRESULT MSABI xa2voice_enable_effect(void* t, uint32_t idx, uint32_t op) { (void)t; (void)idx; (void)op; return S_OK; }
static HRESULT MSABI xa2voice_get_effect_state(void* t, uint32_t idx, int* e) { (void)t; (void)idx; if (e) *e = 0; return S_OK; }

/* Voice vtable — IXAudio2Voice fields then source-specific fields */
typedef struct {
    /* IXAudio2Voice */
    void* GetVoiceDetails;       /* 0 */
    void* SetOutputVoices;       /* 1 */
    void* SetEffectChain;        /* 2 */
    void* EnableEffect;          /* 3 */
    void* DisableEffect;         /* 4 */
    void* GetEffectState;        /* 5 */
    void* SetEffectParameters;   /* 6 */
    void* GetEffectParameters;   /* 7 */
    void* SetFilterParameters;   /* 8 */
    void* GetFilterParameters;   /* 9 */
    void* SetOutputFilterParameters; /* 10 */
    void* GetOutputFilterParameters; /* 11 */
    void* SetVolume;             /* 12 */
    void* GetVolume;             /* 13 */
    void* SetChannelVolumes;     /* 14 */
    void* GetChannelVolumes;     /* 15 */
    void* SetOutputMatrix;       /* 16 */
    void* GetOutputMatrix;       /* 17 */
    void* DestroyVoice;          /* 18 */
    /* IXAudio2SourceVoice extras */
    void* Start;                 /* 19 */
    void* Stop;                  /* 20 */
    void* SubmitSourceBuffer;    /* 21 */
    void* FlushSourceBuffers;    /* 22 */
    void* Discontinuity;         /* 23 */
    void* ExitLoop;              /* 24 */
    void* GetState;              /* 25 */
    void* SetFrequencyRatio;     /* 26 */
    void* GetFrequencyRatio;     /* 27 */
    void* SetSourceSampleRate;   /* 28 */
    /* IXAudio2MasteringVoice extra */
    void* GetChannelMask;        /* 19 (master only, same slot as Start) */
} lsw_xa2voice_vtbl_t;

static const lsw_xa2voice_vtbl_t g_xa2voice_vtbl = {
    xa2voice_get_details,    /* GetVoiceDetails */
    xa2voice_noop2,          /* SetOutputVoices */
    xa2voice_noop2,          /* SetEffectChain */
    xa2voice_enable_effect,  /* EnableEffect */
    xa2voice_enable_effect,  /* DisableEffect */
    xa2voice_get_effect_state, /* GetEffectState */
    xa2voice_noop_iap,       /* SetEffectParameters */
    xa2voice_noop_iap,       /* GetEffectParameters */
    xa2voice_noop2,          /* SetFilterParameters */
    xa2voice_noop2,          /* GetFilterParameters */
    xa2voice_noop3,          /* SetOutputFilterParameters */
    xa2voice_noop3,          /* GetOutputFilterParameters */
    xa2voice_set_vol,        /* SetVolume */
    xa2voice_get_vol,        /* GetVolume */
    xa2voice_noop_iap,       /* SetChannelVolumes */
    xa2voice_noop_iap,       /* GetChannelVolumes */
    xa2voice_noop3,          /* SetOutputMatrix */
    xa2voice_noop3,          /* GetOutputMatrix */
    xa2voice_void_noop,      /* DestroyVoice */
    xa2voice_start,          /* Start / GetChannelMask */
    xa2voice_stop,           /* Stop */
    xa2voice_submit,         /* SubmitSourceBuffer */
    xa2voice_void_noop,      /* FlushSourceBuffers */
    xa2voice_void_noop,      /* Discontinuity */
    xa2voice_void_noop1,     /* ExitLoop */
    xa2voice_get_state,      /* GetState */
    xa2voice_freq,           /* SetFrequencyRatio */
    xa2voice_getfreq,        /* GetFrequencyRatio */
    xa2voice_setsamplerate,  /* SetSourceSampleRate */
};

/* Mastering-voice vtable — same as above but GetChannelMask at slot 19 */
static const lsw_xa2voice_vtbl_t g_xa2master_vtbl = {
    xa2voice_get_details,    /* GetVoiceDetails */
    xa2voice_noop2,          /* SetOutputVoices */
    xa2voice_noop2,          /* SetEffectChain */
    xa2voice_enable_effect,  /* EnableEffect */
    xa2voice_enable_effect,  /* DisableEffect */
    xa2voice_get_effect_state,
    xa2voice_noop_iap,
    xa2voice_noop_iap,
    xa2voice_noop2,
    xa2voice_noop2,
    xa2voice_noop3,
    xa2voice_noop3,
    xa2voice_set_vol,
    xa2voice_get_vol,
    xa2voice_noop_iap,
    xa2voice_noop_iap,
    xa2voice_noop3,
    xa2voice_noop3,
    xa2voice_void_noop,      /* DestroyVoice */
    xa2voice_getchanmask,    /* GetChannelMask (master only) */
};

typedef struct { const void* vtbl; } lsw_xa2voice_obj_t;

/* ---- IXAudio2 vtable (2.8+ layout, no GetDeviceCount/Details/Init) ---- */
static HRESULT MSABI xa2_QueryInterface(void* t, const void* riid, void** ppv) {
    (void)t; (void)riid; if (ppv) *ppv = t; return S_OK;
}
static uint32_t MSABI xa2_AddRef(void* t)  { (void)t; return 1; }
static uint32_t MSABI xa2_Release(void* t) { (void)t; return 0; }
static HRESULT MSABI xa2_RegisterForCallbacks(void* t, void* cb) { (void)t; (void)cb; return S_OK; }
static void    MSABI xa2_UnregisterForCallbacks(void* t, void* cb) { (void)t; (void)cb; }
static HRESULT MSABI xa2_CreateSourceVoice(void* t, void** ppVoice, const void* fmt,
                                             uint32_t flags, float maxFreq, void* cb,
                                             const void* sends, const void* effects) {
    (void)t; (void)fmt; (void)flags; (void)maxFreq; (void)cb; (void)sends; (void)effects;
    if (!ppVoice) return E_POINTER;
    lsw_xa2voice_obj_t* v = calloc(1, sizeof(lsw_xa2voice_obj_t));
    v->vtbl = &g_xa2voice_vtbl;
    *ppVoice = v;
    return S_OK;
}
static HRESULT MSABI xa2_CreateSubmixVoice(void* t, void** ppVoice, uint32_t channels,
                                             uint32_t sampleRate, uint32_t flags, uint32_t stage,
                                             const void* sends, const void* effects) {
    (void)t; (void)channels; (void)sampleRate; (void)flags; (void)stage; (void)sends; (void)effects;
    if (!ppVoice) return E_POINTER;
    lsw_xa2voice_obj_t* v = calloc(1, sizeof(lsw_xa2voice_obj_t));
    v->vtbl = &g_xa2voice_vtbl;
    *ppVoice = v;
    return S_OK;
}
static HRESULT MSABI xa2_CreateMasteringVoice(void* t, void** ppVoice, uint32_t channels,
                                                uint32_t sampleRate, uint32_t flags,
                                                const void* deviceId, const void* effects,
                                                uint32_t streamCat) {
    (void)t; (void)channels; (void)sampleRate; (void)flags; (void)deviceId; (void)effects; (void)streamCat;
    if (!ppVoice) return E_POINTER;
    lsw_xa2voice_obj_t* v = calloc(1, sizeof(lsw_xa2voice_obj_t));
    v->vtbl = &g_xa2master_vtbl;
    *ppVoice = v;
    LSW_LOG_INFO("XAudio2::CreateMasteringVoice -> null device");
    return S_OK;
}
static HRESULT MSABI xa2_StartEngine(void* t) { (void)t; return S_OK; }
static void    MSABI xa2_StopEngine(void* t)  { (void)t; }
static HRESULT MSABI xa2_CommitChanges(void* t, uint32_t op) { (void)t; (void)op; return S_OK; }
static void    MSABI xa2_GetPerformanceData(void* t, void* d) { (void)t; if (d) memset(d, 0, 64); }
static void    MSABI xa2_SetDebugConfiguration(void* t, const void* cfg, void* r) { (void)t; (void)cfg; (void)r; }

typedef struct {
    void* QueryInterface;
    void* AddRef;
    void* Release;
    void* RegisterForCallbacks;
    void* UnregisterForCallbacks;
    void* CreateSourceVoice;
    void* CreateSubmixVoice;
    void* CreateMasteringVoice;
    void* StartEngine;
    void* StopEngine;
    void* CommitChanges;
    void* GetPerformanceData;
    void* SetDebugConfiguration;
} lsw_xa2_vtbl28_t;

static const lsw_xa2_vtbl28_t g_xa2_vtbl28 = {
    xa2_QueryInterface, xa2_AddRef, xa2_Release,
    xa2_RegisterForCallbacks, xa2_UnregisterForCallbacks,
    xa2_CreateSourceVoice, xa2_CreateSubmixVoice, xa2_CreateMasteringVoice,
    xa2_StartEngine, xa2_StopEngine, xa2_CommitChanges,
    xa2_GetPerformanceData, xa2_SetDebugConfiguration,
};

/* XAudio2 2.7 vtable: three extra methods after Release */
static HRESULT MSABI xa2_27_GetDeviceCount(void* t, DWORD* cnt) { (void)t; if (cnt) *cnt = 1; return S_OK; }
static HRESULT MSABI xa2_27_GetDeviceDetails(void* t, DWORD idx, void* d) {
    (void)t; (void)idx; if (d) memset(d, 0, 256); return S_OK;
}
static HRESULT MSABI xa2_27_Initialize(void* t, DWORD flags, uint32_t proc) { (void)t; (void)flags; (void)proc; return S_OK; }

typedef struct {
    void* QueryInterface;
    void* AddRef;
    void* Release;
    void* GetDeviceCount;       /* XAudio2 2.7 only */
    void* GetDeviceDetails;     /* XAudio2 2.7 only */
    void* Initialize;           /* XAudio2 2.7 only */
    void* RegisterForCallbacks;
    void* UnregisterForCallbacks;
    void* CreateSourceVoice;
    void* CreateSubmixVoice;
    void* CreateMasteringVoice;
    void* StartEngine;
    void* StopEngine;
    void* CommitChanges;
    void* GetPerformanceData;
    void* SetDebugConfiguration;
} lsw_xa2_vtbl27_t;

static const lsw_xa2_vtbl27_t g_xa2_vtbl27 = {
    xa2_QueryInterface, xa2_AddRef, xa2_Release,
    xa2_27_GetDeviceCount, xa2_27_GetDeviceDetails, xa2_27_Initialize,
    xa2_RegisterForCallbacks, xa2_UnregisterForCallbacks,
    xa2_CreateSourceVoice, xa2_CreateSubmixVoice, xa2_CreateMasteringVoice,
    xa2_StartEngine, xa2_StopEngine, xa2_CommitChanges,
    xa2_GetPerformanceData, xa2_SetDebugConfiguration,
};

typedef struct { const void* vtbl; } lsw_xa2obj_t;
static lsw_xa2obj_t g_xa2_obj28 = { &g_xa2_vtbl28 };
static lsw_xa2obj_t g_xa2_obj27 = { &g_xa2_vtbl27 };

/* XAudio2Create — entry point for xaudio2_8.dll / xaudio2_9.dll */
HRESULT MSABI lsw_XAudio2Create(void** ppXAudio2, DWORD Flags, DWORD XAudio2Processor) {
    (void)Flags; (void)XAudio2Processor;
    if (!ppXAudio2) return E_POINTER;
    *ppXAudio2 = &g_xa2_obj28;
    LSW_LOG_INFO("XAudio2Create (2.8+) -> null audio device");
    return S_OK;
}

/* XAudio2Create for 2.7 (xaudio2_7.dll and older standalone SDK) */
HRESULT MSABI lsw_XAudio27Create(void** ppXAudio2, DWORD Flags, DWORD proc) {
    (void)Flags; (void)proc;
    if (!ppXAudio2) return E_POINTER;
    *ppXAudio2 = &g_xa2_obj27;
    LSW_LOG_INFO("XAudio2Create (2.7) -> null audio device");
    return S_OK;
}

/* CreateAudioVolumeMeter / CreateAudioReverb — effect factory stubs */
HRESULT MSABI lsw_CreateAudioVolumeMeter(void** ppApo) { if (ppApo) *ppApo = NULL; return E_NOTIMPL; }
HRESULT MSABI lsw_CreateAudioReverb(void** ppApo)      { if (ppApo) *ppApo = NULL; return E_NOTIMPL; }


/* =========================================================================
 * DirectInput8 — dinput8.dll
 *
 * Implements a minimal IDirectInput8A COM stub.  EnumDevices calls the
 * callback with zero devices so games fall back to other input APIs.
 * ========================================================================= */

static HRESULT MSABI di8_QueryInterface(void* t, const void* riid, void** ppv) {
    (void)t; (void)riid; if (ppv) *ppv = t; return S_OK;
}
static uint32_t MSABI di8_AddRef(void* t)  { (void)t; return 1; }
static uint32_t MSABI di8_Release(void* t) { (void)t; return 0; }
static HRESULT MSABI di8_CreateDevice(void* t, const void* rguid, void** ppDevice, void* pUnkOuter) {
    (void)t; (void)rguid; (void)pUnkOuter; if (ppDevice) *ppDevice = NULL; return E_NOTIMPL;
}
static HRESULT MSABI di8_EnumDevices(void* t, DWORD type, void* callback, void* ref, DWORD flags) {
    /* Call callback with zero devices — no DIENUM_CONTINUE needed */
    (void)t; (void)type; (void)callback; (void)ref; (void)flags; return S_OK;
}
static HRESULT MSABI di8_GetDeviceStatus(void* t, const void* rguid) { (void)t; (void)rguid; return 0x80070002; }
static HRESULT MSABI di8_RunControlPanel(void* t, void* hwnd, DWORD flags) { (void)t; (void)hwnd; (void)flags; return E_NOTIMPL; }
static HRESULT MSABI di8_Initialize(void* t, void* hinst, DWORD dwVersion) { (void)t; (void)hinst; (void)dwVersion; return S_OK; }
static HRESULT MSABI di8_FindDevice(void* t, const void* guid, const void* name, void* pGuid) { (void)t; (void)guid; (void)name; (void)pGuid; return E_NOTIMPL; }
static HRESULT MSABI di8_CreateDeviceEx(void* t, const void* rguid, const void* riid, void** ppDevice, void* pUnkOuter) {
    (void)t; (void)rguid; (void)riid; (void)pUnkOuter; if (ppDevice) *ppDevice = NULL; return E_NOTIMPL;
}
static HRESULT MSABI di8_EnumDevicesBySemantics(void* t, const char* user, void* fmt,
                                                  void* cb, void* ref, DWORD flags) {
    (void)t; (void)user; (void)fmt; (void)cb; (void)ref; (void)flags; return S_OK;
}
static HRESULT MSABI di8_ConfigureDevices(void* t, void* cb, void* params, DWORD flags, void* ref) {
    (void)t; (void)cb; (void)params; (void)flags; (void)ref; return S_OK;
}

typedef struct {
    void* QueryInterface;
    void* AddRef;
    void* Release;
    void* CreateDevice;
    void* EnumDevices;
    void* GetDeviceStatus;
    void* RunControlPanel;
    void* Initialize;
    void* FindDevice;
    void* CreateDeviceEx;              /* A version only */
    void* EnumDevicesBySemantics;
    void* ConfigureDevices;
} lsw_di8a_vtbl_t;

static const lsw_di8a_vtbl_t g_di8a_vtbl = {
    di8_QueryInterface, di8_AddRef, di8_Release,
    di8_CreateDevice, di8_EnumDevices, di8_GetDeviceStatus,
    di8_RunControlPanel, di8_Initialize, di8_FindDevice,
    di8_CreateDeviceEx, di8_EnumDevicesBySemantics, di8_ConfigureDevices,
};
typedef struct { const void* vtbl; } lsw_di8_obj_t;
static lsw_di8_obj_t g_di8_obj = { &g_di8a_vtbl };

HRESULT MSABI lsw_DirectInput8Create(void* hinst, DWORD dwVersion, const void* riid,
                                       void** ppvOut, void* punkOuter) {
    (void)hinst; (void)dwVersion; (void)riid; (void)punkOuter;
    if (!ppvOut) return E_POINTER;
    *ppvOut = &g_di8_obj;
    LSW_LOG_INFO("DirectInput8Create -> null device");
    return S_OK;
}

/* DInput1-7 legacy entry */
HRESULT MSABI lsw_DirectInputCreateW(void* hinst, DWORD dwVersion, void** ppvOut, void* punkOuter) {
    (void)hinst; (void)dwVersion; (void)punkOuter;
    if (!ppvOut) return E_POINTER;
    *ppvOut = &g_di8_obj;
    return S_OK;
}
HRESULT MSABI lsw_DirectInputCreateA(void* hinst, DWORD dwVersion, void** ppvOut, void* punkOuter) {
    return lsw_DirectInputCreateW(hinst, dwVersion, ppvOut, punkOuter);
}


/* =========================================================================
 * D3DX stubs — d3dx9_43.dll, d3dx10.dll, d3dx11.dll
 * Only commonly-used math / utility functions are listed.
 * ========================================================================= */

/* 4×4 float matrix helpers */
typedef float lsw_mat4[16];
typedef float lsw_vec3[3];
typedef float lsw_vec4[4];

void* MSABI lsw_D3DXMatrixMultiply(lsw_mat4 out, const lsw_mat4 a, const lsw_mat4 b) {
    if (!out || !a || !b) return NULL;
    lsw_mat4 tmp;
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++) {
            float s = 0;
            for (int k = 0; k < 4; k++) s += a[r*4+k] * b[k*4+c];
            tmp[r*4+c] = s;
        }
    memcpy(out, tmp, sizeof(lsw_mat4));
    return out;
}

void* MSABI lsw_D3DXMatrixIdentity(lsw_mat4 out) {
    if (!out) return NULL;
    memset(out, 0, sizeof(lsw_mat4));
    out[0] = out[5] = out[10] = out[15] = 1.0f;
    return out;
}

void* MSABI lsw_D3DXVec3Normalize(lsw_vec3 out, const lsw_vec3 in) {
    if (!out || !in) return NULL;
    float len = in[0]*in[0] + in[1]*in[1] + in[2]*in[2];
    if (len > 0) { len = 1.0f / __builtin_sqrtf(len); }
    out[0] = in[0] * len; out[1] = in[1] * len; out[2] = in[2] * len;
    return out;
}

float MSABI lsw_D3DXVec3Dot(const lsw_vec3 a, const lsw_vec3 b) {
    if (!a || !b) return 0.0f;
    return a[0]*b[0] + a[1]*b[1] + a[2]*b[2];
}

void* MSABI lsw_D3DXVec3Cross(lsw_vec3 out, const lsw_vec3 a, const lsw_vec3 b) {
    if (!out || !a || !b) return NULL;
    out[0] = a[1]*b[2] - a[2]*b[1];
    out[1] = a[2]*b[0] - a[0]*b[2];
    out[2] = a[0]*b[1] - a[1]*b[0];
    return out;
}

float MSABI lsw_D3DXVec3Length(const lsw_vec3 v) {
    if (!v) return 0.0f;
    return __builtin_sqrtf(v[0]*v[0] + v[1]*v[1] + v[2]*v[2]);
}

void* MSABI lsw_D3DXVec4Transform(lsw_vec4 out, const lsw_vec4 v, const lsw_mat4 m) {
    if (!out || !v || !m) return NULL;
    out[0] = v[0]*m[0]  + v[1]*m[4]  + v[2]*m[8]  + v[3]*m[12];
    out[1] = v[0]*m[1]  + v[1]*m[5]  + v[2]*m[9]  + v[3]*m[13];
    out[2] = v[0]*m[2]  + v[1]*m[6]  + v[2]*m[10] + v[3]*m[14];
    out[3] = v[0]*m[3]  + v[1]*m[7]  + v[2]*m[11] + v[3]*m[15];
    return out;
}

/* D3DX resource stubs — these return E_NOTIMPL; games using them need D3D */
HRESULT MSABI lsw_D3DXCreateTextureFromFileW(void* dev, const uint16_t* file, void** ppTex) {
    (void)dev; (void)file; if (ppTex) *ppTex = NULL; return E_NOTIMPL;
}
HRESULT MSABI lsw_D3DXCreateTextureFromFileA(void* dev, const char* file, void** ppTex) {
    (void)dev; (void)file; if (ppTex) *ppTex = NULL; return E_NOTIMPL;
}
HRESULT MSABI lsw_D3DXCreateEffectFromFileW(void* dev, const uint16_t* file, void* defines,
    void* inc, DWORD flags, void* pool, void** ppEff, void** ppErr) {
    (void)dev; (void)file; (void)defines; (void)inc; (void)flags; (void)pool;
    if (ppEff) *ppEff = NULL; if (ppErr) *ppErr = NULL; return E_NOTIMPL;
}
HRESULT MSABI lsw_D3DX11CreateTextureFromFile(void* dev, const char* file, void* loadInfo,
    void* pump, void** ppTex, HRESULT* pHResult) {
    (void)dev; (void)file; (void)loadInfo; (void)pump;
    if (ppTex) *ppTex = NULL; if (pHResult) *pHResult = E_NOTIMPL; return E_NOTIMPL;
}
HRESULT MSABI lsw_D3DX11CompileFromFile(const char* file, void* defines, void* inc,
    const char* entry, const char* profile, DWORD flags1, DWORD flags2, void* pump,
    void** ppShader, void** ppErr, HRESULT* pHResult) {
    (void)file; (void)defines; (void)inc; (void)entry; (void)profile;
    (void)flags1; (void)flags2; (void)pump;
    if (ppShader) *ppShader = NULL; if (ppErr) *ppErr = NULL;
    if (pHResult) *pHResult = E_NOTIMPL; return E_NOTIMPL;
}


/* =========================================================================
 * Windows Runtime stubs — combase.dll / rpcrt4.dll
 * Modern games (UWP, Game Pass) use WinRT activation for some subsystems.
 * ========================================================================= */

HRESULT MSABI lsw_RoInitialize(DWORD initType) { (void)initType; return S_OK; }
void    MSABI lsw_RoUninitialize(void) {}
HRESULT MSABI lsw_RoGetActivationFactory(const void* activatableClassId, const void* iid, void** ppFactory) {
    (void)activatableClassId; (void)iid; if (ppFactory) *ppFactory = NULL; return E_NOTIMPL;
}
HRESULT MSABI lsw_RoActivateInstance(const void* activatableClassId, void** instance) {
    (void)activatableClassId; if (instance) *instance = NULL; return E_NOTIMPL;
}
HRESULT MSABI lsw_RoRegisterActivationFactories(void* activatableClassIds, void* activationFactoryCallbacks,
                                                  DWORD count, void** cookie) {
    (void)activatableClassIds; (void)activationFactoryCallbacks; (void)count;
    if (cookie) *cookie = NULL; return S_OK;
}

/* WindowsCreateString / DeleteString (combase / api-ms-win-core-winrt-string) */
HRESULT MSABI lsw_WindowsCreateString(const uint16_t* src, uint32_t len, void** str) {
    (void)src; (void)len; if (str) *str = NULL; return S_OK;
}
HRESULT MSABI lsw_WindowsDeleteString(void* str) { (void)str; return S_OK; }
const uint16_t* MSABI lsw_WindowsGetStringRawBuffer(void* str, uint32_t* len) {
    (void)str; if (len) *len = 0;
    static const uint16_t empty = 0; return &empty;
}
HRESULT MSABI lsw_WindowsDuplicateString(void* str, void** newStr) {
    (void)str; if (newStr) *newStr = NULL; return S_OK;
}


/* =========================================================================
 * Misc game/launcher stubs
 * ========================================================================= */

/* GameBar / GameOverlay (GameBarPresenceWriter) */
HRESULT MSABI lsw_GameBarIsSupported(int* pSupported) { if (pSupported) *pSupported = 0; return S_OK; }

/* GameInput (Microsoft.GameInput — game-input.dll) */
HRESULT MSABI lsw_GameInputCreate(void** ppGameInput) { if (ppGameInput) *ppGameInput = NULL; return E_NOTIMPL; }

/* steam_api64 — stub so games that dyn-load Steam don't crash on init */
HRESULT MSABI lsw_SteamAPI_Init(void) { return S_FALSE; }  /* FALSE = not running under Steam */
HRESULT MSABI lsw_SteamAPI_InitFlat(char* errMsg, int errSize) {
    (void)errSize; if (errMsg) strncpy(errMsg, "Steam not available", 64); return S_FALSE;
}
void    MSABI lsw_SteamAPI_Shutdown(void) {}
void    MSABI lsw_SteamAPI_RunCallbacks(void) {}
int     MSABI lsw_SteamAPI_IsSteamRunning(void) { return 0; }
void*   MSABI lsw_SteamInternal_CreateInterface(const char* ver) { (void)ver; return NULL; }

/* BattlEye / EAC stubs (anti-cheat launchers — we just acknowledge load) */
HRESULT MSABI lsw_BEClient_Noop(void) { return S_OK; }
HRESULT MSABI lsw_EACLauncher_Noop(void) { return S_OK; }

/* PDH — Performance Data Helper (pdh.dll) */
HRESULT MSABI lsw_PdhOpenQueryW(const uint16_t* szDataSource, uint64_t dwUserData, void** phQuery) {
    (void)szDataSource; (void)dwUserData; if (phQuery) *phQuery = (void*)1; return S_OK;
}
HRESULT MSABI lsw_PdhAddCounterW(void* hQuery, const uint16_t* szFullCounterPath, uint64_t dwUserData, void** phCounter) {
    (void)hQuery; (void)szFullCounterPath; (void)dwUserData; if (phCounter) *phCounter = (void*)2; return S_OK;
}
HRESULT MSABI lsw_PdhCollectQueryData(void* hQuery) { (void)hQuery; return S_OK; }
HRESULT MSABI lsw_PdhGetFormattedCounterValue(void* hCounter, DWORD dwFormat, DWORD* lpdwType, void* pValue) {
    (void)hCounter; (void)dwFormat; (void)lpdwType; if (pValue) memset(pValue, 0, 24); return S_OK;
}
HRESULT MSABI lsw_PdhCloseQuery(void* hQuery) { (void)hQuery; return S_OK; }

/* PowerCreateRequest / PowerSetRequest / PowerClearRequest */
void* MSABI lsw_PowerCreateRequest(void* context) { (void)context; return (void*)1; }
int   MSABI lsw_PowerSetRequest(void* handle, DWORD type) { (void)handle; (void)type; return 1; }
int   MSABI lsw_PowerClearRequest(void* handle, DWORD type) { (void)handle; (void)type; return 1; }

/* Magnification (magnification.dll) — used by some overlays */
int MSABI lsw_MagInitialize(void) { return 1; }
int MSABI lsw_MagUninitialize(void) { return 1; }
int MSABI lsw_MagSetWindowTransform(void* hwnd, void* pTransform) { (void)hwnd; (void)pTransform; return 1; }

/* SetConsoleCtrlHandler used by game launchers */
/* (Already in win32_api.c, just ensure it exists) */

/* GetUserDefaultLocaleName / GetUserDefaultLCID — for locale-sensitive games */
int MSABI lsw_GetUserDefaultLocaleName(uint16_t* lpLocaleName, int cchLocaleName) {
    /* "en-US" in wide */
    const uint16_t name[] = {'e','n','-','U','S',0};
    if (lpLocaleName && cchLocaleName > 5) {
        for (int i = 0; i < 6; i++) lpLocaleName[i] = name[i];
        return 6;
    }
    return 0;
}
DWORD MSABI lsw_GetUserDefaultLCID(void) { return 0x0409; /* en-US */ }
DWORD MSABI lsw_GetSystemDefaultLCID(void) { return 0x0409; }
DWORD MSABI lsw_GetUserDefaultUILanguage(void) { return 0x0409; }
DWORD MSABI lsw_GetSystemDefaultUILanguage(void) { return 0x0409; }

/* GetDateFormatEx / GetTimeFormatEx — games show clocks/dates */
int MSABI lsw_GetDateFormatEx(const uint16_t* locale, DWORD flags, const void* date,
                               const uint16_t* fmt, uint16_t* buf, int cbuf, const uint16_t* cal) {
    (void)locale; (void)flags; (void)date; (void)fmt; (void)cal;
    if (buf && cbuf > 0) buf[0] = 0;
    return 1;
}
int MSABI lsw_GetTimeFormatEx(const uint16_t* locale, DWORD flags, const void* time,
                               const uint16_t* fmt, uint16_t* buf, int cbuf) {
    (void)locale; (void)flags; (void)time; (void)fmt;
    if (buf && cbuf > 0) buf[0] = 0;
    return 1;
}

/* SetThreadDescription / GetThreadDescription — profiling tools & game engines */
HRESULT MSABI lsw_SetThreadDescription(void* hThread, const uint16_t* lpThreadDescription) {
    (void)hThread; (void)lpThreadDescription; return S_OK;
}
HRESULT MSABI lsw_GetThreadDescription(void* hThread, uint16_t** ppThreadDescription) {
    (void)hThread;
    static const uint16_t empty = 0;
    if (ppThreadDescription) *ppThreadDescription = (uint16_t*)&empty;
    return S_OK;
}

/* SetThreadStackGuarantee */
int MSABI lsw_SetThreadStackGuarantee(DWORD* StackSizeInBytes) {
    (void)StackSizeInBytes; return 1;
}

/* GetSystemCpuSetInformation — used by game engines for thread affinity */
int MSABI lsw_GetSystemCpuSetInformation(void* Information, DWORD BufferLength, DWORD* ReturnedLength,
                                           void* Process, DWORD Flags) {
    (void)Information; (void)BufferLength; (void)Process; (void)Flags;
    if (ReturnedLength) *ReturnedLength = 0;
    return 0; /* FALSE → fall back to legacy affinity */
}

/* SetProcessMitigationPolicy — anti-cheat, security hardening */
int MSABI lsw_SetProcessMitigationPolicy(DWORD Policy, void* lpBuffer, size_t dwLength) {
    (void)Policy; (void)lpBuffer; (void)dwLength; return 1;
}
int MSABI lsw_GetProcessMitigationPolicy(void* hProcess, DWORD Policy, void* lpBuffer, size_t dwLength) {
    (void)hProcess; (void)Policy; if (lpBuffer && dwLength > 0) memset(lpBuffer, 0, dwLength); return 1;
}

/* OpenThread (games use for cross-thread priority setting) — defined in win32_api.c */

/* CreateToolhelp32Snapshot / Process32First / Process32Next — process enumerators */
void* MSABI lsw_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    (void)dwFlags; (void)th32ProcessID;
    return (void*)(uintptr_t)0xDEAD0001; /* fake snapshot */
}
int MSABI lsw_Process32FirstW(void* hSnapshot, void* lppe) {
    (void)hSnapshot; if (lppe) memset(lppe, 0, 308 /* sizeof PROCESSENTRY32W */); return 0;
}
int MSABI lsw_Process32NextW(void* hSnapshot, void* lppe) {
    (void)hSnapshot; (void)lppe; return 0;
}
int MSABI lsw_Process32First(void* hSnapshot, void* lppe) { return lsw_Process32FirstW(hSnapshot, lppe); }
int MSABI lsw_Process32Next(void* hSnapshot, void* lppe)  { return lsw_Process32NextW(hSnapshot, lppe); }
int MSABI lsw_Thread32First(void* hSnapshot, void* lpte)  { (void)hSnapshot; if (lpte) memset(lpte, 0, 28); return 0; }
int MSABI lsw_Thread32Next(void* hSnapshot, void* lpte)   { (void)hSnapshot; (void)lpte; return 0; }
int MSABI lsw_Module32FirstW(void* hSnapshot, void* lpme) { (void)hSnapshot; if (lpme) memset(lpme, 0, 568); return 0; }
int MSABI lsw_Module32NextW(void* hSnapshot, void* lpme)  { (void)hSnapshot; (void)lpme; return 0; }

/* EnumWindows / EnumChildWindows — UI/overlay detection */
int MSABI lsw_EnumWindows(void* lpEnumFunc, void* lParam) { (void)lpEnumFunc; (void)lParam; return 1; }
int MSABI lsw_EnumChildWindows(void* hWndParent, void* lpEnumFunc, void* lParam) {
    (void)hWndParent; (void)lpEnumFunc; (void)lParam; return 1;
}

/* GetSystemFirmwareTable — anti-cheat reads ACPI/SMBIOS tables */
DWORD MSABI lsw_GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID,
                                         void* pFirmwareTableBuffer, DWORD BufferSize) {
    (void)FirmwareTableProviderSignature; (void)FirmwareTableID;
    (void)pFirmwareTableBuffer; (void)BufferSize;
    return 0; /* indicate no data */
}

/* EnumSystemFirmwareTables */
DWORD MSABI lsw_EnumSystemFirmwareTables(DWORD FirmwareTableProviderSignature,
                                          void* pFirmwareTableEnumBuffer, DWORD BufferSize) {
    (void)FirmwareTableProviderSignature; (void)pFirmwareTableEnumBuffer; (void)BufferSize;
    return 0;
}

/* GetUserNameW / GetComputerNameW / GetComputerNameExW — already in advapi32_api.c */

/* =========================================================================
 * Mapping table
 * ========================================================================= */

const win32_api_mapping_t win32_api_game_mappings[] = {
    /* BCrypt */
    MAP("bcrypt.dll", "BCryptOpenAlgorithmProvider",  lsw_BCryptOpenAlgorithmProvider),
    MAP("bcrypt.dll", "BCryptCloseAlgorithmProvider", lsw_BCryptCloseAlgorithmProvider),
    MAP("bcrypt.dll", "BCryptGenRandom",              lsw_BCryptGenRandom),
    MAP("bcrypt.dll", "BCryptGetProperty",            lsw_BCryptGetProperty),
    MAP("bcrypt.dll", "BCryptSetProperty",            lsw_BCryptSetProperty),
    MAP("bcrypt.dll", "BCryptCreateHash",             lsw_BCryptCreateHash),
    MAP("bcrypt.dll", "BCryptHashData",               lsw_BCryptHashData),
    MAP("bcrypt.dll", "BCryptFinishHash",             lsw_BCryptFinishHash),
    MAP("bcrypt.dll", "BCryptDestroyHash",            lsw_BCryptDestroyHash),
    MAP("bcrypt.dll", "BCryptHash",                   lsw_BCryptHash),
    MAP("bcrypt.dll", "BCryptDeriveKey",              lsw_BCryptDeriveKey),
    MAP("bcrypt.dll", "BCryptGenerateSymmetricKey",   lsw_BCryptGenerateSymmetricKey),
    MAP("bcrypt.dll", "BCryptDestroyKey",             lsw_BCryptDestroyKey),
    MAP("bcrypt.dll", "BCryptEncrypt",                lsw_BCryptEncrypt),
    MAP("bcrypt.dll", "BCryptDecrypt",                lsw_BCryptDecrypt),
    MAP("bcrypt.dll", "BCryptImportKey",              lsw_BCryptImportKey),
    MAP("bcrypt.dll", "BCryptExportKey",              lsw_BCryptExportKey),
    /* NCrypt */
    MAP("ncrypt.dll", "NCryptOpenStorageProvider",    lsw_NCryptOpenStorageProvider),
    MAP("ncrypt.dll", "NCryptFreeObject",             lsw_NCryptFreeObject),
    MAP("ncrypt.dll", "NCryptEnumAlgorithms",         lsw_NCryptEnumAlgorithms),
    MAP("ncrypt.dll", "NCryptGetProperty",            lsw_NCryptGetProperty),
    MAP("ncrypt.dll", "NCryptIsAlgSupported",         lsw_NCryptIsAlgSupported),
    /* ETW */
    MAP("advapi32.dll", "EventRegister",              lsw_EventRegister),
    MAP("advapi32.dll", "EventUnregister",            lsw_EventUnregister),
    MAP("advapi32.dll", "EventWrite",                 lsw_EventWrite),
    MAP("advapi32.dll", "EventWriteEx",               lsw_EventWriteEx),
    MAP("advapi32.dll", "EventWriteTransfer",         lsw_EventWriteTransfer),
    MAP("advapi32.dll", "EventWriteString",           lsw_EventWriteString),
    MAP("advapi32.dll", "EventEnabled",               lsw_EventEnabled),
    MAP("advapi32.dll", "EventProviderEnabled",       lsw_EventProviderEnabled),
    MAP("ntdll.dll",    "EtwEventRegister",           lsw_EtwEventRegister),
    MAP("ntdll.dll",    "EtwEventWrite",              lsw_EtwEventWrite),
    MAP("ntdll.dll",    "EtwEventUnregister",         lsw_EtwEventUnregister),
    MAP("tdh.dll",      "TdhGetEventInformation",     lsw_TdhGetEventInformation),
    MAP("tdh.dll",      "TdhLoadManifest",            lsw_TdhLoadManifest),
    /* RawInput */
    MAP("user32.dll",   "RegisterRawInputDevices",    lsw_RegisterRawInputDevices),
    MAP("user32.dll",   "GetRawInputData",            lsw_GetRawInputData),
    MAP("user32.dll",   "GetRawInputBuffer",          lsw_GetRawInputBuffer),
    MAP("user32.dll",   "GetRegisteredRawInputDevices", lsw_GetRegisteredRawInputDevices),
    MAP("user32.dll",   "GetRawInputDeviceList",      lsw_GetRawInputDeviceList),
    MAP("user32.dll",   "GetRawInputDeviceInfoW",     lsw_GetRawInputDeviceInfoW),
    MAP("user32.dll",   "GetRawInputDeviceInfoA",     lsw_GetRawInputDeviceInfoA),
    /* Process priority & affinity */
    MAP("KERNEL32.dll", "SetPriorityClass",           lsw_SetPriorityClass),
    MAP("KERNEL32.dll", "GetPriorityClass",           lsw_GetPriorityClass),
    MAP("KERNEL32.dll", "GetProcessAffinityMask",     lsw_GetProcessAffinityMask),
    MAP("KERNEL32.dll", "SetProcessAffinityMask",     lsw_SetProcessAffinityMask),
    MAP("KERNEL32.dll", "GetProcessHandleCount",      lsw_GetProcessHandleCount),
    MAP("KERNEL32.dll", "ReadProcessMemory",          lsw_ReadProcessMemory),
    MAP("KERNEL32.dll", "WriteProcessMemory",         lsw_WriteProcessMemory),
    MAP("KERNEL32.dll", "VirtualAlloc2",              lsw_VirtualAlloc2),
    MAP("KERNEL32.dll", "VirtualAllocFromApp",        lsw_VirtualAllocFromApp),
    MAP("KERNEL32.dll", "CreateToolhelp32Snapshot",   lsw_CreateToolhelp32Snapshot),
    MAP("KERNEL32.dll", "Process32FirstW",            lsw_Process32FirstW),
    MAP("KERNEL32.dll", "Process32NextW",             lsw_Process32NextW),
    MAP("KERNEL32.dll", "Process32First",             lsw_Process32First),
    MAP("KERNEL32.dll", "Process32Next",              lsw_Process32Next),
    MAP("KERNEL32.dll", "Thread32First",              lsw_Thread32First),
    MAP("KERNEL32.dll", "Thread32Next",               lsw_Thread32Next),
    MAP("KERNEL32.dll", "Module32FirstW",             lsw_Module32FirstW),
    MAP("KERNEL32.dll", "Module32NextW",              lsw_Module32NextW),
    MAP("KERNEL32.dll", "SetThreadDescription",       lsw_SetThreadDescription),
    MAP("KERNEL32.dll", "GetThreadDescription",       lsw_GetThreadDescription),
    MAP("KERNEL32.dll", "SetThreadStackGuarantee",    lsw_SetThreadStackGuarantee),
    MAP("KERNEL32.dll", "GetSystemCpuSetInformation", lsw_GetSystemCpuSetInformation),
    MAP("KERNEL32.dll", "SetProcessMitigationPolicy", lsw_SetProcessMitigationPolicy),
    MAP("KERNEL32.dll", "GetProcessMitigationPolicy", lsw_GetProcessMitigationPolicy),
    MAP("KERNEL32.dll", "GetSystemFirmwareTable",     lsw_GetSystemFirmwareTable),
    MAP("KERNEL32.dll", "EnumSystemFirmwareTables",   lsw_EnumSystemFirmwareTables),
    MAP("KERNEL32.dll", "PowerCreateRequest",         lsw_PowerCreateRequest),
    MAP("KERNEL32.dll", "PowerSetRequest",            lsw_PowerSetRequest),
    MAP("KERNEL32.dll", "PowerClearRequest",          lsw_PowerClearRequest),
    MAP("KERNEL32.dll", "GetUserDefaultLocaleName",   lsw_GetUserDefaultLocaleName),
    MAP("KERNEL32.dll", "GetUserDefaultLCID",         lsw_GetUserDefaultLCID),
    MAP("KERNEL32.dll", "GetSystemDefaultLCID",       lsw_GetSystemDefaultLCID),
    MAP("KERNEL32.dll", "GetUserDefaultUILanguage",   lsw_GetUserDefaultUILanguage),
    MAP("KERNEL32.dll", "GetSystemDefaultUILanguage", lsw_GetSystemDefaultUILanguage),
    MAP("KERNEL32.dll", "GetDateFormatEx",            lsw_GetDateFormatEx),
    MAP("KERNEL32.dll", "GetTimeFormatEx",            lsw_GetTimeFormatEx),
    MAP("KERNEL32.dll", "EnumWindows",                lsw_EnumWindows),
    MAP("KERNEL32.dll", "EnumChildWindows",           lsw_EnumChildWindows),
    /* XAudio2 */
    MAP("xaudio2_9.dll",  "XAudio2Create",            lsw_XAudio2Create),
    MAP("xaudio2_8.dll",  "XAudio2Create",            lsw_XAudio2Create),
    MAP("xaudio2_7.dll",  "XAudio2Create",            lsw_XAudio27Create),
    MAP("xaudio2_6.dll",  "XAudio2Create",            lsw_XAudio27Create),
    MAP("xaudio2_5.dll",  "XAudio2Create",            lsw_XAudio27Create),
    MAP("xaudio2_4.dll",  "XAudio2Create",            lsw_XAudio27Create),
    MAP("xaudio2_9.dll",  "CreateAudioVolumeMeter",   lsw_CreateAudioVolumeMeter),
    MAP("xaudio2_9.dll",  "CreateAudioReverb",        lsw_CreateAudioReverb),
    MAP("xaudio2_8.dll",  "CreateAudioVolumeMeter",   lsw_CreateAudioVolumeMeter),
    MAP("xaudio2_8.dll",  "CreateAudioReverb",        lsw_CreateAudioReverb),
    /* DirectInput */
    MAP("dinput8.dll",  "DirectInput8Create",         lsw_DirectInput8Create),
    MAP("dinput.dll",   "DirectInputCreateW",         lsw_DirectInputCreateW),
    MAP("dinput.dll",   "DirectInputCreateA",         lsw_DirectInputCreateA),
    /* D3DX */
    MAP("d3dx9_43.dll", "D3DXMatrixMultiply",         lsw_D3DXMatrixMultiply),
    MAP("d3dx9_43.dll", "D3DXMatrixIdentity",         lsw_D3DXMatrixIdentity),
    MAP("d3dx9_43.dll", "D3DXVec3Normalize",          lsw_D3DXVec3Normalize),
    MAP("d3dx9_43.dll", "D3DXVec3Dot",                lsw_D3DXVec3Dot),
    MAP("d3dx9_43.dll", "D3DXVec3Cross",              lsw_D3DXVec3Cross),
    MAP("d3dx9_43.dll", "D3DXVec3Length",             lsw_D3DXVec3Length),
    MAP("d3dx9_43.dll", "D3DXVec4Transform",          lsw_D3DXVec4Transform),
    MAP("d3dx9_43.dll", "D3DXCreateTextureFromFileW", lsw_D3DXCreateTextureFromFileW),
    MAP("d3dx9_43.dll", "D3DXCreateTextureFromFileA", lsw_D3DXCreateTextureFromFileA),
    MAP("d3dx9_43.dll", "D3DXCreateEffectFromFileW",  lsw_D3DXCreateEffectFromFileW),
    MAP("d3dx9_42.dll", "D3DXMatrixMultiply",         lsw_D3DXMatrixMultiply),
    MAP("d3dx9_42.dll", "D3DXMatrixIdentity",         lsw_D3DXMatrixIdentity),
    MAP("d3dx9_42.dll", "D3DXVec3Normalize",          lsw_D3DXVec3Normalize),
    MAP("d3dx9_42.dll", "D3DXCreateTextureFromFileW", lsw_D3DXCreateTextureFromFileW),
    MAP("d3dx9_42.dll", "D3DXCreateTextureFromFileA", lsw_D3DXCreateTextureFromFileA),
    MAP("d3dx11.dll",   "D3DX11CreateTextureFromFile",lsw_D3DX11CreateTextureFromFile),
    MAP("d3dx11.dll",   "D3DX11CompileFromFile",      lsw_D3DX11CompileFromFile),
    /* WinRT */
    MAP("combase.dll",  "RoInitialize",               lsw_RoInitialize),
    MAP("combase.dll",  "RoUninitialize",             lsw_RoUninitialize),
    MAP("combase.dll",  "RoGetActivationFactory",     lsw_RoGetActivationFactory),
    MAP("combase.dll",  "RoActivateInstance",         lsw_RoActivateInstance),
    MAP("combase.dll",  "RoRegisterActivationFactories", lsw_RoRegisterActivationFactories),
    MAP("combase.dll",  "WindowsCreateString",        lsw_WindowsCreateString),
    MAP("combase.dll",  "WindowsDeleteString",        lsw_WindowsDeleteString),
    MAP("combase.dll",  "WindowsGetStringRawBuffer",  lsw_WindowsGetStringRawBuffer),
    MAP("combase.dll",  "WindowsDuplicateString",     lsw_WindowsDuplicateString),
    MAP("api-ms-win-core-winrt-string-l1-1-0.dll", "WindowsCreateString",       lsw_WindowsCreateString),
    MAP("api-ms-win-core-winrt-string-l1-1-0.dll", "WindowsDeleteString",       lsw_WindowsDeleteString),
    MAP("api-ms-win-core-winrt-string-l1-1-0.dll", "WindowsGetStringRawBuffer", lsw_WindowsGetStringRawBuffer),
    MAP("api-ms-win-core-winrt-l1-1-0.dll", "RoInitialize",              lsw_RoInitialize),
    MAP("api-ms-win-core-winrt-l1-1-0.dll", "RoGetActivationFactory",    lsw_RoGetActivationFactory),
    /* Misc */
    MAP("pdh.dll",      "PdhOpenQueryW",                  lsw_PdhOpenQueryW),
    MAP("pdh.dll",      "PdhAddCounterW",                 lsw_PdhAddCounterW),
    MAP("pdh.dll",      "PdhCollectQueryData",            lsw_PdhCollectQueryData),
    MAP("pdh.dll",      "PdhGetFormattedCounterValue",    lsw_PdhGetFormattedCounterValue),
    MAP("pdh.dll",      "PdhCloseQuery",                  lsw_PdhCloseQuery),
    MAP("magnification.dll", "MagInitialize",             lsw_MagInitialize),
    MAP("magnification.dll", "MagUninitialize",           lsw_MagUninitialize),
    MAP("magnification.dll", "MagSetWindowTransform",     lsw_MagSetWindowTransform),
    MAP("steam_api64.dll",   "SteamAPI_Init",             lsw_SteamAPI_Init),
    MAP("steam_api64.dll",   "SteamAPI_InitFlat",         lsw_SteamAPI_InitFlat),
    MAP("steam_api64.dll",   "SteamAPI_Shutdown",         lsw_SteamAPI_Shutdown),
    MAP("steam_api64.dll",   "SteamAPI_RunCallbacks",     lsw_SteamAPI_RunCallbacks),
    MAP("steam_api64.dll",   "SteamAPI_IsSteamRunning",   lsw_SteamAPI_IsSteamRunning),
    MAP("steam_api64.dll",   "SteamInternal_CreateInterface", lsw_SteamInternal_CreateInterface),
    MAP("steam_api.dll",     "SteamAPI_Init",             lsw_SteamAPI_Init),
    MAP("steam_api.dll",     "SteamAPI_Shutdown",         lsw_SteamAPI_Shutdown),
    MAP("steam_api.dll",     "SteamAPI_RunCallbacks",     lsw_SteamAPI_RunCallbacks),
    MAP("steam_api.dll",     "SteamInternal_CreateInterface", lsw_SteamInternal_CreateInterface),
    {NULL, NULL, NULL}
};

const size_t win32_api_game_mappings_count =
    (sizeof(win32_api_game_mappings) / sizeof(win32_api_game_mappings[0])) - 1;
