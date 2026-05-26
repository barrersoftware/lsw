#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include "../../include/shared/lsw_log.h"
#include "../../include/win32-api/win32_api.h"

typedef int BOOL;
typedef uint32_t DWORD;
typedef void* HANDLE;
typedef void* HKEY;
typedef const uint16_t* LPCWSTR;
typedef const char* LPCSTR;
typedef uint16_t* LPWSTR;
typedef char* LPSTR;
typedef void SECURITY_ATTRIBUTES;
typedef int TOKEN_TYPE;
typedef long LSTATUS;
typedef uint32_t REGSAM;
typedef void* HLOCAL;
typedef void* HGLOBAL;

#define LSW_ADVAPI_LOG(name) LSW_LOG_DEBUG(name " called")
#define LSW_UNUSED(x) ((void)(x))
#define ERROR_SUCCESS 0L
#define ERROR_FILE_NOT_FOUND 2L
#define ERROR_NO_MORE_ITEMS 259L

static void lsw_zero_u32(DWORD* value) { if (value) *value = 0; }
static void lsw_zero_ptr(void** value) { if (value) *value = NULL; }

LSTATUS __attribute__((ms_abi)) lsw_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY* phkResult) {
    LSW_ADVAPI_LOG("RegOpenKeyExW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey); LSW_UNUSED(ulOptions); LSW_UNUSED(samDesired);
    if (phkResult) *phkResult = (HKEY)0x1234;
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY* phkResult) {
    LSW_ADVAPI_LOG("RegOpenKeyExA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey); LSW_UNUSED(ulOptions); LSW_UNUSED(samDesired);
    if (phkResult) *phkResult = (HKEY)0x1234;
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegCloseKey(HKEY hKey) {
    LSW_ADVAPI_LOG("RegCloseKey");
    LSW_UNUSED(hKey);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD* lpReserved, DWORD* lpType, uint8_t* lpData, DWORD* lpcbData) {
    LSW_ADVAPI_LOG("RegQueryValueExW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpValueName); LSW_UNUSED(lpReserved); LSW_UNUSED(lpType); LSW_UNUSED(lpData); LSW_UNUSED(lpcbData);
    return ERROR_FILE_NOT_FOUND;
}

LSTATUS __attribute__((ms_abi)) lsw_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, DWORD* lpReserved, DWORD* lpType, uint8_t* lpData, DWORD* lpcbData) {
    LSW_ADVAPI_LOG("RegQueryValueExA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpValueName); LSW_UNUSED(lpReserved); LSW_UNUSED(lpType); LSW_UNUSED(lpData); LSW_UNUSED(lpcbData);
    return ERROR_FILE_NOT_FOUND;
}

LSTATUS __attribute__((ms_abi)) lsw_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const uint8_t* lpData, DWORD cbData) {
    LSW_ADVAPI_LOG("RegSetValueExW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpValueName); LSW_UNUSED(Reserved); LSW_UNUSED(dwType); LSW_UNUSED(lpData); LSW_UNUSED(cbData);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const uint8_t* lpData, DWORD cbData) {
    LSW_ADVAPI_LOG("RegSetValueExA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpValueName); LSW_UNUSED(Reserved); LSW_UNUSED(dwType); LSW_UNUSED(lpData); LSW_UNUSED(cbData);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, uint16_t* lpClass, DWORD dwOptions, REGSAM samDesired, SECURITY_ATTRIBUTES* lpSecurityAttributes, HKEY* phkResult, DWORD* lpdwDisposition) {
    LSW_ADVAPI_LOG("RegCreateKeyExW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey); LSW_UNUSED(Reserved); LSW_UNUSED(lpClass); LSW_UNUSED(dwOptions); LSW_UNUSED(samDesired); LSW_UNUSED(lpSecurityAttributes);
    if (phkResult) *phkResult = (HKEY)0x1235;
    if (lpdwDisposition) *lpdwDisposition = 1;
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, char* lpClass, DWORD dwOptions, REGSAM samDesired, SECURITY_ATTRIBUTES* lpSecurityAttributes, HKEY* phkResult, DWORD* lpdwDisposition) {
    LSW_ADVAPI_LOG("RegCreateKeyExA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey); LSW_UNUSED(Reserved); LSW_UNUSED(lpClass); LSW_UNUSED(dwOptions); LSW_UNUSED(samDesired); LSW_UNUSED(lpSecurityAttributes);
    if (phkResult) *phkResult = (HKEY)0x1235;
    if (lpdwDisposition) *lpdwDisposition = 1;
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) {
    LSW_ADVAPI_LOG("RegDeleteKeyW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) {
    LSW_ADVAPI_LOG("RegDeleteKeyA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName) {
    LSW_ADVAPI_LOG("RegDeleteValueW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpValueName);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegDeleteValueA(HKEY hKey, LPCSTR lpValueName) {
    LSW_ADVAPI_LOG("RegDeleteValueA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpValueName);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD* lpcchName, DWORD* lpReserved, LPWSTR lpClass, DWORD* lpcchClass, void* lpftLastWriteTime) {
    LSW_ADVAPI_LOG("RegEnumKeyExW");
    LSW_UNUSED(hKey); LSW_UNUSED(dwIndex); LSW_UNUSED(lpName); LSW_UNUSED(lpcchName); LSW_UNUSED(lpReserved); LSW_UNUSED(lpClass); LSW_UNUSED(lpcchClass); LSW_UNUSED(lpftLastWriteTime);
    return ERROR_NO_MORE_ITEMS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD* lpcchName, DWORD* lpReserved, LPSTR lpClass, DWORD* lpcchClass, void* lpftLastWriteTime) {
    LSW_ADVAPI_LOG("RegEnumKeyExA");
    LSW_UNUSED(hKey); LSW_UNUSED(dwIndex); LSW_UNUSED(lpName); LSW_UNUSED(lpcchName); LSW_UNUSED(lpReserved); LSW_UNUSED(lpClass); LSW_UNUSED(lpcchClass); LSW_UNUSED(lpftLastWriteTime);
    return ERROR_NO_MORE_ITEMS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, DWORD* lpcchValueName, DWORD* lpReserved, DWORD* lpType, uint8_t* lpData, DWORD* lpcbData) {
    LSW_ADVAPI_LOG("RegEnumValueW");
    LSW_UNUSED(hKey); LSW_UNUSED(dwIndex); LSW_UNUSED(lpValueName); LSW_UNUSED(lpcchValueName); LSW_UNUSED(lpReserved); LSW_UNUSED(lpType); LSW_UNUSED(lpData); LSW_UNUSED(lpcbData);
    return ERROR_NO_MORE_ITEMS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName, DWORD* lpcchValueName, DWORD* lpReserved, DWORD* lpType, uint8_t* lpData, DWORD* lpcbData) {
    LSW_ADVAPI_LOG("RegEnumValueA");
    LSW_UNUSED(hKey); LSW_UNUSED(dwIndex); LSW_UNUSED(lpValueName); LSW_UNUSED(lpcchValueName); LSW_UNUSED(lpReserved); LSW_UNUSED(lpType); LSW_UNUSED(lpData); LSW_UNUSED(lpcbData);
    return ERROR_NO_MORE_ITEMS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, DWORD* lpcchClass, DWORD* lpReserved, DWORD* lpcSubKeys, DWORD* lpcbMaxSubKeyLen, DWORD* lpcbMaxClassLen, DWORD* lpcValues, DWORD* lpcbMaxValueNameLen, DWORD* lpcbMaxValueLen, DWORD* lpcbSecurityDescriptor, void* lpftLastWriteTime) {
    LSW_ADVAPI_LOG("RegQueryInfoKeyW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpReserved); LSW_UNUSED(lpftLastWriteTime);
    if (lpClass && lpcchClass && *lpcchClass > 0) lpClass[0] = 0;
    lsw_zero_u32(lpcchClass); lsw_zero_u32(lpcSubKeys); lsw_zero_u32(lpcbMaxSubKeyLen); lsw_zero_u32(lpcbMaxClassLen);
    lsw_zero_u32(lpcValues); lsw_zero_u32(lpcbMaxValueNameLen); lsw_zero_u32(lpcbMaxValueLen); lsw_zero_u32(lpcbSecurityDescriptor);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, DWORD* lpcchClass, DWORD* lpReserved, DWORD* lpcSubKeys, DWORD* lpcbMaxSubKeyLen, DWORD* lpcbMaxClassLen, DWORD* lpcValues, DWORD* lpcbMaxValueNameLen, DWORD* lpcbMaxValueLen, DWORD* lpcbSecurityDescriptor, void* lpftLastWriteTime) {
    LSW_ADVAPI_LOG("RegQueryInfoKeyA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpReserved); LSW_UNUSED(lpftLastWriteTime);
    if (lpClass && lpcchClass && *lpcchClass > 0) lpClass[0] = 0;
    lsw_zero_u32(lpcchClass); lsw_zero_u32(lpcSubKeys); lsw_zero_u32(lpcbMaxSubKeyLen); lsw_zero_u32(lpcbMaxClassLen);
    lsw_zero_u32(lpcValues); lsw_zero_u32(lpcbMaxValueNameLen); lsw_zero_u32(lpcbMaxValueLen); lsw_zero_u32(lpcbSecurityDescriptor);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegConnectRegistryW(LPCWSTR lpMachineName, HKEY hKey, HKEY* phkResult) {
    LSW_ADVAPI_LOG("RegConnectRegistryW");
    LSW_UNUSED(lpMachineName);
    if (phkResult) *phkResult = hKey;
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegFlushKey(HKEY hKey) {
    LSW_ADVAPI_LOG("RegFlushKey");
    LSW_UNUSED(hKey);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegLoadKeyW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpFile) {
    LSW_ADVAPI_LOG("RegLoadKeyW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey); LSW_UNUSED(lpFile);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegSaveKeyW(HKEY hKey, LPCWSTR lpFile, SECURITY_ATTRIBUTES* lpSecurityAttributes) {
    LSW_ADVAPI_LOG("RegSaveKeyW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpFile); LSW_UNUSED(lpSecurityAttributes);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree, DWORD dwNotifyFilter, HANDLE hEvent, BOOL fAsynchronous) {
    LSW_ADVAPI_LOG("RegNotifyChangeKeyValue");
    LSW_UNUSED(hKey); LSW_UNUSED(bWatchSubtree); LSW_UNUSED(dwNotifyFilter); LSW_UNUSED(hEvent); LSW_UNUSED(fAsynchronous);
    return ERROR_SUCCESS;
}

LSTATUS __attribute__((ms_abi)) lsw_RegGetValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, DWORD* pdwType, void* pvData, DWORD* pcbData) {
    LSW_ADVAPI_LOG("RegGetValueW");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey); LSW_UNUSED(lpValue); LSW_UNUSED(dwFlags); LSW_UNUSED(pdwType); LSW_UNUSED(pvData); LSW_UNUSED(pcbData);
    return ERROR_FILE_NOT_FOUND;
}

LSTATUS __attribute__((ms_abi)) lsw_RegGetValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, DWORD* pdwType, void* pvData, DWORD* pcbData) {
    LSW_ADVAPI_LOG("RegGetValueA");
    LSW_UNUSED(hKey); LSW_UNUSED(lpSubKey); LSW_UNUSED(lpValue); LSW_UNUSED(dwFlags); LSW_UNUSED(pdwType); LSW_UNUSED(pvData); LSW_UNUSED(pcbData);
    return ERROR_FILE_NOT_FOUND;
}

BOOL __attribute__((ms_abi)) lsw_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE* TokenHandle) {
    LSW_ADVAPI_LOG("OpenProcessToken");
    LSW_UNUSED(ProcessHandle); LSW_UNUSED(DesiredAccess);
    if (TokenHandle) *TokenHandle = (HANDLE)0x2000;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, HANDLE* TokenHandle) {
    LSW_ADVAPI_LOG("OpenThreadToken");
    LSW_UNUSED(ThreadHandle); LSW_UNUSED(DesiredAccess); LSW_UNUSED(OpenAsSelf);
    if (TokenHandle) *TokenHandle = (HANDLE)0x2001;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetTokenInformation(HANDLE TokenHandle, int TokenInformationClass, void* TokenInformation, DWORD TokenInformationLength, DWORD* ReturnLength) {
    LSW_ADVAPI_LOG("GetTokenInformation");
    LSW_UNUSED(TokenHandle); LSW_UNUSED(TokenInformationClass); LSW_UNUSED(TokenInformationLength);
    if (TokenInformation) memset(TokenInformation, 0, TokenInformationLength);
    if (ReturnLength) *ReturnLength = 4;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_SetTokenInformation(HANDLE TokenHandle, int TokenInformationClass, void* TokenInformation, DWORD TokenInformationLength) {
    LSW_ADVAPI_LOG("SetTokenInformation");
    LSW_UNUSED(TokenHandle); LSW_UNUSED(TokenInformationClass); LSW_UNUSED(TokenInformation); LSW_UNUSED(TokenInformationLength);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, void* NewState, DWORD BufferLength, void* PreviousState, DWORD* ReturnLength) {
    LSW_ADVAPI_LOG("AdjustTokenPrivileges");
    LSW_UNUSED(TokenHandle); LSW_UNUSED(DisableAllPrivileges); LSW_UNUSED(NewState); LSW_UNUSED(BufferLength); LSW_UNUSED(PreviousState); LSW_UNUSED(ReturnLength);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, void* lpLuid) {
    LSW_ADVAPI_LOG("LookupPrivilegeValueW");
    LSW_UNUSED(lpSystemName); LSW_UNUSED(lpName);
    if (lpLuid) memset(lpLuid, 0, sizeof(uint64_t));
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, void* lpLuid) {
    LSW_ADVAPI_LOG("LookupPrivilegeValueA");
    LSW_UNUSED(lpSystemName); LSW_UNUSED(lpName);
    if (lpLuid) memset(lpLuid, 0, sizeof(uint64_t));
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_LookupPrivilegeNameW(LPCWSTR lpSystemName, void* lpLuid, LPWSTR lpName, DWORD* cchName) {
    LSW_ADVAPI_LOG("LookupPrivilegeNameW");
    LSW_UNUSED(lpSystemName); LSW_UNUSED(lpLuid); LSW_UNUSED(lpName); LSW_UNUSED(cchName);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CheckTokenMembership(HANDLE TokenHandle, void* SidToCheck, BOOL* IsMember) {
    LSW_ADVAPI_LOG("CheckTokenMembership");
    LSW_UNUSED(TokenHandle); LSW_UNUSED(SidToCheck);
    if (IsMember) *IsMember = 0;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_IsTokenRestricted(HANDLE TokenHandle) {
    LSW_ADVAPI_LOG("IsTokenRestricted");
    LSW_UNUSED(TokenHandle);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_DuplicateToken(HANDLE ExistingTokenHandle, int ImpersonationLevel, HANDLE* DuplicateTokenHandle) {
    LSW_ADVAPI_LOG("DuplicateToken");
    LSW_UNUSED(ExistingTokenHandle); LSW_UNUSED(ImpersonationLevel);
    if (DuplicateTokenHandle) *DuplicateTokenHandle = (HANDLE)0x2002;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, void* lpTokenAttributes, int ImpersonationLevel, TOKEN_TYPE TokenType, HANDLE* phNewToken) {
    LSW_ADVAPI_LOG("DuplicateTokenEx");
    LSW_UNUSED(hExistingToken); LSW_UNUSED(dwDesiredAccess); LSW_UNUSED(lpTokenAttributes); LSW_UNUSED(ImpersonationLevel); LSW_UNUSED(TokenType);
    if (phNewToken) *phNewToken = (HANDLE)0x2003;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_ImpersonateLoggedOnUser(HANDLE hToken) {
    LSW_ADVAPI_LOG("ImpersonateLoggedOnUser");
    LSW_UNUSED(hToken);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_ImpersonateSelf(int ImpersonationLevel) {
    LSW_ADVAPI_LOG("ImpersonateSelf");
    LSW_UNUSED(ImpersonationLevel);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_RevertToSelf(void) {
    LSW_ADVAPI_LOG("RevertToSelf");
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, HANDLE* phToken) {
    LSW_ADVAPI_LOG("LogonUserW");
    LSW_UNUSED(lpszUsername); LSW_UNUSED(lpszDomain); LSW_UNUSED(lpszPassword); LSW_UNUSED(dwLogonType); LSW_UNUSED(dwLogonProvider);
    if (phToken) *phToken = (HANDLE)0x2004;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_LogonUserA(LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, HANDLE* phToken) {
    LSW_ADVAPI_LOG("LogonUserA");
    LSW_UNUSED(lpszUsername); LSW_UNUSED(lpszDomain); LSW_UNUSED(lpszPassword); LSW_UNUSED(dwLogonType); LSW_UNUSED(dwLogonProvider);
    if (phToken) *phToken = (HANDLE)0x2004;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CreateWellKnownSid(int WellKnownSidType, void* DomainSid, void* pSid, DWORD* cbSid) {
    LSW_ADVAPI_LOG("CreateWellKnownSid");
    LSW_UNUSED(WellKnownSidType); LSW_UNUSED(DomainSid); LSW_UNUSED(pSid);
    if (cbSid) *cbSid = 28;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_IsWellKnownSid(void* pSid, int WellKnownSidType) {
    LSW_ADVAPI_LOG("IsWellKnownSid");
    LSW_UNUSED(pSid); LSW_UNUSED(WellKnownSidType);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_AllocateAndInitializeSid(void* pIdentifierAuthority, uint8_t nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, void** pSid) {
    LSW_ADVAPI_LOG("AllocateAndInitializeSid");
    LSW_UNUSED(pIdentifierAuthority); LSW_UNUSED(nSubAuthorityCount); LSW_UNUSED(nSubAuthority0); LSW_UNUSED(nSubAuthority1); LSW_UNUSED(nSubAuthority2); LSW_UNUSED(nSubAuthority3); LSW_UNUSED(nSubAuthority4); LSW_UNUSED(nSubAuthority5); LSW_UNUSED(nSubAuthority6); LSW_UNUSED(nSubAuthority7);
    if (pSid) *pSid = calloc(1, 68);
    return 1;
}

void* __attribute__((ms_abi)) lsw_FreeSid(void* pSid) {
    LSW_ADVAPI_LOG("FreeSid");
    if (pSid) free(pSid);
    return NULL;
}

DWORD __attribute__((ms_abi)) lsw_GetLengthSid(void* pSid) {
    LSW_ADVAPI_LOG("GetLengthSid");
    LSW_UNUSED(pSid);
    return 28;
}

BOOL __attribute__((ms_abi)) lsw_IsValidSid(void* pSid) {
    LSW_ADVAPI_LOG("IsValidSid");
    return pSid != NULL;
}

BOOL __attribute__((ms_abi)) lsw_CopySid(DWORD nDestinationSidLength, void* pDestinationSid, void* pSourceSid) {
    LSW_ADVAPI_LOG("CopySid");
    LSW_UNUSED(nDestinationSidLength);
    if (pDestinationSid && pSourceSid) memcpy(pDestinationSid, pSourceSid, 28);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_EqualSid(void* pSid1, void* pSid2) {
    LSW_ADVAPI_LOG("EqualSid");
    LSW_UNUSED(pSid1); LSW_UNUSED(pSid2);
    return 0;
}

DWORD* __attribute__((ms_abi)) lsw_GetSidSubAuthority(void* pSid, DWORD nSubAuthority) {
    static DWORD value = 0;
    LSW_ADVAPI_LOG("GetSidSubAuthority");
    LSW_UNUSED(pSid); LSW_UNUSED(nSubAuthority);
    return &value;
}

uint8_t* __attribute__((ms_abi)) lsw_GetSidSubAuthorityCount(void* pSid) {
    static uint8_t count = 0;
    LSW_ADVAPI_LOG("GetSidSubAuthorityCount");
    LSW_UNUSED(pSid);
    return &count;
}

BOOL __attribute__((ms_abi)) lsw_ConvertSidToStringSidW(void* Sid, uint16_t** StringSid) {
    LSW_ADVAPI_LOG("ConvertSidToStringSidW");
    LSW_UNUSED(Sid);
    if (StringSid) *StringSid = NULL;
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_ConvertStringSidToSidW(LPCWSTR StringSid, void** Sid) {
    LSW_ADVAPI_LOG("ConvertStringSidToSidW");
    LSW_UNUSED(StringSid);
    lsw_zero_ptr(Sid);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_GetUserNameW(LPWSTR lpBuffer, DWORD* pcbBuffer) {
    LSW_ADVAPI_LOG("GetUserNameW");
    if (lpBuffer && pcbBuffer && *pcbBuffer > 4) { lpBuffer[0] = 'A'; lpBuffer[1] = 's'; lpBuffer[2] = 'h'; lpBuffer[3] = 0; *pcbBuffer = 4; }
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetUserNameA(LPSTR lpBuffer, DWORD* pcbBuffer) {
    LSW_ADVAPI_LOG("GetUserNameA");
    if (lpBuffer && pcbBuffer && *pcbBuffer > 4) { memcpy(lpBuffer, "Ash", 4); *pcbBuffer = 4; }
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetComputerNameW(LPWSTR lpBuffer, DWORD* nSize) {
    LSW_ADVAPI_LOG("GetComputerNameW");
    if (lpBuffer && nSize && *nSize > 4) { lpBuffer[0] = 'L'; lpBuffer[1] = 'S'; lpBuffer[2] = 'W'; lpBuffer[3] = 0; *nSize = 4; }
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetComputerNameA(LPSTR lpBuffer, DWORD* nSize) {
    LSW_ADVAPI_LOG("GetComputerNameA");
    if (lpBuffer && nSize && *nSize > 4) { memcpy(lpBuffer, "LSW", 4); *nSize = 4; }
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetComputerNameExW(int NameType, LPWSTR lpBuffer, DWORD* nSize) {
    LSW_ADVAPI_LOG("GetComputerNameExW");
    LSW_UNUSED(NameType);
    return lsw_GetComputerNameW(lpBuffer, nSize);
}

BOOL __attribute__((ms_abi)) lsw_GetComputerNameExA(int NameType, LPSTR lpBuffer, DWORD* nSize) {
    LSW_ADVAPI_LOG("GetComputerNameExA");
    LSW_UNUSED(NameType);
    return lsw_GetComputerNameA(lpBuffer, nSize);
}

BOOL __attribute__((ms_abi)) lsw_LookupAccountNameW(LPCWSTR lpSystemName, LPCWSTR lpAccountName, void* Sid, DWORD* cbSid, LPWSTR ReferencedDomainName, DWORD* cchReferencedDomainName, int* peUse) {
    LSW_ADVAPI_LOG("LookupAccountNameW");
    LSW_UNUSED(lpSystemName); LSW_UNUSED(lpAccountName); LSW_UNUSED(Sid); LSW_UNUSED(cbSid); LSW_UNUSED(ReferencedDomainName); LSW_UNUSED(cchReferencedDomainName); LSW_UNUSED(peUse);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_LookupAccountSidW(LPCWSTR lpSystemName, void* lpSid, LPWSTR lpName, DWORD* cchName, LPWSTR lpReferencedDomainName, DWORD* cchReferencedDomainName, int* peUse) {
    LSW_ADVAPI_LOG("LookupAccountSidW");
    LSW_UNUSED(lpSystemName); LSW_UNUSED(lpSid); LSW_UNUSED(lpName); LSW_UNUSED(cchName); LSW_UNUSED(lpReferencedDomainName); LSW_UNUSED(cchReferencedDomainName); LSW_UNUSED(peUse);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_SetFileSecurityW(LPCWSTR lpFileName, DWORD SecurityInformation, void* pSecurityDescriptor) {
    LSW_ADVAPI_LOG("SetFileSecurityW");
    LSW_UNUSED(lpFileName); LSW_UNUSED(SecurityInformation); LSW_UNUSED(pSecurityDescriptor);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_SetFileSecurityA(LPCSTR lpFileName, DWORD SecurityInformation, void* pSecurityDescriptor) {
    LSW_ADVAPI_LOG("SetFileSecurityA");
    LSW_UNUSED(lpFileName); LSW_UNUSED(SecurityInformation); LSW_UNUSED(pSecurityDescriptor);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetFileSecurityW(LPCWSTR lpFileName, DWORD RequestedInformation, void* pSecurityDescriptor, DWORD nLength, DWORD* lpnLengthNeeded) {
    LSW_ADVAPI_LOG("GetFileSecurityW");
    LSW_UNUSED(lpFileName); LSW_UNUSED(RequestedInformation); LSW_UNUSED(pSecurityDescriptor); LSW_UNUSED(nLength);
    lsw_zero_u32(lpnLengthNeeded);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetFileSecurityA(LPCSTR lpFileName, DWORD RequestedInformation, void* pSecurityDescriptor, DWORD nLength, DWORD* lpnLengthNeeded) {
    LSW_ADVAPI_LOG("GetFileSecurityA");
    LSW_UNUSED(lpFileName); LSW_UNUSED(RequestedInformation); LSW_UNUSED(pSecurityDescriptor); LSW_UNUSED(nLength);
    lsw_zero_u32(lpnLengthNeeded);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_InitializeSecurityDescriptor(void* pSecurityDescriptor, DWORD dwRevision) {
    LSW_ADVAPI_LOG("InitializeSecurityDescriptor");
    LSW_UNUSED(dwRevision);
    if (pSecurityDescriptor) memset(pSecurityDescriptor, 0, 20);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_SetSecurityDescriptorDacl(void* pSecurityDescriptor, BOOL bDaclPresent, void* pDacl, BOOL bDaclDefaulted) {
    LSW_ADVAPI_LOG("SetSecurityDescriptorDacl");
    LSW_UNUSED(pSecurityDescriptor); LSW_UNUSED(bDaclPresent); LSW_UNUSED(pDacl); LSW_UNUSED(bDaclDefaulted);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_GetSecurityDescriptorDacl(void* pSecurityDescriptor, BOOL* lpbDaclPresent, void** pDacl, BOOL* lpbDaclDefaulted) {
    LSW_ADVAPI_LOG("GetSecurityDescriptorDacl");
    LSW_UNUSED(pSecurityDescriptor); LSW_UNUSED(pDacl); LSW_UNUSED(lpbDaclDefaulted);
    if (lpbDaclPresent) *lpbDaclPresent = 0;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_MakeAbsoluteSD(void* pSelfRelativeSecurityDescriptor, void* pAbsoluteSecurityDescriptor, DWORD* lpdwAbsoluteSecurityDescriptorSize, void* pDacl, DWORD* lpdwDaclSize, void* pSacl, DWORD* lpdwSaclSize, void* pOwner, DWORD* lpdwOwnerSize, void* pPrimaryGroup, DWORD* lpdwPrimaryGroupSize) {
    LSW_ADVAPI_LOG("MakeAbsoluteSD");
    LSW_UNUSED(pSelfRelativeSecurityDescriptor); LSW_UNUSED(pAbsoluteSecurityDescriptor); LSW_UNUSED(lpdwAbsoluteSecurityDescriptorSize); LSW_UNUSED(pDacl); LSW_UNUSED(lpdwDaclSize); LSW_UNUSED(pSacl); LSW_UNUSED(lpdwSaclSize); LSW_UNUSED(pOwner); LSW_UNUSED(lpdwOwnerSize); LSW_UNUSED(pPrimaryGroup); LSW_UNUSED(lpdwPrimaryGroupSize);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_MakeSelfRelativeSD(void* pAbsoluteSecurityDescriptor, void* pSelfRelativeSecurityDescriptor, DWORD* lpdwBufferLength) {
    LSW_ADVAPI_LOG("MakeSelfRelativeSD");
    LSW_UNUSED(pAbsoluteSecurityDescriptor); LSW_UNUSED(pSelfRelativeSecurityDescriptor); LSW_UNUSED(lpdwBufferLength);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_AccessCheck(void* pSecurityDescriptor, HANDLE ClientToken, DWORD DesiredAccess, void* GenericMapping, void* PrivilegeSet, DWORD* PrivilegeSetLength, DWORD* GrantedAccess, BOOL* AccessStatus) {
    LSW_ADVAPI_LOG("AccessCheck");
    LSW_UNUSED(pSecurityDescriptor); LSW_UNUSED(ClientToken); LSW_UNUSED(GenericMapping); LSW_UNUSED(PrivilegeSet); LSW_UNUSED(PrivilegeSetLength);
    if (GrantedAccess) *GrantedAccess = DesiredAccess;
    if (AccessStatus) *AccessStatus = 1;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CheckTokenMembershipEx(HANDLE TokenHandle, void* SidToCheck, DWORD Flags, BOOL* IsMember) {
    LSW_ADVAPI_LOG("CheckTokenMembershipEx");
    LSW_UNUSED(Flags);
    return lsw_CheckTokenMembership(TokenHandle, SidToCheck, IsMember);
}

BOOL __attribute__((ms_abi)) lsw_CryptAcquireContextW(HANDLE* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptAcquireContextW");
    LSW_UNUSED(szContainer); LSW_UNUSED(szProvider); LSW_UNUSED(dwProvType); LSW_UNUSED(dwFlags);
    if (phProv) *phProv = (HANDLE)0x3000;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptAcquireContextA(HANDLE* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptAcquireContextA");
    LSW_UNUSED(szContainer); LSW_UNUSED(szProvider); LSW_UNUSED(dwProvType); LSW_UNUSED(dwFlags);
    if (phProv) *phProv = (HANDLE)0x3000;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptReleaseContext(HANDLE hProv, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptReleaseContext");
    LSW_UNUSED(hProv); LSW_UNUSED(dwFlags);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptCreateHash(HANDLE hProv, DWORD Algid, HANDLE hKey, DWORD dwFlags, HANDLE* phHash) {
    LSW_ADVAPI_LOG("CryptCreateHash");
    LSW_UNUSED(hProv); LSW_UNUSED(Algid); LSW_UNUSED(hKey); LSW_UNUSED(dwFlags);
    if (phHash) *phHash = (HANDLE)0x3001;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptHashData(HANDLE hHash, const uint8_t* pbData, DWORD dwDataLen, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptHashData");
    LSW_UNUSED(hHash); LSW_UNUSED(pbData); LSW_UNUSED(dwDataLen); LSW_UNUSED(dwFlags);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptGetHashParam(HANDLE hHash, DWORD dwParam, uint8_t* pbData, DWORD* pdwDataLen, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptGetHashParam");
    LSW_UNUSED(hHash); LSW_UNUSED(dwParam); LSW_UNUSED(dwFlags);
    if (pbData) memset(pbData, 0, 32);
    if (pdwDataLen) *pdwDataLen = 32;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptDestroyHash(HANDLE hHash) {
    LSW_ADVAPI_LOG("CryptDestroyHash");
    LSW_UNUSED(hHash);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptDeriveKey(HANDLE hProv, DWORD Algid, HANDLE hBaseData, DWORD dwFlags, HANDLE* phKey) {
    LSW_ADVAPI_LOG("CryptDeriveKey");
    LSW_UNUSED(hProv); LSW_UNUSED(Algid); LSW_UNUSED(hBaseData); LSW_UNUSED(dwFlags);
    if (phKey) *phKey = (HANDLE)0x3002;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptGenKey(HANDLE hProv, DWORD Algid, DWORD dwFlags, HANDLE* phKey) {
    LSW_ADVAPI_LOG("CryptGenKey");
    LSW_UNUSED(hProv); LSW_UNUSED(Algid); LSW_UNUSED(dwFlags);
    if (phKey) *phKey = (HANDLE)0x3003;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptDestroyKey(HANDLE hKey) {
    LSW_ADVAPI_LOG("CryptDestroyKey");
    LSW_UNUSED(hKey);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptEncrypt(HANDLE hKey, HANDLE hHash, BOOL Final, DWORD dwFlags, uint8_t* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    LSW_ADVAPI_LOG("CryptEncrypt");
    LSW_UNUSED(hKey); LSW_UNUSED(hHash); LSW_UNUSED(Final); LSW_UNUSED(dwFlags); LSW_UNUSED(pbData); LSW_UNUSED(pdwDataLen); LSW_UNUSED(dwBufLen);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptDecrypt(HANDLE hKey, HANDLE hHash, BOOL Final, DWORD dwFlags, uint8_t* pbData, DWORD* pdwDataLen) {
    LSW_ADVAPI_LOG("CryptDecrypt");
    LSW_UNUSED(hKey); LSW_UNUSED(hHash); LSW_UNUSED(Final); LSW_UNUSED(dwFlags); LSW_UNUSED(pbData); LSW_UNUSED(pdwDataLen);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptExportKey(HANDLE hKey, HANDLE hExpKey, DWORD dwBlobType, DWORD dwFlags, uint8_t* pbData, DWORD* pdwDataLen) {
    LSW_ADVAPI_LOG("CryptExportKey");
    LSW_UNUSED(hKey); LSW_UNUSED(hExpKey); LSW_UNUSED(dwBlobType); LSW_UNUSED(dwFlags);
    if (pbData) memset(pbData, 0, 16);
    if (pdwDataLen) *pdwDataLen = 16;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptImportKey(HANDLE hProv, const uint8_t* pbData, DWORD dwDataLen, HANDLE hPubKey, DWORD dwFlags, HANDLE* phKey) {
    LSW_ADVAPI_LOG("CryptImportKey");
    LSW_UNUSED(hProv); LSW_UNUSED(pbData); LSW_UNUSED(dwDataLen); LSW_UNUSED(hPubKey); LSW_UNUSED(dwFlags);
    if (phKey) *phKey = (HANDLE)0x3004;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptGenRandom(HANDLE hProv, DWORD dwLen, uint8_t* pbBuffer) {
    LSW_ADVAPI_LOG("CryptGenRandom");
    LSW_UNUSED(hProv);
    if (pbBuffer) for (DWORD i = 0; i < dwLen; ++i) pbBuffer[i] = (uint8_t)(rand() & 0xFF);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptSetHashParam(HANDLE hHash, DWORD dwParam, const uint8_t* pbData, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptSetHashParam");
    LSW_UNUSED(hHash); LSW_UNUSED(dwParam); LSW_UNUSED(pbData); LSW_UNUSED(dwFlags);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptSignHashW(HANDLE hHash, DWORD dwKeySpec, LPCWSTR szDescription, DWORD dwFlags, uint8_t* pbSignature, DWORD* pdwSigLen) {
    LSW_ADVAPI_LOG("CryptSignHashW");
    LSW_UNUSED(hHash); LSW_UNUSED(dwKeySpec); LSW_UNUSED(szDescription); LSW_UNUSED(dwFlags);
    if (pbSignature) memset(pbSignature, 0, 64);
    if (pdwSigLen) *pdwSigLen = 64;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptVerifySignatureW(HANDLE hHash, const uint8_t* pbSignature, DWORD dwSigLen, HANDLE hPubKey, LPCWSTR szDescription, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptVerifySignatureW");
    LSW_UNUSED(hHash); LSW_UNUSED(pbSignature); LSW_UNUSED(dwSigLen); LSW_UNUSED(hPubKey); LSW_UNUSED(szDescription); LSW_UNUSED(dwFlags);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptStringToBinaryW(LPCWSTR pszString, DWORD cchString, DWORD dwFlags, uint8_t* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags) {
    LSW_ADVAPI_LOG("CryptStringToBinaryW");
    LSW_UNUSED(pszString); LSW_UNUSED(cchString); LSW_UNUSED(dwFlags); LSW_UNUSED(pbBinary); LSW_UNUSED(pdwSkip); LSW_UNUSED(pdwFlags);
    if (pcbBinary) *pcbBinary = 0;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptBinaryToStringW(const uint8_t* pbBinary, DWORD cbBinary, DWORD dwFlags, LPWSTR pszString, DWORD* pcchString) {
    LSW_ADVAPI_LOG("CryptBinaryToStringW");
    LSW_UNUSED(pbBinary); LSW_UNUSED(cbBinary); LSW_UNUSED(dwFlags); LSW_UNUSED(pszString);
    if (pcchString) *pcchString = 0;
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptProtectData(void* pDataIn, LPCWSTR szDataDescr, void* pOptionalEntropy, void* pvReserved, void* pPromptStruct, DWORD dwFlags, void* pDataOut) {
    LSW_ADVAPI_LOG("CryptProtectData");
    LSW_UNUSED(pDataIn); LSW_UNUSED(szDataDescr); LSW_UNUSED(pOptionalEntropy); LSW_UNUSED(pvReserved); LSW_UNUSED(pPromptStruct); LSW_UNUSED(dwFlags); LSW_UNUSED(pDataOut);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_CryptUnprotectData(void* pDataIn, uint16_t** ppszDataDescr, void* pOptionalEntropy, void* pvReserved, void* pPromptStruct, DWORD dwFlags, void* pDataOut) {
    LSW_ADVAPI_LOG("CryptUnprotectData");
    LSW_UNUSED(pDataIn); LSW_UNUSED(ppszDataDescr); LSW_UNUSED(pOptionalEntropy); LSW_UNUSED(pvReserved); LSW_UNUSED(pPromptStruct); LSW_UNUSED(dwFlags); LSW_UNUSED(pDataOut);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_CryptSetProvParam(HANDLE hProv, DWORD dwParam, const uint8_t* pbData, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptSetProvParam");
    LSW_UNUSED(hProv); LSW_UNUSED(dwParam); LSW_UNUSED(pbData); LSW_UNUSED(dwFlags);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_CryptGetProvParam(HANDLE hProv, DWORD dwParam, uint8_t* pbData, DWORD* pdwDataLen, DWORD dwFlags) {
    LSW_ADVAPI_LOG("CryptGetProvParam");
    LSW_UNUSED(hProv); LSW_UNUSED(dwParam); LSW_UNUSED(pbData); LSW_UNUSED(pdwDataLen); LSW_UNUSED(dwFlags);
    return 1;
}

HANDLE __attribute__((ms_abi)) lsw_OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess) {
    LSW_ADVAPI_LOG("OpenSCManagerW");
    LSW_UNUSED(lpMachineName); LSW_UNUSED(lpDatabaseName); LSW_UNUSED(dwDesiredAccess);
    return (HANDLE)0x4000;
}

HANDLE __attribute__((ms_abi)) lsw_OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess) {
    LSW_ADVAPI_LOG("OpenSCManagerA");
    LSW_UNUSED(lpMachineName); LSW_UNUSED(lpDatabaseName); LSW_UNUSED(dwDesiredAccess);
    return (HANDLE)0x4001;
}

BOOL __attribute__((ms_abi)) lsw_CloseServiceHandle(HANDLE hSCObject) {
    LSW_ADVAPI_LOG("CloseServiceHandle");
    LSW_UNUSED(hSCObject);
    return 1;
}

HANDLE __attribute__((ms_abi)) lsw_OpenServiceW(HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess) {
    LSW_ADVAPI_LOG("OpenServiceW");
    LSW_UNUSED(hSCManager); LSW_UNUSED(lpServiceName); LSW_UNUSED(dwDesiredAccess);
    return NULL;
}

HANDLE __attribute__((ms_abi)) lsw_OpenServiceA(HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess) {
    LSW_ADVAPI_LOG("OpenServiceA");
    LSW_UNUSED(hSCManager); LSW_UNUSED(lpServiceName); LSW_UNUSED(dwDesiredAccess);
    return NULL;
}

HANDLE __attribute__((ms_abi)) lsw_CreateServiceW(HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, DWORD* lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword) {
    LSW_ADVAPI_LOG("CreateServiceW");
    LSW_UNUSED(hSCManager); LSW_UNUSED(lpServiceName); LSW_UNUSED(lpDisplayName); LSW_UNUSED(dwDesiredAccess); LSW_UNUSED(dwServiceType); LSW_UNUSED(dwStartType); LSW_UNUSED(dwErrorControl); LSW_UNUSED(lpBinaryPathName); LSW_UNUSED(lpLoadOrderGroup); LSW_UNUSED(lpdwTagId); LSW_UNUSED(lpDependencies); LSW_UNUSED(lpServiceStartName); LSW_UNUSED(lpPassword);
    return NULL;
}

BOOL __attribute__((ms_abi)) lsw_StartServiceW(HANDLE hService, DWORD dwNumServiceArgs, const uint16_t** lpServiceArgVectors) {
    LSW_ADVAPI_LOG("StartServiceW");
    LSW_UNUSED(hService); LSW_UNUSED(dwNumServiceArgs); LSW_UNUSED(lpServiceArgVectors);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_QueryServiceStatus(HANDLE hService, void* lpServiceStatus) {
    LSW_ADVAPI_LOG("QueryServiceStatus");
    LSW_UNUSED(hService); LSW_UNUSED(lpServiceStatus);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_QueryServiceStatusEx(HANDLE hService, int InfoLevel, uint8_t* lpBuffer, DWORD cbBufSize, DWORD* pcbBytesNeeded) {
    LSW_ADVAPI_LOG("QueryServiceStatusEx");
    LSW_UNUSED(hService); LSW_UNUSED(InfoLevel); LSW_UNUSED(lpBuffer); LSW_UNUSED(cbBufSize);
    lsw_zero_u32(pcbBytesNeeded);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_ControlService(HANDLE hService, DWORD dwControl, void* lpServiceStatus) {
    LSW_ADVAPI_LOG("ControlService");
    LSW_UNUSED(hService); LSW_UNUSED(dwControl); LSW_UNUSED(lpServiceStatus);
    return 0;
}

BOOL __attribute__((ms_abi)) lsw_DeleteService(HANDLE hService) {
    LSW_ADVAPI_LOG("DeleteService");
    LSW_UNUSED(hService);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_EnumServicesStatusW(HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, void* lpServices, DWORD cbBufSize, DWORD* pcbBytesNeeded, DWORD* lpServicesReturned, DWORD* lpResumeHandle) {
    LSW_ADVAPI_LOG("EnumServicesStatusW");
    LSW_UNUSED(hSCManager); LSW_UNUSED(dwServiceType); LSW_UNUSED(dwServiceState); LSW_UNUSED(lpServices); LSW_UNUSED(cbBufSize); LSW_UNUSED(pcbBytesNeeded); LSW_UNUSED(lpResumeHandle);
    if (lpServicesReturned) *lpServicesReturned = 0;
    return 1;
}

HANDLE __attribute__((ms_abi)) lsw_RegisterServiceCtrlHandlerW(LPCWSTR lpServiceName, void* lpHandlerProc) {
    LSW_ADVAPI_LOG("RegisterServiceCtrlHandlerW");
    LSW_UNUSED(lpServiceName); LSW_UNUSED(lpHandlerProc);
    return (HANDLE)0x4002;
}

BOOL __attribute__((ms_abi)) lsw_SetServiceStatus(HANDLE hServiceStatus, void* lpServiceStatus) {
    LSW_ADVAPI_LOG("SetServiceStatus");
    LSW_UNUSED(hServiceStatus); LSW_UNUSED(lpServiceStatus);
    return 1;
}

HANDLE __attribute__((ms_abi)) lsw_OpenEventLogW(LPCWSTR lpUNCServerName, LPCWSTR lpSourceName) {
    LSW_ADVAPI_LOG("OpenEventLogW");
    LSW_UNUSED(lpUNCServerName); LSW_UNUSED(lpSourceName);
    return (HANDLE)0x5000;
}

BOOL __attribute__((ms_abi)) lsw_CloseEventLog(HANDLE hEventLog) {
    LSW_ADVAPI_LOG("CloseEventLog");
    LSW_UNUSED(hEventLog);
    return 1;
}

BOOL __attribute__((ms_abi)) lsw_ReportEventW(HANDLE hEventLog, uint16_t wType, uint16_t wCategory, DWORD dwEventID, void* lpUserSid, uint16_t wNumStrings, DWORD dwDataSize, const uint16_t** lpStrings, void* lpRawData) {
    LSW_ADVAPI_LOG("ReportEventW");
    LSW_UNUSED(hEventLog); LSW_UNUSED(wType); LSW_UNUSED(wCategory); LSW_UNUSED(dwEventID); LSW_UNUSED(lpUserSid); LSW_UNUSED(wNumStrings); LSW_UNUSED(dwDataSize); LSW_UNUSED(lpStrings); LSW_UNUSED(lpRawData);
    return 1;
}

HANDLE __attribute__((ms_abi)) lsw_RegisterEventSourceW(LPCWSTR lpUNCServerName, LPCWSTR lpSourceName) {
    LSW_ADVAPI_LOG("RegisterEventSourceW");
    LSW_UNUSED(lpUNCServerName); LSW_UNUSED(lpSourceName);
    return (HANDLE)0x5001;
}

BOOL __attribute__((ms_abi)) lsw_DeregisterEventSource(HANDLE hEventLog) {
    LSW_ADVAPI_LOG("DeregisterEventSource");
    LSW_UNUSED(hEventLog);
    return 1;
}

win32_api_mapping_t win32_api_advapi32_mappings[] = {
    {"advapi32.dll", "RegOpenKeyExW", (void*)lsw_RegOpenKeyExW},
    {"advapi32.dll", "RegOpenKeyExA", (void*)lsw_RegOpenKeyExA},
    {"advapi32.dll", "RegCloseKey", (void*)lsw_RegCloseKey},
    {"advapi32.dll", "RegQueryValueExW", (void*)lsw_RegQueryValueExW},
    {"advapi32.dll", "RegQueryValueExA", (void*)lsw_RegQueryValueExA},
    {"advapi32.dll", "RegSetValueExW", (void*)lsw_RegSetValueExW},
    {"advapi32.dll", "RegSetValueExA", (void*)lsw_RegSetValueExA},
    {"advapi32.dll", "RegCreateKeyExW", (void*)lsw_RegCreateKeyExW},
    {"advapi32.dll", "RegCreateKeyExA", (void*)lsw_RegCreateKeyExA},
    {"advapi32.dll", "RegDeleteKeyW", (void*)lsw_RegDeleteKeyW},
    {"advapi32.dll", "RegDeleteKeyA", (void*)lsw_RegDeleteKeyA},
    {"advapi32.dll", "RegDeleteValueW", (void*)lsw_RegDeleteValueW},
    {"advapi32.dll", "RegDeleteValueA", (void*)lsw_RegDeleteValueA},
    {"advapi32.dll", "RegEnumKeyExW", (void*)lsw_RegEnumKeyExW},
    {"advapi32.dll", "RegEnumKeyExA", (void*)lsw_RegEnumKeyExA},
    {"advapi32.dll", "RegEnumValueW", (void*)lsw_RegEnumValueW},
    {"advapi32.dll", "RegEnumValueA", (void*)lsw_RegEnumValueA},
    {"advapi32.dll", "RegQueryInfoKeyW", (void*)lsw_RegQueryInfoKeyW},
    {"advapi32.dll", "RegQueryInfoKeyA", (void*)lsw_RegQueryInfoKeyA},
    {"advapi32.dll", "RegConnectRegistryW", (void*)lsw_RegConnectRegistryW},
    {"advapi32.dll", "RegFlushKey", (void*)lsw_RegFlushKey},
    {"advapi32.dll", "RegLoadKeyW", (void*)lsw_RegLoadKeyW},
    {"advapi32.dll", "RegSaveKeyW", (void*)lsw_RegSaveKeyW},
    {"advapi32.dll", "RegNotifyChangeKeyValue", (void*)lsw_RegNotifyChangeKeyValue},
    {"advapi32.dll", "RegGetValueW", (void*)lsw_RegGetValueW},
    {"advapi32.dll", "RegGetValueA", (void*)lsw_RegGetValueA},
    {"advapi32.dll", "OpenProcessToken", (void*)lsw_OpenProcessToken},
    {"advapi32.dll", "OpenThreadToken", (void*)lsw_OpenThreadToken},
    {"advapi32.dll", "GetTokenInformation", (void*)lsw_GetTokenInformation},
    {"advapi32.dll", "SetTokenInformation", (void*)lsw_SetTokenInformation},
    {"advapi32.dll", "AdjustTokenPrivileges", (void*)lsw_AdjustTokenPrivileges},
    {"advapi32.dll", "LookupPrivilegeValueW", (void*)lsw_LookupPrivilegeValueW},
    {"advapi32.dll", "LookupPrivilegeValueA", (void*)lsw_LookupPrivilegeValueA},
    {"advapi32.dll", "LookupPrivilegeNameW", (void*)lsw_LookupPrivilegeNameW},
    {"advapi32.dll", "CheckTokenMembership", (void*)lsw_CheckTokenMembership},
    {"advapi32.dll", "IsTokenRestricted", (void*)lsw_IsTokenRestricted},
    {"advapi32.dll", "DuplicateToken", (void*)lsw_DuplicateToken},
    {"advapi32.dll", "DuplicateTokenEx", (void*)lsw_DuplicateTokenEx},
    {"advapi32.dll", "ImpersonateLoggedOnUser", (void*)lsw_ImpersonateLoggedOnUser},
    {"advapi32.dll", "ImpersonateSelf", (void*)lsw_ImpersonateSelf},
    {"advapi32.dll", "RevertToSelf", (void*)lsw_RevertToSelf},
    {"advapi32.dll", "LogonUserW", (void*)lsw_LogonUserW},
    {"advapi32.dll", "LogonUserA", (void*)lsw_LogonUserA},
    {"advapi32.dll", "CreateWellKnownSid", (void*)lsw_CreateWellKnownSid},
    {"advapi32.dll", "IsWellKnownSid", (void*)lsw_IsWellKnownSid},
    {"advapi32.dll", "AllocateAndInitializeSid", (void*)lsw_AllocateAndInitializeSid},
    {"advapi32.dll", "FreeSid", (void*)lsw_FreeSid},
    {"advapi32.dll", "GetLengthSid", (void*)lsw_GetLengthSid},
    {"advapi32.dll", "IsValidSid", (void*)lsw_IsValidSid},
    {"advapi32.dll", "CopySid", (void*)lsw_CopySid},
    {"advapi32.dll", "EqualSid", (void*)lsw_EqualSid},
    {"advapi32.dll", "GetSidSubAuthority", (void*)lsw_GetSidSubAuthority},
    {"advapi32.dll", "GetSidSubAuthorityCount", (void*)lsw_GetSidSubAuthorityCount},
    {"advapi32.dll", "ConvertSidToStringSidW", (void*)lsw_ConvertSidToStringSidW},
    {"advapi32.dll", "ConvertStringSidToSidW", (void*)lsw_ConvertStringSidToSidW},
    {"advapi32.dll", "GetUserNameW", (void*)lsw_GetUserNameW},
    {"advapi32.dll", "GetUserNameA", (void*)lsw_GetUserNameA},
    {"advapi32.dll", "GetComputerNameW", (void*)lsw_GetComputerNameW},
    {"advapi32.dll", "GetComputerNameA", (void*)lsw_GetComputerNameA},
    {"advapi32.dll", "GetComputerNameExW", (void*)lsw_GetComputerNameExW},
    {"advapi32.dll", "GetComputerNameExA", (void*)lsw_GetComputerNameExA},
    {"advapi32.dll", "LookupAccountNameW", (void*)lsw_LookupAccountNameW},
    {"advapi32.dll", "LookupAccountSidW", (void*)lsw_LookupAccountSidW},
    {"advapi32.dll", "SetFileSecurityW", (void*)lsw_SetFileSecurityW},
    {"advapi32.dll", "SetFileSecurityA", (void*)lsw_SetFileSecurityA},
    {"advapi32.dll", "GetFileSecurityW", (void*)lsw_GetFileSecurityW},
    {"advapi32.dll", "GetFileSecurityA", (void*)lsw_GetFileSecurityA},
    {"advapi32.dll", "InitializeSecurityDescriptor", (void*)lsw_InitializeSecurityDescriptor},
    {"advapi32.dll", "SetSecurityDescriptorDacl", (void*)lsw_SetSecurityDescriptorDacl},
    {"advapi32.dll", "GetSecurityDescriptorDacl", (void*)lsw_GetSecurityDescriptorDacl},
    {"advapi32.dll", "MakeAbsoluteSD", (void*)lsw_MakeAbsoluteSD},
    {"advapi32.dll", "MakeSelfRelativeSD", (void*)lsw_MakeSelfRelativeSD},
    {"advapi32.dll", "AccessCheck", (void*)lsw_AccessCheck},
    {"advapi32.dll", "CheckTokenMembershipEx", (void*)lsw_CheckTokenMembershipEx},
    {"advapi32.dll", "CryptAcquireContextW", (void*)lsw_CryptAcquireContextW},
    {"advapi32.dll", "CryptAcquireContextA", (void*)lsw_CryptAcquireContextA},
    {"advapi32.dll", "CryptReleaseContext", (void*)lsw_CryptReleaseContext},
    {"advapi32.dll", "CryptCreateHash", (void*)lsw_CryptCreateHash},
    {"advapi32.dll", "CryptHashData", (void*)lsw_CryptHashData},
    {"advapi32.dll", "CryptGetHashParam", (void*)lsw_CryptGetHashParam},
    {"advapi32.dll", "CryptDestroyHash", (void*)lsw_CryptDestroyHash},
    {"advapi32.dll", "CryptDeriveKey", (void*)lsw_CryptDeriveKey},
    {"advapi32.dll", "CryptGenKey", (void*)lsw_CryptGenKey},
    {"advapi32.dll", "CryptDestroyKey", (void*)lsw_CryptDestroyKey},
    {"advapi32.dll", "CryptEncrypt", (void*)lsw_CryptEncrypt},
    {"advapi32.dll", "CryptDecrypt", (void*)lsw_CryptDecrypt},
    {"advapi32.dll", "CryptExportKey", (void*)lsw_CryptExportKey},
    {"advapi32.dll", "CryptImportKey", (void*)lsw_CryptImportKey},
    {"advapi32.dll", "CryptGenRandom", (void*)lsw_CryptGenRandom},
    {"advapi32.dll", "CryptSetHashParam", (void*)lsw_CryptSetHashParam},
    {"advapi32.dll", "CryptSignHashW", (void*)lsw_CryptSignHashW},
    {"advapi32.dll", "CryptVerifySignatureW", (void*)lsw_CryptVerifySignatureW},
    {"advapi32.dll", "CryptStringToBinaryW", (void*)lsw_CryptStringToBinaryW},
    {"advapi32.dll", "CryptBinaryToStringW", (void*)lsw_CryptBinaryToStringW},
    {"advapi32.dll", "CryptProtectData", (void*)lsw_CryptProtectData},
    {"advapi32.dll", "CryptUnprotectData", (void*)lsw_CryptUnprotectData},
    {"advapi32.dll", "CryptSetProvParam", (void*)lsw_CryptSetProvParam},
    {"advapi32.dll", "CryptGetProvParam", (void*)lsw_CryptGetProvParam},
    {"advapi32.dll", "OpenSCManagerW", (void*)lsw_OpenSCManagerW},
    {"advapi32.dll", "OpenSCManagerA", (void*)lsw_OpenSCManagerA},
    {"advapi32.dll", "CloseServiceHandle", (void*)lsw_CloseServiceHandle},
    {"advapi32.dll", "OpenServiceW", (void*)lsw_OpenServiceW},
    {"advapi32.dll", "OpenServiceA", (void*)lsw_OpenServiceA},
    {"advapi32.dll", "CreateServiceW", (void*)lsw_CreateServiceW},
    {"advapi32.dll", "StartServiceW", (void*)lsw_StartServiceW},
    {"advapi32.dll", "QueryServiceStatus", (void*)lsw_QueryServiceStatus},
    {"advapi32.dll", "QueryServiceStatusEx", (void*)lsw_QueryServiceStatusEx},
    {"advapi32.dll", "ControlService", (void*)lsw_ControlService},
    {"advapi32.dll", "DeleteService", (void*)lsw_DeleteService},
    {"advapi32.dll", "EnumServicesStatusW", (void*)lsw_EnumServicesStatusW},
    {"advapi32.dll", "RegisterServiceCtrlHandlerW", (void*)lsw_RegisterServiceCtrlHandlerW},
    {"advapi32.dll", "SetServiceStatus", (void*)lsw_SetServiceStatus},
    {"advapi32.dll", "OpenEventLogW", (void*)lsw_OpenEventLogW},
    {"advapi32.dll", "CloseEventLog", (void*)lsw_CloseEventLog},
    {"advapi32.dll", "ReportEventW", (void*)lsw_ReportEventW},
    {"advapi32.dll", "RegisterEventSourceW", (void*)lsw_RegisterEventSourceW},
    {"advapi32.dll", "DeregisterEventSource", (void*)lsw_DeregisterEventSource},
    {NULL, NULL, NULL}
};

size_t win32_api_advapi32_mappings_count =
    (sizeof(win32_api_advapi32_mappings) / sizeof(win32_api_advapi32_mappings[0])) - 1;
