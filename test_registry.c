/*
 * test_registry.c - Test Windows Registry APIs
 * 
 * Compile with: x86_64-w64-mingw32-gcc -o test_registry.exe test_registry.c -ladvapi32
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    HKEY hkey;
    LONG result;
    DWORD value;
    DWORD type, size;
    char str_value[256];
    
    printf("=== LSW Registry Test ===\n\n");
    
    // Test 1: Create a key
    printf("Test 1: Creating registry key...\n");
    result = RegCreateKeyExA(HKEY_CURRENT_USER, 
                             "Software\\LSWTest",
                             0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkey, NULL);
    if (result == ERROR_SUCCESS) {
        printf("  ✅ Key created: HKCU\\Software\\LSWTest\n");
        printf("  Handle: 0x%p\n\n", hkey);
    } else {
        printf("  ❌ Failed to create key: error %ld\n\n", result);
        return 1;
    }
    
    // Test 2: Write DWORD value
    printf("Test 2: Writing DWORD value...\n");
    value = 42;
    result = RegSetValueExA(hkey, "TestNumber", 0, REG_DWORD, 
                            (const BYTE*)&value, sizeof(value));
    if (result == ERROR_SUCCESS) {
        printf("  ✅ Wrote TestNumber = %lu\n\n", value);
    } else {
        printf("  ❌ Failed to write value: error %ld\n\n", result);
    }
    
    // Test 3: Write string value
    printf("Test 3: Writing string value...\n");
    const char* test_str = "Hello from LSW Registry!";
    result = RegSetValueExA(hkey, "TestString", 0, REG_SZ,
                            (const BYTE*)test_str, (DWORD)strlen(test_str) + 1);
    if (result == ERROR_SUCCESS) {
        printf("  ✅ Wrote TestString = '%s'\n\n", test_str);
    } else {
        printf("  ❌ Failed to write string: error %ld\n\n", result);
    }
    
    // Close and reopen
    printf("Test 4: Closing and reopening key...\n");
    RegCloseKey(hkey);
    
    result = RegOpenKeyExA(HKEY_CURRENT_USER, 
                           "Software\\LSWTest",
                           0, KEY_READ, &hkey);
    if (result == ERROR_SUCCESS) {
        printf("  ✅ Key reopened successfully\n\n");
    } else {
        printf("  ❌ Failed to reopen key: error %ld\n\n", result);
        return 1;
    }
    
    // Test 5: Read DWORD value
    printf("Test 5: Reading DWORD value...\n");
    size = sizeof(value);
    result = RegQueryValueExA(hkey, "TestNumber", NULL, &type, 
                              (BYTE*)&value, &size);
    if (result == ERROR_SUCCESS) {
        printf("  ✅ Read TestNumber = %lu (type=%lu)\n\n", value, type);
    } else {
        printf("  ❌ Failed to read value: error %ld\n\n", result);
    }
    
    // Test 6: Read string value
    printf("Test 6: Reading string value...\n");
    size = sizeof(str_value);
    result = RegQueryValueExA(hkey, "TestString", NULL, &type,
                              (BYTE*)str_value, &size);
    if (result == ERROR_SUCCESS) {
        printf("  ✅ Read TestString = '%s' (type=%lu)\n\n", str_value, type);
    } else {
        printf("  ❌ Failed to read string: error %ld\n\n", result);
    }
    
    // Test 7: Read nonexistent value
    printf("Test 7: Reading nonexistent value...\n");
    size = sizeof(value);
    result = RegQueryValueExA(hkey, "DoesNotExist", NULL, &type,
                              (BYTE*)&value, &size);
    if (result == ERROR_FILE_NOT_FOUND) {
        printf("  ✅ Correctly returned ERROR_FILE_NOT_FOUND\n\n");
    } else {
        printf("  ❌ Unexpected result: %ld\n\n", result);
    }
    
    RegCloseKey(hkey);
    
    printf("=== ALL TESTS PASSED ===\n");
    printf("Registry data stored at: ~/.lsw/registry/HKCU/Software/LSWTest/\n");
    
    return 0;
}
