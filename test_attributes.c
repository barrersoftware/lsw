/*
 * Test for file attribute operations
 */

#include <windows.h>
#include <stdio.h>

int main() {
    printf("Testing File Attribute Operations...\n\n");
    
    // Test 1: Get attributes of existing directory
    printf("Test 1: Get attributes of C:\\Windows\n");
    DWORD attrs = GetFileAttributesW(L"C:\\Windows");
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("  ❌ GetFileAttributesW failed!\n");
        return 1;
    }
    printf("  ✅ Attributes: 0x%08lx\n", attrs);
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        printf("  ✅ Correctly identified as directory\n");
    } else {
        printf("  ❌ Should be a directory!\n");
        return 1;
    }
    
    // Test 2: Create a test file
    printf("\nTest 2: Create test file\n");
    HANDLE hFile = CreateFileW(L"C:\\temp\\attrtest.txt",
                                GENERIC_WRITE,
                                0,
                                NULL,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("  ❌ CreateFileW failed!\n");
        return 1;
    }
    
    const char* data = "Test file for attributes\n";
    DWORD written;
    WriteFile(hFile, data, strlen(data), &written, NULL);
    CloseHandle(hFile);
    printf("  ✅ File created\n");
    
    // Test 3: Get attributes of the file
    printf("\nTest 3: Get file attributes\n");
    attrs = GetFileAttributesW(L"C:\\temp\\attrtest.txt");
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("  ❌ GetFileAttributesW failed!\n");
        return 1;
    }
    printf("  ✅ File attributes: 0x%08lx\n", attrs);
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("  ✅ Correctly identified as file (not directory)\n");
    }
    
    // Test 4: Set file to read-only
    printf("\nTest 4: Set file to read-only\n");
    if (!SetFileAttributesW(L"C:\\temp\\attrtest.txt", FILE_ATTRIBUTE_READONLY)) {
        printf("  ❌ SetFileAttributesW failed!\n");
        return 1;
    }
    printf("  ✅ File set to read-only\n");
    
    // Test 5: Verify read-only attribute
    printf("\nTest 5: Verify read-only attribute\n");
    attrs = GetFileAttributesW(L"C:\\temp\\attrtest.txt");
    if (attrs & FILE_ATTRIBUTE_READONLY) {
        printf("  ✅ File is now read-only\n");
    } else {
        printf("  ❌ File should be read-only!\n");
        return 1;
    }
    
    // Test 6: Remove read-only and delete
    printf("\nTest 6: Remove read-only attribute\n");
    if (!SetFileAttributesW(L"C:\\temp\\attrtest.txt", FILE_ATTRIBUTE_NORMAL)) {
        printf("  ❌ SetFileAttributesW failed!\n");
        return 1;
    }
    printf("  ✅ Read-only removed\n");
    
    // Test 7: Verify it's no longer read-only
    printf("\nTest 7: Verify attributes changed\n");
    attrs = GetFileAttributesW(L"C:\\temp\\attrtest.txt");
    if (!(attrs & FILE_ATTRIBUTE_READONLY)) {
        printf("  ✅ File is no longer read-only\n");
    } else {
        printf("  ❌ File should not be read-only!\n");
        return 1;
    }
    
    // Test 8: Delete the file
    printf("\nTest 8: Delete test file\n");
    if (!DeleteFileW(L"C:\\temp\\attrtest.txt")) {
        printf("  ❌ DeleteFileW failed!\n");
        return 1;
    }
    printf("  ✅ File deleted\n");
    
    // Test 9: Verify file no longer exists
    printf("\nTest 9: Verify file deleted\n");
    attrs = GetFileAttributesW(L"C:\\temp\\attrtest.txt");
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("  ✅ File correctly doesn't exist\n");
    } else {
        printf("  ❌ File should not exist!\n");
        return 1;
    }
    
    printf("\n🎉 All tests passed!\n");
    return 0;
}
