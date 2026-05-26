/*
 * Test for directory operations (CreateDirectoryW, RemoveDirectoryW)
 */

#include <windows.h>
#include <stdio.h>
#include <wchar.h>

int main() {
    printf("Testing Directory Operations...\n\n");
    
    // Test 1: CreateDirectoryW
    printf("Test 1: CreateDirectoryW\n");
    if (!CreateDirectoryW(L"C:\\temp\\test_dir", NULL)) {
        printf("  ❌ CreateDirectoryW failed!\n");
        return 1;
    }
    printf("  ✅ CreateDirectoryW succeeded\n");
    
    // Test 2: Create nested directory
    printf("\nTest 2: Create nested directory\n");
    if (!CreateDirectoryW(L"C:\\temp\\test_dir\\subdir", NULL)) {
        printf("  ❌ CreateDirectoryW (nested) failed!\n");
        return 1;
    }
    printf("  ✅ Nested directory created\n");
    
    // Test 3: Try to create existing directory (should fail)
    printf("\nTest 3: Try to create existing directory\n");
    if (CreateDirectoryW(L"C:\\temp\\test_dir", NULL)) {
        printf("  ❌ Should have failed on existing directory!\n");
        return 1;
    }
    printf("  ✅ Correctly failed on existing directory\n");
    
    // Test 4: Create a file in the directory to test cleanup
    printf("\nTest 4: Create file in directory\n");
    HANDLE hFile = CreateFileW(L"C:\\temp\\test_dir\\test.txt",
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
    
    const char* data = "Test file in directory\n";
    DWORD bytesWritten;
    WriteFile(hFile, data, strlen(data), &bytesWritten, NULL);
    CloseHandle(hFile);
    printf("  ✅ File created in directory\n");
    
    // Test 5: Try to remove non-empty directory (should fail)
    printf("\nTest 5: Try to remove non-empty directory\n");
    if (RemoveDirectoryW(L"C:\\temp\\test_dir")) {
        printf("  ❌ Should have failed on non-empty directory!\n");
        return 1;
    }
    printf("  ✅ Correctly failed on non-empty directory\n");
    
    // Test 6: Clean up - delete file first
    printf("\nTest 6: Delete file\n");
    if (!DeleteFileW(L"C:\\temp\\test_dir\\test.txt")) {
        printf("  ❌ DeleteFileW failed!\n");
        return 1;
    }
    printf("  ✅ File deleted\n");
    
    // Test 7: Remove subdirectory
    printf("\nTest 7: Remove subdirectory\n");
    if (!RemoveDirectoryW(L"C:\\temp\\test_dir\\subdir")) {
        printf("  ❌ RemoveDirectoryW (subdir) failed!\n");
        return 1;
    }
    printf("  ✅ Subdirectory removed\n");
    
    // Test 8: Remove main directory (now empty)
    printf("\nTest 8: Remove main directory\n");
    if (!RemoveDirectoryW(L"C:\\temp\\test_dir")) {
        printf("  ❌ RemoveDirectoryW failed!\n");
        return 1;
    }
    printf("  ✅ Main directory removed\n");
    
    printf("\n🎉 All tests passed!\n");
    return 0;
}
