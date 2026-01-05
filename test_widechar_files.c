/*
 * Test for wide-char file operations (CreateFileW, DeleteFileW, CopyFileW)
 */

#include <windows.h>
#include <stdio.h>
#include <wchar.h>

int main() {
    printf("Testing Wide-Char File Operations...\n\n");
    
    // Test 1: CreateFileW
    printf("Test 1: CreateFileW\n");
    HANDLE hFile = CreateFileW(L"C:\\temp\\test_wide.txt", 
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
    printf("  ✅ CreateFileW succeeded (handle: %p)\n", hFile);
    
    // Write some data
    const char* data = "Hello from wide-char file!\n";
    DWORD bytesWritten;
    if (!WriteFile(hFile, data, strlen(data), &bytesWritten, NULL)) {
        printf("  ❌ WriteFile failed!\n");
        CloseHandle(hFile);
        return 1;
    }
    printf("  ✅ Wrote %lu bytes\n", bytesWritten);
    
    CloseHandle(hFile);
    
    // Test 2: CopyFileW
    printf("\nTest 2: CopyFileW\n");
    if (!CopyFileW(L"C:\\temp\\test_wide.txt", L"C:\\temp\\test_wide_copy.txt", FALSE)) {
        printf("  ❌ CopyFileW failed!\n");
        return 1;
    }
    printf("  ✅ CopyFileW succeeded\n");
    
    // Verify the copy exists by opening it
    HANDLE hCopy = CreateFileW(L"C:\\temp\\test_wide_copy.txt", 
                                GENERIC_READ, 
                                0, 
                                NULL, 
                                OPEN_EXISTING, 
                                FILE_ATTRIBUTE_NORMAL, 
                                NULL);
    if (hCopy == INVALID_HANDLE_VALUE) {
        printf("  ❌ Copied file doesn't exist!\n");
        return 1;
    }
    printf("  ✅ Copied file exists and can be opened\n");
    CloseHandle(hCopy);
    
    // Test 3: DeleteFileW
    printf("\nTest 3: DeleteFileW\n");
    if (!DeleteFileW(L"C:\\temp\\test_wide.txt")) {
        printf("  ❌ DeleteFileW failed for original file!\n");
        return 1;
    }
    printf("  ✅ Original file deleted\n");
    
    if (!DeleteFileW(L"C:\\temp\\test_wide_copy.txt")) {
        printf("  ❌ DeleteFileW failed for copied file!\n");
        return 1;
    }
    printf("  ✅ Copied file deleted\n");
    
    printf("\n🎉 All tests passed!\n");
    return 0;
}
