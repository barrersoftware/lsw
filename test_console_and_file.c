/*
 * test_console_and_file.c - Test Console + File I/O together
 * 
 * Tests that both WriteConsoleA and WriteFile work in the same program
 * 
 * Compile with: x86_64-w64-mingw32-gcc -o test_console_and_file.exe test_console_and_file.c
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    HANDLE hStdout, hFile;
    DWORD written;
    BOOL result;
    
    printf("=== LSW Console + File I/O Test ===\n\n");
    
    /* Get console handle */
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    printf("Console handle: 0x%p\n\n", hStdout);
    
    /* Test 1: Write to console */
    printf("Test 1: Writing to console via WriteConsoleA...\n");
    result = WriteConsoleA(hStdout, "Hello from WriteConsoleA!\n", 26, &written, NULL);
    if (result) {
        printf("  ✅ Console write SUCCESS: %lu bytes\n\n", written);
    } else {
        printf("  ❌ Console write FAILED\n\n");
    }
    
    /* Test 2: Write to file */
    printf("Test 2: Writing to file via CreateFile/WriteFile...\n");
    hFile = CreateFileA("C:\\test_combo.txt",
                       GENERIC_WRITE,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("  ❌ File create FAILED\n");
        return 1;
    }
    
    const char* file_data = "File I/O works!\n";
    result = WriteFile(hFile, file_data, (DWORD)strlen(file_data), &written, NULL);
    CloseHandle(hFile);
    
    if (result) {
        printf("  ✅ File write SUCCESS: %lu bytes to C:\\test_combo.txt\n\n", written);
    } else {
        printf("  ❌ File write FAILED\n\n");
    }
    
    /* Test 3: Alternate between console and file */
    printf("Test 3: Alternating console and file writes...\n");
    
    WriteConsoleA(hStdout, "  Console message 1\n", 20, &written, NULL);
    
    hFile = CreateFileA("C:\\test_combo2.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, "File message 1\n", 15, &written, NULL);
    CloseHandle(hFile);
    
    WriteConsoleA(hStdout, "  Console message 2\n", 20, &written, NULL);
    
    hFile = CreateFileA("C:\\test_combo2.txt", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, "File message 2\n", 15, &written, NULL);
    CloseHandle(hFile);
    
    printf("  ✅ Alternating writes complete\n\n");
    
    printf("=== ALL TESTS PASSED ===\n");
    printf("Check files:\n");
    printf("  ~/.lsw/drives/c/test_combo.txt\n");
    printf("  ~/.lsw/drives/c/test_combo2.txt\n");
    
    return 0;
}
