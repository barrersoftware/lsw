/*
 * test_console.c - Test Console I/O functionality
 * 
 * Compile with: x86_64-w64-mingw32-gcc -o test_console.exe test_console.c
 */

#include <windows.h>
#include <stdio.h>

int main(void)
{
    HANDLE hStdout, hStderr, hStdin;
    DWORD written, read_count;
    char buffer[256];
    BOOL result;
    
    printf("LSW Console I/O Test\n");
    printf("====================\n\n");
    
    /* Get standard handles */
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    hStderr = GetStdHandle(STD_ERROR_HANDLE);
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    
    printf("Standard handles:\n");
    printf("  STDOUT: 0x%p\n", hStdout);
    printf("  STDERR: 0x%p\n", hStderr);
    printf("  STDIN:  0x%p\n\n", hStdin);
    
    /* Test WriteConsole to stdout */
    result = WriteConsoleA(hStdout, "Hello from WriteConsoleA!\n", 26, &written, NULL);
    if (result) {
        printf("WriteConsole SUCCESS: wrote %lu chars\n", written);
    } else {
        printf("WriteConsole FAILED\n");
    }
    
    /* Test WriteConsole to stderr */
    result = WriteConsoleA(hStderr, "Error message to stderr\n", 24, &written, NULL);
    if (result) {
        printf("WriteConsole to stderr: %lu chars\n", written);
    }
    
    /* Test multiple writes */
    printf("\nTesting multiple console writes:\n");
    WriteConsoleA(hStdout, "Line 1\n", 7, &written, NULL);
    WriteConsoleA(hStdout, "Line 2\n", 7, &written, NULL);
    WriteConsoleA(hStdout, "Line 3\n", 7, &written, NULL);
    
    printf("\n=== Console I/O Test Complete ===\n");
    
    return 0;
}
