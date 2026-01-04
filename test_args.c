/*
 * Test command-line arguments
 * Tests GetCommandLineA and argc/argv passing
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    
    // Test GetCommandLineA
    LPSTR cmdline = GetCommandLineA();
    
    // Print via WriteConsoleA
    WriteConsoleA(stdout_handle, "Command line test:\n", 19, &written, NULL);
    WriteConsoleA(stdout_handle, "GetCommandLineA() = ", 20, &written, NULL);
    
    if (cmdline && *cmdline) {
        DWORD len = 0;
        while (cmdline[len]) len++;
        WriteConsoleA(stdout_handle, cmdline, len, &written, NULL);
        WriteConsoleA(stdout_handle, "\n", 1, &written, NULL);
    } else {
        WriteConsoleA(stdout_handle, "(empty)\n", 8, &written, NULL);
    }
    
    WriteConsoleA(stdout_handle, "\nTest complete!\n", 16, &written, NULL);
    
    return 0;
}
