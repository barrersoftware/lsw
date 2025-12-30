/*
 * Simple Win32 Console Application
 * Tests LSW (Linux Subsystem for Windows)
 */

#include <windows.h>

int main(void)
{
    // Simple message box
    MessageBoxA(NULL, "Hello from Win32 on Linux!", "LSW Test", MB_OK);
    
    // Console output
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    const char *msg = "Hello, World from Win32!\r\n";
    DWORD written;
    WriteFile(hConsole, msg, lstrlenA(msg), &written, NULL);
    
    return 0;
}
