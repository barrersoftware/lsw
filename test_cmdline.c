// Simple no-CRT test of command line
// Build: x86_64-w64-mingw32-gcc -o test_cmdline.exe test_cmdline.c -nostdlib -lkernel32 -e _start

typedef void* HANDLE;
typedef unsigned long DWORD;
typedef char* LPSTR;
typedef int BOOL;

#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite, DWORD* lpNumberOfCharsWritten, void* lpReserved);
__declspec(dllimport) LPSTR __stdcall GetCommandLineA(void);
__declspec(dllimport) void __stdcall ExitProcess(DWORD uExitCode);

void _start(void) {
    HANDLE stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    
    const char* msg1 = "Testing command line...\n";
    int len1 = 0;
    while (msg1[len1]) len1++;
    WriteConsoleA(stdout_h, msg1, len1, &written, 0);
    
    LPSTR cmdline = GetCommandLineA();
    
    const char* msg2 = "GetCommandLineA() = ";
    int len2 = 0;
    while (msg2[len2]) len2++;
    WriteConsoleA(stdout_h, msg2, len2, &written, 0);
    
    if (cmdline) {
        int len3 = 0;
        while (cmdline[len3]) len3++;
        WriteConsoleA(stdout_h, cmdline, len3, &written, 0);
    }
    
    const char* msg3 = "\nDone!\n";
    int len4 = 0;
    while (msg3[len4]) len4++;
    WriteConsoleA(stdout_h, msg3, len4, &written, 0);
    
    ExitProcess(0);
}
