typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE h, const void* buf, DWORD len, DWORD* written, void* reserved);
__declspec(dllimport) void __stdcall ExitProcess(DWORD code);

void _start(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    const char* msg = "Hello!\n";
    DWORD written;
    WriteConsoleA(h, msg, 7, &written, 0);
    ExitProcess(0);
}
