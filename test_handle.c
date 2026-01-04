typedef void* HANDLE;
typedef unsigned long DWORD;
#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) void __stdcall ExitProcess(DWORD code);

void _start(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    ExitProcess(h ? 1 : 0);
}
