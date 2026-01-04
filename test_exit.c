// Minimal test - just exit
__declspec(dllimport) void __stdcall ExitProcess(unsigned long code);

void _start(void) {
    ExitProcess(42);
}
