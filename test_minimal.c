// Minimal Windows program with NO CRT
// Compile with: x86_64-w64-mingw32-gcc -nostdlib -e WinMainCRTStartup test_minimal.c -o test_minimal.exe

void ExitProcess(int code);
int MessageBoxA(void* hwnd, const char* text, const char* caption, unsigned int type);

void WinMainCRTStartup(void) {
    MessageBoxA(0, "Hello from LSW!", "Success", 0);
    ExitProcess(0);
}

// Stub implementations that will be resolved by LSW
void ExitProcess(int code) {
    (void)code;
    __asm__ volatile("hlt");
}

int MessageBoxA(void* hwnd, const char* text, const char* caption, unsigned int type) {
    (void)hwnd; (void)text; (void)caption; (void)type;
    return 0;
}
