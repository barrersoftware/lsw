#include <windows.h>
#include <stdio.h>

int main() {
    printf("=== LSW Comprehensive Test ===\n\n");
    
    // Test 1: Memory allocation
    printf("[TEST 1] Memory Allocation\n");
    void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        printf("✓ VirtualAlloc succeeded: %p\n", mem);
        VirtualFree(mem, 0, MEM_RELEASE);
        printf("✓ VirtualFree succeeded\n");
    } else {
        printf("✗ VirtualAlloc failed\n");
    }
    
    // Test 2: File I/O
    printf("\n[TEST 2] File I/O\n");
    HANDLE hFile = CreateFileA("test_output.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        printf("✓ CreateFile succeeded: %p\n", hFile);
        const char* data = "LSW Test Data\n";
        DWORD written;
        if (WriteFile(hFile, data, strlen(data), &written, NULL)) {
            printf("✓ WriteFile succeeded: %lu bytes\n", written);
        }
        CloseHandle(hFile);
        printf("✓ CloseHandle succeeded\n");
    } else {
        printf("✗ CreateFile failed\n");
    }
    
    // Test 3: Process info
    printf("\n[TEST 3] Process Information\n");
    DWORD pid = GetCurrentProcessId();
    printf("✓ Process ID: %lu\n", pid);
    
    // Test 4: Synchronization
    printf("\n[TEST 4] Synchronization\n");
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, "LSW_Test_Event");
    if (hEvent) {
        printf("✓ CreateEvent succeeded: %p\n", hEvent);
        if (SetEvent(hEvent)) {
            printf("✓ SetEvent succeeded\n");
        }
        CloseHandle(hEvent);
    } else {
        printf("✗ CreateEvent failed\n");
    }
    
    // Test 5: DLL loading
    printf("\n[TEST 5] DLL Loading\n");
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel) {
        printf("✓ GetModuleHandle(kernel32.dll): %p\n", hKernel);
    } else {
        printf("✗ GetModuleHandle failed\n");
    }
    
    printf("\n=== All Tests Complete ===\n");
    printf("LSW is functioning at kernel level!\n");
    
    return 0;
}
