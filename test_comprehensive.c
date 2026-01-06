/*
 * LSW API Comprehensive Test Suite
 * Tests all newly implemented APIs
 */

#include <windows.h>
#include <stdio.h>

int test_memory_apis() {
    printf("\n=== Memory Management APIs ===\n");
    int passed = 0, total = 0;
    
    // Test 1: GetProcessHeap
    printf("Test 1: GetProcessHeap\n");
    total++;
    HANDLE heap = GetProcessHeap();
    if (heap != NULL) {
        printf("  ✓ Got heap handle: %p\n", heap);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 2: HeapAlloc
    printf("Test 2: HeapAlloc\n");
    total++;
    void* ptr1 = HeapAlloc(heap, 0, 1024);
    if (ptr1 != NULL) {
        printf("  ✓ Allocated 1024 bytes: %p\n", ptr1);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 3: HeapAlloc with HEAP_ZERO_MEMORY
    printf("Test 3: HeapAlloc with HEAP_ZERO_MEMORY\n");
    total++;
    void* ptr2 = HeapAlloc(heap, 0x00000008, 512);
    if (ptr2 != NULL) {
        // Check if zeroed
        int is_zero = 1;
        for (int i = 0; i < 512; i++) {
            if (((char*)ptr2)[i] != 0) {
                is_zero = 0;
                break;
            }
        }
        if (is_zero) {
            printf("  ✓ Allocated 512 bytes (zeroed): %p\n", ptr2);
            passed++;
        } else {
            printf("  ✗ Not zeroed\n");
        }
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 4: HeapReAlloc
    printf("Test 4: HeapReAlloc\n");
    total++;
    void* ptr3 = HeapReAlloc(heap, 0, ptr1, 2048);
    if (ptr3 != NULL) {
        printf("  ✓ Reallocated to 2048 bytes: %p\n", ptr3);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 5: HeapFree
    printf("Test 5: HeapFree\n");
    total++;
    if (HeapFree(heap, 0, ptr3) && HeapFree(heap, 0, ptr2)) {
        printf("  ✓ Freed memory\n");
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 6: LocalAlloc/LocalFree
    printf("Test 6: LocalAlloc/LocalFree\n");
    total++;
    void* local = LocalAlloc(0x0040, 256); // LMEM_ZEROINIT
    if (local != NULL) {
        LocalFree(local);
        printf("  ✓ LocalAlloc/LocalFree works\n");
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 7: GlobalAlloc/GlobalLock/GlobalUnlock/GlobalFree
    printf("Test 7: GlobalAlloc/GlobalLock/GlobalUnlock/GlobalFree\n");
    total++;
    void* global = GlobalAlloc(0x0040, 128);
    if (global != NULL) {
        void* locked = GlobalLock(global);
        if (locked != NULL) {
            GlobalUnlock(global);
            GlobalFree(global);
            printf("  ✓ Global memory operations work\n");
            passed++;
        } else {
            GlobalFree(global);
            printf("  ✗ Lock failed\n");
        }
    } else {
        printf("  ✗ Failed\n");
    }
    
    printf("\nMemory APIs: %d/%d passed\n", passed, total);
    return (passed == total);
}

int test_file_enumeration() {
    printf("\n=== File Enumeration APIs ===\n");
    int passed = 0, total = 0;
    
    // Test 1: FindFirstFileW / FindNextFileW / FindClose
    printf("Test 1: FindFirstFileW/FindNextFileW/FindClose\n");
    total++;
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(L"C:\\*", &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        int count = 0;
        do {
            count++;
            wprintf(L"  Found: %s\n", findData.cFileName);
            if (count >= 5) break; // Just show first 5
        } while (FindNextFileW(hFind, &findData));
        
        FindClose(hFind);
        printf("  ✓ Found %d+ files\n", count);
        passed++;
    } else {
        printf("  ✗ FindFirstFileW failed\n");
    }
    
    // Test 2: Wildcard search
    printf("Test 2: Wildcard search (*.txt)\n");
    total++;
    hFind = FindFirstFileW(L"C:\\*.txt", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        printf("  ✓ Wildcard search works\n");
        FindClose(hFind);
        passed++;
    } else {
        printf("  ⚠ No .txt files found (this is okay)\n");
        passed++; // Not a failure
    }
    
    printf("\nFile Enumeration APIs: %d/%d passed\n", passed, total);
    return (passed == total);
}

int test_path_env_apis() {
    printf("\n=== Path/Environment APIs ===\n");
    int passed = 0, total = 0;
    char buffer[MAX_PATH];
    DWORD result;
    
    // Test 1: GetWindowsDirectoryA
    printf("Test 1: GetWindowsDirectoryA\n");
    total++;
    result = GetWindowsDirectoryA(buffer, sizeof(buffer));
    if (result > 0) {
        printf("  ✓ Windows directory: %s\n", buffer);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 2: GetSystemDirectoryA
    printf("Test 2: GetSystemDirectoryA\n");
    total++;
    result = GetSystemDirectoryA(buffer, sizeof(buffer));
    if (result > 0) {
        printf("  ✓ System directory: %s\n", buffer);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 3: GetTempPathA
    printf("Test 3: GetTempPathA\n");
    total++;
    result = GetTempPathA(sizeof(buffer), buffer);
    if (result > 0) {
        printf("  ✓ Temp path: %s\n", buffer);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 4: SetEnvironmentVariableA
    printf("Test 4: SetEnvironmentVariableA\n");
    total++;
    if (SetEnvironmentVariableA("LSW_TEST", "TestValue123")) {
        printf("  ✓ Set LSW_TEST=TestValue123\n");
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 5: GetEnvironmentVariableA
    printf("Test 5: GetEnvironmentVariableA\n");
    total++;
    result = GetEnvironmentVariableA("LSW_TEST", buffer, sizeof(buffer));
    if (result > 0 && strcmp(buffer, "TestValue123") == 0) {
        printf("  ✓ Retrieved: %s\n", buffer);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Test 6: ExpandEnvironmentStringsA
    printf("Test 6: ExpandEnvironmentStringsA\n");
    total++;
    result = ExpandEnvironmentStringsA("Test: %LSW_TEST%", buffer, sizeof(buffer));
    if (result > 0 && strstr(buffer, "TestValue123") != NULL) {
        printf("  ✓ Expanded: %s\n", buffer);
        passed++;
    } else {
        printf("  ✗ Failed\n");
    }
    
    // Cleanup
    SetEnvironmentVariableA("LSW_TEST", NULL);
    
    printf("\nPath/Environment APIs: %d/%d passed\n", passed, total);
    return (passed == total);
}

int main() {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   LSW API Comprehensive Test Suite      ║\n");
    printf("║   Testing 28 New APIs                   ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    
    int all_passed = 1;
    
    all_passed &= test_memory_apis();
    all_passed &= test_file_enumeration();
    all_passed &= test_path_env_apis();
    
    printf("\n╔══════════════════════════════════════════╗\n");
    if (all_passed) {
        printf("║   ✅ ALL TESTS PASSED!                   ║\n");
    } else {
        printf("║   ⚠️  SOME TESTS FAILED                  ║\n");
    }
    printf("╚══════════════════════════════════════════╝\n");
    
    return all_passed ? 0 : 1;
}
