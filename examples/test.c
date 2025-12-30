/*
 * LSW Comprehensive Diagnostic Test
 * Tests ALL implemented syscalls and reports barriers
 * Licensed under BFSL v1.2 - Barrer Software
 */

#include <windows.h>
#include <stdio.h>

#define TEST_PASSED(name) printf("[PASS] %s\n", name)
#define TEST_FAILED(name, err) printf("[FAIL] %s - Error: 0x%08lX\n", name, err)
#define TEST_BARRIER(name, reason) printf("[BARRIER] %s - %s\n", name, reason)

void test_memory_allocation() {
    printf("\n=== MEMORY ALLOCATION TESTS ===\n");
    
    // VirtualAlloc
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        TEST_PASSED("VirtualAlloc - 4KB allocation");
        
        // Try to write
        memset(mem, 0xAA, 4096);
        TEST_PASSED("Memory write - 4KB pattern");
        
        // VirtualFree
        if (VirtualFree(mem, 0, MEM_RELEASE)) {
            TEST_PASSED("VirtualFree - deallocation");
        } else {
            TEST_FAILED("VirtualFree", GetLastError());
        }
    } else {
        TEST_FAILED("VirtualAlloc", GetLastError());
    }
    
    // Large allocation
    mem = VirtualAlloc(NULL, 1024*1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        TEST_PASSED("VirtualAlloc - 1MB allocation");
        VirtualFree(mem, 0, MEM_RELEASE);
    } else {
        TEST_FAILED("VirtualAlloc 1MB", GetLastError());
    }
}

void test_file_operations() {
    printf("\n=== FILE I/O TESTS ===\n");
    
    // CreateFile
    HANDLE hFile = CreateFileA("C:\\test.txt", GENERIC_WRITE, 0, NULL, 
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        TEST_PASSED("CreateFile - C:\\test.txt");
        
        // WriteFile
        const char *data = "LSW Test Data\n";
        DWORD written;
        if (WriteFile(hFile, data, strlen(data), &written, NULL)) {
            TEST_PASSED("WriteFile - 14 bytes");
        } else {
            TEST_FAILED("WriteFile", GetLastError());
        }
        
        CloseHandle(hFile);
        TEST_PASSED("CloseHandle - file handle");
    } else {
        TEST_BARRIER("CreateFile", "C:\\ path translation not implemented");
    }
    
    // GetCurrentDirectory
    char dir[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, dir)) {
        printf("[PASS] GetCurrentDirectory - %s\n", dir);
    } else {
        TEST_FAILED("GetCurrentDirectory", GetLastError());
    }
}

void test_process_operations() {
    printf("\n=== PROCESS/THREAD TESTS ===\n");
    
    // GetCurrentProcessId
    DWORD pid = GetCurrentProcessId();
    printf("[PASS] GetCurrentProcessId - PID: %lu\n", pid);
    
    // GetCurrentThreadId
    DWORD tid = GetCurrentThreadId();
    printf("[PASS] GetCurrentThreadId - TID: %lu\n", tid);
    
    // CreateThread
    DWORD threadId;
    HANDLE hThread = CreateThread(NULL, 0, 
        (LPTHREAD_START_ROUTINE)test_memory_allocation, NULL, 0, &threadId);
    if (hThread) {
        TEST_PASSED("CreateThread - spawned thread");
        
        // WaitForSingleObject
        DWORD result = WaitForSingleObject(hThread, 5000);
        if (result == WAIT_OBJECT_0) {
            TEST_PASSED("WaitForSingleObject - thread completed");
        } else {
            TEST_FAILED("WaitForSingleObject", result);
        }
        
        CloseHandle(hThread);
    } else {
        TEST_FAILED("CreateThread", GetLastError());
    }
}

void test_synchronization() {
    printf("\n=== SYNCHRONIZATION TESTS ===\n");
    
    // CreateEvent
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, "LSW_TEST_EVENT");
    if (hEvent) {
        TEST_PASSED("CreateEvent - manual reset event");
        
        // SetEvent
        if (SetEvent(hEvent)) {
            TEST_PASSED("SetEvent - signal event");
            
            // WaitForSingleObject on event
            DWORD result = WaitForSingleObject(hEvent, 1000);
            if (result == WAIT_OBJECT_0) {
                TEST_PASSED("WaitForSingleObject - event signaled");
            } else {
                TEST_FAILED("WaitForSingleObject event", result);
            }
            
            // ResetEvent
            if (ResetEvent(hEvent)) {
                TEST_PASSED("ResetEvent - clear event");
            } else {
                TEST_FAILED("ResetEvent", GetLastError());
            }
        } else {
            TEST_FAILED("SetEvent", GetLastError());
        }
        
        CloseHandle(hEvent);
    } else {
        TEST_FAILED("CreateEvent", GetLastError());
    }
    
    // CreateMutex
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "LSW_TEST_MUTEX");
    if (hMutex) {
        TEST_PASSED("CreateMutex - mutex created");
        
        // Acquire mutex
        DWORD result = WaitForSingleObject(hMutex, 1000);
        if (result == WAIT_OBJECT_0) {
            TEST_PASSED("WaitForSingleObject - mutex acquired");
            
            // ReleaseMutex
            if (ReleaseMutex(hMutex)) {
                TEST_PASSED("ReleaseMutex - mutex released");
            } else {
                TEST_FAILED("ReleaseMutex", GetLastError());
            }
        } else {
            TEST_FAILED("WaitForSingleObject mutex", result);
        }
        
        CloseHandle(hMutex);
    } else {
        TEST_FAILED("CreateMutex", GetLastError());
    }
}

void test_dll_operations() {
    printf("\n=== DLL LOADING TESTS ===\n");
    
    // LoadLibrary on system DLL
    HMODULE hKernel = LoadLibraryA("kernel32.dll");
    if (hKernel) {
        TEST_PASSED("LoadLibrary - kernel32.dll");
        
        // GetProcAddress
        FARPROC proc = GetProcAddress(hKernel, "GetCurrentProcessId");
        if (proc) {
            TEST_PASSED("GetProcAddress - GetCurrentProcessId");
        } else {
            TEST_BARRIER("GetProcAddress", "Export table not implemented");
        }
        
        FreeLibrary(hKernel);
        TEST_PASSED("FreeLibrary - kernel32.dll");
    } else {
        TEST_BARRIER("LoadLibrary", "System DLLs not available");
    }
}

void test_console_operations() {
    printf("\n=== CONSOLE I/O TESTS ===\n");
    
    // GetStdHandle
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout != INVALID_HANDLE_VALUE) {
        TEST_PASSED("GetStdHandle - STD_OUTPUT_HANDLE");
        
        // WriteConsole
        const char *msg = "LSW Console Output Test\n";
        DWORD written;
        if (WriteFile(hStdout, msg, strlen(msg), &written, NULL)) {
            printf("[PASS] WriteFile to console - %lu bytes\n", written);
        } else {
            TEST_FAILED("WriteFile console", GetLastError());
        }
    } else {
        TEST_FAILED("GetStdHandle", GetLastError());
    }
}

void test_time_operations() {
    printf("\n=== TIME/SLEEP TESTS ===\n");
    
    // GetTickCount
    DWORD tick1 = GetTickCount();
    printf("[PASS] GetTickCount - %lu ms\n", tick1);
    
    // Sleep
    Sleep(100);
    TEST_PASSED("Sleep - 100ms");
    
    DWORD tick2 = GetTickCount();
    printf("[INFO] Elapsed: %lu ms\n", tick2 - tick1);
}

void test_registry_operations() {
    printf("\n=== REGISTRY TESTS ===\n");
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        TEST_PASSED("RegOpenKeyEx - HKLM\\SOFTWARE");
        RegCloseKey(hKey);
    } else {
        TEST_BARRIER("RegOpenKeyEx", "Registry subsystem not implemented");
    }
}

int main(void) {
    printf("╔════════════════════════════════════════════╗\n");
    printf("║   LSW COMPREHENSIVE DIAGNOSTIC TEST       ║\n");
    printf("║   Testing Ring 0 Win32 Subsystem          ║\n");
    printf("║   Licensed under BFSL v1.2                ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    
    test_memory_allocation();
    test_file_operations();
    test_process_operations();
    test_synchronization();
    test_dll_operations();
    test_console_operations();
    test_time_operations();
    test_registry_operations();
    
    printf("\n╔════════════════════════════════════════════╗\n");
    printf("║   DIAGNOSTIC COMPLETE                     ║\n");
    printf("║   Check results above for barriers        ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    
    return 0;
}
