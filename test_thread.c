#include <windows.h>
#include <stdio.h>

// Thread function
DWORD WINAPI ThreadFunction(LPVOID param) {
    int thread_num = (int)(uintptr_t)param;
    char filename[64];
    sprintf(filename, "thread_%d.txt", thread_num);
    
    printf("[Thread %d] Starting...\n", thread_num);
    
    // Create file
    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, 
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[Thread %d] ERROR: CreateFile failed\n", thread_num);
        return 1;
    }
    
    // Write data
    char buffer[256];
    sprintf(buffer, "Hello from thread %d!\n", thread_num);
    DWORD written = 0;
    
    if (!WriteFile(hFile, buffer, strlen(buffer), &written, NULL)) {
        printf("[Thread %d] ERROR: WriteFile failed\n", thread_num);
        CloseHandle(hFile);
        return 1;
    }
    
    printf("[Thread %d] Wrote %lu bytes to %s\n", thread_num, written, filename);
    
    CloseHandle(hFile);
    
    printf("[Thread %d] Complete!\n", thread_num);
    return 0;
}

int main() {
    printf("Testing multi-threaded file I/O\n\n");
    
    const int NUM_THREADS = 3;
    HANDLE threads[NUM_THREADS];
    DWORD threadIds[NUM_THREADS];
    
    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        printf("Creating thread %d...\n", i);
        threads[i] = CreateThread(
            NULL,                           // Security attributes
            0,                              // Stack size (0 = default)
            ThreadFunction,                 // Thread function
            (LPVOID)(uintptr_t)i,          // Thread parameter
            0,                              // Creation flags
            &threadIds[i]                   // Thread ID
        );
        
        if (threads[i] == NULL) {
            printf("ERROR: CreateThread %d failed\n", i);
            return 1;
        }
        
        printf("Thread %d created: TID=%lu\n", i, threadIds[i]);
    }
    
    printf("\n✅ All threads created successfully!\n");
    printf("🏴‍☠️ Multi-threaded file I/O test complete!\n");
    
    return 0;
}
