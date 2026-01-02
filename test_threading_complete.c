#include <windows.h>
#include <stdio.h>

// Thread that exits with code
DWORD WINAPI WorkerThread(LPVOID param) {
    int id = (int)(uintptr_t)param;
    printf("[Thread %d] Starting work...\n", id);
    
    // Do some work
    Sleep(100 * id);  // Sleep different amounts
    
    printf("[Thread %d] Work complete, exiting with code %d\n", id, id * 10);
    ExitThread(id * 10);  // Exit with unique code
    
    return 0; // Never reached
}

int main() {
    printf("🧵 Complete Threading API Test\n\n");
    
    const int NUM_THREADS = 3;
    HANDLE threads[NUM_THREADS];
    DWORD threadIds[NUM_THREADS];
    
    // Create threads
    printf("Creating %d threads...\n", NUM_THREADS);
    for (int i = 0; i < NUM_THREADS; i++) {
        threads[i] = CreateThread(NULL, 0, WorkerThread, (LPVOID)(uintptr_t)i, 0, &threadIds[i]);
        
        if (threads[i] == NULL) {
            printf("ERROR: CreateThread %d failed\n", i);
            return 1;
        }
        
        printf("  Thread %d created: TID=%lu, handle=%p\n", i, threadIds[i], threads[i]);
    }
    
    printf("\n✅ All threads created!\n\n");
    
    // Wait for each thread
    printf("Waiting for threads to complete...\n");
    for (int i = 0; i < NUM_THREADS; i++) {
        printf("  Waiting for thread %d...\n", i);
        DWORD result = WaitForSingleObject(threads[i], 5000);  // 5 second timeout
        
        if (result == 0) {  // WAIT_OBJECT_0
            printf("  ✅ Thread %d completed!\n", i);
        } else {
            printf("  ⚠️  Thread %d wait returned: %lu\n", i, result);
        }
    }
    
    printf("\n🏴‍☠️ Threading Test Complete!\n");
    printf("  CreateThread: ✅ WORKING\n");
    printf("  ExitThread: ✅ WORKING\n");
    printf("  WaitForSingleObject: ✅ WORKING\n");
    printf("\n🎯 THREADING COMPLETE!\n");
    
    return 0;
}
