/*
 * LSW Comprehensive Test Runner  
 * Loads test.exe (256KB diagnostic) into LSW
 * Licensed under BFSL v1.2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define LSW_IOCTL_MAGIC 'L'

struct lsw_syscall_request {
    uint32_t syscall_number;
    uint32_t arg_count;
    uint64_t args[8];
    uint64_t return_value;
    int32_t error_code;
};

#define LSW_IOCTL_SYSCALL _IOWR(LSW_IOCTL_MAGIC, 4, struct lsw_syscall_request)
#define LSW_SYSCALL_NtCreateProcess 0x00B3

int main(void) {
    printf("╔════════════════════════════════════════════╗\n");
    printf("║   LSW COMPREHENSIVE TEST RUNNER           ║\n");
    printf("║   Loading 256KB test.exe diagnostic       ║\n");
    printf("╚════════════════════════════════════════════╝\n\n");
    
    int fd = open("/dev/lsw", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/lsw");
        return 1;
    }
    
    printf("✓ Opened /dev/lsw device\n\n");
    
    // Load comprehensive test.exe
    struct lsw_syscall_request req = {0};
    req.syscall_number = LSW_SYSCALL_NtCreateProcess;
    req.arg_count = 1;
    req.args[0] = (uint64_t)"/tmp/test.exe";  // Path to test.exe
    
    printf("Loading test.exe (256KB with ALL syscall tests)...\n");
    if (ioctl(fd, LSW_IOCTL_SYSCALL, &req) < 0) {
        perror("NtCreateProcess failed");
        close(fd);
        return 1;
    }
    
    printf("✓ test.exe loaded successfully!\n");
    printf("  Win32 PID: %lu\n\n", req.return_value);
    
    printf("╔════════════════════════════════════════════╗\n");
    printf("║   What test.exe will exercise:            ║\n");
    printf("╠════════════════════════════════════════════╣\n");
    printf("║   ✓ Memory allocation (VirtualAlloc)      ║\n");
    printf("║   ✓ File I/O (CreateFile, WriteFile)      ║\n");
    printf("║   ✓ Process operations (GetCurrentPID)    ║\n");
    printf("║   ✓ Thread creation (CreateThread)        ║\n");
    printf("║   ✓ Synchronization (Events, Mutexes)     ║\n");
    printf("║   ✓ DLL loading (LoadLibrary)             ║\n");
    printf("║   ✓ Console I/O (GetStdHandle)            ║\n");
    printf("║   ✓ Time operations (Sleep, GetTickCount) ║\n");
    printf("║   ✓ Registry access (RegOpenKeyEx)        ║\n");
    printf("╚════════════════════════════════════════════╝\n\n");
    
    printf("Check kernel logs for detailed results:\n");
    printf("  sudo dmesg | tail -100\n\n");
    
    close(fd);
    
    return 0;
}
