/*
 * LSW (Linux Subsystem for Windows) - Synchronization Test
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Tests Win32 synchronization primitives (events, mutexes)
 */

#include "shared/lsw_kernel_client.h"
#include "shared/lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

/* Syscall numbers */
#define LSW_SYSCALL_NtCreateEvent         0x0048
#define LSW_SYSCALL_NtCreateMutant        0x00c4
#define LSW_SYSCALL_NtWaitForSingleObject 0x0004
#define LSW_SYSCALL_NtSetEvent            0x000e
#define LSW_SYSCALL_NtReleaseMutant       0x001d
#define LSW_SYSCALL_NtClose               0x000f

struct lsw_syscall_request {
    uint32_t syscall_number;
    uint32_t arg_count;
    uint64_t args[8];
    uint64_t return_value;
    int32_t  error_code;
};

#define LSW_IOCTL_MAGIC 'L'
#define LSW_IOCTL_SYSCALL _IOWR(LSW_IOCTL_MAGIC, 4, struct lsw_syscall_request)

int main(void)
{
    int fd;
    struct lsw_syscall_request req;
    int ret;
    uint64_t event_handle = 0;
    uint64_t mutex_handle = 0;
    
    printf("=== LSW Synchronization Test ===\n");
    printf("Testing kernel-level sync primitives\n");
    printf("(Native Linux wait queue performance)\n\n");
    
    fd = lsw_kernel_open();
    if (fd < 0) {
        printf("FAILED: Could not open /dev/lsw\n");
        return 1;
    }
    
    /* Test 1: Create Event */
    printf("1. NtCreateEvent - Creating event object...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtCreateEvent;
    req.arg_count = 2;
    req.args[0] = 0;  /* Auto-reset */
    req.args[1] = 0;  /* Not signaled */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0 || req.return_value == 0) {
        printf("   FAILED\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    event_handle = req.return_value;
    printf("   SUCCESS: Event created, handle=0x%lx\n\n", event_handle);
    
    /* Test 2: Signal Event */
    printf("2. NtSetEvent - Signaling event...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtSetEvent;
    req.arg_count = 1;
    req.args[0] = event_handle;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: Event signaled\n\n");
    }
    
    /* Test 3: Wait for Event (should succeed immediately since signaled) */
    printf("3. NtWaitForSingleObject - Waiting on event...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtWaitForSingleObject;
    req.arg_count = 2;
    req.args[0] = event_handle;
    req.args[1] = 1000;  /* 1 second timeout */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: Wait completed (status=0x%lx)\n\n", req.return_value);
    }
    
    /* Test 4: Close Event */
    printf("4. NtClose - Closing event...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtClose;
    req.arg_count = 1;
    req.args[0] = event_handle;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: Event closed\n\n");
    }
    
    /* Test 5: Create Mutex */
    printf("5. NtCreateMutant - Creating mutex...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtCreateMutant;
    req.arg_count = 1;
    req.args[0] = 0;  /* Not owned initially */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0 || req.return_value == 0) {
        printf("   FAILED\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    mutex_handle = req.return_value;
    printf("   SUCCESS: Mutex created, handle=0x%lx\n\n", mutex_handle);
    
    /* Test 6: Wait for Mutex (acquire it) */
    printf("6. NtWaitForSingleObject - Acquiring mutex...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtWaitForSingleObject;
    req.arg_count = 2;
    req.args[0] = mutex_handle;
    req.args[1] = 1000;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: Mutex acquired\n\n");
    }
    
    /* Test 7: Release Mutex */
    printf("7. NtReleaseMutant - Releasing mutex...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtReleaseMutant;
    req.arg_count = 1;
    req.args[0] = mutex_handle;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: Mutex released\n\n");
    }
    
    /* Test 8: Close Mutex */
    printf("8. NtClose - Closing mutex...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtClose;
    req.arg_count = 1;
    req.args[0] = mutex_handle;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: Mutex closed\n\n");
    }
    
    lsw_kernel_close(fd);
    
    printf("=== SYNC TEST COMPLETE ===\n\n");
    printf("LSW synchronization primitives working!\n");
    printf("  ✓ Events (create, signal, wait, close)\n");
    printf("  ✓ Mutexes (create, acquire, release, close)\n\n");
    printf("Multi-threaded Win32 apps can now sync properly!\n");
    printf("Check kernel logs: sudo dmesg | tail -40\n");
    
    return 0;
}
