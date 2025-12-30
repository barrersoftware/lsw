/*
 * LSW (Linux Subsystem for Windows) - System Information Test
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Tests Win32 NtQuerySystemInformation - kernel-level system introspection
 * This is what anti-cheat systems use to scan the system
 */

#include "shared/lsw_kernel_client.h"
#include "shared/lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#define LSW_SYSCALL_NtQuerySystemInformation 0x0036

/* Syscall request structure */
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
    
    printf("=== LSW System Introspection Test ===\n");
    printf("Testing kernel-level process enumeration\n");
    printf("(This is what anti-cheat systems use)\n\n");
    
    /* Open LSW device */
    printf("1. Opening LSW kernel device...\n");
    fd = lsw_kernel_open();
    if (fd < 0) {
        printf("   FAILED: Could not open /dev/lsw\n");
        return 1;
    }
    printf("   SUCCESS\n\n");
    
    /* Test SystemBasicInformation (class 0) */
    printf("2. Querying system basic information...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtQuerySystemInformation;
    req.arg_count = 1;
    req.args[0] = 0;  /* SystemBasicInformation */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED: ioctl error\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    printf("   SUCCESS: System information retrieved\n");
    printf("   Check kernel log for details\n\n");
    
    /* Test SystemProcessInformation (class 5) - enumerate processes */
    printf("3. Enumerating all system processes...\n");
    printf("   (Anti-cheat uses this to detect cheating software)\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtQuerySystemInformation;
    req.arg_count = 1;
    req.args[0] = 5;  /* SystemProcessInformation */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED: ioctl error\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    printf("   SUCCESS: Process enumeration completed\n");
    printf("   Total processes found: %lu\n", (unsigned long)req.return_value);
    printf("   First 10 processes logged to kernel\n\n");
    
    /* Close device */
    printf("4. Closing device...\n");
    lsw_kernel_close(fd);
    printf("   SUCCESS\n\n");
    
    printf("=== SYSTEM INTROSPECTION TEST PASSED ===\n\n");
    printf("LSW can enumerate processes at kernel level!\n");
    printf("This proves LSW has the capabilities anti-cheat needs.\n");
    printf("\nCheck kernel logs: sudo dmesg | tail -30\n");
    printf("You should see all running processes enumerated.\n");
    
    return 0;
}
