/*
 * LSW (Linux Subsystem for Windows) - Syscall Test
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Tests Win32 syscall translation
 */

#include "shared/lsw_kernel_client.h"
#include "shared/lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

/* Win32 Syscall Numbers */
#define LSW_SYSCALL_NtAllocateVirtualMemory 0x0018
#define LSW_SYSCALL_NtFreeVirtualMemory     0x001e
#define LSW_SYSCALL_NtCreateFile            0x0055

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
    
    printf("=== LSW Win32 Syscall Translation Test ===\n\n");
    
    /* Open LSW device */
    printf("1. Opening LSW kernel device...\n");
    fd = lsw_kernel_open();
    if (fd < 0) {
        printf("   FAILED: Could not open /dev/lsw\n");
        return 1;
    }
    printf("   SUCCESS: Device opened\n\n");
    
    /* Test NtAllocateVirtualMemory */
    printf("2. Testing NtAllocateVirtualMemory syscall...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtAllocateVirtualMemory;
    req.arg_count = 2;
    req.args[0] = 0x400000;  /* Base address */
    req.args[1] = 0x10000;   /* Size: 64KB */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED: ioctl error\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    printf("   SUCCESS: NtAllocateVirtualMemory completed\n");
    printf("     Requested: base=0x%lx, size=0x%lx\n", 
           (unsigned long)req.args[0], (unsigned long)req.args[1]);
    printf("     Returned: 0x%lx (error=%d)\n", 
           (unsigned long)req.return_value, req.error_code);
    printf("\n");
    
    /* Test NtCreateFile */
    printf("3. Testing NtCreateFile syscall...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtCreateFile;
    req.arg_count = 0;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED: ioctl error\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    printf("   SUCCESS: NtCreateFile completed\n");
    printf("     File handle: 0x%lx\n", (unsigned long)req.return_value);
    printf("\n");
    
    /* Test NtFreeVirtualMemory */
    printf("4. Testing NtFreeVirtualMemory syscall...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtFreeVirtualMemory;
    req.arg_count = 1;
    req.args[0] = 0x400000;  /* Base address to free */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED: ioctl error\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    printf("   SUCCESS: NtFreeVirtualMemory completed\n");
    printf("     Freed: 0x%lx\n", (unsigned long)req.args[0]);
    printf("\n");
    
    /* Close device */
    printf("5. Closing device...\n");
    lsw_kernel_close(fd);
    printf("   SUCCESS\n\n");
    
    printf("=== ALL SYSCALL TESTS PASSED ===\n");
    printf("Win32 syscalls are being translated by the kernel!\n");
    printf("Check kernel log: sudo dmesg | tail -20\n");
    
    return 0;
}
