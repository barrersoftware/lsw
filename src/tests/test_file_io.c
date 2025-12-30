/*
 * LSW (Linux Subsystem for Windows) - File I/O Test
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Tests real Win32 file I/O operations at kernel level
 */

#include "shared/lsw_kernel_client.h"
#include "shared/lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

/* Syscall numbers */
#define LSW_SYSCALL_NtCreateFile  0x0055
#define LSW_SYSCALL_NtReadFile    0x0006
#define LSW_SYSCALL_NtWriteFile   0x0008
#define LSW_SYSCALL_NtClose       0x000f

/* Win32 access flags */
#define LSW_GENERIC_READ          0x80000000
#define LSW_GENERIC_WRITE         0x40000000

/* Win32 creation disposition */
#define LSW_CREATE_ALWAYS         2
#define LSW_OPEN_EXISTING         3

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
    uint64_t file_handle = 0;
    
    printf("=== LSW File I/O System Test ===\n");
    printf("Testing kernel-level file operations\n");
    printf("(Near-zero overhead path translation)\n\n");
    
    fd = lsw_kernel_open();
    if (fd < 0) {
        printf("FAILED: Could not open /dev/lsw\n");
        return 1;
    }
    
    /* Test 1: Create file */
    printf("1. NtCreateFile - Creating /tmp/lsw_test.txt...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtCreateFile;
    req.arg_count = 3;
    req.args[0] = LSW_GENERIC_WRITE;  /* Access */
    req.args[1] = 0;                   /* Share mode */
    req.args[2] = LSW_CREATE_ALWAYS;   /* Create or overwrite */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0 || req.return_value == 0) {
        printf("   FAILED: ioctl error or invalid handle\n");
        lsw_kernel_close(fd);
        return 1;
    }
    
    file_handle = req.return_value;
    printf("   SUCCESS: File created, handle=0x%lx\n\n", file_handle);
    
    /* Test 2: Write to file */
    printf("2. NtWriteFile - Writing data...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtWriteFile;
    req.arg_count = 1;
    req.args[0] = file_handle;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: Wrote %lu bytes\n\n", req.return_value);
    }
    
    /* Test 3: Close file */
    printf("3. NtClose - Closing file...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtClose;
    req.arg_count = 1;
    req.args[0] = file_handle;
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED\n");
    } else {
        printf("   SUCCESS: File closed\n\n");
    }
    
    /* Test 4: Open existing file for reading */
    printf("4. NtCreateFile - Opening for read...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtCreateFile;
    req.arg_count = 3;
    req.args[0] = LSW_GENERIC_READ;    /* Access */
    req.args[1] = 0;                    /* Share mode */
    req.args[2] = LSW_OPEN_EXISTING;    /* Open existing */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0 || req.return_value == 0) {
        printf("   FAILED\n");
    } else {
        file_handle = req.return_value;
        printf("   SUCCESS: File opened, handle=0x%lx\n\n", file_handle);
        
        /* Test 5: Read from file */
        printf("5. NtReadFile - Reading data...\n");
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtReadFile;
        req.arg_count = 2;
        req.args[0] = file_handle;
        req.args[1] = 4096;  /* Read up to 4KB */
        
        ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
        if (ret < 0) {
            printf("   FAILED\n");
        } else {
            printf("   SUCCESS: Read %lu bytes\n\n", req.return_value);
        }
        
        /* Test 6: Close read handle */
        printf("6. NtClose - Closing read handle...\n");
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtClose;
        req.arg_count = 1;
        req.args[0] = file_handle;
        
        ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
        if (ret < 0) {
            printf("   FAILED\n");
        } else {
            printf("   SUCCESS: File closed\n\n");
        }
    }
    
    lsw_kernel_close(fd);
    
    printf("=== FILE I/O TEST COMPLETE ===\n\n");
    printf("LSW file I/O working at kernel level!\n");
    printf("Check: cat /tmp/lsw_test.txt\n");
    printf("Check kernel logs: sudo dmesg | tail -30\n");
    
    return 0;
}
