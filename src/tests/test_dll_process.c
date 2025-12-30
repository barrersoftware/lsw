/*
 * LSW (Linux Subsystem for Windows) - DLL Loading Test
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Tests DLL loading and process creation from userspace
 */

#include "shared/lsw_kernel_client.h"
#include "shared/lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

/* Syscall numbers */
#define LSW_SYSCALL_LdrLoadDll            0x0026
#define LSW_SYSCALL_LdrGetProcedureAddress 0x00b8
#define LSW_SYSCALL_NtCreateProcess       0x00b3
#define LSW_SYSCALL_NtCreateThreadEx      0x00bd

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
    uint64_t dll_base = 0;
    uint32_t process_pid = 0;
    uint32_t thread_tid = 0;
    
    printf("=== LSW DLL Loading & Process Creation Test ===\n");
    printf("Testing userspace → kernel syscall path\n\n");
    
    fd = lsw_kernel_open();
    if (fd < 0) {
        printf("FAILED: Could not open /dev/lsw\n");
        return 1;
    }
    
    /* Test 1: Load DLL */
    printf("1. LdrLoadDll - Loading test DLL from /tmp/test.dll...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_LdrLoadDll;
    req.arg_count = 0;  /* Path is hardcoded in kernel for now */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED: ioctl returned %d\n", ret);
        lsw_kernel_close(fd);
        return 1;
    }
    
    if (req.error_code != 0) {
        printf("   FAILED: Kernel returned error %d\n", req.error_code);
    } else {
        dll_base = req.return_value;
        printf("   SUCCESS: DLL loaded at base address 0x%lx\n", dll_base);
    }
    printf("\n");
    
    /* Test 2: Get Proc Address (if DLL loaded) */
    if (dll_base != 0) {
        printf("2. LdrGetProcedureAddress - Getting function address...\n");
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_LdrGetProcedureAddress;
        req.arg_count = 1;
        req.args[0] = dll_base;
        
        ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
        if (ret < 0) {
            printf("   FAILED: ioctl returned %d\n", ret);
        } else if (req.error_code != 0) {
            printf("   FAILED: Kernel returned error %d\n", req.error_code);
        } else {
            printf("   SUCCESS: Function address 0x%lx\n", req.return_value);
        }
        printf("\n");
    }
    
    /* Test 3: Create Process */
    printf("3. NtCreateProcess - Creating Win32 process...\n");
    memset(&req, 0, sizeof(req));
    req.syscall_number = LSW_SYSCALL_NtCreateProcess;
    req.arg_count = 0;  /* Path is hardcoded in kernel for now */
    
    ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
    if (ret < 0) {
        printf("   FAILED: ioctl returned %d\n", ret);
    } else if (req.error_code != 0) {
        printf("   FAILED: Kernel returned error %d\n", req.error_code);
    } else {
        process_pid = req.return_value;
        printf("   SUCCESS: Process created with Win32 PID %u\n", process_pid);
        printf("   Check kernel logs for Linux PID mapping\n");
    }
    printf("\n");
    
    /* Test 4: Create Thread (if process created) */
    if (process_pid != 0) {
        printf("4. NtCreateThreadEx - Creating thread in process...\n");
        memset(&req, 0, sizeof(req));
        req.syscall_number = LSW_SYSCALL_NtCreateThreadEx;
        req.arg_count = 3;
        req.args[0] = process_pid;
        req.args[1] = 0x1000;  /* Start address */
        req.args[2] = 0;       /* Parameter */
        
        ret = ioctl(fd, LSW_IOCTL_SYSCALL, &req);
        if (ret < 0) {
            printf("   FAILED: ioctl returned %d\n", ret);
        } else if (req.error_code != 0) {
            printf("   FAILED: Kernel returned error %d\n", req.error_code);
        } else {
            thread_tid = req.return_value;
            printf("   SUCCESS: Thread created with Win32 TID %u\n", thread_tid);
            printf("   Check kernel logs for Linux TID mapping\n");
        }
        printf("\n");
    }
    
    lsw_kernel_close(fd);
    
    printf("=== TEST COMPLETE ===\n\n");
    
    printf("Summary:\n");
    printf("  DLL Loading:      %s\n", dll_base ? "✓ SUCCESS" : "✗ FAILED");
    printf("  Process Creation: %s\n", process_pid ? "✓ SUCCESS" : "✗ FAILED");
    printf("  Thread Creation:  %s\n", thread_tid ? "✓ SUCCESS" : "✗ FAILED");
    printf("\n");
    printf("Check kernel logs: sudo dmesg | tail -50\n");
    
    return (dll_base && process_pid && thread_tid) ? 0 : 1;
}
