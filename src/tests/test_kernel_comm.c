/*
 * LSW (Linux Subsystem for Windows) - Kernel Communication Test
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Tests userspace <-> kernel module communication
 */

#include "shared/lsw_kernel_client.h"
#include "shared/lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int fd;
    int ret;
    struct lsw_pe_info test_pe;
    
    printf("=== LSW Kernel Communication Test ===\n\n");
    
    /* Step 1: Open device */
    printf("1. Opening LSW kernel device...\n");
    fd = lsw_kernel_open();
    if (fd < 0) {
        printf("   FAILED: Could not open /dev/lsw\n");
        printf("   Make sure the LSW kernel module is loaded: sudo insmod kernel-module/lsw.ko\n");
        return 1;
    }
    printf("   SUCCESS: Device opened (fd=%d)\n\n", fd);
    
    /* Step 2: Get initial status */
    printf("2. Getting kernel status...\n");
    ret = lsw_kernel_get_status(fd);
    if (ret < 0) {
        printf("   FAILED: Could not get status\n");
        lsw_kernel_close(fd);
        return 1;
    }
    printf("   SUCCESS: %d PE processes currently registered\n\n", ret);
    
    /* Step 3: Register a test PE */
    printf("3. Registering test PE process...\n");
    memset(&test_pe, 0, sizeof(test_pe));
    test_pe.pid = getpid();
    test_pe.base_address = 0x400000;  /* Typical Win32 base */
    test_pe.entry_point = 0x1000;     /* Example entry point RVA */
    test_pe.image_size = 0x10000;     /* 64KB test image */
    test_pe.is_64bit = 0;             /* 32-bit test */
    strncpy(test_pe.executable_path, "/test/lsw_comm_test.exe", sizeof(test_pe.executable_path) - 1);
    
    ret = lsw_kernel_register_pe(fd, &test_pe);
    if (ret < 0) {
        printf("   FAILED: Could not register PE\n");
        lsw_kernel_close(fd);
        return 1;
    }
    printf("   SUCCESS: Test PE registered\n");
    printf("     PID: %u\n", test_pe.pid);
    printf("     Base: 0x%lx\n", test_pe.base_address);
    printf("     Entry: 0x%lx\n", test_pe.entry_point);
    printf("     Size: 0x%x\n", test_pe.image_size);
    printf("     Path: %s\n\n", test_pe.executable_path);
    
    /* Step 4: Verify registration */
    printf("4. Verifying registration...\n");
    ret = lsw_kernel_get_status(fd);
    if (ret < 0) {
        printf("   FAILED: Could not get status\n");
        lsw_kernel_close(fd);
        return 1;
    }
    printf("   SUCCESS: Now %d PE processes registered\n\n", ret);
    
    /* Step 5: Unregister PE */
    printf("5. Unregistering test PE...\n");
    ret = lsw_kernel_unregister_pe(fd, test_pe.pid);
    if (ret < 0) {
        printf("   FAILED: Could not unregister PE\n");
        lsw_kernel_close(fd);
        return 1;
    }
    printf("   SUCCESS: Test PE unregistered\n\n");
    
    /* Step 6: Final status check */
    printf("6. Final status check...\n");
    ret = lsw_kernel_get_status(fd);
    if (ret < 0) {
        printf("   FAILED: Could not get status\n");
        lsw_kernel_close(fd);
        return 1;
    }
    printf("   SUCCESS: Back to %d PE processes registered\n\n", ret);
    
    /* Step 7: Close device */
    printf("7. Closing device...\n");
    lsw_kernel_close(fd);
    printf("   SUCCESS: Device closed\n\n");
    
    printf("=== ALL TESTS PASSED ===\n");
    printf("Userspace <-> Kernel communication is working!\n");
    
    return 0;
}
