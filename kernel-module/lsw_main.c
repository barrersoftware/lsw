/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * 
 * Main kernel module implementation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_device.h"
#include "../include/kernel-module/lsw_syscall.h"
#include "../include/kernel-module/lsw_memory.h"
#include "../include/kernel-module/lsw_file.h"
#include "../include/kernel-module/lsw_sync.h"
#include "../include/kernel-module/lsw_dll.h"
#include "../include/kernel-module/lsw_process.h"

/* Forward declarations for console and env subsystems */
extern int lsw_console_init(void);
extern void lsw_console_cleanup(void);
extern int lsw_env_init(void);
extern void lsw_env_cleanup(void);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(LSW_MODULE_AUTHOR);
MODULE_DESCRIPTION(LSW_MODULE_DESC);
MODULE_VERSION(LSW_MODULE_VERSION);

/* Module state */
struct lsw_state lsw_module_state = {
    .initialized = false,
    .syscall_hooks_active = false,
    .syscall_table_addr = 0,
    .pe_process_count = 0,
};

/* Hot-swap support */
static atomic_t module_refcount_held = ATOMIC_INIT(0);
static bool module_persistent = false;  // Changed to false for easier hot-reloading
module_param(module_persistent, bool, 0444);
MODULE_PARM_DESC(module_persistent, "Keep module loaded when no PE processes are running");

/**
 * lsw_init - Initialize LSW kernel module
 * 
 * Called when module is loaded into kernel
 */
static int __init lsw_init(void)
{
    int ret;
    
    lsw_info("Initializing LSW v%s", LSW_MODULE_VERSION);
    lsw_info("Linux Subsystem for Windows - Kernel Module");
    lsw_info("Kernel version: %d.%d.%d", 
             LINUX_VERSION_CODE >> 16,
             (LINUX_VERSION_CODE >> 8) & 0xFF,
             LINUX_VERSION_CODE & 0xFF);
    
    /* Initialize module state */
    lsw_module_state.initialized = false;
    lsw_module_state.syscall_hooks_active = false;
    lsw_module_state.pe_process_count = 0;
    
    /* TODO: Find syscall table address */
    lsw_info("Searching for syscall table...");
    
    /* kallsyms_lookup_name is not exported in newer kernels */
    /* We'll need alternative methods to find the syscall table */
    /* For now, just log that we need to implement this */
    lsw_info("Syscall table lookup - TODO: implement for kernel %d.%d",
             LINUX_VERSION_CODE >> 16,
             (LINUX_VERSION_CODE >> 8) & 0xFF);
    
    /* Placeholder - will implement kprobes or other method later */
    lsw_module_state.syscall_table_addr = 0;
    
    /* TODO: Initialize syscall hooks */
    /* TODO: Initialize PE process tracking */
    
    /* Initialize syscall translation system */
    ret = lsw_syscall_init();
    if (ret != 0) {
        lsw_err("Failed to initialize syscall system: %d", ret);
        return ret;
    }
    
    /* Initialize memory management system */
    ret = lsw_memory_init();
    if (ret != 0) {
        lsw_err("Failed to initialize memory management: %d", ret);
        lsw_syscall_exit();
        return ret;
    }
    
    /* Initialize file I/O system */
    ret = lsw_file_init();
    if (ret != 0) {
        lsw_err("Failed to initialize file I/O: %d", ret);
        lsw_memory_exit();
        lsw_syscall_exit();
        return ret;
    }
    
    /* Initialize synchronization system */
    ret = lsw_sync_init();
    if (ret != 0) {
        lsw_err("Failed to initialize synchronization: %d", ret);
        lsw_file_exit();
        lsw_memory_exit();
        lsw_syscall_exit();
        return ret;
    }
    
    /* Initialize DLL loading system */
    ret = lsw_dll_init();
    if (ret != 0) {
        lsw_err("Failed to initialize DLL loading: %d", ret);
        lsw_sync_exit();
        lsw_file_exit();
        lsw_memory_exit();
        lsw_syscall_exit();
        return ret;
    }
    
    /* Initialize process/thread management */
    ret = lsw_process_init();
    if (ret != 0) {
        lsw_err("Failed to initialize process management: %d", ret);
        lsw_dll_exit();
        lsw_sync_exit();
        lsw_file_exit();
        lsw_memory_exit();
        lsw_syscall_exit();
        return ret;
    }
    
    /* Initialize console I/O */
    ret = lsw_console_init();
    if (ret != 0) {
        lsw_err("Failed to initialize console I/O: %d", ret);
        lsw_process_exit();
        lsw_dll_exit();
        lsw_sync_exit();
        lsw_file_exit();
        lsw_memory_exit();
        lsw_syscall_exit();
        return ret;
    }
    
    /* Initialize environment/system info */
    ret = lsw_env_init();
    if (ret != 0) {
        lsw_err("Failed to initialize environment/system info: %d", ret);
        lsw_console_cleanup();
        lsw_process_exit();
        lsw_dll_exit();
        lsw_sync_exit();
        lsw_file_exit();
        lsw_memory_exit();
        lsw_syscall_exit();
        return ret;
    }
    
    /* Initialize device interface */
    ret = lsw_device_init();
    if (ret != 0) {
        lsw_err("Failed to initialize device interface: %d", ret);
        return ret;
    }
    
    lsw_module_state.initialized = true;
    
    /* Increment module reference count to prevent auto-unload */
    if (module_persistent) {
        if (try_module_get(THIS_MODULE)) {
            atomic_set(&module_refcount_held, 1);
            lsw_info("Module persistence enabled - will remain loaded");
        } else {
            lsw_warn("Failed to hold module reference - hot-swap may not work correctly");
        }
    }
    
    lsw_info("LSW kernel module initialized successfully");
    lsw_info("Ready to execute Windows PE files on Linux");
    lsw_info("Device: %s", LSW_DEVICE_PATH);
    lsw_info("Hot-swap mode: %s", module_persistent ? "persistent" : "enabled");
    
    return 0;
}

/**
 * lsw_exit - Cleanup LSW kernel module
 * 
 * Called when module is unloaded from kernel
 */
static void __exit lsw_exit(void)
{
    lsw_info("Shutting down LSW kernel module");
    
    /* Mark module as shutting down to prevent new operations */
    lsw_module_state.initialized = false;
    
    /* Wait for any in-flight operations to complete */
    if (lsw_module_state.pe_process_count > 0) {
        lsw_warn("Warning: %u PE processes still active during shutdown - waiting...",
                 lsw_module_state.pe_process_count);
        /* Give processes a moment to finish - don't force kill */
        msleep(100);
    }
    
    /* Release module reference if it was held */
    if (atomic_read(&module_refcount_held) > 0) {
        module_put(THIS_MODULE);
        atomic_set(&module_refcount_held, 0);
        lsw_info("Module reference released - hot-swap ready");
    }
    
    /* Cleanup device interface first - stops new requests */
    lsw_device_exit();
    
    /* Cleanup environment/system info */
    lsw_env_cleanup();
    
    /* Cleanup console I/O */
    lsw_console_cleanup();
    
    /* Cleanup process/thread management */
    lsw_process_exit();
    
    /* Cleanup DLL loading */
    lsw_dll_exit();
    
    /* Cleanup synchronization */
    lsw_sync_exit();
    
    /* Cleanup file I/O */
    lsw_file_exit();
    
    /* Cleanup memory management */
    lsw_memory_exit();
    
    /* Cleanup syscall system */
    lsw_syscall_exit();
    
    lsw_module_state.syscall_hooks_active = false;
    
    lsw_info("LSW kernel module unloaded - hot-swap complete");
}

module_init(lsw_init);
module_exit(lsw_exit);
