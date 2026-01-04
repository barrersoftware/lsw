/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * 
 * LSW Kernel Module - Windows-on-Linux Integration
 * Reverse WSL - Run Windows executables natively on Linux
 */

#ifndef LSW_KERNEL_H
#define LSW_KERNEL_H

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

/* Kernel version compatibility */
#define LSW_KERNEL_VERSION LINUX_VERSION_CODE

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
#error "LSW requires Linux kernel 5.10 or newer"
#endif

/* Module information */
#define LSW_MODULE_NAME    "lsw"
#define LSW_MODULE_VERSION "0.1.0-alpha"
#define LSW_MODULE_DESC    "Linux Subsystem for Windows - Native PE Execution"
#define LSW_MODULE_AUTHOR  "BarrerSoftware"
#define LSW_MODULE_LICENSE "Proprietary" /* BSL v1.0 */

/* Debug logging */
#define lsw_debug(fmt, ...) \
    pr_debug("[LSW] " fmt "\n", ##__VA_ARGS__)

#define lsw_info(fmt, ...) \
    pr_info("[LSW] " fmt "\n", ##__VA_ARGS__)

#define lsw_warn(fmt, ...) \
    pr_warn("[LSW] " fmt "\n", ##__VA_ARGS__)

#define lsw_err(fmt, ...) \
    pr_err("[LSW] " fmt "\n", ##__VA_ARGS__)

/* LSW kernel module state */
struct lsw_state {
    bool initialized;
    bool syscall_hooks_active;
    unsigned long syscall_table_addr;
    unsigned int pe_process_count;
};

extern struct lsw_state lsw_module_state;

/* Console subsystem */
int lsw_console_init(void);
void lsw_console_cleanup(void);
__u64 lsw_console_GetStdHandle(__u32 std_handle);
int lsw_console_WriteConsole(__u64 handle, const void __user *buffer, __u32 chars_to_write, __u32 __user *chars_written_ptr);
int lsw_console_ReadConsole(__u64 handle, void __user *buffer, __u32 chars_to_read, __u32 __user *chars_read_ptr);

/* Module initialization/cleanup */
int lsw_module_init(void);
void lsw_module_exit(void);

#endif /* LSW_KERNEL_H */
