/*
 * LSW (Linux Subsystem for Windows) - Userspace Kernel Interface
 * Copyright (c) 2025 BarrerSoftware  
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Userspace library for communicating with LSW kernel module
 */

#ifndef LSW_KERNEL_CLIENT_H
#define LSW_KERNEL_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* Device path */
#define LSW_DEVICE_PATH "/dev/lsw"

/* ioctl magic number */
#define LSW_IOCTL_MAGIC 'L'

/* PE Process Registration Info */
struct lsw_pe_info {
    uint64_t base_address;      /* Base address where PE is loaded */
    uint64_t entry_point;       /* Entry point RVA */
    uint32_t image_size;        /* Size of loaded image */
    uint32_t pid;               /* Process ID */
    uint8_t  is_64bit;          /* 1 = PE32+, 0 = PE32 */
    uint8_t  reserved[3];       /* Padding */
    char     executable_path[256]; /* Path to .exe file */
};

/* ioctl commands */
#define LSW_IOCTL_REGISTER_PE   _IOW(LSW_IOCTL_MAGIC, 1, struct lsw_pe_info)
#define LSW_IOCTL_UNREGISTER_PE _IOW(LSW_IOCTL_MAGIC, 2, uint32_t)
#define LSW_IOCTL_GET_STATUS    _IOR(LSW_IOCTL_MAGIC, 3, uint32_t)
#define LSW_IOCTL_EXECUTE_PE    _IOW(LSW_IOCTL_MAGIC, 4, uint32_t)

/**
 * Initialize connection to LSW kernel module
 * Returns: file descriptor on success, -1 on error
 */
int lsw_kernel_open(void);

/**
 * Close connection to LSW kernel module
 */
void lsw_kernel_close(int fd);

/**
 * Register a PE process with the kernel
 * Returns: 0 on success, -1 on error
 */
int lsw_kernel_register_pe(int fd, const struct lsw_pe_info *info);

/**
 * Unregister a PE process from the kernel
 * Returns: 0 on success, -1 on error
 */
int lsw_kernel_unregister_pe(int fd, pid_t pid);

/**
 * Get kernel module status (number of registered PE processes)
 * Returns: number of processes on success, -1 on error
 */
int lsw_kernel_get_status(int fd);

/**
 * Execute a registered PE process
 * Returns: 0 on success, -1 on error
 */
int lsw_kernel_execute_pe(int fd, pid_t pid);

#endif /* LSW_KERNEL_CLIENT_H */
