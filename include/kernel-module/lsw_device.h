/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Open Source License (BOSL) v1.1
 * 
 * Device Interface - Communication between userspace and kernel
 */

#ifndef LSW_DEVICE_H
#define LSW_DEVICE_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* Device name */
#define LSW_DEVICE_NAME "lsw"
#define LSW_DEVICE_PATH "/dev/lsw"

/* ioctl magic number */
#define LSW_IOCTL_MAGIC 'L'

/* PE Process Registration */
struct lsw_pe_info {
    __u64 base_address;      /* Base address where PE is loaded */
    __u64 entry_point;       /* Entry point RVA */
    __u32 image_size;        /* Size of loaded image */
    __u32 pid;               /* Process ID */
    __u8  is_64bit;          /* 1 = PE32+, 0 = PE32 */
    __u8  reserved[3];       /* Padding */
    char  executable_path[256]; /* Path to .exe file */
};

/* ioctl commands */
#define LSW_IOCTL_REGISTER_PE   _IOW(LSW_IOCTL_MAGIC, 1, struct lsw_pe_info)
#define LSW_IOCTL_UNREGISTER_PE _IOW(LSW_IOCTL_MAGIC, 2, __u32)
#define LSW_IOCTL_GET_STATUS    _IOR(LSW_IOCTL_MAGIC, 3, __u32)
#define LSW_IOCTL_SYSCALL       _IOWR(LSW_IOCTL_MAGIC, 4, struct lsw_syscall_request)

/* Device functions */
int lsw_device_init(void);
void lsw_device_exit(void);

#endif /* LSW_DEVICE_H */
