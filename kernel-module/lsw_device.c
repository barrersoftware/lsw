/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Open Source License (BOSL) v1.1
 * 
 * Device Interface Implementation
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_device.h"
#include "../include/kernel-module/lsw_syscall.h"

/* Device data */
static dev_t lsw_dev_number;
static struct cdev lsw_cdev;
static struct class *lsw_class;
static struct device *lsw_device;

/* Track registered PE processes */
#define LSW_MAX_PE_PROCESSES 256
static struct lsw_pe_info pe_processes[LSW_MAX_PE_PROCESSES];
static int pe_process_count = 0;
static DEFINE_MUTEX(pe_list_mutex);

/**
 * lsw_device_open - Called when userspace opens /dev/lsw
 */
static int lsw_device_open(struct inode *inode, struct file *file)
{
    lsw_debug("Device opened");
    return 0;
}

/**
 * lsw_device_release - Called when userspace closes /dev/lsw
 */
static int lsw_device_release(struct inode *inode, struct file *file)
{
    lsw_debug("Device closed");
    return 0;
}

/**
 * lsw_register_pe - Register a PE process with the kernel
 */
static long lsw_register_pe(struct lsw_pe_info __user *user_info)
{
    struct lsw_pe_info info;
    int slot = -1;
    int i;
    
    /* Copy from userspace */
    if (copy_from_user(&info, user_info, sizeof(info))) {
        lsw_err("Failed to copy PE info from userspace");
        return -EFAULT;
    }
    
    mutex_lock(&pe_list_mutex);
    
    /* Find empty slot */
    for (i = 0; i < LSW_MAX_PE_PROCESSES; i++) {
        if (pe_processes[i].pid == 0) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        mutex_unlock(&pe_list_mutex);
        lsw_err("PE process table full");
        return -ENOMEM;
    }
    
    /* Register PE */
    memcpy(&pe_processes[slot], &info, sizeof(info));
    pe_process_count++;
    
    mutex_unlock(&pe_list_mutex);
    
    lsw_info("Registered PE process: PID=%u, base=0x%llx, entry=0x%llx, %s-bit",
             info.pid, info.base_address, info.entry_point,
             info.is_64bit ? "64" : "32");
    lsw_info("  Executable: %s", info.executable_path);
    
    return 0;
}

/**
 * lsw_unregister_pe - Unregister a PE process
 */
static long lsw_unregister_pe(pid_t pid)
{
    int i;
    
    mutex_lock(&pe_list_mutex);
    
    for (i = 0; i < LSW_MAX_PE_PROCESSES; i++) {
        if (pe_processes[i].pid == pid) {
            memset(&pe_processes[i], 0, sizeof(struct lsw_pe_info));
            pe_process_count--;
            mutex_unlock(&pe_list_mutex);
            
            lsw_info("Unregistered PE process: PID=%u", pid);
            return 0;
        }
    }
    
    mutex_unlock(&pe_list_mutex);
    
    lsw_warn("PE process not found: PID=%u", pid);
    return -ESRCH;
}

/**
 * lsw_device_ioctl - Handle ioctl commands
 */
static long lsw_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct lsw_syscall_request syscall_req;
    
    switch (cmd) {
    case LSW_IOCTL_REGISTER_PE:
        return lsw_register_pe((struct lsw_pe_info __user *)arg);
        
    case LSW_IOCTL_UNREGISTER_PE:
        return lsw_unregister_pe((pid_t)arg);
        
    case LSW_IOCTL_GET_STATUS:
        if (copy_to_user((int __user *)arg, &pe_process_count, sizeof(int)))
            return -EFAULT;
        return 0;
        
    case LSW_IOCTL_SYSCALL:
        /* Copy syscall request from userspace */
        if (copy_from_user(&syscall_req, (void __user *)arg, sizeof(syscall_req)))
            return -EFAULT;
        
        /* Handle the syscall */
        lsw_handle_syscall(&syscall_req);
        
        /* Copy result back to userspace */
        if (copy_to_user((void __user *)arg, &syscall_req, sizeof(syscall_req)))
            return -EFAULT;
        
        return 0;
        
    default:
        lsw_warn("Unknown ioctl command: 0x%x", cmd);
        return -EINVAL;
    }
}

/* File operations */
static struct file_operations lsw_fops = {
    .owner = THIS_MODULE,
    .open = lsw_device_open,
    .release = lsw_device_release,
    .unlocked_ioctl = lsw_device_ioctl,
};

/**
 * lsw_device_init - Initialize device interface
 */
int lsw_device_init(void)
{
    int ret;
    
    /* Allocate device number */
    ret = alloc_chrdev_region(&lsw_dev_number, 0, 1, LSW_DEVICE_NAME);
    if (ret < 0) {
        lsw_err("Failed to allocate device number: %d", ret);
        return ret;
    }
    
    lsw_info("Device number allocated: %d:%d", MAJOR(lsw_dev_number), MINOR(lsw_dev_number));
    
    /* Initialize cdev */
    cdev_init(&lsw_cdev, &lsw_fops);
    lsw_cdev.owner = THIS_MODULE;
    
    /* Add cdev */
    ret = cdev_add(&lsw_cdev, lsw_dev_number, 1);
    if (ret < 0) {
        lsw_err("Failed to add cdev: %d", ret);
        unregister_chrdev_region(lsw_dev_number, 1);
        return ret;
    }
    
    /* Create device class */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    lsw_class = class_create(LSW_DEVICE_NAME);
#else
    lsw_class = class_create(THIS_MODULE, LSW_DEVICE_NAME);
#endif
    if (IS_ERR(lsw_class)) {
        ret = PTR_ERR(lsw_class);
        lsw_err("Failed to create device class: %d", ret);
        cdev_del(&lsw_cdev);
        unregister_chrdev_region(lsw_dev_number, 1);
        return ret;
    }
    
    /* Create device */
    lsw_device = device_create(lsw_class, NULL, lsw_dev_number, NULL, LSW_DEVICE_NAME);
    if (IS_ERR(lsw_device)) {
        ret = PTR_ERR(lsw_device);
        lsw_err("Failed to create device: %d", ret);
        class_destroy(lsw_class);
        cdev_del(&lsw_cdev);
        unregister_chrdev_region(lsw_dev_number, 1);
        return ret;
    }
    
    lsw_info("Device created: %s", LSW_DEVICE_PATH);
    lsw_info("LSW device interface initialized");
    
    return 0;
}

/**
 * lsw_device_exit - Cleanup device interface
 */
void lsw_device_exit(void)
{
    /* Remove device */
    if (lsw_device) {
        device_destroy(lsw_class, lsw_dev_number);
    }
    
    /* Remove class */
    if (lsw_class) {
        class_destroy(lsw_class);
    }
    
    /* Remove cdev */
    cdev_del(&lsw_cdev);
    
    /* Free device number */
    unregister_chrdev_region(lsw_dev_number, 1);
    
    lsw_info("LSW device interface cleaned up");
}
