/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * File I/O Management Implementation
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_file.h"

/* Global file handle list */
static LIST_HEAD(lsw_file_list);
static DEFINE_MUTEX(lsw_file_mutex);
static __u64 next_handle = 0x1000;  /* Start handles at 0x1000 */

/* Statistics */
static atomic_t lsw_open_files = ATOMIC_INIT(0);

/**
 * lsw_file_open - Open or create a file
 */
__u64 lsw_file_open(__u32 pid, const char *path, __u32 access,
                    __u32 share, __u32 disposition)
{
    struct lsw_file_handle *fh;
    struct file *linux_file;
    int flags = 0;
    __u64 handle;
    
    /* Translate Win32 access to Linux flags */
    if (access & LSW_GENERIC_READ) {
        if (access & LSW_GENERIC_WRITE) {
            flags = O_RDWR;
        } else {
            flags = O_RDONLY;
        }
    } else if (access & LSW_GENERIC_WRITE) {
        flags = O_WRONLY;
    } else {
        flags = O_RDONLY;  /* Default */
    }
    
    /* Translate creation disposition */
    switch (disposition) {
    case LSW_CREATE_NEW:
        flags |= O_CREAT | O_EXCL;
        break;
    case LSW_CREATE_ALWAYS:
        flags |= O_CREAT | O_TRUNC;
        break;
    case LSW_OPEN_EXISTING:
        /* No additional flags */
        break;
    case LSW_OPEN_ALWAYS:
        flags |= O_CREAT;
        break;
    case LSW_TRUNCATE_EXISTING:
        flags |= O_TRUNC;
        break;
    }
    
    /* Open the file using Linux kernel API */
    linux_file = filp_open(path, flags, 0644);
    if (IS_ERR(linux_file)) {
        lsw_err("Failed to open file '%s': %ld", path, PTR_ERR(linux_file));
        return 0;
    }
    
    /* Allocate file handle structure */
    fh = kmalloc(sizeof(*fh), GFP_KERNEL);
    if (!fh) {
        filp_close(linux_file, NULL);
        lsw_err("Failed to allocate file handle structure");
        return 0;
    }
    
    /* Assign handle number */
    mutex_lock(&lsw_file_mutex);
    handle = next_handle++;
    mutex_unlock(&lsw_file_mutex);
    
    /* Fill in file handle */
    fh->handle = handle;
    fh->pid = pid;
    fh->linux_file = linux_file;
    fh->position = 0;
    fh->access = access;
    fh->share = share;
    strncpy(fh->path, path, sizeof(fh->path) - 1);
    fh->path[sizeof(fh->path) - 1] = '\0';
    
    /* Add to global list */
    mutex_lock(&lsw_file_mutex);
    list_add(&fh->list, &lsw_file_list);
    mutex_unlock(&lsw_file_mutex);
    
    atomic_inc(&lsw_open_files);
    
    lsw_info("Opened file: PID=%u, handle=0x%llx, path='%s', flags=0x%x",
             pid, handle, path, flags);
    
    return handle;
}

/**
 * lsw_file_read - Read from a file
 */
int lsw_file_read(__u64 handle, void *buffer, __u64 size, __u64 *bytes_read)
{
    struct lsw_file_handle *fh;
    loff_t pos;
    ssize_t ret;
    int found = 0;
    
    if (!buffer || size == 0) {
        return -EINVAL;
    }
    
    mutex_lock(&lsw_file_mutex);
    
    /* Find file handle */
    list_for_each_entry(fh, &lsw_file_list, list) {
        if (fh->handle == handle) {
            found = 1;
            pos = fh->position;
            
            /* Read from file */
            ret = kernel_read(fh->linux_file, buffer, size, &pos);
            
            if (ret < 0) {
                lsw_err("Read failed for handle 0x%llx: %ld", handle, ret);
                mutex_unlock(&lsw_file_mutex);
                return (int)ret;
            }
            
            /* Update position */
            fh->position = pos;
            
            if (bytes_read) {
                *bytes_read = ret;
            }
            
            lsw_debug("Read %ld bytes from handle 0x%llx (pos=%lld)",
                     ret, handle, fh->position);
            
            mutex_unlock(&lsw_file_mutex);
            return 0;
        }
    }
    
    mutex_unlock(&lsw_file_mutex);
    
    if (!found) {
        lsw_warn("File handle not found: 0x%llx", handle);
        return -EBADF;
    }
    
    return 0;
}

/**
 * lsw_file_write - Write to a file
 */
int lsw_file_write(__u64 handle, const void *buffer, __u64 size, __u64 *bytes_written)
{
    struct lsw_file_handle *fh;
    loff_t pos;
    ssize_t ret;
    int found = 0;
    
    if (!buffer || size == 0) {
        return -EINVAL;
    }
    
    mutex_lock(&lsw_file_mutex);
    
    /* Find file handle */
    list_for_each_entry(fh, &lsw_file_list, list) {
        if (fh->handle == handle) {
            found = 1;
            pos = fh->position;
            
            /* Write to file */
            ret = kernel_write(fh->linux_file, buffer, size, &pos);
            
            if (ret < 0) {
                lsw_err("Write failed for handle 0x%llx: %ld", handle, ret);
                mutex_unlock(&lsw_file_mutex);
                return (int)ret;
            }
            
            /* Update position */
            fh->position = pos;
            
            if (bytes_written) {
                *bytes_written = ret;
            }
            
            lsw_debug("Wrote %ld bytes to handle 0x%llx (pos=%lld)",
                     ret, handle, fh->position);
            
            mutex_unlock(&lsw_file_mutex);
            return 0;
        }
    }
    
    mutex_unlock(&lsw_file_mutex);
    
    if (!found) {
        lsw_warn("File handle not found: 0x%llx", handle);
        return -EBADF;
    }
    
    return 0;
}

/**
 * lsw_file_close - Close a file handle
 */
int lsw_file_close(__u64 handle)
{
    struct lsw_file_handle *fh, *tmp;
    int found = 0;
    
    mutex_lock(&lsw_file_mutex);
    
    list_for_each_entry_safe(fh, tmp, &lsw_file_list, list) {
        if (fh->handle == handle) {
            found = 1;
            
            lsw_info("Closing file: handle=0x%llx, path='%s'",
                     handle, fh->path);
            
            /* Close Linux file */
            if (fh->linux_file) {
                filp_close(fh->linux_file, NULL);
            }
            
            atomic_dec(&lsw_open_files);
            
            /* Remove from list */
            list_del(&fh->list);
            kfree(fh);
            
            break;
        }
    }
    
    mutex_unlock(&lsw_file_mutex);
    
    if (!found) {
        lsw_warn("File handle not found: 0x%llx", handle);
        return -EBADF;
    }
    
    return 0;
}

/**
 * lsw_file_cleanup_process - Close all files for a process
 */
void lsw_file_cleanup_process(__u32 pid)
{
    struct lsw_file_handle *fh, *tmp;
    int closed_count = 0;
    
    mutex_lock(&lsw_file_mutex);
    
    list_for_each_entry_safe(fh, tmp, &lsw_file_list, list) {
        if (fh->pid == pid) {
            lsw_debug("Cleaning up file: handle=0x%llx, path='%s'",
                     fh->handle, fh->path);
            
            if (fh->linux_file) {
                filp_close(fh->linux_file, NULL);
            }
            
            atomic_dec(&lsw_open_files);
            closed_count++;
            
            list_del(&fh->list);
            kfree(fh);
        }
    }
    
    mutex_unlock(&lsw_file_mutex);
    
    if (closed_count > 0) {
        lsw_info("Cleaned up %d file handles for PID %u", closed_count, pid);
    }
}

/**
 * lsw_file_init - Initialize file I/O system
 */
int lsw_file_init(void)
{
    lsw_info("File I/O system initialized");
    lsw_info("Ready to handle Win32 file operations");
    return 0;
}

/**
 * lsw_file_exit - Cleanup file I/O system
 */
void lsw_file_exit(void)
{
    struct lsw_file_handle *fh, *tmp;
    int leaked_count = 0;
    
    mutex_lock(&lsw_file_mutex);
    
    /* Close any remaining files */
    list_for_each_entry_safe(fh, tmp, &lsw_file_list, list) {
        lsw_warn("File handle leak: PID=%u, handle=0x%llx, path='%s'",
                 fh->pid, fh->handle, fh->path);
        
        if (fh->linux_file) {
            filp_close(fh->linux_file, NULL);
        }
        
        leaked_count++;
        
        list_del(&fh->list);
        kfree(fh);
    }
    
    mutex_unlock(&lsw_file_mutex);
    
    if (leaked_count > 0) {
        lsw_warn("Closed %d leaked file handles during cleanup", leaked_count);
    }
    
    lsw_info("File I/O system cleaned up");
}
