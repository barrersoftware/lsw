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
    
    // Special case for Windows pseudo-handles (stdout/stderr)
    // STD_OUTPUT_HANDLE = 0xfffffff5 (-11 as signed)
    // STD_ERROR_HANDLE = 0xfffffff4 (-12 as signed)
    // Only handle NEGATIVE values as Windows pseudo-handles
    if ((int64_t)handle < 0) {
        // This is a Windows pseudo-handle, write to kernel log
        char log_buffer[512];
        size_t log_size = size > sizeof(log_buffer) - 1 ? sizeof(log_buffer) - 1 : size;
        memcpy(log_buffer, buffer, log_size);
        log_buffer[log_size] = '\0';
        
        lsw_info("WIN32 STDOUT: %s", log_buffer);
        
        if (bytes_written) {
            *bytes_written = size;
        }
        return 0;
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

/**
 * lsw_file_get_size - Get file size from handle
 */
int lsw_file_get_size(__u64 handle, __u64 *size_out)
{
    struct lsw_file_handle *fh;
    struct kstat stat;
    int ret;
    int found = 0;
    
    if (!size_out) {
        return -EINVAL;
    }
    
    mutex_lock(&lsw_file_mutex);
    
    /* Find file handle */
    list_for_each_entry(fh, &lsw_file_list, list) {
        if (fh->handle == handle) {
            found = 1;
            
            /* Get file stats */
            ret = vfs_getattr(&fh->linux_file->f_path, &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);
            if (ret != 0) {
                lsw_err("vfs_getattr failed for handle 0x%llx: %d", handle, ret);
                mutex_unlock(&lsw_file_mutex);
                return ret;
            }
            
            *size_out = stat.size;
            lsw_info("File handle 0x%llx size: %llu bytes", handle, stat.size);
            
            mutex_unlock(&lsw_file_mutex);
            return 0;
        }
    }
    
    mutex_unlock(&lsw_file_mutex);
    
    if (!found) {
        lsw_err("Invalid file handle: 0x%llx", handle);
        return -EBADF;
    }
    
    return 0;
}

/**
 * lsw_file_seek - Seek to position in file
 */
int lsw_file_seek(__u64 handle, __s64 offset, __u32 whence, __u64 *new_pos_out)
{
    struct lsw_file_handle *fh;
    loff_t new_pos;
    int linux_whence;
    int found = 0;
    
    /* Map Windows to Linux whence */
    switch (whence) {
        case 0: linux_whence = SEEK_SET; break;  /* FILE_BEGIN */
        case 1: linux_whence = SEEK_CUR; break;  /* FILE_CURRENT */
        case 2: linux_whence = SEEK_END; break;  /* FILE_END */
        default:
            lsw_err("Invalid whence: %u", whence);
            return -EINVAL;
    }
    
    mutex_lock(&lsw_file_mutex);
    
    /* Find file handle */
    list_for_each_entry(fh, &lsw_file_list, list) {
        if (fh->handle == handle) {
            found = 1;
            
            /* Seek */
            new_pos = vfs_llseek(fh->linux_file, offset, linux_whence);
            if (new_pos < 0) {
                lsw_err("vfs_llseek failed for handle 0x%llx: %lld", handle, new_pos);
                mutex_unlock(&lsw_file_mutex);
                return (int)new_pos;
            }
            
            /* Update our tracked position */
            fh->position = new_pos;
            
            if (new_pos_out) {
                *new_pos_out = (__u64)new_pos;
            }
            
            lsw_info("File handle 0x%llx seeked to: %lld", handle, new_pos);
            
            mutex_unlock(&lsw_file_mutex);
            return 0;
        }
    }
    
    mutex_unlock(&lsw_file_mutex);
    
    if (!found) {
        lsw_err("Invalid file handle: 0x%llx", handle);
        return -EBADF;
    }
    
    return 0;
}
