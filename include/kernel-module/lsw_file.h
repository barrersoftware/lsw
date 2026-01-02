/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * File I/O Management for Win32
 * Translates Win32 file operations to Linux kernel file operations
 */

#ifndef LSW_FILE_H
#define LSW_FILE_H

#include <linux/types.h>
#include <linux/list.h>

/* File handle entry */
struct lsw_file_handle {
    struct list_head list;      /* List linkage */
    __u64 handle;               /* Win32 file handle */
    __u32 pid;                  /* Process ID that owns this */
    struct file *linux_file;    /* Linux kernel file pointer */
    __u64 position;             /* Current file position */
    __u32 access;               /* Access flags */
    __u32 share;                /* Share mode */
    char path[256];             /* File path */
};

/* Win32 access flags */
#define LSW_GENERIC_READ          0x80000000
#define LSW_GENERIC_WRITE         0x40000000
#define LSW_GENERIC_EXECUTE       0x20000000
#define LSW_GENERIC_ALL           0x10000000

/* Win32 share mode */
#define LSW_FILE_SHARE_READ       0x00000001
#define LSW_FILE_SHARE_WRITE      0x00000002
#define LSW_FILE_SHARE_DELETE     0x00000004

/* Win32 creation disposition */
#define LSW_CREATE_NEW            1
#define LSW_CREATE_ALWAYS         2
#define LSW_OPEN_EXISTING         3
#define LSW_OPEN_ALWAYS           4
#define LSW_TRUNCATE_EXISTING     5

/**
 * lsw_file_open - Open or create a file
 * 
 * @pid: Process ID
 * @path: File path
 * @access: Access flags
 * @share: Share mode
 * @disposition: Creation disposition
 * 
 * Returns: File handle or 0 on error
 */
__u64 lsw_file_open(__u32 pid, const char *path, __u32 access,
                    __u32 share, __u32 disposition);

/**
 * lsw_file_read - Read from a file
 * 
 * @handle: File handle
 * @buffer: Output buffer
 * @size: Number of bytes to read
 * @bytes_read: Returns actual bytes read
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_file_read(__u64 handle, void *buffer, __u64 size, __u64 *bytes_read);

/**
 * lsw_file_write - Write to a file
 * 
 * @handle: File handle
 * @buffer: Data to write
 * @size: Number of bytes to write
 * @bytes_written: Returns actual bytes written
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_file_write(__u64 handle, const void *buffer, __u64 size, __u64 *bytes_written);

/**
 * lsw_file_close - Close a file handle
 * 
 * @handle: File handle to close
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_file_close(__u64 handle);

/**
 * lsw_file_get_size - Get file size from handle
 * 
 * @handle: File handle
 * @size_out: Returns file size in bytes
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_file_get_size(__u64 handle, __u64 *size_out);

/**
 * lsw_file_seek - Seek to position in file
 * 
 * @handle: File handle
 * @offset: Offset to seek to
 * @whence: 0=FILE_BEGIN, 1=FILE_CURRENT, 2=FILE_END
 * @new_pos_out: Returns new file position (optional, can be NULL)
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_file_seek(__u64 handle, __s64 offset, __u32 whence, __u64 *new_pos_out);

/**
 * lsw_file_cleanup_process - Close all files for a process
 * 
 * @pid: Process ID to cleanup
 */
void lsw_file_cleanup_process(__u32 pid);

/* Initialize/cleanup file I/O system */
int lsw_file_init(void);
void lsw_file_exit(void);

#endif /* LSW_FILE_H */
