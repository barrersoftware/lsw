/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Process and Thread Management
 * Creates Win32 processes and threads on Linux
 */

#ifndef LSW_PROCESS_H
#define LSW_PROCESS_H

#include <linux/types.h>
#include <linux/list.h>

/* Win32 process entry */
struct lsw_process {
    struct list_head list;      /* List linkage */
    __u32 win32_pid;            /* Win32 process ID */
    __u32 linux_pid;            /* Linux process ID */
    __u64 image_base;           /* Base address of executable */
    __u64 entry_point;          /* Entry point address */
    char executable[256];       /* Path to executable */
    struct task_struct *task;   /* Linux task struct */
};

/* Win32 thread entry */
struct lsw_thread {
    struct list_head list;      /* List linkage */
    __u32 win32_tid;            /* Win32 thread ID */
    __u32 linux_tid;            /* Linux thread ID */
    __u32 win32_pid;            /* Parent process ID */
    __u64 start_address;        /* Thread start address */
    struct task_struct *task;   /* Linux task struct */
};

/**
 * lsw_process_create - Create a Win32 process
 * 
 * @path: Path to executable
 * @win32_pid: Returns Win32 process ID
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_process_create(const char *path, __u32 *win32_pid);

/**
 * lsw_thread_create - Create a Win32 thread
 * 
 * @win32_pid: Process ID to create thread in
 * @start_address: Thread start address
 * @parameter: Thread parameter
 * @win32_tid: Returns Win32 thread ID
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_thread_create(__u32 win32_pid, __u64 start_address, 
                      __u64 parameter, __u32 *win32_tid);

/**
 * lsw_process_terminate - Terminate a process
 * 
 * @win32_pid: Process ID to terminate
 * @exit_code: Exit code
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_process_terminate(__u32 win32_pid, __u32 exit_code);

/**
 * lsw_thread_terminate - Terminate a thread
 * 
 * @win32_tid: Thread ID to terminate
 * @exit_code: Exit code
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_thread_terminate(__u32 win32_tid, __u32 exit_code);

/* Initialize/cleanup process system */
int lsw_process_init(void);
void lsw_process_exit(void);

#endif /* LSW_PROCESS_H */
