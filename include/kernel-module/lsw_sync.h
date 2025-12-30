/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Synchronization Primitives for Win32
 * Translates Win32 events/mutexes/semaphores to Linux futex
 */

#ifndef LSW_SYNC_H
#define LSW_SYNC_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/wait.h>

/* Sync object types */
#define LSW_SYNC_EVENT      1
#define LSW_SYNC_MUTEX      2
#define LSW_SYNC_SEMAPHORE  3

/* Sync object entry */
struct lsw_sync_object {
    struct list_head list;         /* List linkage */
    __u64 handle;                  /* Win32 handle */
    __u32 type;                    /* Object type */
    __u32 pid;                     /* Process ID that owns this */
    wait_queue_head_t wait_queue;  /* Linux wait queue */
    atomic_t signaled;             /* Signal state */
    atomic_t count;                /* For semaphores */
    __u32 max_count;               /* Max count for semaphores */
    char name[64];                 /* Object name */
};

/**
 * lsw_sync_create_event - Create an event object
 * 
 * @pid: Process ID
 * @manual_reset: True for manual reset, false for auto-reset
 * @initial_state: Initial signaled state
 * 
 * Returns: Event handle or 0 on error
 */
__u64 lsw_sync_create_event(__u32 pid, bool manual_reset, bool initial_state);

/**
 * lsw_sync_create_mutex - Create a mutex object
 * 
 * @pid: Process ID
 * @initial_owner: True if creating process owns the mutex
 * 
 * Returns: Mutex handle or 0 on error
 */
__u64 lsw_sync_create_mutex(__u32 pid, bool initial_owner);

/**
 * lsw_sync_wait - Wait for sync object to be signaled
 * 
 * @handle: Sync object handle
 * @timeout_ms: Timeout in milliseconds (0 = infinite)
 * 
 * Returns: 0 on success, -ETIMEDOUT on timeout, negative on error
 */
int lsw_sync_wait(__u64 handle, __u32 timeout_ms);

/**
 * lsw_sync_signal - Signal a sync object
 * 
 * @handle: Sync object handle
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_sync_signal(__u64 handle);

/**
 * lsw_sync_close - Close sync object handle
 * 
 * @handle: Handle to close
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_sync_close(__u64 handle);

/**
 * lsw_sync_cleanup_process - Close all sync objects for a process
 * 
 * @pid: Process ID to cleanup
 */
void lsw_sync_cleanup_process(__u32 pid);

/* Initialize/cleanup sync system */
int lsw_sync_init(void);
void lsw_sync_exit(void);

#endif /* LSW_SYNC_H */
