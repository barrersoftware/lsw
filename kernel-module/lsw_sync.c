/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Synchronization Primitives Implementation
 * Uses Linux kernel wait queues for native performance
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_sync.h"

/* Global sync object list */
static LIST_HEAD(lsw_sync_list);
static DEFINE_MUTEX(lsw_sync_mutex);
static __u64 next_sync_handle = 0x2000;  /* Start sync handles at 0x2000 */

/* Statistics */
static atomic_t lsw_sync_objects = ATOMIC_INIT(0);

/**
 * lsw_sync_create_event - Create an event object
 */
__u64 lsw_sync_create_event(__u32 pid, bool manual_reset, bool initial_state)
{
    struct lsw_sync_object *obj;
    __u64 handle;
    
    obj = kmalloc(sizeof(*obj), GFP_KERNEL);
    if (!obj) {
        lsw_err("Failed to allocate sync object");
        return 0;
    }
    
    /* Assign handle */
    mutex_lock(&lsw_sync_mutex);
    handle = next_sync_handle++;
    mutex_unlock(&lsw_sync_mutex);
    
    /* Initialize event */
    obj->handle = handle;
    obj->type = LSW_SYNC_EVENT;
    obj->pid = pid;
    init_waitqueue_head(&obj->wait_queue);
    atomic_set(&obj->signaled, initial_state ? 1 : 0);
    snprintf(obj->name, sizeof(obj->name), "event_%llx", handle);
    
    /* Add to list */
    mutex_lock(&lsw_sync_mutex);
    list_add(&obj->list, &lsw_sync_list);
    mutex_unlock(&lsw_sync_mutex);
    
    atomic_inc(&lsw_sync_objects);
    
    lsw_info("Created event: PID=%u, handle=0x%llx, manual=%d, signaled=%d",
             pid, handle, manual_reset, initial_state);
    
    return handle;
}

/**
 * lsw_sync_create_mutex - Create a mutex object
 */
__u64 lsw_sync_create_mutex(__u32 pid, bool initial_owner)
{
    struct lsw_sync_object *obj;
    __u64 handle;
    
    obj = kmalloc(sizeof(*obj), GFP_KERNEL);
    if (!obj) {
        lsw_err("Failed to allocate sync object");
        return 0;
    }
    
    /* Assign handle */
    mutex_lock(&lsw_sync_mutex);
    handle = next_sync_handle++;
    mutex_unlock(&lsw_sync_mutex);
    
    /* Initialize mutex */
    obj->handle = handle;
    obj->type = LSW_SYNC_MUTEX;
    obj->pid = pid;
    init_waitqueue_head(&obj->wait_queue);
    atomic_set(&obj->signaled, initial_owner ? 0 : 1);
    snprintf(obj->name, sizeof(obj->name), "mutex_%llx", handle);
    
    /* Add to list */
    mutex_lock(&lsw_sync_mutex);
    list_add(&obj->list, &lsw_sync_list);
    mutex_unlock(&lsw_sync_mutex);
    
    atomic_inc(&lsw_sync_objects);
    
    lsw_info("Created mutex: PID=%u, handle=0x%llx, owned=%d",
             pid, handle, initial_owner);
    
    return handle;
}

/**
 * lsw_sync_wait - Wait for sync object
 */
int lsw_sync_wait(__u64 handle, __u32 timeout_ms)
{
    struct lsw_sync_object *obj;
    int ret = -EBADF;
    long timeout_jiffies;
    
    mutex_lock(&lsw_sync_mutex);
    
    /* Find sync object */
    list_for_each_entry(obj, &lsw_sync_list, list) {
        if (obj->handle == handle) {
            mutex_unlock(&lsw_sync_mutex);
            
            /* Calculate timeout */
            if (timeout_ms == 0) {
                timeout_jiffies = MAX_SCHEDULE_TIMEOUT;  /* Infinite */
            } else {
                timeout_jiffies = msecs_to_jiffies(timeout_ms);
            }
            
            lsw_debug("Waiting on object 0x%llx (timeout=%u ms)", handle, timeout_ms);
            
            /* Wait for signal */
            ret = wait_event_interruptible_timeout(
                obj->wait_queue,
                atomic_read(&obj->signaled) != 0,
                timeout_jiffies
            );
            
            if (ret == 0) {
                lsw_debug("Wait timed out on 0x%llx", handle);
                return -ETIMEDOUT;
            } else if (ret < 0) {
                lsw_warn("Wait interrupted on 0x%llx: %d", handle, ret);
                return ret;
            }
            
            /* Object is signaled */
            lsw_debug("Object 0x%llx signaled", handle);
            
            /* For mutex, acquire it (set to non-signaled) */
            if (obj->type == LSW_SYNC_MUTEX) {
                atomic_set(&obj->signaled, 0);
            }
            
            return 0;
        }
    }
    
    mutex_unlock(&lsw_sync_mutex);
    
    lsw_warn("Sync object not found: 0x%llx", handle);
    return ret;
}

/**
 * lsw_sync_signal - Signal a sync object
 */
int lsw_sync_signal(__u64 handle)
{
    struct lsw_sync_object *obj;
    int found = 0;
    
    mutex_lock(&lsw_sync_mutex);
    
    list_for_each_entry(obj, &lsw_sync_list, list) {
        if (obj->handle == handle) {
            found = 1;
            
            lsw_debug("Signaling object 0x%llx", handle);
            
            /* Set signaled state */
            atomic_set(&obj->signaled, 1);
            
            /* Wake up waiters */
            wake_up_interruptible(&obj->wait_queue);
            
            break;
        }
    }
    
    mutex_unlock(&lsw_sync_mutex);
    
    if (!found) {
        lsw_warn("Sync object not found: 0x%llx", handle);
        return -EBADF;
    }
    
    return 0;
}

/**
 * lsw_sync_close - Close sync object
 */
int lsw_sync_close(__u64 handle)
{
    struct lsw_sync_object *obj, *tmp;
    int found = 0;
    
    mutex_lock(&lsw_sync_mutex);
    
    list_for_each_entry_safe(obj, tmp, &lsw_sync_list, list) {
        if (obj->handle == handle) {
            found = 1;
            
            lsw_info("Closing sync object: handle=0x%llx, type=%u",
                     handle, obj->type);
            
            /* Wake any waiters */
            wake_up_interruptible_all(&obj->wait_queue);
            
            atomic_dec(&lsw_sync_objects);
            
            list_del(&obj->list);
            kfree(obj);
            
            break;
        }
    }
    
    mutex_unlock(&lsw_sync_mutex);
    
    if (!found) {
        lsw_warn("Sync object not found: 0x%llx", handle);
        return -EBADF;
    }
    
    return 0;
}

/**
 * lsw_sync_cleanup_process - Cleanup all sync objects for a process
 */
void lsw_sync_cleanup_process(__u32 pid)
{
    struct lsw_sync_object *obj, *tmp;
    int closed_count = 0;
    
    mutex_lock(&lsw_sync_mutex);
    
    list_for_each_entry_safe(obj, tmp, &lsw_sync_list, list) {
        if (obj->pid == pid) {
            lsw_debug("Cleaning up sync object: handle=0x%llx", obj->handle);
            
            wake_up_interruptible_all(&obj->wait_queue);
            
            atomic_dec(&lsw_sync_objects);
            closed_count++;
            
            list_del(&obj->list);
            kfree(obj);
        }
    }
    
    mutex_unlock(&lsw_sync_mutex);
    
    if (closed_count > 0) {
        lsw_info("Cleaned up %d sync objects for PID %u", closed_count, pid);
    }
}

/**
 * lsw_sync_init - Initialize sync system
 */
int lsw_sync_init(void)
{
    lsw_info("Synchronization system initialized");
    lsw_info("Using Linux kernel wait queues for native performance");
    return 0;
}

/**
 * lsw_sync_exit - Cleanup sync system
 */
void lsw_sync_exit(void)
{
    struct lsw_sync_object *obj, *tmp;
    int leaked_count = 0;
    
    mutex_lock(&lsw_sync_mutex);
    
    list_for_each_entry_safe(obj, tmp, &lsw_sync_list, list) {
        lsw_warn("Sync object leak: PID=%u, handle=0x%llx, type=%u",
                 obj->pid, obj->handle, obj->type);
        
        wake_up_interruptible_all(&obj->wait_queue);
        leaked_count++;
        
        list_del(&obj->list);
        kfree(obj);
    }
    
    mutex_unlock(&lsw_sync_mutex);
    
    if (leaked_count > 0) {
        lsw_warn("Closed %d leaked sync objects during cleanup", leaked_count);
    }
    
    lsw_info("Synchronization system cleaned up");
}
