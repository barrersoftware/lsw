/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Memory Management Implementation
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_memory.h"

/* Global memory allocation list */
static LIST_HEAD(lsw_memory_list);
static DEFINE_MUTEX(lsw_memory_mutex);

/* Statistics */
static atomic_t lsw_allocation_count = ATOMIC_INIT(0);
static atomic64_t lsw_total_allocated = ATOMIC64_INIT(0);

/**
 * lsw_memory_allocate - Allocate virtual memory for PE process
 */
__u64 lsw_memory_allocate(__u32 pid, __u64 base, __u64 size, 
                          __u32 protect, __u32 flags)
{
    struct lsw_memory_region *region;
    void *kernel_addr;
    __u64 allocated_base;
    
    /* Validate size */
    if (size == 0 || size > (1ULL << 32)) {  /* Max 4GB allocation */
        lsw_err("Invalid allocation size: 0x%llx", size);
        return 0;
    }
    
    /* Allocate kernel memory using vmalloc (works for any size) */
    kernel_addr = vmalloc(size);
    if (!kernel_addr) {
        lsw_err("Failed to allocate %llu bytes of kernel memory", size);
        return 0;
    }
    
    /* Zero the memory (Win32 VirtualAlloc behavior) */
    memset(kernel_addr, 0, size);
    
    /* Allocate tracking structure */
    region = kmalloc(sizeof(*region), GFP_KERNEL);
    if (!region) {
        vfree(kernel_addr);
        lsw_err("Failed to allocate memory region structure");
        return 0;
    }
    
    /* Use requested base if provided, otherwise use kernel address as base */
    allocated_base = base ? base : (__u64)(unsigned long)kernel_addr;
    
    /* Fill in region info */
    region->base_address = allocated_base;
    region->size = size;
    region->pid = pid;
    region->kernel_addr = kernel_addr;
    region->protect = protect;
    region->flags = flags;
    
    /* Add to global list */
    mutex_lock(&lsw_memory_mutex);
    list_add(&region->list, &lsw_memory_list);
    mutex_unlock(&lsw_memory_mutex);
    
    /* Update statistics */
    atomic_inc(&lsw_allocation_count);
    atomic64_add(size, &lsw_total_allocated);
    
    lsw_info("Allocated memory: PID=%u, base=0x%llx, size=0x%llx (%llu KB), kernel=%p",
             pid, allocated_base, size, size / 1024, kernel_addr);
    
    return allocated_base;
}

/**
 * lsw_memory_free - Free virtual memory
 */
int lsw_memory_free(__u32 pid, __u64 base, __u64 size, __u32 free_type)
{
    struct lsw_memory_region *region, *tmp;
    int found = 0;
    
    mutex_lock(&lsw_memory_mutex);
    
    list_for_each_entry_safe(region, tmp, &lsw_memory_list, list) {
        /* Match by PID and base address */
        if (region->pid == pid && region->base_address == base) {
            found = 1;
            
            lsw_info("Freeing memory: PID=%u, base=0x%llx, size=0x%llx, type=0x%x",
                     pid, base, region->size, free_type);
            
            /* Free kernel memory */
            if (region->kernel_addr) {
                vfree(region->kernel_addr);
            }
            
            /* Update statistics */
            atomic_dec(&lsw_allocation_count);
            atomic64_sub(region->size, &lsw_total_allocated);
            
            /* Remove from list */
            list_del(&region->list);
            kfree(region);
            
            break;
        }
    }
    
    mutex_unlock(&lsw_memory_mutex);
    
    if (!found) {
        lsw_warn("Memory region not found: PID=%u, base=0x%llx", pid, base);
        return -EINVAL;
    }
    
    return 0;
}

/**
 * lsw_memory_cleanup_process - Free all memory for a process
 */
void lsw_memory_cleanup_process(__u32 pid)
{
    struct lsw_memory_region *region, *tmp;
    int freed_count = 0;
    __u64 freed_size = 0;
    
    mutex_lock(&lsw_memory_mutex);
    
    list_for_each_entry_safe(region, tmp, &lsw_memory_list, list) {
        if (region->pid == pid) {
            lsw_debug("Cleaning up memory: base=0x%llx, size=0x%llx",
                     region->base_address, region->size);
            
            /* Free kernel memory */
            if (region->kernel_addr) {
                vfree(region->kernel_addr);
            }
            
            freed_size += region->size;
            freed_count++;
            
            /* Update statistics */
            atomic_dec(&lsw_allocation_count);
            atomic64_sub(region->size, &lsw_total_allocated);
            
            /* Remove from list */
            list_del(&region->list);
            kfree(region);
        }
    }
    
    mutex_unlock(&lsw_memory_mutex);
    
    if (freed_count > 0) {
        lsw_info("Cleaned up %d allocations (%llu KB) for PID %u",
                 freed_count, freed_size / 1024, pid);
    }
}

/**
 * lsw_memory_get_info - Get memory allocation info
 */
void lsw_memory_get_info(__u32 pid, __u32 *count, __u64 *total_size)
{
    struct lsw_memory_region *region;
    __u32 alloc_count = 0;
    __u64 alloc_size = 0;
    
    mutex_lock(&lsw_memory_mutex);
    
    if (pid == 0) {
        /* Global statistics */
        alloc_count = atomic_read(&lsw_allocation_count);
        alloc_size = atomic64_read(&lsw_total_allocated);
    } else {
        /* Per-process statistics */
        list_for_each_entry(region, &lsw_memory_list, list) {
            if (region->pid == pid) {
                alloc_count++;
                alloc_size += region->size;
            }
        }
    }
    
    mutex_unlock(&lsw_memory_mutex);
    
    if (count)
        *count = alloc_count;
    if (total_size)
        *total_size = alloc_size;
}

/**
 * lsw_memory_read - Read memory from a process
 * 
 * Used by anti-cheat to inspect process memory for injected code
 */
int lsw_memory_read(__u32 pid, __u64 base, void *buffer, __u64 size)
{
    struct lsw_memory_region *region;
    int found = 0;
    __u64 offset;
    __u64 bytes_to_read;
    
    if (!buffer || size == 0) {
        return -EINVAL;
    }
    
    mutex_lock(&lsw_memory_mutex);
    
    /* Find the memory region */
    list_for_each_entry(region, &lsw_memory_list, list) {
        if (region->pid == pid && 
            base >= region->base_address &&
            base < (region->base_address + region->size)) {
            
            found = 1;
            
            /* Calculate offset and size */
            offset = base - region->base_address;
            bytes_to_read = region->size - offset;
            if (bytes_to_read > size) {
                bytes_to_read = size;
            }
            
            /* Copy memory from kernel allocation */
            memcpy(buffer, (char *)region->kernel_addr + offset, bytes_to_read);
            
            lsw_info("Read memory: PID=%u, base=0x%llx, size=%llu bytes",
                     pid, base, bytes_to_read);
            
            mutex_unlock(&lsw_memory_mutex);
            return (int)bytes_to_read;
        }
    }
    
    mutex_unlock(&lsw_memory_mutex);
    
    if (!found) {
        lsw_warn("Memory region not found for read: PID=%u, base=0x%llx",
                 pid, base);
        return -EINVAL;
    }
    
    return 0;
}

/**
 * lsw_memory_protect - Change memory protection flags
 * 
 * Used by anti-cheat to verify memory protection hasn't been tampered with
 */
int lsw_memory_protect(__u32 pid, __u64 base, __u64 size,
                       __u32 new_protect, __u32 *old_protect)
{
    struct lsw_memory_region *region;
    int found = 0;
    
    mutex_lock(&lsw_memory_mutex);
    
    /* Find the memory region */
    list_for_each_entry(region, &lsw_memory_list, list) {
        if (region->pid == pid && region->base_address == base) {
            found = 1;
            
            /* Return old protection flags */
            if (old_protect) {
                *old_protect = region->protect;
            }
            
            /* Set new protection flags */
            region->protect = new_protect;
            
            lsw_info("Changed memory protection: PID=%u, base=0x%llx, old=0x%x, new=0x%x",
                     pid, base, old_protect ? *old_protect : 0, new_protect);
            
            mutex_unlock(&lsw_memory_mutex);
            return 0;
        }
    }
    
    mutex_unlock(&lsw_memory_mutex);
    
    if (!found) {
        lsw_warn("Memory region not found for protect: PID=%u, base=0x%llx",
                 pid, base);
        return -EINVAL;
    }
    
    return 0;
}

/**
 * lsw_memory_init - Initialize memory management
 */
int lsw_memory_init(void)
{
    lsw_info("Memory management system initialized");
    lsw_info("Ready to manage Win32 virtual memory allocations");
    return 0;
}

/**
 * lsw_memory_exit - Cleanup memory management
 */
void lsw_memory_exit(void)
{
    struct lsw_memory_region *region, *tmp;
    int leaked_count = 0;
    __u64 leaked_size = 0;
    
    mutex_lock(&lsw_memory_mutex);
    
    /* Free any remaining allocations */
    list_for_each_entry_safe(region, tmp, &lsw_memory_list, list) {
        lsw_warn("Memory leak: PID=%u, base=0x%llx, size=0x%llx",
                 region->pid, region->base_address, region->size);
        
        if (region->kernel_addr) {
            vfree(region->kernel_addr);
        }
        
        leaked_size += region->size;
        leaked_count++;
        
        list_del(&region->list);
        kfree(region);
    }
    
    mutex_unlock(&lsw_memory_mutex);
    
    if (leaked_count > 0) {
        lsw_warn("Freed %d leaked allocations (%llu KB) during cleanup",
                 leaked_count, leaked_size / 1024);
    }
    
    lsw_info("Memory management system cleaned up");
}
