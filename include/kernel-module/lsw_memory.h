/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Memory Management for Win32 PE Processes
 * Translates Win32 VirtualAlloc/VirtualFree to Linux kernel mm
 */

#ifndef LSW_MEMORY_H
#define LSW_MEMORY_H

#include <linux/types.h>
#include <linux/list.h>

/* Memory allocation entry */
struct lsw_memory_region {
    struct list_head list;      /* List linkage */
    __u64 base_address;         /* Virtual base address */
    __u64 size;                 /* Size in bytes */
    __u32 pid;                  /* Process ID that owns this */
    void *kernel_addr;          /* Actual kernel allocation */
    __u32 protect;              /* Protection flags */
    __u32 flags;                /* Allocation flags */
};

/* Win32 memory protection flags */
#define LSW_PAGE_NOACCESS          0x01
#define LSW_PAGE_READONLY          0x02
#define LSW_PAGE_READWRITE         0x04
#define LSW_PAGE_WRITECOPY         0x08
#define LSW_PAGE_EXECUTE           0x10
#define LSW_PAGE_EXECUTE_READ      0x20
#define LSW_PAGE_EXECUTE_READWRITE 0x40
#define LSW_PAGE_EXECUTE_WRITECOPY 0x80

/* Win32 memory allocation types */
#define LSW_MEM_COMMIT             0x1000
#define LSW_MEM_RESERVE            0x2000
#define LSW_MEM_RESET              0x80000
#define LSW_MEM_LARGE_PAGES        0x20000000
#define LSW_MEM_PHYSICAL           0x400000
#define LSW_MEM_TOP_DOWN           0x100000

/* Win32 memory free types */
#define LSW_MEM_DECOMMIT           0x4000
#define LSW_MEM_RELEASE            0x8000

/**
 * lsw_memory_allocate - Allocate virtual memory for PE process
 * 
 * @pid: Process ID
 * @base: Requested base address (0 = let kernel choose)
 * @size: Size in bytes
 * @protect: Memory protection flags
 * @flags: Allocation type flags
 * 
 * Returns: Allocated base address or 0 on error
 */
__u64 lsw_memory_allocate(__u32 pid, __u64 base, __u64 size, 
                          __u32 protect, __u32 flags);

/**
 * lsw_memory_free - Free virtual memory
 * 
 * @pid: Process ID
 * @base: Base address to free
 * @size: Size in bytes (0 = free entire allocation)
 * @free_type: Type of free operation
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_memory_free(__u32 pid, __u64 base, __u64 size, __u32 free_type);

/**
 * lsw_memory_cleanup_process - Free all memory for a process
 * 
 * @pid: Process ID to cleanup
 * 
 * Called when PE process exits
 */
void lsw_memory_cleanup_process(__u32 pid);

/**
 * lsw_memory_read - Read memory from a process
 * 
 * @pid: Process ID to read from
 * @base: Base address to read
 * @buffer: Output buffer
 * @size: Number of bytes to read
 * 
 * Returns: Number of bytes read, or negative on error
 */
int lsw_memory_read(__u32 pid, __u64 base, void *buffer, __u64 size);

/**
 * lsw_memory_protect - Change memory protection flags
 * 
 * @pid: Process ID
 * @base: Base address
 * @size: Size of region
 * @new_protect: New protection flags
 * @old_protect: Returns old protection flags
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_memory_protect(__u32 pid, __u64 base, __u64 size,
                       __u32 new_protect, __u32 *old_protect);

/**
 * lsw_memory_get_info - Get information about allocated memory
 * 
 * @pid: Process ID
 * @count: Returns number of allocations
 * @total_size: Returns total allocated bytes
 */
void lsw_memory_get_info(__u32 pid, __u32 *count, __u64 *total_size);

/* Initialize/cleanup memory management system */
int lsw_memory_init(void);
void lsw_memory_exit(void);

#endif /* LSW_MEMORY_H */
