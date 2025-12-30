/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Win32 to Linux Syscall Translation Implementation
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_syscall.h"
#include "../include/kernel-module/lsw_memory.h"

/* Syscall handler table */
struct lsw_syscall_entry {
    __u32 syscall_number;
    lsw_syscall_handler_t handler;
    const char *name;
};

static struct lsw_syscall_entry syscall_table[] = {
    { LSW_SYSCALL_NtCreateFile, lsw_syscall_NtCreateFile, "NtCreateFile" },
    { LSW_SYSCALL_NtReadFile, lsw_syscall_NtReadFile, "NtReadFile" },
    { LSW_SYSCALL_NtWriteFile, lsw_syscall_NtWriteFile, "NtWriteFile" },
    { LSW_SYSCALL_NtClose, lsw_syscall_NtClose, "NtClose" },
    { LSW_SYSCALL_NtAllocateVirtualMemory, lsw_syscall_NtAllocateVirtualMemory, "NtAllocateVirtualMemory" },
    { LSW_SYSCALL_NtFreeVirtualMemory, lsw_syscall_NtFreeVirtualMemory, "NtFreeVirtualMemory" },
    { 0, NULL, NULL } /* Terminator */
};

/**
 * lsw_handle_syscall - Main syscall dispatcher
 */
long lsw_handle_syscall(struct lsw_syscall_request *req)
{
    int i;
    
    if (!req) {
        return -EINVAL;
    }
    
    /* Find handler for this syscall */
    for (i = 0; syscall_table[i].handler != NULL; i++) {
        if (syscall_table[i].syscall_number == req->syscall_number) {
            lsw_debug("Dispatching syscall: %s (0x%04x)",
                     syscall_table[i].name, req->syscall_number);
            
            /* Call the handler */
            return syscall_table[i].handler(req);
        }
    }
    
    lsw_warn("Unimplemented syscall: 0x%04x", req->syscall_number);
    return -ENOSYS;
}

/**
 * lsw_syscall_NtCreateFile - Translate NtCreateFile to Linux open()
 * 
 * Win32: NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, ...)
 * Linux: int open(const char *pathname, int flags, mode_t mode)
 */
long lsw_syscall_NtCreateFile(struct lsw_syscall_request *req)
{
    /* TODO: Implement full NtCreateFile translation
     * For now, return stub implementation */
    
    lsw_info("NtCreateFile called (STUB)");
    
    /* Stub: just return success with dummy handle */
    req->return_value = 0x1000; /* Fake file handle */
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtReadFile - Translate NtReadFile to Linux read()
 */
long lsw_syscall_NtReadFile(struct lsw_syscall_request *req)
{
    lsw_info("NtReadFile called (STUB)");
    
    req->return_value = 0;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtWriteFile - Translate NtWriteFile to Linux write()
 */
long lsw_syscall_NtWriteFile(struct lsw_syscall_request *req)
{
    lsw_info("NtWriteFile called (STUB)");
    
    req->return_value = 0;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtClose - Translate NtClose to Linux close()
 */
long lsw_syscall_NtClose(struct lsw_syscall_request *req)
{
    lsw_info("NtClose called (STUB)");
    
    req->return_value = 0;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtAllocateVirtualMemory - Translate to Linux vmalloc/mmap
 * 
 * This is critical for PE loader memory allocation
 * 
 * Win32: NTSTATUS NtAllocateVirtualMemory(
 *     HANDLE ProcessHandle,
 *     PVOID *BaseAddress,
 *     ULONG_PTR ZeroBits,
 *     PSIZE_T RegionSize,
 *     ULONG AllocationType,
 *     ULONG Protect
 * )
 */
long lsw_syscall_NtAllocateVirtualMemory(struct lsw_syscall_request *req)
{
    __u64 base_address = req->args[0];
    __u64 region_size = req->args[1];
    __u32 alloc_type = req->args[2];
    __u32 protect = req->args[3];
    __u64 allocated_base;
    
    lsw_info("NtAllocateVirtualMemory: base=0x%llx, size=0x%llx, type=0x%x, protect=0x%x",
             base_address, region_size, alloc_type, protect);
    
    /* Use current PID as process identifier */
    __u32 pid = current->pid;
    
    /* Allocate memory via LSW memory manager */
    allocated_base = lsw_memory_allocate(pid, base_address, region_size, 
                                         protect, alloc_type);
    
    if (allocated_base == 0) {
        lsw_err("Memory allocation failed");
        req->return_value = 0;
        req->error_code = -ENOMEM;
        return -ENOMEM;
    }
    
    /* Return allocated address */
    req->return_value = allocated_base;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtFreeVirtualMemory - Translate to Linux vfree
 * 
 * Win32: NTSTATUS NtFreeVirtualMemory(
 *     HANDLE ProcessHandle,
 *     PVOID *BaseAddress,
 *     PSIZE_T RegionSize,
 *     ULONG FreeType
 * )
 */
long lsw_syscall_NtFreeVirtualMemory(struct lsw_syscall_request *req)
{
    __u64 base_address = req->args[0];
    __u64 region_size = req->args[1];
    __u32 free_type = req->args[2];
    int ret;
    
    lsw_info("NtFreeVirtualMemory: base=0x%llx, size=0x%llx, type=0x%x",
             base_address, region_size, free_type);
    
    /* Use current PID */
    __u32 pid = current->pid;
    
    /* Free memory via LSW memory manager */
    ret = lsw_memory_free(pid, base_address, region_size, free_type);
    
    if (ret != 0) {
        lsw_err("Memory free failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = 0;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_init - Initialize syscall translation system
 */
int lsw_syscall_init(void)
{
    int count = 0;
    int i;
    
    /* Count registered syscalls */
    for (i = 0; syscall_table[i].handler != NULL; i++) {
        count++;
    }
    
    lsw_info("Syscall translation system initialized: %d syscalls registered", count);
    
    return 0;
}

/**
 * lsw_syscall_exit - Cleanup syscall translation system
 */
void lsw_syscall_exit(void)
{
    lsw_info("Syscall translation system cleaned up");
}
