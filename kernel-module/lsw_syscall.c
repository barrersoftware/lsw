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
#include <linux/sched/signal.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_syscall.h"
#include "../include/kernel-module/lsw_memory.h"
#include "../include/kernel-module/lsw_file.h"
#include "../include/kernel-module/lsw_sync.h"
#include "../include/kernel-module/lsw_dll.h"

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
    { LSW_SYSCALL_NtReadVirtualMemory, lsw_syscall_NtReadVirtualMemory, "NtReadVirtualMemory" },
    { LSW_SYSCALL_NtProtectVirtualMemory, lsw_syscall_NtProtectVirtualMemory, "NtProtectVirtualMemory" },
    { LSW_SYSCALL_NtQuerySystemInformation, lsw_syscall_NtQuerySystemInformation, "NtQuerySystemInformation" },
    { LSW_SYSCALL_NtCreateEvent, lsw_syscall_NtCreateEvent, "NtCreateEvent" },
    { LSW_SYSCALL_NtCreateMutant, lsw_syscall_NtCreateMutant, "NtCreateMutant" },
    { LSW_SYSCALL_NtWaitForSingleObject, lsw_syscall_NtWaitForSingleObject, "NtWaitForSingleObject" },
    { LSW_SYSCALL_NtSetEvent, lsw_syscall_NtSetEvent, "NtSetEvent" },
    { LSW_SYSCALL_NtReleaseMutant, lsw_syscall_NtReleaseMutant, "NtReleaseMutant" },
    { LSW_SYSCALL_LdrLoadDll, lsw_syscall_LdrLoadDll, "LdrLoadDll" },
    { LSW_SYSCALL_LdrGetProcedureAddress, lsw_syscall_LdrGetProcedureAddress, "LdrGetProcedureAddress" },
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
    const char *path = "/tmp/test.txt";  /* TODO: Get from userspace */
    __u32 access = req->args[0];
    __u32 share = req->args[1];
    __u32 disposition = req->args[2];
    __u64 handle;
    
    lsw_info("NtCreateFile: path='%s', access=0x%x, share=0x%x, disposition=%u",
             path, access, share, disposition);
    
    /* Use current PID */
    __u32 pid = current->pid;
    
    /* Open file via LSW file manager */
    handle = lsw_file_open(pid, path, access, share, disposition);
    
    if (handle == 0) {
        lsw_err("File open failed");
        req->return_value = 0;
        req->error_code = -ENOENT;
        return -ENOENT;
    }
    
    req->return_value = handle;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtReadFile - Translate NtReadFile to Linux read()
 */
long lsw_syscall_NtReadFile(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    __u64 size = req->args[1];
    __u64 bytes_read = 0;
    char temp_buffer[4096];
    int ret;
    
    lsw_info("NtReadFile: handle=0x%llx, size=%llu", handle, size);
    
    /* Limit read size */
    if (size > sizeof(temp_buffer)) {
        size = sizeof(temp_buffer);
    }
    
    /* Read via LSW file manager */
    ret = lsw_file_read(handle, temp_buffer, size, &bytes_read);
    
    if (ret != 0) {
        lsw_err("File read failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    lsw_info("Read %llu bytes from handle 0x%llx", bytes_read, handle);
    
    req->return_value = bytes_read;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtWriteFile - Translate NtWriteFile to Linux write()
 */
long lsw_syscall_NtWriteFile(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    const char *data = "LSW Test Write\n";  /* TODO: Get from userspace */
    __u64 size = strlen(data);
    __u64 bytes_written = 0;
    int ret;
    
    lsw_info("NtWriteFile: handle=0x%llx, size=%llu", handle, size);
    
    /* Write via LSW file manager */
    ret = lsw_file_write(handle, data, size, &bytes_written);
    
    if (ret != 0) {
        lsw_err("File write failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    lsw_info("Wrote %llu bytes to handle 0x%llx", bytes_written, handle);
    
    req->return_value = bytes_written;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtClose - Translate NtClose to Linux close()
 */
long lsw_syscall_NtClose(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    int ret;
    
    lsw_info("NtClose: handle=0x%llx", handle);
    
    /* Close via LSW file manager */
    ret = lsw_file_close(handle);
    
    if (ret != 0) {
        lsw_err("File close failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
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
 * lsw_syscall_NtReadVirtualMemory - Read memory from another process
 * 
 * Used by anti-cheat to inspect process memory for injected code
 * 
 * Win32: NTSTATUS NtReadVirtualMemory(
 *     HANDLE ProcessHandle,
 *     PVOID BaseAddress,
 *     PVOID Buffer,
 *     SIZE_T BufferSize,
 *     PSIZE_T NumberOfBytesRead
 * )
 */
long lsw_syscall_NtReadVirtualMemory(struct lsw_syscall_request *req)
{
    __u32 target_pid = req->args[0];  /* Process to read from */
    __u64 base_address = req->args[1];
    __u64 size = req->args[2];
    char temp_buffer[256];
    int bytes_read;
    
    /* Use current PID if target is 0 (self) */
    if (target_pid == 0) {
        target_pid = current->pid;
    }
    
    lsw_info("NtReadVirtualMemory: target_pid=%u, base=0x%llx, size=%llu",
             target_pid, base_address, size);
    
    /* Limit read size for safety */
    if (size > sizeof(temp_buffer)) {
        size = sizeof(temp_buffer);
    }
    
    /* Read memory via LSW memory manager */
    bytes_read = lsw_memory_read(target_pid, base_address, temp_buffer, size);
    
    if (bytes_read < 0) {
        lsw_err("Memory read failed: %d", bytes_read);
        req->return_value = 0;
        req->error_code = bytes_read;
        return bytes_read;
    }
    
    lsw_info("Successfully read %d bytes from PID %u", bytes_read, target_pid);
    
    req->return_value = bytes_read;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtProtectVirtualMemory - Change memory protection
 * 
 * Used by anti-cheat to verify memory protection flags
 * 
 * Win32: NTSTATUS NtProtectVirtualMemory(
 *     HANDLE ProcessHandle,
 *     PVOID *BaseAddress,
 *     PSIZE_T RegionSize,
 *     ULONG NewProtect,
 *     PULONG OldProtect
 * )
 */
long lsw_syscall_NtProtectVirtualMemory(struct lsw_syscall_request *req)
{
    __u64 base_address = req->args[0];
    __u64 size = req->args[1];
    __u32 new_protect = req->args[2];
    __u32 old_protect = 0;
    int ret;
    
    lsw_info("NtProtectVirtualMemory: base=0x%llx, size=%llu, new_protect=0x%x",
             base_address, size, new_protect);
    
    /* Use current PID */
    __u32 pid = current->pid;
    
    /* Change protection via LSW memory manager */
    ret = lsw_memory_protect(pid, base_address, size, new_protect, &old_protect);
    
    if (ret != 0) {
        lsw_err("Memory protect failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    lsw_info("Protection changed: old=0x%x, new=0x%x", old_protect, new_protect);
    
    req->return_value = old_protect;  /* Return old protection flags */
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtQuerySystemInformation - Query system information
 * 
 * Used by anti-cheat to enumerate processes and get system state
 * 
 * Win32: NTSTATUS NtQuerySystemInformation(
 *     SYSTEM_INFORMATION_CLASS SystemInformationClass,
 *     PVOID SystemInformation,
 *     ULONG SystemInformationLength,
 *     PULONG ReturnLength
 * )
 */
long lsw_syscall_NtQuerySystemInformation(struct lsw_syscall_request *req)
{
    __u32 info_class = req->args[0];
    struct task_struct *task;
    int process_count = 0;
    
    lsw_info("NtQuerySystemInformation: class=0x%x (SystemProcessInformation=5)",
             info_class);
    
    /* SystemProcessInformation = 5 (enumerate processes) */
    if (info_class == 5) {
        /* Enumerate all processes using Linux kernel */
        rcu_read_lock();
        for_each_process(task) {
            if (process_count < 10) {  /* Show first 10 for demo */
                lsw_info("  Process: PID=%d, name=%s, state=%ld",
                         task->pid, task->comm, task->__state);
            }
            process_count++;
        }
        rcu_read_unlock();
        
        lsw_info("Total processes enumerated: %d", process_count);
        
        /* Return process count in return_value */
        req->return_value = process_count;
        req->error_code = 0;
        
        return 0;
    }
    
    /* SystemBasicInformation = 0 (system info) */
    if (info_class == 0) {
        lsw_info("  System basic information requested");
        lsw_info("  Total RAM: %lu KB", totalram_pages() * (PAGE_SIZE / 1024));
        lsw_info("  Kernel version: %d.%d.%d",
                 LINUX_VERSION_CODE >> 16,
                 (LINUX_VERSION_CODE >> 8) & 0xFF,
                 LINUX_VERSION_CODE & 0xFF);
        
        req->return_value = 0;
        req->error_code = 0;
        
        return 0;
    }
    
    /* Other information classes not yet implemented */
    lsw_info("Information class 0x%x not yet implemented", info_class);
    req->return_value = 0;
    req->error_code = -ENOSYS;
    
    return 0;
}

/**
 * lsw_syscall_NtCreateEvent - Create an event object
 */
long lsw_syscall_NtCreateEvent(struct lsw_syscall_request *req)
{
    bool manual_reset = req->args[0];
    bool initial_state = req->args[1];
    __u64 handle;
    
    lsw_info("NtCreateEvent: manual=%d, initial=%d", manual_reset, initial_state);
    
    handle = lsw_sync_create_event(current->pid, manual_reset, initial_state);
    
    if (handle == 0) {
        lsw_err("Failed to create event");
        req->return_value = 0;
        req->error_code = -ENOMEM;
        return -ENOMEM;
    }
    
    req->return_value = handle;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtCreateMutant - Create a mutex object
 */
long lsw_syscall_NtCreateMutant(struct lsw_syscall_request *req)
{
    bool initial_owner = req->args[0];
    __u64 handle;
    
    lsw_info("NtCreateMutant: owned=%d", initial_owner);
    
    handle = lsw_sync_create_mutex(current->pid, initial_owner);
    
    if (handle == 0) {
        lsw_err("Failed to create mutex");
        req->return_value = 0;
        req->error_code = -ENOMEM;
        return -ENOMEM;
    }
    
    req->return_value = handle;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtWaitForSingleObject - Wait for object
 */
long lsw_syscall_NtWaitForSingleObject(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    __u32 timeout_ms = req->args[1];
    int ret;
    
    lsw_info("NtWaitForSingleObject: handle=0x%llx, timeout=%u ms", handle, timeout_ms);
    
    ret = lsw_sync_wait(handle, timeout_ms);
    
    if (ret == -ETIMEDOUT) {
        req->return_value = 0x102;  /* STATUS_TIMEOUT */
        req->error_code = 0;
        return 0;
    } else if (ret < 0) {
        lsw_err("Wait failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = 0;  /* STATUS_SUCCESS */
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtSetEvent - Signal an event
 */
long lsw_syscall_NtSetEvent(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    int ret;
    
    lsw_info("NtSetEvent: handle=0x%llx", handle);
    
    ret = lsw_sync_signal(handle);
    
    if (ret < 0) {
        lsw_err("Set event failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = 0;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtReleaseMutant - Release a mutex
 */
long lsw_syscall_NtReleaseMutant(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    int ret;
    
    lsw_info("NtReleaseMutant: handle=0x%llx", handle);
    
    ret = lsw_sync_signal(handle);
    
    if (ret < 0) {
        lsw_err("Release mutex failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = 0;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_LdrLoadDll - Load a DLL
 */
long lsw_syscall_LdrLoadDll(struct lsw_syscall_request *req)
{
    const char *path = "/tmp/test.dll";  /* TODO: Get from userspace */
    __u64 base_address = 0;
    int ret;
    
    lsw_info("LdrLoadDll: path='%s'", path);
    
    ret = lsw_dll_load(current->pid, path, &base_address);
    
    if (ret != 0) {
        lsw_err("DLL load failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = base_address;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_LdrGetProcedureAddress - Get function address from DLL
 */
long lsw_syscall_LdrGetProcedureAddress(struct lsw_syscall_request *req)
{
    __u64 base_address = req->args[0];
    const char *function_name = "TestFunction";  /* TODO: Get from userspace */
    __u64 proc_address;
    
    lsw_info("LdrGetProcedureAddress: base=0x%llx, function='%s'",
             base_address, function_name);
    
    proc_address = lsw_dll_get_proc_address(base_address, function_name);
    
    if (proc_address == 0) {
        lsw_err("Function not found");
        req->return_value = 0;
        req->error_code = -ENOENT;
        return -ENOENT;
    }
    
    req->return_value = proc_address;
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
