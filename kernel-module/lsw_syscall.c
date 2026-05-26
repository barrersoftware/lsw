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
#include <linux/kprobes.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_syscall.h"
#include "../include/kernel-module/lsw_memory.h"
#include "../include/kernel-module/lsw_file.h"
#include "../include/kernel-module/lsw_sync.h"
#include "../include/kernel-module/lsw_dll.h"
#include "../include/kernel-module/lsw_process.h"

/* Forward declarations */
long lsw_syscall_NtCreateFile(struct lsw_syscall_request *req);
long lsw_syscall_NtReadFile(struct lsw_syscall_request *req);
long lsw_syscall_NtWriteFile(struct lsw_syscall_request *req);
long lsw_syscall_NtClose(struct lsw_syscall_request *req);
long lsw_syscall_LswGetFileSize(struct lsw_syscall_request *req);
long lsw_syscall_LswSetFilePointer(struct lsw_syscall_request *req);
long lsw_syscall_NtAllocateVirtualMemory(struct lsw_syscall_request *req);
long lsw_syscall_NtFreeVirtualMemory(struct lsw_syscall_request *req);
long lsw_syscall_NtReadVirtualMemory(struct lsw_syscall_request *req);
long lsw_syscall_NtProtectVirtualMemory(struct lsw_syscall_request *req);
long lsw_syscall_NtQuerySystemInformation(struct lsw_syscall_request *req);
long lsw_syscall_NtCreateEvent(struct lsw_syscall_request *req);
long lsw_syscall_NtCreateMutant(struct lsw_syscall_request *req);
long lsw_syscall_NtWaitForSingleObject(struct lsw_syscall_request *req);
long lsw_syscall_NtSetEvent(struct lsw_syscall_request *req);
long lsw_syscall_NtReleaseMutant(struct lsw_syscall_request *req);
long lsw_syscall_LdrLoadDll(struct lsw_syscall_request *req);
long lsw_syscall_LdrGetProcedureAddress(struct lsw_syscall_request *req);
long lsw_syscall_NtCreateProcess(struct lsw_syscall_request *req);
long lsw_syscall_NtCreateThreadEx(struct lsw_syscall_request *req);
long lsw_syscall_NtTerminateProcess(struct lsw_syscall_request *req);
long lsw_syscall_LswWriteConsole(struct lsw_syscall_request *req);
long lsw_syscall_LswReadConsole(struct lsw_syscall_request *req);
long lsw_syscall_LswGetStdHandle(struct lsw_syscall_request *req);

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
    { LSW_SYSCALL_LswGetFileSize, lsw_syscall_LswGetFileSize, "LswGetFileSize" },
    { LSW_SYSCALL_LswSetFilePointer, lsw_syscall_LswSetFilePointer, "LswSetFilePointer" },
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
    { LSW_SYSCALL_NtCreateProcess, lsw_syscall_NtCreateProcess, "NtCreateProcess" },
    { LSW_SYSCALL_NtCreateThreadEx, lsw_syscall_NtCreateThreadEx, "NtCreateThreadEx" },
    { LSW_SYSCALL_NtTerminateProcess, lsw_syscall_NtTerminateProcess, "NtTerminateProcess" },
    { LSW_SYSCALL_LswWriteConsole, lsw_syscall_LswWriteConsole, "LswWriteConsole" },
    { LSW_SYSCALL_LswReadConsole, lsw_syscall_LswReadConsole, "LswReadConsole" },
    { LSW_SYSCALL_LswGetStdHandle, lsw_syscall_LswGetStdHandle, "LswGetStdHandle" },
    /* NT syscalls added for broad app compatibility */
    { 0x0033, lsw_syscall_NtDelayExecution,        "NtDelayExecution" },
    { 0x0019, lsw_syscall_NtQueryInformationProcess,"NtQueryInformationProcess" },
    { 0x0053, lsw_syscall_NtTerminateThread,        "NtTerminateThread" },
    { 0x0058, lsw_syscall_NtWaitForMultipleObjects, "NtWaitForMultipleObjects" },
    { 0x0075, lsw_syscall_NtFlushBuffersFile,       "NtFlushBuffersFile" },
    { 0x000D, lsw_syscall_NtQueryInformationFile,   "NtQueryInformationFile" },
    { 0x0027, lsw_syscall_NtSetInformationFile,     "NtSetInformationFile" },
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
    __u64 path_ptr = req->args[0];       // Userspace path pointer
    __u32 access = req->args[1];         // Access flags
    __u32 disposition = req->args[2];    // Creation disposition
    __u32 flags = req->args[3];          // Flags
    char path_kernel[256];
    __u64 handle;
    
    // Copy path from userspace
    if (copy_from_user(path_kernel, (const char __user *)path_ptr, sizeof(path_kernel) - 1)) {
        lsw_err("Failed to copy path from userspace");
        req->return_value = (__u64)-1;
        req->error_code = -EFAULT;
        return -EFAULT;
    }
    path_kernel[sizeof(path_kernel) - 1] = '\0';
    
    lsw_info("NtCreateFile: path='%s', access=0x%x, disposition=%u, flags=0x%x",
             path_kernel, access, disposition, flags);
    
    /* Use current PID */
    __u32 pid = current->pid;
    
    /* Open file via LSW file manager */
    handle = lsw_file_open(pid, path_kernel, access, 0, disposition);
    
    if (handle == 0) {
        lsw_err("File open failed for: %s", path_kernel);
        req->return_value = (__u64)-1;
        req->error_code = -ENOENT;
        return -ENOENT;
    }
    
    lsw_info("NtCreateFile success: handle=0x%llx for path='%s'", handle, path_kernel);
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
    __u64 buffer_ptr = req->args[1];  /* Userspace buffer pointer */
    __u64 size = req->args[2];
    __u64 bytes_read = 0;
    char *temp_buffer;
    int ret;
    
    lsw_info("NtReadFile: handle=0x%llx, buffer=0x%llx, size=%llu", handle, buffer_ptr, size);
    
    /* Allocate temp buffer on heap to avoid stack frame issues */
    temp_buffer = kmalloc(4096, GFP_KERNEL);
    if (!temp_buffer) {
        lsw_err("Failed to allocate temp buffer");
        req->return_value = 0;
        req->error_code = -ENOMEM;
        return -ENOMEM;
    }
    
    /* Limit read size */
    if (size > 4096) {
        size = 4096;
    }
    
    /* Read via LSW file manager */
    ret = lsw_file_read(handle, temp_buffer, size, &bytes_read);
    
    if (ret != 0) {
        lsw_err("File read failed: %d", ret);
        kfree(temp_buffer);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    lsw_info("Read %llu bytes from handle 0x%llx", bytes_read, handle);
    
    /* Copy data to userspace buffer */
    if (bytes_read > 0 && buffer_ptr != 0) {
        if (copy_to_user((void __user *)buffer_ptr, temp_buffer, bytes_read)) {
            lsw_err("Failed to copy data to userspace buffer");
            kfree(temp_buffer);
            req->return_value = 0;
            req->error_code = -EFAULT;
            return -EFAULT;
        }
        lsw_info("Copied %llu bytes to userspace buffer at 0x%llx", bytes_read, buffer_ptr);
    }
    
    kfree(temp_buffer);
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
    __u64 buffer_ptr = req->args[1];  /* Userspace buffer pointer */
    __u64 size = req->args[2];
    __u64 bytes_written = 0;
    char *kernel_buffer;
    int ret;
    size_t copy_size;
    
    lsw_info("NtWriteFile: handle=0x%llx, buffer=0x%llx, size=%llu", handle, buffer_ptr, size);
    
    /* Allocate buffer on heap to avoid stack frame issues */
    kernel_buffer = kmalloc(4096, GFP_KERNEL);
    if (!kernel_buffer) {
        lsw_err("Failed to allocate kernel buffer");
        req->return_value = 0;
        req->error_code = -ENOMEM;
        return -ENOMEM;
    }
    
    /* Limit size to our buffer */
    copy_size = size > 4096 ? 4096 : size;
    
    /* Copy data from userspace */
    if (copy_from_user(kernel_buffer, (void __user *)buffer_ptr, copy_size)) {
        lsw_err("Failed to copy buffer from userspace");
        kfree(kernel_buffer);
        req->return_value = 0;
        req->error_code = -EFAULT;
        return -EFAULT;
    }
    
    /* Write via LSW file manager */
    ret = lsw_file_write(handle, kernel_buffer, copy_size, &bytes_written);
    
    kfree(kernel_buffer);
    
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
 * lsw_syscall_LswGetFileSize - Get file size from LSW handle
 */
long lsw_syscall_LswGetFileSize(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    __u64 size;
    int ret;
    
    lsw_info("LswGetFileSize: handle=0x%llx", handle);
    
    ret = lsw_file_get_size(handle, &size);
    if (ret != 0) {
        req->return_value = 0xFFFFFFFFFFFFFFFFULL;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = size;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_LswSetFilePointer - Set file pointer position
 */
long lsw_syscall_LswSetFilePointer(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    __s64 offset = (__s64)req->args[1];
    __u32 whence = (__u32)req->args[2];
    __u64 new_pos;
    int ret;
    
    lsw_info("LswSetFilePointer: handle=0x%llx, offset=%lld, whence=%u", handle, offset, whence);
    
    ret = lsw_file_seek(handle, offset, whence, &new_pos);
    if (ret != 0) {
        req->return_value = 0xFFFFFFFFFFFFFFFFULL;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = new_pos;
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
                /* Kernel API compatibility: __state (5.14+) vs state (older) */
                unsigned int task_state;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
                task_state = (unsigned int)READ_ONCE(task->__state);
#else
                task_state = (unsigned int)task->state;
#endif
                lsw_info("  Process: PID=%d, name=%s, state=%u",
                         task->pid, task->comm, task_state);
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
    __u64 path_ptr = req->args[0];  // DLL path from userspace
    char path_kernel[256];
    __u64 base_address = 0;
    int ret;
    
    // Copy path from userspace (like NtCreateFile does)
    if (copy_from_user(path_kernel, (const char __user *)path_ptr, sizeof(path_kernel) - 1)) {
        lsw_err("LdrLoadDll: Failed to copy DLL path from userspace");
        req->return_value = 0;
        req->error_code = -EFAULT;
        return -EFAULT;
    }
    path_kernel[sizeof(path_kernel) - 1] = '\0';
    
    lsw_info("LdrLoadDll: path='%s' (from userspace)", path_kernel);
    
    ret = lsw_dll_load(current->pid, path_kernel, &base_address);
    
    if (ret != 0) {
        lsw_err("DLL load failed for '%s': %d", path_kernel, ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    lsw_info("LdrLoadDll success: base=0x%llx for '%s'", base_address, path_kernel);
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
 * lsw_syscall_NtCreateProcess - Create a Win32 process
 */
long lsw_syscall_NtCreateProcess(struct lsw_syscall_request *req)
{
    const char *path = (const char *)req->args[0];
    __u32 win32_pid = 0;
    int ret;
    
    if (!path) {
        lsw_err("NtCreateProcess: NULL path");
        req->return_value = 0;
        req->error_code = -EINVAL;
        return -EINVAL;
    }
    
    lsw_info("NtCreateProcess: path='%s'", path);
    
    ret = lsw_process_create(path, &win32_pid);
    
    if (ret != 0) {
        lsw_err("Process creation failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    lsw_info("Process created: Win32 PID=%u", win32_pid);
    
    req->return_value = win32_pid;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtCreateThreadEx - Create a thread
 */
long lsw_syscall_NtCreateThreadEx(struct lsw_syscall_request *req)
{
    __u32 win32_pid = req->args[0];
    __u64 start_address = req->args[1];
    __u64 parameter = req->args[2];
    __u32 win32_tid = 0;
    int ret;
    
    lsw_info("NtCreateThreadEx: PID=%u, start=0x%llx, param=0x%llx",
             win32_pid, start_address, parameter);
    
    ret = lsw_thread_create(win32_pid, start_address, parameter, &win32_tid);
    
    if (ret != 0) {
        lsw_err("Thread creation failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    lsw_info("Thread created: Win32 TID=%u", win32_tid);
    
    req->return_value = win32_tid;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtTerminateProcess - Terminate a process
 */
long lsw_syscall_NtTerminateProcess(struct lsw_syscall_request *req)
{
    __u32 win32_pid = req->args[0];
    __u32 exit_code = req->args[1];
    int ret;
    
    lsw_info("NtTerminateProcess: PID=%u, exit_code=%u", win32_pid, exit_code);
    
    ret = lsw_process_terminate(win32_pid, exit_code);
    
    if (ret != 0) {
        lsw_err("Process termination failed: %d", ret);
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = 0;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_LswGetStdHandle - Get standard console handle
 */
long lsw_syscall_LswGetStdHandle(struct lsw_syscall_request *req)
{
    __u32 std_handle = req->args[0];
    __u64 handle;
    
    lsw_info("LswGetStdHandle: std_handle=%u", std_handle);
    
    handle = lsw_console_GetStdHandle(std_handle);
    
    req->return_value = handle;
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_LswWriteConsole - Write to console
 */
long lsw_syscall_LswWriteConsole(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    const void __user *buffer = (const void __user *)req->args[1];
    __u32 chars_to_write = req->args[2];
    __u32 __user *chars_written_ptr = (__u32 __user *)req->args[3];
    int ret;
    
    lsw_info("LswWriteConsole: handle=0x%llx, chars=%u", handle, chars_to_write);
    
    ret = lsw_console_WriteConsole(handle, buffer, chars_to_write, chars_written_ptr);
    
    if (ret < 0) {
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = 1;  /* Success */
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_LswReadConsole - Read from console
 */
long lsw_syscall_LswReadConsole(struct lsw_syscall_request *req)
{
    __u64 handle = req->args[0];
    void __user *buffer = (void __user *)req->args[1];
    __u32 chars_to_read = req->args[2];
    __u32 __user *chars_read_ptr = (__u32 __user *)req->args[3];
    int ret;
    
    lsw_info("LswReadConsole: handle=0x%llx, chars=%u", handle, chars_to_read);
    
    ret = lsw_console_ReadConsole(handle, buffer, chars_to_read, chars_read_ptr);
    
    if (ret < 0) {
        req->return_value = 0;
        req->error_code = ret;
        return ret;
    }
    
    req->return_value = 1;  /* Success */
    req->error_code = 0;
    
    return 0;
}

/**
 * lsw_syscall_NtDelayExecution - Sleep for specified interval
 *
 * Win32: NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
 * DelayInterval is negative 100ns units (relative), positive = absolute time.
 */
long lsw_syscall_NtDelayExecution(struct lsw_syscall_request *req)
{
    /* args[0] = Alertable (ignored), args[1] = interval in 100ns units */
    s64 interval_100ns = (s64)req->args[1];
    u64 ns;
    ktime_t delay;

    if (interval_100ns == 0) {
        yield();
        req->return_value = 0;
        req->error_code   = 0;
        return 0;
    }

    /* Negative = relative delay */
    if (interval_100ns < 0)
        interval_100ns = -interval_100ns;

    ns    = (u64)interval_100ns * 100;  /* 100 ns → ns */
    delay = ns_to_ktime(ns);
    schedule_hrtimeout(&delay, HRTIMER_MODE_REL);

    req->return_value = 0;
    req->error_code   = 0;
    return 0;
}

/**
 * lsw_syscall_NtQueryInformationProcess - Query process information
 *
 * Win32: NTSTATUS NtQueryInformationProcess(
 *     HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
 *     PVOID ProcessInformation, ULONG ProcessInformationLength,
 *     PULONG ReturnLength)
 *
 * Only ProcessBasicInformation (class 0) and ProcessImageFileName (27) are
 * handled; all other classes succeed with zeroed output.
 */
long lsw_syscall_NtQueryInformationProcess(struct lsw_syscall_request *req)
{
    __u32  info_class = (__u32)req->args[1];
    void __user *buf  = (void __user *)(uintptr_t)req->args[2];
    __u32  buf_len    = (__u32)req->args[3];

    lsw_info("NtQueryInformationProcess: class=%u", info_class);

    /* ProcessBasicInformation = 0 */
    if (info_class == 0 && buf && buf_len >= 48) {
        /* PROCESS_BASIC_INFORMATION layout (6 × u64 = 48 bytes) */
        u64 pbi[6] = {0};
        pbi[4] = (u64)(uintptr_t)current->tgid;  /* UniqueProcessId */
        pbi[5] = (u64)(uintptr_t)current->real_parent->tgid;
        if (copy_to_user(buf, pbi, sizeof(pbi))) {
            req->return_value = (u64)(u32)0xC0000005UL; /* STATUS_ACCESS_VIOLATION */
            req->error_code   = -EFAULT;
            return -EFAULT;
        }
    } else if (buf && buf_len > 0) {
        /* Zero out whatever the caller provided */
        clear_user(buf, buf_len);
    }

    req->return_value = 0;
    req->error_code   = 0;
    return 0;
}

/**
 * lsw_syscall_NtTerminateThread - Terminate the current (or specified) thread
 */
long lsw_syscall_NtTerminateThread(struct lsw_syscall_request *req)
{
    __u32 exit_code = (__u32)req->args[1];
    lsw_info("NtTerminateThread: exit_code=%u", exit_code);
    /* For now, just signal the current thread */
    do_exit((long)exit_code);
    /* unreachable */
    req->return_value = 0;
    req->error_code   = 0;
    return 0;
}

/**
 * lsw_syscall_NtWaitForMultipleObjects - Wait on several handles
 *
 * Best-effort stub: yield and return STATUS_WAIT_0.
 */
long lsw_syscall_NtWaitForMultipleObjects(struct lsw_syscall_request *req)
{
    __u32 timeout_ms = (__u32)req->args[3];
    lsw_info("NtWaitForMultipleObjects: count=%u, timeout=%u ms",
             (__u32)req->args[0], timeout_ms);
    if (timeout_ms != 0xFFFFFFFF)
        msleep_interruptible(min(timeout_ms, 5000U));
    req->return_value = 0; /* STATUS_WAIT_0 */
    req->error_code   = 0;
    return 0;
}

/**
 * lsw_syscall_NtFlushBuffersFile - Flush file buffers
 * Best-effort stub: returns STATUS_SUCCESS.
 */
long lsw_syscall_NtFlushBuffersFile(struct lsw_syscall_request *req)
{
    lsw_info("NtFlushBuffersFile: handle=0x%llx", req->args[0]);
    req->return_value = 0;
    req->error_code   = 0;
    return 0;
}

/**
 * lsw_syscall_NtQueryInformationFile - Query file information
 * Stub: zero out output buffer and return success.
 */
long lsw_syscall_NtQueryInformationFile(struct lsw_syscall_request *req)
{
    void __user *buf = (void __user *)(uintptr_t)req->args[3];
    __u32 len = (__u32)req->args[4];
    if (buf && len) clear_user(buf, len);
    req->return_value = 0;
    req->error_code   = 0;
    return 0;
}

/**
 * lsw_syscall_NtSetInformationFile - Set file information
 * Stub: accept and ignore.
 */
long lsw_syscall_NtSetInformationFile(struct lsw_syscall_request *req)
{
    (void)req;
    req->return_value = 0;
    req->error_code   = 0;
    return 0;
}

/* ============================================================
 * kretprobe-based NT syscall interception
 *
 * When a PE process issues a bare `syscall` instruction (e.g. by
 * calling NtCreateFile directly), the CPU dispatches to
 * entry_SYSCALL_64 which calls do_syscall_64(pt_regs*, nr).
 * We hook do_syscall_64 with a kretprobe:
 *   entry_handler — intercepts NT numbers, runs our handler,
 *                   stores result, and replaces nr with getpid
 *                   so the kernel runs a harmless syscall.
 *   ret_handler   — overwrites the getpid result with our value.
 * ============================================================ */

/* Per-invocation data stored in the kretprobe instance */
struct lsw_intercept_data {
    struct pt_regs *syscall_regs;  /* The ACTUAL syscall pt_regs */
    u64             result;         /* Our NT return value */
    bool            intercepted;    /* Was this an NT syscall? */
};

static int lsw_kretprobe_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct lsw_intercept_data *d = (struct lsw_intercept_data *)ri->data;
    struct pt_regs *sc_regs;
    int             nr;
    unsigned int    i;
    struct lsw_syscall_request req;

    d->intercepted = false;

    /* Fast path: skip if no PE processes are registered */
    if (!lsw_module_state.pe_process_count)
        return 0;

    /* Skip if the current task isn't a registered PE process */
    if (!lsw_process_is_pe_pid(current->pid))
        return 0;

    /*
     * do_syscall_64(struct pt_regs *regs, int nr)
     * System-V x86-64: arg1=rdi, arg2=rsi
     */
    sc_regs = (struct pt_regs *)(uintptr_t)regs->di;
    nr      = (int)(regs->si & 0xFFFFFFFF);

    /* Scan our dispatch table for a matching NT syscall number */
    for (i = 0; syscall_table[i].handler != NULL; i++) {
        if ((unsigned int)nr != syscall_table[i].syscall_number)
            continue;

        memset(&req, 0, sizeof(req));
        req.syscall_number = (u32)nr;
        req.arg_count      = 6;

        /*
         * NT calling convention: before the `syscall` instruction the
         * Windows stub does `mov r10, rcx` to preserve the first arg
         * (rcx is clobbered by syscall).  So arg0 = r10, arg1 = rdx,
         * arg2 = r8, arg3 = r9; further args are on the stack.
         */
        if (sc_regs) {
            req.args[0] = sc_regs->r10;
            req.args[1] = sc_regs->dx;
            req.args[2] = sc_regs->r8;
            req.args[3] = sc_regs->r9;
        }

        syscall_table[i].handler(&req);

        /* Save result and mark as intercepted */
        d->syscall_regs  = sc_regs;
        d->result        = req.return_value;
        d->intercepted   = true;

        /*
         * Replace the syscall number with sys_getpid (39) so the kernel
         * runs a harmless call instead of the wrong Linux syscall.
         * The return handler will overwrite the result in regs->ax.
         */
        regs->si = __NR_getpid;

        lsw_debug("kretprobe: intercepted NT syscall %s (0x%x) → 0x%llx",
                  syscall_table[i].name, nr, req.return_value);
        return 0;
    }

    return 0;
}

static int lsw_kretprobe_ret(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct lsw_intercept_data *d = (struct lsw_intercept_data *)ri->data;

    if (d->intercepted && d->syscall_regs) {
        /*
         * do_syscall_64 has returned.  The result of the harmless
         * getpid() call is now in d->syscall_regs->ax.
         * Overwrite it with our NT return value.
         */
        d->syscall_regs->ax = d->result;
    }
    return 0;
}

static struct kretprobe lsw_kretprobe_syscall = {
    .kp.symbol_name = "do_syscall_64",
    .entry_handler  = lsw_kretprobe_entry,
    .handler        = lsw_kretprobe_ret,
    .data_size      = sizeof(struct lsw_intercept_data),
    .maxactive      = 64,   /* max simultaneous intercepts */
};

/**
 * lsw_syscall_init - Initialize syscall translation system
 */
int lsw_syscall_init(void)
{
    int count = 0;
    int i;
    int ret;
    
    /* Count registered syscalls */
    for (i = 0; syscall_table[i].handler != NULL; i++) {
        count++;
    }
    
    lsw_info("Syscall translation system initialized: %d syscalls registered", count);

    /* Register kretprobe so bare NT syscall instructions are intercepted */
    ret = register_kretprobe(&lsw_kretprobe_syscall);
    if (ret < 0) {
        lsw_warn("kretprobe on do_syscall_64 failed (%d) — ioctl path only", ret);
        /* Non-fatal: apps that go through our Win32 stubs still work */
    } else {
        lsw_info("kretprobe on do_syscall_64 registered — bare NT syscalls intercepted");
        lsw_module_state.syscall_hooks_active = true;
    }

    return 0;
}

/**
 * lsw_syscall_exit - Cleanup syscall translation system
 */
void lsw_syscall_exit(void)
{
    if (lsw_module_state.syscall_hooks_active) {
        unregister_kretprobe(&lsw_kretprobe_syscall);
        lsw_module_state.syscall_hooks_active = false;
        lsw_info("kretprobe on do_syscall_64 unregistered");
    }
    lsw_info("Syscall translation system cleaned up");
}
