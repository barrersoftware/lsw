/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * DLL Loading and PE Management
 * Loads Win32 DLLs at kernel level for maximum performance
 */

#ifndef LSW_DLL_H
#define LSW_DLL_H

#include <linux/types.h>
#include <linux/list.h>

/* Loaded module entry */
struct lsw_module {
    struct list_head list;      /* List linkage */
    __u64 base_address;         /* Base address in memory */
    __u64 size;                 /* Size of loaded image */
    __u32 pid;                  /* Process ID */
    char name[64];              /* Module name */
    void *image_data;           /* Loaded PE image */
    __u32 entry_point;          /* Entry point RVA */
    __u32 export_count;         /* Number of exports */
};

/**
 * lsw_dll_load - Load a DLL into process memory
 * 
 * @pid: Process ID
 * @path: Path to DLL file
 * @base_address: Returns base address of loaded module
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_dll_load(__u32 pid, const char *path, __u64 *base_address);

/**
 * lsw_dll_get_proc_address - Get address of exported function
 * 
 * @base_address: Module base address
 * @function_name: Name of function to find
 * 
 * Returns: Function address or 0 if not found
 */
__u64 lsw_dll_get_proc_address(__u64 base_address, const char *function_name);

/**
 * lsw_dll_unload - Unload a DLL
 * 
 * @base_address: Base address of module to unload
 * 
 * Returns: 0 on success, negative on error
 */
int lsw_dll_unload(__u64 base_address);

/**
 * lsw_dll_cleanup_process - Unload all DLLs for a process
 * 
 * @pid: Process ID
 */
void lsw_dll_cleanup_process(__u32 pid);

/* Initialize/cleanup DLL system */
int lsw_dll_init(void);
void lsw_dll_exit(void);

#endif /* LSW_DLL_H */
