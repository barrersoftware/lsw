/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * DLL Loading Implementation
 * PE format parser and loader at kernel level
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_dll.h"
#include "../include/kernel-module/lsw_pe.h"

/* Global module list */
static LIST_HEAD(lsw_module_list);
static DEFINE_MUTEX(lsw_module_mutex);
static atomic_t lsw_loaded_modules = ATOMIC_INIT(0);

/**
 * lsw_pe_validate - Validate PE file headers
 */
static int lsw_pe_validate(void *data, size_t size)
{
    struct lsw_dos_header *dos;
    __u32 *pe_sig;
    
    if (size < sizeof(struct lsw_dos_header)) {
        lsw_err("File too small for DOS header");
        return -EINVAL;
    }
    
    dos = (struct lsw_dos_header *)data;
    
    if (dos->e_magic != LSW_DOS_MAGIC) {
        lsw_err("Invalid DOS magic: 0x%x", dos->e_magic);
        return -EINVAL;
    }
    
    if (dos->e_lfanew >= size - 4) {
        lsw_err("Invalid PE offset: 0x%x", dos->e_lfanew);
        return -EINVAL;
    }
    
    pe_sig = (__u32 *)((char *)data + dos->e_lfanew);
    
    if (*pe_sig != LSW_PE_SIGNATURE) {
        lsw_err("Invalid PE signature: 0x%x", *pe_sig);
        return -EINVAL;
    }
    
    lsw_info("Valid PE file detected");
    
    return 0;
}

/**
 * lsw_dll_load - Load a DLL into memory
 */
int lsw_dll_load(__u32 pid, const char *path, __u64 *base_address)
{
    struct file *file;
    void *file_data;
    loff_t file_size;
    loff_t pos = 0;
    ssize_t bytes_read;
    struct lsw_module *mod;
    struct lsw_dos_header *dos;
    struct lsw_coff_header *coff;
    struct lsw_optional_header64 *opt;
    int ret;
    
    lsw_info("Loading DLL: PID=%u, path='%s'", pid, path);
    
    /* Open DLL file */
    file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        lsw_err("Failed to open DLL: %ld", PTR_ERR(file));
        return PTR_ERR(file);
    }
    
    /* Get file size */
    file_size = i_size_read(file_inode(file));
    
    if (file_size > 100 * 1024 * 1024) {  /* Limit to 100MB */
        lsw_err("DLL too large: %lld bytes", file_size);
        filp_close(file, NULL);
        return -EFBIG;
    }
    
    lsw_info("DLL size: %lld bytes", file_size);
    
    /* Allocate buffer for entire file */
    file_data = vmalloc(file_size);
    if (!file_data) {
        lsw_err("Failed to allocate %lld bytes", file_size);
        filp_close(file, NULL);
        return -ENOMEM;
    }
    
    /* Read entire file */
    bytes_read = kernel_read(file, file_data, file_size, &pos);
    filp_close(file, NULL);
    
    if (bytes_read != file_size) {
        lsw_err("Failed to read DLL: %ld != %lld", bytes_read, file_size);
        vfree(file_data);
        return -EIO;
    }
    
    /* Validate PE format */
    ret = lsw_pe_validate(file_data, file_size);
    if (ret != 0) {
        vfree(file_data);
        return ret;
    }
    
    /* Parse PE headers */
    dos = (struct lsw_dos_header *)file_data;
    coff = (struct lsw_coff_header *)((char *)file_data + dos->e_lfanew + 4);
    opt = (struct lsw_optional_header64 *)((char *)coff + sizeof(*coff));
    
    lsw_info("PE headers: Sections=%u, EntryPoint=0x%x, ImageBase=0x%llx",
             coff->NumberOfSections, opt->AddressOfEntryPoint, opt->ImageBase);
    
    /* Create module entry */
    mod = kmalloc(sizeof(*mod), GFP_KERNEL);
    if (!mod) {
        vfree(file_data);
        return -ENOMEM;
    }
    
    mod->base_address = opt->ImageBase;
    mod->size = opt->SizeOfImage;
    mod->pid = pid;
    mod->image_data = file_data;
    mod->entry_point = opt->AddressOfEntryPoint;
    mod->export_count = 0;  /* TODO: Parse export table */
    
    /* Extract module name from path */
    {
        const char *name_start = path;
        const char *p = path;
        while (*p) {
            if (*p == '/' || *p == '\\')
                name_start = p + 1;
            p++;
        }
        strncpy(mod->name, name_start, sizeof(mod->name) - 1);
        mod->name[sizeof(mod->name) - 1] = '\0';
    }
    
    /* Add to module list */
    mutex_lock(&lsw_module_mutex);
    list_add(&mod->list, &lsw_module_list);
    mutex_unlock(&lsw_module_mutex);
    
    atomic_inc(&lsw_loaded_modules);
    
    lsw_info("DLL loaded: base=0x%llx, size=0x%llx, name='%s'",
             mod->base_address, mod->size, mod->name);
    
    if (base_address) {
        *base_address = mod->base_address;
    }
    
    return 0;
}

/**
 * lsw_dll_get_proc_address - Get exported function address
 */
__u64 lsw_dll_get_proc_address(__u64 base_address, const char *function_name)
{
    struct lsw_module *mod;
    __u64 address = 0;
    
    lsw_info("GetProcAddress: base=0x%llx, function='%s'", base_address, function_name);
    
    mutex_lock(&lsw_module_mutex);
    
    list_for_each_entry(mod, &lsw_module_list, list) {
        if (mod->base_address == base_address) {
            /* TODO: Parse export table and find function */
            lsw_info("Found module '%s' but export parsing not yet implemented",
                     mod->name);
            
            /* For now, return a stub address */
            address = base_address + 0x1000;
            break;
        }
    }
    
    mutex_unlock(&lsw_module_mutex);
    
    if (address == 0) {
        lsw_warn("Module not found or function not exported: base=0x%llx", base_address);
    }
    
    return address;
}

/**
 * lsw_dll_unload - Unload a DLL
 */
int lsw_dll_unload(__u64 base_address)
{
    struct lsw_module *mod, *tmp;
    int found = 0;
    
    mutex_lock(&lsw_module_mutex);
    
    list_for_each_entry_safe(mod, tmp, &lsw_module_list, list) {
        if (mod->base_address == base_address) {
            found = 1;
            
            lsw_info("Unloading DLL: base=0x%llx, name='%s'",
                     base_address, mod->name);
            
            if (mod->image_data) {
                vfree(mod->image_data);
            }
            
            atomic_dec(&lsw_loaded_modules);
            
            list_del(&mod->list);
            kfree(mod);
            
            break;
        }
    }
    
    mutex_unlock(&lsw_module_mutex);
    
    if (!found) {
        lsw_warn("Module not found: base=0x%llx", base_address);
        return -ENOENT;
    }
    
    return 0;
}

/**
 * lsw_dll_cleanup_process - Cleanup all modules for a process
 */
void lsw_dll_cleanup_process(__u32 pid)
{
    struct lsw_module *mod, *tmp;
    int unloaded_count = 0;
    
    mutex_lock(&lsw_module_mutex);
    
    list_for_each_entry_safe(mod, tmp, &lsw_module_list, list) {
        if (mod->pid == pid) {
            lsw_debug("Cleaning up module: name='%s'", mod->name);
            
            if (mod->image_data) {
                vfree(mod->image_data);
            }
            
            atomic_dec(&lsw_loaded_modules);
            unloaded_count++;
            
            list_del(&mod->list);
            kfree(mod);
        }
    }
    
    mutex_unlock(&lsw_module_mutex);
    
    if (unloaded_count > 0) {
        lsw_info("Cleaned up %d modules for PID %u", unloaded_count, pid);
    }
}

/**
 * lsw_dll_init - Initialize DLL system
 */
int lsw_dll_init(void)
{
    lsw_info("DLL loading system initialized");
    lsw_info("PE format parser ready");
    return 0;
}

/**
 * lsw_dll_exit - Cleanup DLL system
 */
void lsw_dll_exit(void)
{
    struct lsw_module *mod, *tmp;
    int leaked_count = 0;
    
    mutex_lock(&lsw_module_mutex);
    
    list_for_each_entry_safe(mod, tmp, &lsw_module_list, list) {
        lsw_warn("Module leak: PID=%u, name='%s', base=0x%llx",
                 mod->pid, mod->name, mod->base_address);
        
        if (mod->image_data) {
            vfree(mod->image_data);
        }
        
        leaked_count++;
        
        list_del(&mod->list);
        kfree(mod);
    }
    
    mutex_unlock(&lsw_module_mutex);
    
    if (leaked_count > 0) {
        lsw_warn("Unloaded %d leaked modules during cleanup", leaked_count);
    }
    
    lsw_info("DLL loading system cleaned up");
}
