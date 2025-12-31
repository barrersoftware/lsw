/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * PE Loader Implementation
 */

#include "pe-loader/pe_loader.h"
#include "pe-loader/pe_parser.h"
#include "pe-loader/pe_format.h"
#include "win32-api/win32_api.h"
#include "shared/lsw_kernel_client.h"
#include "lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

bool pe_load_image(pe_image_t* image, const char* filepath) {
    if (!image || !filepath) {
        LSW_LOG_ERROR("Invalid arguments to pe_load_image");
        return false;
    }
    
    memset(image, 0, sizeof(*image));
    
    // Open file
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        LSW_LOG_ERROR("Failed to open file: %s (%s)", filepath, strerror(errno));
        return false;
    }
    
    // Get file size
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        LSW_LOG_ERROR("Failed to get file size: %s", strerror(errno));
        close(fd);
        return false;
    }
    lseek(fd, 0, SEEK_SET);
    
    // Map file into memory
    void* file_data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (file_data == MAP_FAILED) {
        LSW_LOG_ERROR("Failed to map file: %s", strerror(errno));
        return false;
    }
    
    LSW_LOG_INFO("File mapped: %s (%ld bytes)", filepath, file_size);
    
    // Parse PE file
    if (!pe_parse_file(&image->pe, file_data, file_size)) {
        LSW_LOG_ERROR("Failed to parse PE file");
        munmap(file_data, file_size);
        return false;
    }
    
    // Get image size
    if (image->pe.is_64bit) {
        image->image_size = image->pe.nt_headers64->OptionalHeader.SizeOfImage;
    } else {
        image->image_size = image->pe.nt_headers32->OptionalHeader.SizeOfImage;
    }
    
    LSW_LOG_INFO("Image size: 0x%lx bytes", image->image_size);
    
    // Try to allocate memory at preferred base address
    uint64_t preferred_base = pe_get_image_base(&image->pe);
    void* hint_addr = (void*)preferred_base;
    
    image->image_base = mmap(hint_addr, image->image_size, 
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    
    if (image->image_base == MAP_FAILED) {
        // Preferred address not available, try anywhere
        LSW_LOG_WARN("Could not load at preferred base 0x%llx, loading elsewhere", 
                    (unsigned long long)preferred_base);
        image->image_base = mmap(NULL, image->image_size, 
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    
    if (image->image_base == MAP_FAILED) {
        LSW_LOG_ERROR("Failed to allocate image memory: %s", strerror(errno));
        munmap(file_data, file_size);
        return false;
    }
    
    LSW_LOG_INFO("Image base allocated at: %p (preferred: 0x%llx)", 
                image->image_base, (unsigned long long)preferred_base);
    
    // Map sections
    if (!pe_map_sections(image)) {
        LSW_LOG_ERROR("Failed to map sections");
        munmap(image->image_base, image->image_size);
        munmap(file_data, file_size);
        return false;
    }
    
    // Calculate entry point
    uint32_t entry_rva = pe_get_entry_point(&image->pe);
    image->entry_point = (uint8_t*)image->image_base + entry_rva;
    
    LSW_LOG_INFO("Entry point: %p (RVA: 0x%08x)", image->entry_point, entry_rva);
    
    // Initialize Win32 API
    win32_api_init();
    
    // Resolve imports
    if (!pe_resolve_imports(image)) {
        LSW_LOG_ERROR("Failed to resolve imports");
        munmap(image->image_base, image->image_size);
        munmap(file_data, file_size);
        return false;
    }
    
    // Apply relocations if needed
    if (!pe_apply_relocations(image)) {
        LSW_LOG_ERROR("Failed to apply relocations");
        munmap(image->image_base, image->image_size);
        munmap(file_data, file_size);
        return false;
    }
    
    image->loaded = true;
    
    // Keep file_data mapped - we'll need it for relocs/imports
    // TODO: Should probably copy what we need and unmap
    
    return true;
}

bool pe_map_sections(pe_image_t* image) {
    if (!image || !image->pe.sections) {
        LSW_LOG_ERROR("Invalid image or no sections");
        return false;
    }
    
    LSW_LOG_INFO("Mapping %u sections...", image->pe.num_sections);
    
    for (uint16_t i = 0; i < image->pe.num_sections; i++) {
        pe_section_header_t* section = &image->pe.sections[i];
        
        char name[9] = {0};
        memcpy(name, section->Name, 8);
        
        // Skip empty sections
        if (section->SizeOfRawData == 0) {
            LSW_LOG_DEBUG("Skipping empty section: %s", name);
            continue;
        }
        
        // Calculate destination
        void* dest = (uint8_t*)image->image_base + section->VirtualAddress;
        
        // Calculate source
        void* src = (uint8_t*)image->pe.file_data + section->PointerToRawData;
        
        // Copy section data
        size_t copy_size = section->SizeOfRawData < section->VirtualSize ? 
                          section->SizeOfRawData : section->VirtualSize;
        
        memcpy(dest, src, copy_size);
        
        LSW_LOG_DEBUG("Mapped section %s: %p (0x%x bytes)", name, dest, copy_size);
        
        // Set memory protections
        int prot = 0;
        if (section->Characteristics & PE_SCN_MEM_READ) prot |= PROT_READ;
        if (section->Characteristics & PE_SCN_MEM_WRITE) prot |= PROT_WRITE;
        if (section->Characteristics & PE_SCN_MEM_EXECUTE) prot |= PROT_EXEC;
        
        // Apply protections (aligned to page boundary)
        size_t page_size = sysconf(_SC_PAGESIZE);
        void* aligned_addr = (void*)((uintptr_t)dest & ~(page_size - 1));
        size_t aligned_size = ((copy_size + page_size - 1) / page_size) * page_size;
        
        if (mprotect(aligned_addr, aligned_size, prot) != 0) {
            LSW_LOG_WARN("Failed to set protection for %s: %s", name, strerror(errno));
        }
    }
    
    LSW_LOG_INFO("All sections mapped successfully");
    return true;
}

bool pe_resolve_imports(pe_image_t* image) {
    pe_data_directory_t* import_dir = pe_get_data_directory(&image->pe, PE_DIR_IMPORT);
    if (!import_dir || !import_dir->VirtualAddress) {
        LSW_LOG_INFO("No import directory - skipping import resolution");
        return true;
    }
    
    LSW_LOG_INFO("Resolving imports...");
    
    // Get import descriptor table
    uint32_t import_rva = import_dir->VirtualAddress;
    pe_import_descriptor_t* import_desc = (pe_import_descriptor_t*)((uint8_t*)image->image_base + import_rva);
    
    int dll_count = 0;
    int func_count = 0;
    
    // Iterate through each DLL
    while (import_desc->NameRVA != 0) {
        const char* dll_name = (const char*)((uint8_t*)image->image_base + import_desc->NameRVA);
        LSW_LOG_INFO("  DLL: %s", dll_name);
        dll_count++;
        
        // Get the Import Address Table (IAT)
        uint64_t* iat = (uint64_t*)((uint8_t*)image->image_base + import_desc->ImportAddressTableRVA);
        uint64_t* ilt = (uint64_t*)((uint8_t*)image->image_base + 
                                     (import_desc->ImportLookupTableRVA ? import_desc->ImportLookupTableRVA : import_desc->ImportAddressTableRVA));
        
        // Resolve each function
        for (int i = 0; ilt[i] != 0; i++) {
            const char* func_name = NULL;
            
            // Check if import by name or ordinal
            if (!(ilt[i] & PE_ORDINAL_FLAG64)) {
                // Import by name
                pe_import_by_name_t* import_name = (pe_import_by_name_t*)((uint8_t*)image->image_base + ilt[i]);
                func_name = (const char*)import_name->Name;
            } else {
                // Import by ordinal - skip for now
                LSW_LOG_WARN("    Ordinal import not supported yet");
                continue;
            }
            
            // Resolve the function
            void* func_addr = win32_api_resolve(dll_name, func_name);
            if (func_addr) {
                iat[i] = (uint64_t)func_addr;
                func_count++;
                LSW_LOG_DEBUG("    ✓ %s -> %p", func_name, func_addr);
            } else {
                LSW_LOG_WARN("    ✗ %s - unresolved", func_name);
                // Leave as NULL - will crash if called
                iat[i] = 0;
            }
        }
        
        import_desc++;
    }
    
    LSW_LOG_INFO("Import resolution complete: %d DLLs, %d functions", dll_count, func_count);
    return true;
}

bool pe_apply_relocations(pe_image_t* image) {
    LSW_LOG_INFO("Relocation not yet implemented");
    // TODO: Implement base relocations
    // This is needed if image isn't loaded at preferred base address
    return true;
}

int pe_execute(pe_image_t* image, int argc, char** argv) {
    if (!image || !image->loaded || !image->entry_point) {
        LSW_LOG_ERROR("Image not loaded or no entry point");
        return -1;
    }
    
    LSW_LOG_INFO("🚀 Executing PE image via kernel module...");
    LSW_LOG_INFO("Entry point: %p", image->entry_point);
    
    // Open kernel device
    int kernel_fd = lsw_kernel_open();
    if (kernel_fd < 0) {
        LSW_LOG_ERROR("Failed to open kernel device /dev/lsw");
        LSW_LOG_ERROR("Make sure the LSW kernel module is loaded: sudo insmod kernel-module/lsw.ko");
        return -1;
    }
    
    // Prepare PE info for kernel
    struct lsw_pe_info pe_info;
    memset(&pe_info, 0, sizeof(pe_info));
    pe_info.pid = getpid();
    pe_info.base_address = (uint64_t)image->image_base;
    pe_info.entry_point = (uint64_t)image->entry_point;
    pe_info.image_size = image->image_size;
    pe_info.is_64bit = image->pe.is_64bit ? 1 : 0;
    
    // Get executable path from argv or use placeholder
    const char* exe_path = (argc > 0 && argv && argv[0]) ? argv[0] : "unknown.exe";
    strncpy(pe_info.executable_path, exe_path, sizeof(pe_info.executable_path) - 1);
    
    LSW_LOG_INFO("Registering PE with kernel:");
    LSW_LOG_INFO("  PID: %u", pe_info.pid);
    LSW_LOG_INFO("  Base: 0x%lx", pe_info.base_address);
    LSW_LOG_INFO("  Entry: 0x%lx", pe_info.entry_point);
    LSW_LOG_INFO("  Size: 0x%x", pe_info.image_size);
    LSW_LOG_INFO("  Arch: %s", pe_info.is_64bit ? "64-bit" : "32-bit");
    
    // Register PE with kernel
    int ret = lsw_kernel_register_pe(kernel_fd, &pe_info);
    if (ret < 0) {
        LSW_LOG_ERROR("Failed to register PE with kernel");
        lsw_kernel_close(kernel_fd);
        return -1;
    }
    
    LSW_LOG_INFO("✅ PE registered with kernel successfully");
    LSW_LOG_INFO("TODO: Kernel needs to execute the PE at entry point");
    LSW_LOG_INFO("For now, PE is loaded and registered but not executed");
    
    // TODO: Trigger kernel execution
    // TODO: Wait for execution completion
    // TODO: Get exit code from kernel
    
    // Cleanup
    lsw_kernel_unregister_pe(kernel_fd, pe_info.pid);
    lsw_kernel_close(kernel_fd);
    
    return 0;
}

void pe_unload_image(pe_image_t* image) {
    if (!image) {
        return;
    }
    
    if (image->image_base && image->image_size > 0) {
        munmap(image->image_base, image->image_size);
    }
    
    if (image->pe.file_data && image->pe.file_size > 0) {
        munmap(image->pe.file_data, image->pe.file_size);
    }
    
    pe_free(&image->pe);
    memset(image, 0, sizeof(*image));
    
    LSW_LOG_INFO("PE image unloaded");
}
