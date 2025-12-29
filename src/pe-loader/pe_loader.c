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
    
    // Allocate memory for image
    image->image_base = mmap(NULL, image->image_size, 
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (image->image_base == MAP_FAILED) {
        LSW_LOG_ERROR("Failed to allocate image memory: %s", strerror(errno));
        munmap(file_data, file_size);
        return false;
    }
    
    LSW_LOG_INFO("Image base allocated at: %p", image->image_base);
    
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
    LSW_LOG_INFO("Import resolution not yet implemented");
    // TODO: Implement import resolution
    // This is where we'd load DLLs and resolve function addresses
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
    
    LSW_LOG_INFO("🚀 Executing PE image...");
    LSW_LOG_INFO("Entry point: %p", image->entry_point);
    
    // TODO: Set up Windows environment (TEB, PEB, etc.)
    // TODO: Set up exception handlers
    // TODO: Initialize Win32 API stubs
    
    LSW_LOG_WARN("⚠️  Execution not fully implemented yet");
    LSW_LOG_INFO("Would execute function at: %p", image->entry_point);
    
    // This would be something like:
    // typedef int (*entry_func_t)(void);
    // entry_func_t entry = (entry_func_t)image->entry_point;
    // return entry();
    
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
