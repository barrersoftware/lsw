/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * PE Parser Implementation
 */

#include "pe-loader/pe_parser.h"
#include "pe-loader/pe_format.h"
#include "lsw_log.h"
#include <string.h>
#include <stdlib.h>

bool pe_parse_file(pe_file_t* pe, const void* file_data, size_t file_size) {
    if (!pe || !file_data || file_size < sizeof(pe_dos_header_t)) {
        LSW_LOG_ERROR("Invalid arguments to pe_parse_file");
        return false;
    }
    
    memset(pe, 0, sizeof(*pe));
    pe->file_data = (void*)file_data;
    pe->file_size = file_size;
    
    // Parse DOS header
    pe->dos_header = (pe_dos_header_t*)file_data;
    
    if (pe->dos_header->e_magic != PE_DOS_SIGNATURE) {
        LSW_LOG_ERROR("Invalid DOS signature: 0x%04x (expected 0x%04x)", 
                     pe->dos_header->e_magic, PE_DOS_SIGNATURE);
        return false;
    }
    
    // Validate PE header offset
    if (pe->dos_header->e_lfanew == 0 || 
        pe->dos_header->e_lfanew >= file_size - sizeof(uint32_t)) {
        LSW_LOG_ERROR("Invalid PE header offset: 0x%08x", pe->dos_header->e_lfanew);
        return false;
    }
    
    // Check NT signature
    uint32_t* nt_sig = (uint32_t*)((uint8_t*)file_data + pe->dos_header->e_lfanew);
    if (*nt_sig != PE_NT_SIGNATURE) {
        LSW_LOG_ERROR("Invalid NT signature: 0x%08x (expected 0x%08x)", 
                     *nt_sig, PE_NT_SIGNATURE);
        return false;
    }
    
    // Determine if 32-bit or 64-bit
    uint16_t* magic = (uint16_t*)((uint8_t*)nt_sig + sizeof(uint32_t) + sizeof(pe_coff_header_t));
    
    if (*magic == PE_MAGIC_PE32) {
        pe->is_64bit = false;
        pe->nt_headers32 = (pe_nt_headers32_t*)nt_sig;
        pe->num_sections = pe->nt_headers32->FileHeader.NumberOfSections;
        
        LSW_LOG_DEBUG("PE32 (32-bit) executable detected");
        LSW_LOG_DEBUG("Sections: %u", pe->num_sections);
        LSW_LOG_DEBUG("Entry point: 0x%08x", pe->nt_headers32->OptionalHeader.AddressOfEntryPoint);
        
    } else if (*magic == PE_MAGIC_PE32PLUS) {
        pe->is_64bit = true;
        pe->nt_headers64 = (pe_nt_headers64_t*)nt_sig;
        pe->num_sections = pe->nt_headers64->FileHeader.NumberOfSections;
        
        LSW_LOG_DEBUG("PE32+ (64-bit) executable detected");
        LSW_LOG_DEBUG("Sections: %u", pe->num_sections);
        LSW_LOG_DEBUG("Entry point: 0x%08x", pe->nt_headers64->OptionalHeader.AddressOfEntryPoint);
        
    } else {
        LSW_LOG_ERROR("Unknown PE magic: 0x%04x", *magic);
        return false;
    }
    
    // Parse section table
    size_t sections_offset = pe->dos_header->e_lfanew + 
                            sizeof(uint32_t) + 
                            sizeof(pe_coff_header_t) +
                            (pe->is_64bit ? 
                             pe->nt_headers64->FileHeader.SizeOfOptionalHeader :
                             pe->nt_headers32->FileHeader.SizeOfOptionalHeader);
    
    if (sections_offset + (pe->num_sections * sizeof(pe_section_header_t)) > file_size) {
        LSW_LOG_ERROR("Section table extends beyond file");
        return false;
    }
    
    pe->sections = (pe_section_header_t*)((uint8_t*)file_data + sections_offset);
    
    // Log sections
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        char name[9] = {0};
        memcpy(name, pe->sections[i].Name, 8);
        LSW_LOG_DEBUG("Section %u: %s (VA: 0x%08x, Size: 0x%08x)", 
                     i, name, 
                     pe->sections[i].VirtualAddress,
                     pe->sections[i].VirtualSize);
    }
    
    return true;
}

bool pe_validate(const pe_file_t* pe) {
    if (!pe || !pe->dos_header) {
        return false;
    }
    
    if (pe->dos_header->e_magic != PE_DOS_SIGNATURE) {
        return false;
    }
    
    if (pe->is_64bit && !pe->nt_headers64) {
        return false;
    }
    
    if (!pe->is_64bit && !pe->nt_headers32) {
        return false;
    }
    
    return true;
}

pe_section_header_t* pe_get_section(const pe_file_t* pe, const char* name) {
    if (!pe || !name || !pe->sections) {
        return NULL;
    }
    
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        if (strncmp((char*)pe->sections[i].Name, name, 8) == 0) {
            return &pe->sections[i];
        }
    }
    
    return NULL;
}

pe_section_header_t* pe_get_section_by_rva(const pe_file_t* pe, uint32_t rva) {
    if (!pe || !pe->sections) {
        return NULL;
    }
    
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        uint32_t section_start = pe->sections[i].VirtualAddress;
        uint32_t section_end = section_start + pe->sections[i].VirtualSize;
        
        if (rva >= section_start && rva < section_end) {
            return &pe->sections[i];
        }
    }
    
    return NULL;
}

bool pe_rva_to_offset(const pe_file_t* pe, uint32_t rva, uint32_t* offset) {
    if (!pe || !offset) {
        return false;
    }
    
    pe_section_header_t* section = pe_get_section_by_rva(pe, rva);
    if (!section) {
        return false;
    }
    
    *offset = rva - section->VirtualAddress + section->PointerToRawData;
    return true;
}

void* pe_rva_to_ptr(const pe_file_t* pe, uint32_t rva) {
    uint32_t offset;
    if (!pe_rva_to_offset(pe, rva, &offset)) {
        return NULL;
    }
    
    if (offset >= pe->file_size) {
        return NULL;
    }
    
    return (uint8_t*)pe->file_data + offset;
}

uint32_t pe_get_entry_point(const pe_file_t* pe) {
    if (!pe) {
        return 0;
    }
    
    if (pe->is_64bit) {
        return pe->nt_headers64->OptionalHeader.AddressOfEntryPoint;
    } else {
        return pe->nt_headers32->OptionalHeader.AddressOfEntryPoint;
    }
}

uint64_t pe_get_image_base(const pe_file_t* pe) {
    if (!pe) {
        return 0;
    }
    
    if (pe->is_64bit) {
        return pe->nt_headers64->OptionalHeader.ImageBase;
    } else {
        return pe->nt_headers32->OptionalHeader.ImageBase;
    }
}

uint16_t pe_get_subsystem(const pe_file_t* pe) {
    if (!pe) {
        return 0;
    }
    
    if (pe->is_64bit) {
        return pe->nt_headers64->OptionalHeader.Subsystem;
    } else {
        return pe->nt_headers32->OptionalHeader.Subsystem;
    }
}

bool pe_is_dll(const pe_file_t* pe) {
    if (!pe) {
        return false;
    }
    
    uint16_t characteristics;
    if (pe->is_64bit) {
        characteristics = pe->nt_headers64->FileHeader.Characteristics;
    } else {
        characteristics = pe->nt_headers32->FileHeader.Characteristics;
    }
    
    return (characteristics & PE_CHAR_DLL) != 0;
}

pe_data_directory_t* pe_get_data_directory(const pe_file_t* pe, int index) {
    if (!pe || index < 0 || index >= PE_NUMBER_OF_DIRECTORY_ENTRIES) {
        return NULL;
    }
    
    if (pe->is_64bit) {
        return &pe->nt_headers64->OptionalHeader.DataDirectory[index];
    } else {
        return &pe->nt_headers32->OptionalHeader.DataDirectory[index];
    }
}

void pe_free(pe_file_t* pe) {
    if (pe) {
        // We don't own file_data, so don't free it
        memset(pe, 0, sizeof(*pe));
    }
}
