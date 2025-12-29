/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * PE Parser - Parse Portable Executable files
 */

#ifndef LSW_PE_PARSER_H
#define LSW_PE_PARSER_H

#include "pe_format.h"
#include "lsw_types.h"
#include <stdbool.h>
#include <stdint.h>

// PE file handle
typedef struct {
    void* file_data;
    size_t file_size;
    pe_dos_header_t* dos_header;
    pe_nt_headers32_t* nt_headers32;
    pe_nt_headers64_t* nt_headers64;
    pe_section_header_t* sections;
    bool is_64bit;
    uint16_t num_sections;
} pe_file_t;

// Parse PE file from memory
bool pe_parse_file(pe_file_t* pe, const void* file_data, size_t file_size);

// Validate PE file
bool pe_validate(const pe_file_t* pe);

// Get section by name
pe_section_header_t* pe_get_section(const pe_file_t* pe, const char* name);

// Get section by RVA
pe_section_header_t* pe_get_section_by_rva(const pe_file_t* pe, uint32_t rva);

// Convert RVA to file offset
bool pe_rva_to_offset(const pe_file_t* pe, uint32_t rva, uint32_t* offset);

// Get pointer from RVA
void* pe_rva_to_ptr(const pe_file_t* pe, uint32_t rva);

// Get entry point RVA
uint32_t pe_get_entry_point(const pe_file_t* pe);

// Get image base
uint64_t pe_get_image_base(const pe_file_t* pe);

// Get subsystem
uint16_t pe_get_subsystem(const pe_file_t* pe);

// Check if DLL
bool pe_is_dll(const pe_file_t* pe);

// Free PE resources
void pe_free(pe_file_t* pe);

#endif // LSW_PE_PARSER_H
