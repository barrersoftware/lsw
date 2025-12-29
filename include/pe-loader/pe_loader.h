/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * PE Loader - Load and execute PE files
 */

#ifndef LSW_PE_LOADER_H
#define LSW_PE_LOADER_H

#include "pe_parser.h"
#include <stdbool.h>

// Loaded PE image
typedef struct {
    pe_file_t pe;
    void* image_base;
    size_t image_size;
    void* entry_point;
    bool loaded;
} pe_image_t;

// Load PE file into memory
bool pe_load_image(pe_image_t* image, const char* filepath);

// Map sections into memory
bool pe_map_sections(pe_image_t* image);

// Resolve imports
bool pe_resolve_imports(pe_image_t* image);

// Apply relocations
bool pe_apply_relocations(pe_image_t* image);

// Execute PE image
int pe_execute(pe_image_t* image, int argc, char** argv);

// Unload PE image
void pe_unload_image(pe_image_t* image);

#endif // LSW_PE_LOADER_H
