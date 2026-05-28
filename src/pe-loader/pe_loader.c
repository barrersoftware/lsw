/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * PE Loader Implementation
 */

#define _GNU_SOURCE
#include "pe-loader/pe_loader.h"
#include "pe-loader/pe_parser.h"
#include "pe-loader/pe_format.h"
#include "win32-api/win32_api.h"
#include "win32-api/win32_teb.h"
#include "shared/lsw_kernel_client.h"
#include "lsw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>
#include <ucontext.h>
#include <setjmp.h>
#include <ctype.h>

// ============================================================================
// DLL chain loader — real DLL search & export resolution
// ============================================================================

/* Forward declaration — implementation after pe_resolve_imports */
static const char* apiset_resolve(const char* dll_name);

/*
 * Search paths for real Windows DLL files, in priority order.
 * Users can place DLL files (from a Windows installation, Wine, or the
 * official Windows Compatibility Toolkit) in any of these locations.
 * Set LSW_SYSTEM32 env var to override the default search paths.
 */
#define LSW_MAX_DLL_SEARCH_PATHS 8
#define LSW_MAX_LOADED_DLLS      64

typedef struct {
    char   dll_name[64];    /* lower-cased DLL name, e.g. "msvcrt.dll" */
    void*  image_base;
    size_t image_size;
    pe_file_t pe;
} lsw_loaded_dll_t;

static lsw_loaded_dll_t g_loaded_dlls[LSW_MAX_LOADED_DLLS];
static int g_loaded_dll_count = 0;

/* Case-insensitive DLL name match */
static int dll_name_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

/* Build search paths from environment or defaults */
static int build_dll_search_paths(char paths[][512], int max_paths)
{
    int n = 0;
    const char* env_path = getenv("LSW_SYSTEM32");

    /* User-specified path takes priority */
    if (env_path && env_path[0] && n < max_paths) {
        snprintf(paths[n++], 512, "%s", env_path);
    }

    const char* home = getenv("HOME");
    if (!home) home = "/root";

    /* ~/.lsw/system32/ — LSW-specific Windows files */
    if (n < max_paths) snprintf(paths[n++], 512, "%s/.lsw/system32", home);
    /* ~/.wine/drive_c/windows/system32/ — Wine installation */
    if (n < max_paths) snprintf(paths[n++], 512, "%s/.wine/drive_c/windows/system32", home);
    /* /opt/lsw/system32/ — system-wide installation */
    if (n < max_paths) snprintf(paths[n++], 512, "/opt/lsw/system32");
    /* /usr/share/lsw/system32/ — package manager installation */
    if (n < max_paths) snprintf(paths[n++], 512, "/usr/share/lsw/system32");

    return n;
}

/* Look up an already-loaded DLL by name */
static lsw_loaded_dll_t* find_loaded_dll(const char* dll_name)
{
    for (int i = 0; i < g_loaded_dll_count; i++) {
        if (dll_name_eq(g_loaded_dlls[i].dll_name, dll_name))
            return &g_loaded_dlls[i];
    }
    return NULL;
}

/* Resolve a named export from a loaded DLL image */
static void* resolve_export_from_dll(lsw_loaded_dll_t* dll, const char* func_name)
{
    pe_data_directory_t* exp_dir = pe_get_data_directory(&dll->pe, PE_DIR_EXPORT);
    if (!exp_dir || !exp_dir->VirtualAddress) return NULL;

    pe_export_directory_t* exp = (pe_export_directory_t*)(
        (uint8_t*)dll->image_base + exp_dir->VirtualAddress);

    uint32_t* name_ptrs = (uint32_t*)((uint8_t*)dll->image_base + exp->AddressOfNames);
    uint16_t* ordinals  = (uint16_t*)((uint8_t*)dll->image_base + exp->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)((uint8_t*)dll->image_base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)((uint8_t*)dll->image_base + name_ptrs[i]);
        if (strcmp(name, func_name) == 0) {
            uint32_t rva = functions[ordinals[i]];
            return (void*)((uint8_t*)dll->image_base + rva);
        }
    }
    return NULL;
}

/* Load a real DLL file from disk, map it, and register it in g_loaded_dlls */
static lsw_loaded_dll_t* load_real_dll(const char* dll_name)
{
    char search_paths[LSW_MAX_DLL_SEARCH_PATHS][512];
    int  n_paths;
    char filepath[640];

    /* Already at capacity? */
    if (g_loaded_dll_count >= LSW_MAX_LOADED_DLLS) {
        LSW_LOG_WARN("DLL chain: table full (%d), cannot load %s",
                     LSW_MAX_LOADED_DLLS, dll_name);
        return NULL;
    }

    n_paths = build_dll_search_paths(search_paths, LSW_MAX_DLL_SEARCH_PATHS);

    for (int p = 0; p < n_paths; p++) {
        snprintf(filepath, sizeof(filepath), "%s/%s", search_paths[p], dll_name);
        /* Try exact case first, then lower-cased */
        struct stat st;
        if (stat(filepath, &st) != 0) {
            /* Try lower-cased filename */
            char lower_name[64];
            size_t j;
            for (j = 0; dll_name[j] && j < sizeof(lower_name) - 1; j++)
                lower_name[j] = (char)tolower((unsigned char)dll_name[j]);
            lower_name[j] = '\0';
            snprintf(filepath, sizeof(filepath), "%s/%s", search_paths[p], lower_name);
            if (stat(filepath, &st) != 0)
                continue;
        }

        /* Found the file — load it */
        int fd = open(filepath, O_RDONLY);
        if (fd < 0) continue;

        off_t file_size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        if (file_size <= 0) { close(fd); continue; }

        void* file_data = mmap(NULL, (size_t)file_size, PROT_READ,
                               MAP_PRIVATE, fd, 0);
        close(fd);
        if (file_data == MAP_FAILED) continue;

        /* Parse the DLL PE headers */
        lsw_loaded_dll_t* slot = &g_loaded_dlls[g_loaded_dll_count];
        memset(slot, 0, sizeof(*slot));

        if (!pe_parse_file(&slot->pe, file_data, (size_t)file_size)) {
            LSW_LOG_WARN("DLL chain: pe_parse_file failed for %s", filepath);
            munmap(file_data, (size_t)file_size);
            continue;
        }

        /* Allocate memory for the DLL image */
        size_t image_size = slot->pe.is_64bit
            ? slot->pe.nt_headers64->OptionalHeader.SizeOfImage
            : slot->pe.nt_headers32->OptionalHeader.SizeOfImage;

        void* image_base = mmap(NULL, image_size,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (image_base == MAP_FAILED) {
            munmap(file_data, (size_t)file_size);
            continue;
        }

        /* Copy sections */
        for (uint16_t s = 0; s < slot->pe.num_sections; s++) {
            pe_section_header_t* sec = &slot->pe.sections[s];
            if (sec->SizeOfRawData == 0) continue;
            void* dst = (uint8_t*)image_base + sec->VirtualAddress;
            void* src = (uint8_t*)file_data  + sec->PointerToRawData;
            size_t copy_sz = sec->SizeOfRawData < sec->VirtualSize
                           ? sec->SizeOfRawData : sec->VirtualSize;
            memcpy(dst, src, copy_sz);
        }

        munmap(file_data, (size_t)file_size);

        slot->image_base = image_base;
        slot->image_size = image_size;

        /* Store lower-cased name */
        size_t k;
        for (k = 0; dll_name[k] && k < sizeof(slot->dll_name) - 1; k++)
            slot->dll_name[k] = (char)tolower((unsigned char)dll_name[k]);
        slot->dll_name[k] = '\0';

        g_loaded_dll_count++;
        LSW_LOG_INFO("DLL chain: loaded real %s from %s (base=%p, size=0x%zx)",
                     dll_name, filepath, image_base, image_size);
        return slot;
    }

    LSW_LOG_DEBUG("DLL chain: %s not found in any search path — using stubs", dll_name);
    return NULL;
}

/*
 * Resolve a Win32 import first from our stub table, then from any real
 * DLL files found on disk.  Returns NULL only if completely unresolved
 * (caller will install a generic stub so execution can continue).
 */
static void* resolve_import_with_dll_chain(const char* dll_name,
                                            const char* func_name)
{
    /* 1. Try our built-in Win32 API stubs (fast path, covers most apps) */
    void* addr = win32_api_resolve(dll_name, func_name);
    if (addr) return addr;

    /* 2. Check already-loaded real DLLs */
    lsw_loaded_dll_t* dll = find_loaded_dll(dll_name);
    if (!dll) {
        /* 3. Try loading the DLL from disk */
        dll = load_real_dll(dll_name);
    }

    if (dll) {
        addr = resolve_export_from_dll(dll, func_name);
        if (addr) {
            LSW_LOG_DEBUG("DLL chain: resolved %s!%s from real DLL → %p",
                          dll_name, func_name, addr);
            return addr;
        }
    }

    return NULL;
}

void pe_dll_chain_cleanup(void)
{
    for (int i = 0; i < g_loaded_dll_count; i++) {
        if (g_loaded_dlls[i].image_base)
            munmap(g_loaded_dlls[i].image_base, g_loaded_dlls[i].image_size);
    }
    g_loaded_dll_count = 0;
}


// SEH / Signal-based exception handling
// ============================================================================

// Windows exception codes mapped from Linux signals
#define WIN_EXCEPTION_ACCESS_VIOLATION   0xC0000005
#define WIN_EXCEPTION_ILLEGAL_INSTRUCTION 0xC000001D
#define WIN_EXCEPTION_INT_DIVIDE_BY_ZERO  0xC0000094
#define WIN_EXCEPTION_STACK_OVERFLOW      0xC00000FD
#define WIN_EXCEPTION_GUARD_PAGE          0x80000001

// Simple vectored exception handler type (mirrors Windows VEH signature)
typedef int (*lsw_veh_handler_t)(uint32_t exception_code, void* context);

#define LSW_MAX_VEH_HANDLERS 16
static lsw_veh_handler_t g_veh_handlers[LSW_MAX_VEH_HANDLERS];
static int g_veh_count = 0;

void lsw_add_veh_handler(lsw_veh_handler_t h) {
    if (g_veh_count < LSW_MAX_VEH_HANDLERS)
        g_veh_handlers[g_veh_count++] = h;
}

// Dispatch an exception through VEH handlers and the SEH chain in the TEB.
// Returns 1 if handled (execution continues), 0 if unhandled (terminate).
static int lsw_dispatch_exception(uint32_t code, siginfo_t* si, ucontext_t* uc) {
    LSW_LOG_ERROR("Win32 Exception: code=0x%08x addr=%p", code, si->si_addr);

    // Walk VEH handlers first
    for (int i = 0; i < g_veh_count; i++) {
        if (g_veh_handlers[i](code, uc) != 0) {
            LSW_LOG_INFO("Exception handled by VEH handler %d", i);
            return 1;
        }
    }

    // Walk SEH chain from TEB.ExceptionList (gs:0x00)
    win32_teb_t* teb = win32_teb_get();
    if (teb) {
        // SEH frame: { EXCEPTION_REGISTRATION_RECORD* Next; void* Handler; }
        typedef struct _seh_frame {
            struct _seh_frame* next;
            void* handler;
        } seh_frame_t;

        seh_frame_t* frame = (seh_frame_t*)teb->ExceptionList;
        int depth = 0;
        while (frame && (uintptr_t)frame != 0xFFFFFFFFFFFFFFFFULL && depth < 64) {
            typedef int (*seh_handler_t)(uint32_t, seh_frame_t*, void*, void*);
            seh_handler_t h = (seh_handler_t)frame->handler;
            if (h) {
                LSW_LOG_INFO("  SEH frame[%d] handler=%p", depth, (void*)h);
                // EXCEPTION_EXECUTE_HANDLER = 1, EXCEPTION_CONTINUE_EXECUTION = -1
                // We pass minimal args; real SEH needs full EXCEPTION_RECORD + CONTEXT
                // but this at least gives handlers a chance to run
                int r = h(code, frame, uc, NULL);
                if (r == -1) { // EXCEPTION_CONTINUE_EXECUTION
                    LSW_LOG_INFO("  SEH: continue execution");
                    return 1;
                }
                if (r == 1) { // EXCEPTION_EXECUTE_HANDLER
                    LSW_LOG_INFO("  SEH: execute handler (unwind)");
                    // In a full implementation, we'd unwind the stack here.
                    // For now, log and terminate gracefully.
                    break;
                }
            }
            frame = frame->next;
            depth++;
        }
    }

    // Print backtrace before giving up
    void* bt[16];
    int n = backtrace(bt, 16);
    LSW_LOG_ERROR("Unhandled exception — backtrace:");
    backtrace_symbols_fd(bt, n, STDERR_FILENO);
    return 0;
}

static void lsw_signal_handler(int sig, siginfo_t* si, void* ctx) {
    ucontext_t* uc = (ucontext_t*)ctx;
    uint32_t code;
    switch (sig) {
        case SIGSEGV: code = WIN_EXCEPTION_ACCESS_VIOLATION;    break;
        case SIGILL:  code = WIN_EXCEPTION_ILLEGAL_INSTRUCTION; break;
        case SIGFPE:  code = WIN_EXCEPTION_INT_DIVIDE_BY_ZERO;  break;
        case SIGBUS:  code = WIN_EXCEPTION_ACCESS_VIOLATION;    break;
        case SIGTRAP: code = 0x80000003; /* EXCEPTION_BREAKPOINT */ break;
        default:      code = 0xC0000000 | (uint32_t)sig;       break;
    }

    if (!lsw_dispatch_exception(code, si, uc)) {
        LSW_LOG_ERROR("Fatal: unhandled signal %d at %p — terminating", sig, si->si_addr);
        _exit(139);
    }
}

static void lsw_install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = lsw_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    LSW_LOG_INFO("SEH signal handlers installed (SIGSEGV/SIGILL/SIGFPE/SIGBUS/SIGTRAP)");
}

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
    lsw_set_exe_path(filepath);
    win32_api_init();
    
    // Resolve imports
    if (!pe_resolve_imports(image)) {
        LSW_LOG_ERROR("Failed to resolve imports");
        munmap(image->image_base, image->image_size);
        munmap(file_data, file_size);
        return false;
    }

    // Resolve delay-load imports (eager resolution)
    if (!pe_resolve_delay_imports(image)) {
        LSW_LOG_WARN("Delay-load import resolution had errors (non-fatal)");
    }

    // Apply relocations if needed
    if (!pe_apply_relocations(image)) {
        LSW_LOG_ERROR("Failed to apply relocations");
        munmap(image->image_base, image->image_size);
        munmap(file_data, file_size);
        return false;
    }

    // Apply correct R/W/X protections now that IAT is written
    pe_apply_section_permissions(image);

    // Run TLS callbacks (MSVC CRT static constructors, etc.)
    if (!pe_process_tls_callbacks(image)) {
        LSW_LOG_ERROR("Failed to process TLS callbacks");
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
        // For now, make everything RWX to avoid protection issues during CRT init
        // TODO: Apply proper protections after CRT initialization completes
        int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
        
        // Original protection logic (disabled for now):
        // if (section->Characteristics & PE_SCN_MEM_READ) prot |= PROT_READ;
        // if (section->Characteristics & PE_SCN_MEM_WRITE) prot |= PROT_WRITE;
        // if (section->Characteristics & PE_SCN_MEM_EXECUTE) prot |= PROT_EXEC;
        
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

bool pe_apply_section_permissions(pe_image_t* image) {
    if (!image || !image->pe.sections) return true;

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    LSW_LOG_INFO("Applying section permissions (%u sections)...", image->pe.num_sections);

    for (uint16_t i = 0; i < image->pe.num_sections; i++) {
        pe_section_header_t* sec = &image->pe.sections[i];
        if (sec->VirtualSize == 0 && sec->SizeOfRawData == 0) continue;

        uint32_t ch = sec->Characteristics;
        int prot = 0;
        if (ch & PE_SCN_MEM_READ)    prot |= PROT_READ;
        if (ch & PE_SCN_MEM_WRITE)   prot |= PROT_WRITE;
        if (ch & PE_SCN_MEM_EXECUTE) prot |= PROT_READ | PROT_EXEC;
        if (prot == 0) prot = PROT_READ; // at least readable

        void* va   = (uint8_t*)image->image_base + sec->VirtualAddress;
        size_t sz  = sec->VirtualSize ? sec->VirtualSize : sec->SizeOfRawData;

        // Align to page boundaries
        uintptr_t base_aligned = (uintptr_t)va & ~(page_size - 1);
        size_t    size_aligned = ((sz + page_size - 1) / page_size) * page_size;

        char name[9] = {0};
        memcpy(name, sec->Name, 8);
        if (mprotect((void*)base_aligned, size_aligned, prot) != 0) {
            LSW_LOG_WARN("mprotect failed for section %s: %s", name, strerror(errno));
        } else {
            LSW_LOG_DEBUG("  %s: %c%c%c", name,
                (prot & PROT_READ)  ? 'R' : '-',
                (prot & PROT_WRITE) ? 'W' : '-',
                (prot & PROT_EXEC)  ? 'X' : '-');
        }
    }
    LSW_LOG_INFO("Section permissions applied");
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
        const char* raw_dll  = (const char*)((uint8_t*)image->image_base + import_desc->NameRVA);
        const char* dll_name = apiset_resolve(raw_dll);
        if (strcmp(raw_dll, dll_name) != 0)
            LSW_LOG_INFO("  DLL: %s → %s", raw_dll, dll_name);
        else
            LSW_LOG_INFO("  DLL: %s", dll_name);
        dll_count++;
        
        // Get the Import Address Table (IAT) — entry width depends on PE32 vs PE64
        uint32_t ilt_rva = import_desc->ImportLookupTableRVA
                           ? import_desc->ImportLookupTableRVA
                           : import_desc->ImportAddressTableRVA;
        void* ilt_base = (uint8_t*)image->image_base + ilt_rva;
        void* iat_base = (uint8_t*)image->image_base + import_desc->ImportAddressTableRVA;

        // Resolve each function — handle PE32 (4-byte) and PE64 (8-byte) entries
        for (int i = 0; ; i++) {
            uint64_t entry, ordinal_flag;
            if (image->pe.is_64bit) {
                entry        = ((uint64_t*)ilt_base)[i];
                ordinal_flag = PE_ORDINAL_FLAG64;
            } else {
                uint32_t e32 = ((uint32_t*)ilt_base)[i];
                if (e32 == 0) break;
                entry        = (uint64_t)e32;
                ordinal_flag = PE_ORDINAL_FLAG32;
            }
            if (entry == 0) break;

            const char* func_name = NULL;

            // Check if import by name or ordinal
            if (!(entry & ordinal_flag)) {
                // Import by name (RVA points to pe_import_by_name_t)
                pe_import_by_name_t* import_name = (pe_import_by_name_t*)((uint8_t*)image->image_base + (uint32_t)entry);
                func_name = (const char*)import_name->Name;
            } else {
                // Import by ordinal — low 16 bits are the ordinal
                uint16_t ordinal = (uint16_t)(entry & 0xFFFF);
                void* func_addr = win32_api_resolve_ordinal(dll_name, ordinal);
                if (func_addr) {
                    LSW_LOG_DEBUG("    ✓ %s!#%u -> %p", dll_name, ordinal, func_addr);
                } else {
                    LSW_LOG_WARN("    ✗ %s!#%u (ordinal) - using generic stub", dll_name, ordinal);
                    func_addr = win32_api_get_generic_stub();
                }
                // Write resolved address into the IAT — width matches PE bitness
                if (image->pe.is_64bit) {
                    ((uint64_t*)iat_base)[i] = (uint64_t)func_addr;
                } else {
                    ((uint32_t*)iat_base)[i] = (uint32_t)(uintptr_t)func_addr;
                }
                func_count++;
                continue;
            }

            // Resolve the function — data symbols first, then stubs, then DLL chain
            void* func_addr = win32_api_resolve_data(dll_name, func_name);
            if (!func_addr)
                func_addr = resolve_import_with_dll_chain(dll_name, func_name);
            if (func_addr) {
                LSW_LOG_DEBUG("    ✓ %s -> %p", func_name, func_addr);
            } else {
                LSW_LOG_WARN("    ✗ %s!%s - unresolved, using stub", dll_name, func_name);
                func_addr = win32_api_get_generic_stub();
            }
            if (image->pe.is_64bit) {
                ((uint64_t*)iat_base)[i] = (uint64_t)func_addr;
            } else {
                ((uint32_t*)iat_base)[i] = (uint32_t)(uintptr_t)func_addr;
            }
            func_count++;
        }
        
        import_desc++;
    }
    
    LSW_LOG_INFO("Import resolution complete: %d DLLs, %d functions", dll_count, func_count);
    return true;
}

// ============================================================================
// API-set (api-ms-win-*) → host DLL name mapping
// ============================================================================

/*
 * Windows API sets are virtual DLL names (api-ms-win-crt-runtime-l1-1-0.dll)
 * that map to real host DLLs (ucrtbase.dll, ntdll.dll, etc.).
 * Our Win32 stub tables are registered under the real DLL names, so we need to
 * map api-ms-win-* names before attempting resolution.
 *
 * Table covers the most common API sets used by MSVC-linked binaries.
 */
typedef struct { const char* prefix; const char* host; } apiset_entry_t;

static const apiset_entry_t g_apiset_map[] = {
    /* CRT */
    { "api-ms-win-crt-runtime",    "ucrtbase.dll"  },
    { "api-ms-win-crt-string",     "ucrtbase.dll"  },
    { "api-ms-win-crt-stdio",      "ucrtbase.dll"  },
    { "api-ms-win-crt-math",       "ucrtbase.dll"  },
    { "api-ms-win-crt-convert",    "ucrtbase.dll"  },
    { "api-ms-win-crt-locale",     "ucrtbase.dll"  },
    { "api-ms-win-crt-heap",       "ucrtbase.dll"  },
    { "api-ms-win-crt-environment","ucrtbase.dll"  },
    { "api-ms-win-crt-filesystem", "ucrtbase.dll"  },
    { "api-ms-win-crt-time",       "ucrtbase.dll"  },
    { "api-ms-win-crt-multibyte",  "ucrtbase.dll"  },
    { "api-ms-win-crt-private",    "ucrtbase.dll"  },
    /* Core */
    { "api-ms-win-core-processthreads", "KERNEL32.dll" },
    { "api-ms-win-core-synch",          "KERNEL32.dll" },
    { "api-ms-win-core-file",           "KERNEL32.dll" },
    { "api-ms-win-core-heap",           "KERNEL32.dll" },
    { "api-ms-win-core-memory",         "KERNEL32.dll" },
    { "api-ms-win-core-string",         "KERNEL32.dll" },
    { "api-ms-win-core-sysinfo",        "KERNEL32.dll" },
    { "api-ms-win-core-localization",   "KERNEL32.dll" },
    { "api-ms-win-core-errorhandling",  "KERNEL32.dll" },
    { "api-ms-win-core-console",        "KERNEL32.dll" },
    { "api-ms-win-core-debug",          "KERNEL32.dll" },
    { "api-ms-win-core-handle",         "KERNEL32.dll" },
    { "api-ms-win-core-libraryloader",  "KERNEL32.dll" },
    { "api-ms-win-core-namedpipe",      "KERNEL32.dll" },
    { "api-ms-win-core-io",             "KERNEL32.dll" },
    { "api-ms-win-core-com",            "ole32.dll"    },
    { "api-ms-win-core-registry",       "ADVAPI32.dll" },
    { "api-ms-win-security",            "ADVAPI32.dll" },
    { "api-ms-win-eventing",            "ADVAPI32.dll" },
    { "api-ms-win-ntuser",              "USER32.dll"   },
    { "api-ms-win-dx",                  "GDI32.dll"    },
    { NULL, NULL }
};

static const char* apiset_resolve(const char* dll_name) {
    char lower[128];
    size_t len = strlen(dll_name);
    if (len >= sizeof(lower)) len = sizeof(lower) - 1;
    for (size_t i = 0; i < len; i++) lower[i] = (char)tolower((unsigned char)dll_name[i]);
    lower[len] = '\0';
    if (strncmp(lower, "api-ms-win-", 11) != 0 &&
        strncmp(lower, "ext-ms-win-", 11) != 0) return dll_name;
    for (const apiset_entry_t* e = g_apiset_map; e->prefix; e++) {
        if (strncmp(lower, e->prefix, strlen(e->prefix)) == 0) return e->host;
    }
    /* Unknown api-ms-win- → fall back to KERNEL32 as best-effort */
    return "KERNEL32.dll";
}

// ============================================================================
// Delay-load import resolution
// ============================================================================

/*
 * Delay-load imports (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) are normally resolved
 * on first call via a small thunk generated by the linker.  Since we don't run
 * those thunks, we resolve them eagerly at load time using the same
 * resolve_import_with_dll_chain() logic as regular imports.
 *
 * Each entry in the delay-load IAT is patched to the real address.  If the
 * function can't be resolved, the IAT slot is left pointing at the generic stub
 * so the program doesn't hard-crash on a NULL call.
 */
bool pe_resolve_delay_imports(pe_image_t* image) {
    pe_data_directory_t* delay_dir = pe_get_data_directory(&image->pe, PE_DIR_DELAY_IMPORT);
    if (!delay_dir || !delay_dir->VirtualAddress) {
        LSW_LOG_INFO("No delay-load import directory");
        return true;
    }

    LSW_LOG_INFO("Resolving delay-load imports...");
    uint8_t* base = (uint8_t*)image->image_base;
    pe_delay_load_descriptor_t* desc =
        (pe_delay_load_descriptor_t*)(base + delay_dir->VirtualAddress);

    int total_funcs = 0, resolved = 0;
    while (desc->DllNameRVA) {
        const char* raw_name = (const char*)(base + desc->DllNameRVA);
        const char* dll_name = apiset_resolve(raw_name);
        if (strcmp(raw_name, dll_name) != 0)
            LSW_LOG_INFO("  Delay-load DLL: %s → %s", raw_name, dll_name);
        else
            LSW_LOG_INFO("  Delay-load DLL: %s", raw_name);

        if (!desc->ImportAddressTableRVA || !desc->ImportNameTableRVA) {
            desc++;
            continue;
        }

        uint64_t delay_ordinal_flag = image->pe.is_64bit ? PE_ORDINAL_FLAG64 : PE_ORDINAL_FLAG32;
        uint32_t int_rva = desc->ImportNameTableRVA;
        uint32_t iat_rva = desc->ImportAddressTableRVA;
        void* int_base = base + int_rva;
        void* iat_base_dl = base + iat_rva;

        for (int i = 0; ; i++) {
            uint64_t entry;
            if (image->pe.is_64bit) {
                entry = ((uint64_t*)int_base)[i];
            } else {
                uint32_t e32 = ((uint32_t*)int_base)[i];
                if (e32 == 0) break;
                entry = (uint64_t)e32;
            }
            if (entry == 0) break;

            total_funcs++;
            void* addr = NULL;
            if (entry & delay_ordinal_flag) {
                uint16_t ord = (uint16_t)(entry & 0xFFFF);
                addr = win32_api_resolve_ordinal(dll_name, ord);
                if (!addr) addr = resolve_import_with_dll_chain(dll_name, NULL);
                if (addr) {
                    resolved++;
                    LSW_LOG_DEBUG("    ✓ %s!#%u (delay) -> %p", dll_name, ord, addr);
                } else {
                    addr = win32_api_get_generic_stub();
                    LSW_LOG_WARN("    ✗ %s!#%u (delay-ord) - stub", dll_name, ord);
                }
            } else {
                pe_import_by_name_t* ibn = (pe_import_by_name_t*)(base + (uint32_t)entry);
                const char* fn = (const char*)ibn->Name;
                addr = resolve_import_with_dll_chain(dll_name, fn);
                if (addr) {
                    resolved++;
                    LSW_LOG_DEBUG("    ✓ %s!%s (delay) -> %p", dll_name, fn, addr);
                } else {
                    addr = win32_api_get_generic_stub();
                    LSW_LOG_WARN("    ✗ %s!%s (delay) - stub", dll_name, fn);
                }
            }
            if (image->pe.is_64bit) {
                ((uint64_t*)iat_base_dl)[i] = (uint64_t)addr;
            } else {
                ((uint32_t*)iat_base_dl)[i] = (uint32_t)(uintptr_t)addr;
            }
        }
        desc++;
    }
    LSW_LOG_INFO("Delay-load resolution: %d/%d resolved", resolved, total_funcs);
    return true;
}

bool pe_apply_relocations(pe_image_t* image) {
    uint64_t preferred_base = pe_get_image_base(&image->pe);
    uint64_t actual_base    = (uint64_t)(uintptr_t)image->image_base;
    int64_t  delta          = (int64_t)(actual_base - preferred_base);

    if (delta == 0) {
        LSW_LOG_INFO("Relocations: loaded at preferred base 0x%llx — no fixup needed",
                     (unsigned long long)preferred_base);
        return true;
    }

    LSW_LOG_INFO("Relocations: base delta = 0x%llx (preferred=0x%llx actual=0x%llx)",
                 (unsigned long long)(uint64_t)delta,
                 (unsigned long long)preferred_base,
                 (unsigned long long)actual_base);

    pe_data_directory_t* reloc_dir = pe_get_data_directory(&image->pe, PE_DIR_BASERELOC);
    if (!reloc_dir || reloc_dir->VirtualAddress == 0 || reloc_dir->Size == 0) {
        LSW_LOG_WARN("Relocations: no .reloc section present — ASLR may cause crashes");
        return true;
    }

    // Relocation block header layout (8 bytes per block):
    //   uint32_t VirtualAddress   -- RVA of the 4 KB page
    //   uint32_t SizeOfBlock      -- total bytes including this header
    //   uint16_t Entries[]        -- (SizeOfBlock-8)/2 entries follow
    // Each entry: upper 4 bits = type, lower 12 bits = offset within page.
    //   0  = IMAGE_REL_BASED_ABSOLUTE  (padding, skip)
    //   3  = IMAGE_REL_BASED_HIGHLOW   (32-bit fixup)
    //   10 = IMAGE_REL_BASED_DIR64     (64-bit fixup)

    uint8_t* reloc_base = (uint8_t*)image->image_base + reloc_dir->VirtualAddress;
    uint32_t remaining  = reloc_dir->Size;
    int total_fixups    = 0;

    while (remaining >= 8) {
        uint32_t page_rva      = *(uint32_t*)(reloc_base);
        uint32_t block_size    = *(uint32_t*)(reloc_base + 4);

        if (block_size < 8 || block_size > remaining) {
            LSW_LOG_ERROR("Relocations: malformed block at RVA 0x%x (size=%u)", page_rva, block_size);
            break;
        }

        uint16_t* entries    = (uint16_t*)(reloc_base + 8);
        int       num_entries = (int)((block_size - 8) / 2);

        for (int i = 0; i < num_entries; i++) {
            int      type   = entries[i] >> 12;
            uint32_t offset = entries[i] & 0x0FFF;
            uint8_t* target = (uint8_t*)image->image_base + page_rva + offset;

            if (type == 0) {
                // IMAGE_REL_BASED_ABSOLUTE — padding, skip
            } else if (type == 3) {
                // IMAGE_REL_BASED_HIGHLOW — add 32-bit delta
                uint32_t val;
                memcpy(&val, target, 4);
                val = (uint32_t)(val + (int32_t)delta);
                memcpy(target, &val, 4);
                total_fixups++;
            } else if (type == 10) {
                // IMAGE_REL_BASED_DIR64 — add 64-bit delta
                uint64_t val;
                memcpy(&val, target, 8);
                val = (uint64_t)((int64_t)val + delta);
                memcpy(target, &val, 8);
                total_fixups++;
            } else {
                LSW_LOG_WARN("Relocations: unsupported type %d at RVA 0x%x+0x%x", type, page_rva, offset);
            }
        }

        reloc_base += block_size;
        remaining  -= block_size;
    }

    LSW_LOG_INFO("Relocations: applied %d fixups", total_fixups);
    return true;
}

/*
 * pe_process_tls_callbacks - Execute TLS callbacks before the entry point.
 *
 * Windows PE files may have a TLS (Thread-Local Storage) directory that
 * contains a NULL-terminated list of callback function pointers.  These
 * must be invoked with reason DLL_PROCESS_ATTACH (1) before the executable
 * entry point runs — typically the MSVC CRT uses them to call per-module
 * C++ static constructors.
 *
 * Both 32-bit and 64-bit TLS directory layouts are handled.
 * If there is no TLS directory the function returns true immediately.
 */
bool pe_process_tls_callbacks(pe_image_t* image) {
    pe_data_directory_t* tls_dir = pe_get_data_directory(&image->pe, PE_DIR_TLS);
    if (!tls_dir || tls_dir->VirtualAddress == 0 || tls_dir->Size == 0) {
        return true;  /* No TLS directory — nothing to do */
    }

    LSW_LOG_INFO("TLS directory found at RVA 0x%x — processing callbacks", tls_dir->VirtualAddress);

    if (image->pe.is_64bit) {
        pe_tls_directory64_t* tls = (pe_tls_directory64_t*)(
            (uint8_t*)image->image_base + tls_dir->VirtualAddress);

        if (tls->AddressOfCallBacks) {
            pe_tls_callback_t* cb = (pe_tls_callback_t*)(uintptr_t)tls->AddressOfCallBacks;
            int n = 0;
            while (*cb) {
                LSW_LOG_INFO("  TLS callback[%d]: %p", n, (void*)(uintptr_t)*cb);
                (*cb)(image->image_base, 1 /* DLL_PROCESS_ATTACH */, NULL);
                cb++;
                n++;
            }
            LSW_LOG_INFO("  Executed %d TLS callback(s)", n);
        }
    } else {
        pe_tls_directory32_t* tls = (pe_tls_directory32_t*)(
            (uint8_t*)image->image_base + tls_dir->VirtualAddress);

        if (tls->AddressOfCallBacks) {
            pe_tls_callback_t* cb = (pe_tls_callback_t*)(uintptr_t)tls->AddressOfCallBacks;
            int n = 0;
            while (*cb) {
                LSW_LOG_INFO("  TLS callback[%d]: %p", n, (void*)(uintptr_t)*cb);
                (*cb)(image->image_base, 1 /* DLL_PROCESS_ATTACH */, NULL);
                cb++;
                n++;
            }
            LSW_LOG_INFO("  Executed %d TLS callback(s)", n);
        }
    }

    return true;
}

int pe_execute(pe_image_t* image, int argc, char** argv) {
    if (!image || !image->loaded || !image->entry_point) {
        LSW_LOG_ERROR("Image not loaded or no entry point");
        return -1;
    }
    
    LSW_LOG_INFO("🚀 Executing PE image...");
    LSW_LOG_INFO("Entry point: %p", image->entry_point);
    
    // Open kernel device — fall back to userspace-only mode if unavailable
    int kernel_fd = lsw_kernel_open();
    int kernel_available = (kernel_fd >= 0);
    
    if (!kernel_available) {
        LSW_LOG_WARN("Kernel device /dev/lsw not available — running in userspace-only mode");
        LSW_LOG_WARN("(Load the kernel module for full ring-0 integration: sudo insmod kernel-module/lsw.ko)");
    } else {
        // Prepare PE info for kernel
        struct lsw_pe_info pe_info;
        memset(&pe_info, 0, sizeof(pe_info));
        pe_info.pid = getpid();
        pe_info.base_address = (uint64_t)image->image_base;
        pe_info.entry_point = (uint64_t)image->entry_point;
        pe_info.image_size = image->image_size;
        pe_info.is_64bit = image->pe.is_64bit ? 1 : 0;
        
        const char* exe_path = (argc > 0 && argv && argv[0]) ? argv[0] : "unknown.exe";
        strncpy(pe_info.executable_path, exe_path, sizeof(pe_info.executable_path) - 1);
        
        LSW_LOG_INFO("Registering PE with kernel (PID=%u base=0x%lx entry=0x%lx)",
                     pe_info.pid, pe_info.base_address, pe_info.entry_point);
        
        int ret = lsw_kernel_register_pe(kernel_fd, &pe_info);
        if (ret < 0) {
            LSW_LOG_WARN("Failed to register PE with kernel — continuing in userspace-only mode");
            lsw_kernel_close(kernel_fd);
            kernel_fd = -1;
            kernel_available = 0;
        } else {
            LSW_LOG_INFO("✅ PE registered with kernel successfully");
            ret = lsw_kernel_execute_pe(kernel_fd, pe_info.pid);
            if (ret < 0) {
                LSW_LOG_WARN("Kernel execute_pe failed — continuing in userspace-only mode");
            } else {
                LSW_LOG_INFO("✅ Kernel acknowledged execution request");
            }
        }
    }
    
    // NOW: Actually jump to the PE entry point in userspace!
    LSW_LOG_INFO("🚀 Jumping to PE entry point: 0x%lx", (unsigned long)image->entry_point);
    
    // Set up entry point function pointer
    // PE entry points are typically: int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
    // For console apps: int main(void)
    typedef int (*pe_entry_func_t)(void);
    pe_entry_func_t entry_func = (pe_entry_func_t)image->entry_point;
    
    // Install SEH-emulating signal handlers
    lsw_install_signal_handlers();
    
    LSW_LOG_INFO("Entry point type: %s", 
                 image->pe.nt_headers64 && image->pe.nt_headers64->OptionalHeader.Subsystem == 3 ? 
                 "Console" : "GUI");
    
    // Set up Win32 environment (TEB, PEB, etc)
    LSW_LOG_INFO("Setting up Windows environment (TEB/PEB)...");
    if (win32_teb_init() != 0) {
        LSW_LOG_ERROR("Failed to initialize TEB/PEB");
        if (kernel_available) lsw_kernel_close(kernel_fd);
        return -1;
    }
    
    // Set command line from argc/argv
    win32_set_command_line(argc, argv);
    LSW_LOG_INFO("Command line arguments: %d args", argc);
    
    // Set PEB image base
    win32_teb_t* teb = win32_teb_get();
    if (teb && teb->ProcessEnvironmentBlock) {
        win32_peb_t* peb = (win32_peb_t*)teb->ProcessEnvironmentBlock;
        peb->ImageBaseAddress = image->image_base;
        LSW_LOG_INFO("PEB ImageBaseAddress set to: %p", image->image_base);
    }
    
    int exit_code = 0;
    LSW_LOG_INFO("Calling PE entry point at 0x%lx...", (unsigned long)entry_func);
    LSW_LOG_INFO("Image base: 0x%lx, Size: 0x%x", 
                 (unsigned long)image->image_base, image->image_size);
    
    // Give Win32 APIs access to kernel fd for syscalls (or -1 in userspace mode)
    win32_api_set_kernel_fd(kernel_fd);
    
    // Register .pdata section so _CxxThrowException can dispatch C++ exceptions
    {
        pe_section_header_t* pdata_sec = pe_get_section(&image->pe, ".pdata");
        if (pdata_sec) {
            void* pdata_va = (uint8_t*)image->image_base + pdata_sec->VirtualAddress;
            win32_api_set_pe_image_info((uint64_t)image->image_base,
                                        pdata_va,
                                        pdata_sec->VirtualSize,
                                        (uint32_t)image->image_size);
        } else {
            LSW_LOG_WARN("[pe_loader] .pdata section not found; C++ exceptions disabled");
        }
    }
    
    // This is where we actually execute Windows code on Linux!
    if (kernel_available) {
        LSW_LOG_INFO("🚀 Executing PE with kernel syscall routing enabled!");
    } else {
        LSW_LOG_INFO("🚀 Executing PE in userspace-only mode!");
    }
    exit_code = entry_func();
    
    LSW_LOG_INFO("✅ PE execution returned: exit_code=%d", exit_code);
    
    // Cleanup
    if (kernel_available) {
        lsw_kernel_close(kernel_fd);
    }
    
    return exit_code;
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
