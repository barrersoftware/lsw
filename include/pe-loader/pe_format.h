/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 * 
 * PE (Portable Executable) Format Structures
 * Based on Microsoft PE/COFF Specification
 */

#ifndef LSW_PE_FORMAT_H
#define LSW_PE_FORMAT_H

#include <stdint.h>

// DOS Header (MZ Header)
#define PE_DOS_SIGNATURE 0x5A4D  // "MZ"
#define PE_NT_SIGNATURE  0x00004550  // "PE\0\0"

typedef struct {
    uint16_t e_magic;      // Magic number (MZ)
    uint16_t e_cblp;       // Bytes on last page
    uint16_t e_cp;         // Pages in file
    uint16_t e_crlc;       // Relocations
    uint16_t e_cparhdr;    // Size of header in paragraphs
    uint16_t e_minalloc;   // Minimum extra paragraphs needed
    uint16_t e_maxalloc;   // Maximum extra paragraphs needed
    uint16_t e_ss;         // Initial (relative) SS value
    uint16_t e_sp;         // Initial SP value
    uint16_t e_csum;       // Checksum
    uint16_t e_ip;         // Initial IP value
    uint16_t e_cs;         // Initial (relative) CS value
    uint16_t e_lfarlc;     // File address of relocation table
    uint16_t e_ovno;       // Overlay number
    uint16_t e_res[4];     // Reserved words
    uint16_t e_oemid;      // OEM identifier
    uint16_t e_oeminfo;    // OEM information
    uint16_t e_res2[10];   // Reserved words
    uint32_t e_lfanew;     // File address of new exe header (PE)
} pe_dos_header_t;

// COFF File Header
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_coff_header_t;

// Machine Types
#define PE_MACHINE_I386   0x014c  // x86
#define PE_MACHINE_AMD64  0x8664  // x64

// Characteristics
#define PE_CHAR_EXECUTABLE_IMAGE       0x0002
#define PE_CHAR_LARGE_ADDRESS_AWARE    0x0020
#define PE_CHAR_32BIT_MACHINE          0x0100
#define PE_CHAR_DLL                    0x2000

// Data Directory
typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} pe_data_directory_t;

#define PE_NUMBER_OF_DIRECTORY_ENTRIES 16

// Directory indices
#define PE_DIR_EXPORT         0
#define PE_DIR_IMPORT         1
#define PE_DIR_RESOURCE       2
#define PE_DIR_EXCEPTION      3
#define PE_DIR_SECURITY       4
#define PE_DIR_BASERELOC      5
#define PE_DIR_DEBUG          6
#define PE_DIR_ARCHITECTURE   7
#define PE_DIR_GLOBALPTR      8
#define PE_DIR_TLS            9
#define PE_DIR_LOAD_CONFIG    10
#define PE_DIR_BOUND_IMPORT   11
#define PE_DIR_IAT            12
#define PE_DIR_DELAY_IMPORT   13
#define PE_DIR_COM_DESCRIPTOR 14

// Optional Header (PE32)
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory_t DataDirectory[PE_NUMBER_OF_DIRECTORY_ENTRIES];
} pe_optional_header32_t;

// Optional Header (PE32+)
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory_t DataDirectory[PE_NUMBER_OF_DIRECTORY_ENTRIES];
} pe_optional_header64_t;

#define PE_MAGIC_PE32  0x010b
#define PE_MAGIC_PE32PLUS 0x020b

// Subsystem values
#define PE_SUBSYSTEM_NATIVE               1
#define PE_SUBSYSTEM_WINDOWS_GUI          2
#define PE_SUBSYSTEM_WINDOWS_CUI          3
#define PE_SUBSYSTEM_WINDOWS_CE_GUI       9

// NT Headers
typedef struct {
    uint32_t Signature;
    pe_coff_header_t FileHeader;
    pe_optional_header32_t OptionalHeader;
} pe_nt_headers32_t;

typedef struct {
    uint32_t Signature;
    pe_coff_header_t FileHeader;
    pe_optional_header64_t OptionalHeader;
} pe_nt_headers64_t;

// Section Header
#define PE_SECTION_NAME_SIZE 8

typedef struct {
    uint8_t  Name[PE_SECTION_NAME_SIZE];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_section_header_t;

// Section characteristics
#define PE_SCN_MEM_EXECUTE 0x20000000
#define PE_SCN_MEM_READ    0x40000000
#define PE_SCN_MEM_WRITE   0x80000000

// Import Directory Entry
typedef struct {
    uint32_t ImportLookupTableRVA;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t NameRVA;
    uint32_t ImportAddressTableRVA;
} pe_import_descriptor_t;

// Import Lookup Entry
typedef struct {
    union {
        uint32_t ForwarderString;
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;
    };
} pe_import_lookup32_t;

typedef struct {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;
    };
} pe_import_lookup64_t;

#define PE_ORDINAL_FLAG32 0x80000000
#define PE_ORDINAL_FLAG64 0x8000000000000000ULL

// Import by Name
typedef struct {
    uint16_t Hint;
    char Name[1];  // Variable length
} pe_import_by_name_t;

// Export Directory
typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} pe_export_directory_t;

#endif // LSW_PE_FORMAT_H
