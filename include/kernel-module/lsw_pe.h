/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * PE (Portable Executable) Format Definitions
 * Based on Microsoft PE/COFF specification
 */

#ifndef LSW_PE_H
#define LSW_PE_H

#include <linux/types.h>

/* DOS header */
struct lsw_dos_header {
    __u16 e_magic;       /* Magic number "MZ" */
    __u16 e_cblp;
    __u16 e_cp;
    __u16 e_crlc;
    __u16 e_cparhdr;
    __u16 e_minalloc;
    __u16 e_maxalloc;
    __u16 e_ss;
    __u16 e_sp;
    __u16 e_csum;
    __u16 e_ip;
    __u16 e_cs;
    __u16 e_lfarlc;
    __u16 e_ovno;
    __u16 e_res[4];
    __u16 e_oemid;
    __u16 e_oeminfo;
    __u16 e_res2[10];
    __u32 e_lfanew;      /* File offset of PE header */
} __attribute__((packed));

/* PE signature */
#define LSW_PE_SIGNATURE 0x00004550  /* "PE\0\0" */

/* COFF header */
struct lsw_coff_header {
    __u16 Machine;
    __u16 NumberOfSections;
    __u32 TimeDateStamp;
    __u32 PointerToSymbolTable;
    __u32 NumberOfSymbols;
    __u16 SizeOfOptionalHeader;
    __u16 Characteristics;
} __attribute__((packed));

/* Optional header (PE32) */
struct lsw_optional_header32 {
    __u16 Magic;
    __u8  MajorLinkerVersion;
    __u8  MinorLinkerVersion;
    __u32 SizeOfCode;
    __u32 SizeOfInitializedData;
    __u32 SizeOfUninitializedData;
    __u32 AddressOfEntryPoint;
    __u32 BaseOfCode;
    __u32 BaseOfData;
    __u32 ImageBase;
    __u32 SectionAlignment;
    __u32 FileAlignment;
    __u16 MajorOperatingSystemVersion;
    __u16 MinorOperatingSystemVersion;
    __u16 MajorImageVersion;
    __u16 MinorImageVersion;
    __u16 MajorSubsystemVersion;
    __u16 MinorSubsystemVersion;
    __u32 Win32VersionValue;
    __u32 SizeOfImage;
    __u32 SizeOfHeaders;
    __u32 CheckSum;
    __u16 Subsystem;
    __u16 DllCharacteristics;
    __u32 SizeOfStackReserve;
    __u32 SizeOfStackCommit;
    __u32 SizeOfHeapReserve;
    __u32 SizeOfHeapCommit;
    __u32 LoaderFlags;
    __u32 NumberOfRvaAndSizes;
} __attribute__((packed));

/* Optional header (PE32+) */
struct lsw_optional_header64 {
    __u16 Magic;
    __u8  MajorLinkerVersion;
    __u8  MinorLinkerVersion;
    __u32 SizeOfCode;
    __u32 SizeOfInitializedData;
    __u32 SizeOfUninitializedData;
    __u32 AddressOfEntryPoint;
    __u32 BaseOfCode;
    __u64 ImageBase;
    __u32 SectionAlignment;
    __u32 FileAlignment;
    __u16 MajorOperatingSystemVersion;
    __u16 MinorOperatingSystemVersion;
    __u16 MajorImageVersion;
    __u16 MinorImageVersion;
    __u16 MajorSubsystemVersion;
    __u16 MinorSubsystemVersion;
    __u32 Win32VersionValue;
    __u32 SizeOfImage;
    __u32 SizeOfHeaders;
    __u32 CheckSum;
    __u16 Subsystem;
    __u16 DllCharacteristics;
    __u64 SizeOfStackReserve;
    __u64 SizeOfStackCommit;
    __u64 SizeOfHeapReserve;
    __u64 SizeOfHeapCommit;
    __u32 LoaderFlags;
    __u32 NumberOfRvaAndSizes;
} __attribute__((packed));

/* Data directory */
struct lsw_data_directory {
    __u32 VirtualAddress;
    __u32 Size;
} __attribute__((packed));

/* Section header */
struct lsw_section_header {
    __u8  Name[8];
    __u32 VirtualSize;
    __u32 VirtualAddress;
    __u32 SizeOfRawData;
    __u32 PointerToRawData;
    __u32 PointerToRelocations;
    __u32 PointerToLinenumbers;
    __u16 NumberOfRelocations;
    __u16 NumberOfLinenumbers;
    __u32 Characteristics;
} __attribute__((packed));

/* Export directory */
struct lsw_export_directory {
    __u32 Characteristics;
    __u32 TimeDateStamp;
    __u16 MajorVersion;
    __u16 MinorVersion;
    __u32 Name;
    __u32 Base;
    __u32 NumberOfFunctions;
    __u32 NumberOfNames;
    __u32 AddressOfFunctions;
    __u32 AddressOfNames;
    __u32 AddressOfNameOrdinals;
} __attribute__((packed));

/* Import descriptor */
struct lsw_import_descriptor {
    __u32 OriginalFirstThunk;  /* RVA to original unbound IAT */
    __u32 TimeDateStamp;
    __u32 ForwarderChain;
    __u32 Name;                /* RVA to DLL name */
    __u32 FirstThunk;          /* RVA to IAT */
} __attribute__((packed));

/* Magic numbers */
#define LSW_DOS_MAGIC    0x5A4D  /* "MZ" */
#define LSW_PE32_MAGIC   0x010B
#define LSW_PE32P_MAGIC  0x020B

/* Data directory indices */
#define LSW_DIRECTORY_EXPORT     0
#define LSW_DIRECTORY_IMPORT     1
#define LSW_DIRECTORY_RESOURCE   2
#define LSW_DIRECTORY_BASERELOC  5

#endif /* LSW_PE_H */
