# LSW Sources and References

This document tracks ALL external sources used in LSW development. Every API we implement, every specification we reference, every document we study.

**Purpose:** Legal transparency and proper attribution.

---

## Microsoft Official Documentation

### Microsoft Learn (Primary Documentation Portal)
**Source:** https://learn.microsoft.com/  
**License:** Public documentation, free to use  
**Usage:** Primary reference hub for all Microsoft technical documentation

**Sub-portals:**
- Windows API: https://learn.microsoft.com/en-us/windows/win32/
- Windows Kernel: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/
- .NET Documentation: https://learn.microsoft.com/en-us/dotnet/
- Azure Documentation: https://learn.microsoft.com/en-us/azure/

### Win32 API Documentation  
**Source:** https://learn.microsoft.com/en-us/windows/win32/  
**Alternate:** https://docs.microsoft.com/en-us/windows/win32/ (redirects to learn.microsoft.com)  
**License:** Public documentation, free to use  
**Usage:** Primary reference for Win32 function signatures and behavior

**Specific Functions Implemented:**
- CreateFileA: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
- WriteFile: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
- VirtualAlloc: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
- VirtualFree: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
- CreateEventA: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa
- GetModuleHandleA: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea

### PE Format Documentation
**Source:** https://learn.microsoft.com/en-us/windows/win32/debug/pe-format  
**Alternate:** https://docs.microsoft.com/en-us/windows/win32/debug/pe-format (redirects)  
**Usage:** Understanding Windows executable file format

### Windows Data Types
**Source:** [MS-DTYP] Windows Data Types  
**URL:** https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/  
**Alternate:** https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/ (redirects)  
**Usage:** Standard Windows data type definitions

---

## Microsoft Open Specifications

**Main Portal:** https://docs.microsoft.com/en-us/openspecs/  
**License:** Microsoft Open Specification Promise (OSP)

### Specifications Referenced:
1. **[MS-DTYP]** Windows Data Types
2. **[MS-ERREF]** Windows Error Codes
3. **[MS-RDP]** Remote Desktop Protocol (for understanding Windows architecture)

---

## Open Source Projects (Research Only)

### Wine Project
**URL:** https://gitlab.winehq.org/wine/wine  
**License:** LGPL  
**Usage:** Research reference for Win32 API behavior (NO CODE COPIED)  
**What We Learn:** How Win32 functions should behave, edge cases, error handling

### ReactOS
**URL:** https://github.com/reactos/reactos  
**License:** GPL  
**Usage:** Research reference for NT kernel architecture (NO CODE COPIED)  
**What We Learn:** Kernel structure, syscall organization, design patterns

### Microsoft GitHub Repositories
**Organization:** https://github.com/microsoft

**Repositories Studied:**
1. **Windows-Driver-Frameworks**  
   URL: https://github.com/microsoft/Windows-Driver-Frameworks  
   Usage: Understanding driver architecture and kernel interfaces

2. **terminal**  
   URL: https://github.com/microsoft/terminal  
   Usage: Understanding Windows console APIs

3. **STL**  
   URL: https://github.com/microsoft/STL  
   Usage: Understanding Windows C++ runtime structure

**Note:** We study these for ARCHITECTURE and BEHAVIOR understanding only. We do NOT copy code.

---

## Books and Publications

### Windows Internals (7th Edition)
**Authors:** Pavel Yosifovich, Mark Russinovich, David Solomon, Alex Ionescu  
**Publisher:** Microsoft Press  
**ISBN:** 978-0135462409  
**Usage:** Understanding NT kernel architecture and internal structures

### Undocumented Windows 2000 Secrets
**Author:** Sven Schreiber  
**Publisher:** Addison-Wesley  
**Usage:** Understanding undocumented NT behaviors

---

## Standards and Protocols

### PE/COFF Specification
**Source:** Microsoft PE/COFF Specification  
**URL:** https://docs.microsoft.com/en-us/windows/win32/debug/pe-format  
**Usage:** Parsing Windows executables

### C Runtime Library Standards
**Source:** ISO C Standard Documentation  
**Usage:** Implementing MSVCRT compatibility

---

## Development Tools (All Legal)

### MinGW-w64
**URL:** https://www.mingw-w64.org/  
**License:** Public domain and various free licenses  
**Usage:** Cross-compiling Windows test applications

### x86_64-w64-mingw32-gcc
**Package:** Available in Ubuntu/Debian repositories  
**Usage:** Building test executables for LSW validation

---

## Testing Resources

### Public Test Applications
All test applications (hello.exe, test.exe) are built by us using MinGW-w64 from our own source code.

**Source Code:**
- test.c: Our own test code
- hello.c: Our own hello world implementation
- examples/: All written by BarrerSoftware

---

## Code Review Standards

### Every Implementation Must Have:
1. ✅ **Comment** citing the specification used
2. ✅ **URL** to public documentation
3. ✅ **Statement** that implementation is our own
4. ✅ **No proprietary code** used

### Example:
```c
/**
 * lsw_VirtualAlloc - Allocate virtual memory
 * 
 * Reference: Microsoft Win32 API Documentation
 * https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
 * 
 * Specification: Documented Win32 function signature and behavior
 * Implementation: BarrerSoftware clean-room implementation using Linux mmap()
 * 
 * NO Microsoft source code used
 */
```

---

## What We DO NOT Use

### Prohibited Sources:
❌ Windows source code (proprietary, never accessed)  
❌ Leaked Microsoft code (illegal, never used)  
❌ Decompiled Windows binaries (reverse engineering of code)  
❌ Proprietary debugging symbols  
❌ Confidential Microsoft documentation  
❌ Code from non-open-source Windows projects  

---

## Attribution Policy

When implementing any Windows API function:

1. **Identify Source:** Find public documentation
2. **Document Reference:** Add URL to source code comments
3. **Clean-Room Implementation:** Write our own code
4. **Test Behavior:** Verify against documented behavior
5. **Track in SOURCES.md:** Add to this document

---

## Legal Compliance Checklist

Before implementing any new API:

- [ ] Is the API documented publicly? (Yes = proceed, No = skip)
- [ ] Have we found the specification URL? (Add to comments)
- [ ] Are we implementing behavior, not copying code? (Always yes)
- [ ] Have we added proper attribution? (Required)
- [ ] Is this tracked in SOURCES.md? (This file)

---

## Updates and Maintenance

This document is updated whenever:
- New APIs are implemented
- New documentation sources are found
- New research materials are consulted
- Legal requirements change

**Maintainer:** BarrerSoftware Development Team  
**Last Updated:** January 1, 2026  
**Version:** 1.0

---

## Contact

Questions about our sources or legal compliance?
- Open an issue: https://github.com/barrersoftware/lsw/issues
- Label: [legal] or [compliance]

We are committed to full transparency and legal compliance.

🏴‍☠️ **Every line of code, every reference, fully documented.**
