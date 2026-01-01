# Legal Documentation - LSW (Linux Subsystem for Windows)

## Legal Foundation

LSW is a **clean-room implementation** of the Windows NT kernel API. We implement published specifications and documented behaviors without using any proprietary Microsoft source code.

---

## Supreme Court Precedent

### Google LLC v. Oracle America, Inc., 593 U.S. ___ (2021)

**Case:** 18-956  
**Decision Date:** April 5, 2021  
**Ruling:** The Supreme Court held that Google's use of Oracle's Java API was **fair use** under copyright law.

**Key Holdings:**
1. **APIs are functional and therefore subject to fair use analysis**
2. **Reimplementing an API for interoperability is transformative use**
3. **The public interest in software development favors fair use**

**Relevance to LSW:**
- We reimplement the Windows NT API for interoperability
- Our use is transformative (Linux kernel module, not Windows replacement)
- Promotes software compatibility and user freedom
- Follows same legal principles as Wine, ReactOS, Samba

**Citation:** Google LLC v. Oracle America, Inc., 593 U.S. ___ (2021)  
**Opinion:** https://www.supremecourt.gov/opinions/20pdf/18-956_d18f.pdf

---

## Legal Precedents - Similar Projects (No Lawsuits)

### Wine (1993-Present, 30+ years)
- **What:** Reimplements Win32 API in userspace
- **Status:** Active, no legal challenges from Microsoft
- **Website:** https://www.winehq.org/
- **Legal:** Clean-room implementation using public documentation

### ReactOS (1996-Present, 25+ years)
- **What:** Complete Windows NT reimplementation (kernel + userspace)
- **Status:** Active, no legal challenges from Microsoft
- **Website:** https://reactos.org/
- **Legal:** Clean-room implementation, strict code review process

### Samba (1992-Present, 30+ years)
- **What:** Reimplements SMB/CIFS protocol (Windows file sharing)
- **Status:** Active, widely used, no legal challenges from Microsoft
- **Website:** https://www.samba.org/
- **Legal:** Implemented from protocol documentation

### FreeDOS (1994-Present, 30+ years)
- **What:** Reimplements MS-DOS
- **Status:** Active, no legal challenges from Microsoft
- **Website:** https://www.freedos.org/
- **Legal:** Clean-room implementation

---

## Our Sources (All Legal and Public)

### 1. Microsoft Open Specifications
**Source:** https://docs.microsoft.com/en-us/openspecs/  
**Status:** PUBLICLY PUBLISHED by Microsoft for interoperability  
**License:** Microsoft Open Specification Promise (OSP)

**Documents We Reference:**
- [MS-DTYP]: Windows Data Types
- [MS-ERREF]: Windows Error Codes  
- [MS-NRPC]: Netlogon Remote Protocol
- [MS-RDPEGFX]: Remote Desktop Protocol
- [MS-SMB2]: Server Message Block Protocol

**Legal:** Microsoft explicitly permits implementation of these specifications without licensing fees

### 2. Microsoft Learn / MSDN Documentation
**Primary Source:** https://learn.microsoft.com/  
**Legacy URL:** https://docs.microsoft.com/ (redirects to learn.microsoft.com)  
**Status:** PUBLIC documentation  
**Content:** Win32 API reference, system call documentation, kernel documentation

**Key Resources:**
- Microsoft Learn Portal: https://learn.microsoft.com/
- Win32 API Documentation: https://learn.microsoft.com/en-us/windows/win32/
- Windows Driver Kit (WDK) Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/
- NT Kernel Documentation: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/
- Windows Internals: https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals

**Usage:** Primary reference for all Windows API implementations. Every function we implement references its learn.microsoft.com documentation page.

### 3. Microsoft Open Source Projects (GitHub)
**Source:** https://github.com/microsoft  
**Status:** OPEN SOURCE under permissive licenses (MIT, Apache, etc.)

**Projects We Study (Research Only, No Code Copying):**
- Windows Driver Kit (WDK): https://github.com/microsoft/Windows-Driver-Frameworks
- Game Development Kit (GDK): https://github.com/microsoft/GDK
- Windows Terminal: https://github.com/microsoft/terminal
- Windows SDK Headers: Publicly distributed with Visual Studio

**Usage:** We study these for understanding APIs and behaviors. We do NOT copy code.

### 4. Academic and Research Materials
- **Windows Internals** by Mark Russinovich & David Solomon (published book)
- **Undocumented Windows** series (published books)
- Academic papers on NT kernel architecture
- Conference presentations (PDFs, Black Hat, DEF CON)

---

## What We DO NOT Use

❌ **Windows Source Code:** We have NEVER accessed, viewed, or used Microsoft's proprietary source code  
❌ **Leaked Code:** We do not use any leaked Microsoft code  
❌ **Decompilation:** We do not decompile Windows binaries  
❌ **Reverse Engineering of Binaries:** We implement from documentation only  
❌ **Proprietary Interfaces:** We only implement documented, public APIs

---

## Clean-Room Methodology

**Our Development Process:**
1. **Read:** Public specifications and documentation
2. **Design:** Architecture based on documented behavior
3. **Implement:** Write our own code from scratch
4. **Test:** Verify compatibility with public test applications
5. **Document:** Track all sources and references

**Code Review Standards:**
- All code is original BarrerSoftware implementation
- Any reference to external documentation is clearly cited
- No copy-paste from proprietary sources
- Regular legal compliance audits

---

## Legal Protection Measures

### 1. Attribution
Every implementation references the specification or documentation used:
```c
/**
 * NtCreateFile - Create or open a file
 * 
 * Reference: Microsoft Win32 API Documentation
 * https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
 * 
 * Implementation: BarrerSoftware clean-room implementation
 * No Microsoft source code used
 */
```

### 2. License
LSW is licensed under **BarrerSoftware License (BFSL) v1.0**
- Our code, our rules
- Open source and free
- Protects our intellectual property
- Permits commercial and non-commercial use

### 3. Disclaimers
- LSW is NOT affiliated with Microsoft Corporation
- LSW is NOT endorsed by Microsoft Corporation  
- Windows, Win32, and NT are trademarks of Microsoft Corporation
- LSW is an independent, compatible implementation

---

## Why Microsoft Won't Sue

### Business Reasons:
1. **Bad PR:** Attacking open source projects hurts reputation
2. **Lost Battle:** Already lost API copyrightability in Google v. Oracle
3. **Precedent:** Wine/ReactOS exist for 30+ years without lawsuits
4. **Market Benefit:** LSW increases Windows app ecosystem reach

### Legal Reasons:
1. **We Would Win:** API reimplementation is legal (SCOTUS precedent)
2. **Fair Use:** Interoperability is transformative use
3. **No Code Theft:** We use zero Microsoft proprietary code
4. **Published Specs:** Microsoft published these APIs for implementation

### Strategic Reasons:
1. **Microsoft is Pro-Open Source:** GitHub, VS Code, TypeScript, .NET
2. **Interoperability Goal:** They publish specs FOR implementation
3. **Developer Relations:** Suing us alienates developers
4. **Streisand Effect:** Lawsuit makes us famous

---

## Contact and Compliance

**Project:** LSW - Linux Subsystem for Windows  
**Organization:** BarrerSoftware  
**License:** BFSL v1.0  
**Repository:** https://github.com/barrersoftware/lsw

**Legal Inquiries:**
If you are a Microsoft legal representative or have legal concerns, please contact:
- **GitHub:** @barrersoftware
- **Issues:** https://github.com/barrersoftware/lsw/issues

We are committed to:
- Full legal compliance
- Proper attribution of sources
- Clean-room implementation standards
- Respectful use of public specifications

---

## Statement of Intent

LSW exists to promote **software freedom** and **interoperability**. We implement published APIs to allow Windows applications to run on Linux, benefiting users and developers worldwide.

We respect Microsoft's intellectual property rights and use only public, documented interfaces. Our goal is compatibility, not copying.

**We are implementing BEHAVIOR, not copying CODE.**

This is the same legal foundation that has allowed Wine, ReactOS, Samba, and countless other compatibility projects to exist and thrive for decades.

---

## References

1. Google LLC v. Oracle America, Inc., 593 U.S. ___ (2021)
2. Microsoft Open Specifications: https://docs.microsoft.com/en-us/openspecs/
3. Wine Project Legal Status: https://wiki.winehq.org/Developer_FAQ#Is_Wine_legal.3F
4. ReactOS Legal Framework: https://reactos.org/wiki/Legal
5. Clean Room Design (Wikipedia): https://en.wikipedia.org/wiki/Clean_room_design

---

**Document Version:** 1.0  
**Last Updated:** January 1, 2026  
**Maintained By:** BarrerSoftware

🏴‍☠️ **Built legally, built right, built to last.**

---

## LSW vs Wine - Legal Comparison

### Wine's Approach
Wine provides excellent Windows compatibility through clean-room API implementation. However:

**Potential Gray Area:**
- **Winetricks** (Wine's helper tool) downloads actual Microsoft DLLs
- Users can install native Windows components (d3dx9, vcrun, etc.)
- These are Microsoft binaries redistributed without explicit license
- Wine argues this is user choice, not Wine distribution
- **Microsoft has not challenged this in 30+ years**

### LSW's Approach - Cleaner Legal Position

**LSW implements EVERYTHING in-house:**
```
❌ NO Microsoft DLLs
❌ NO Microsoft CAB files  
❌ NO Microsoft binaries
❌ NO Microsoft redistributables
✅ 100% BarrerSoftware implementation
✅ Pure clean-room code
✅ Zero Microsoft binary dependencies
```

**Why This Matters:**
1. **No Redistribution Issues:** We never touch Microsoft binaries
2. **Clearer Legal Position:** No gray areas whatsoever
3. **Full Control:** We control every line of code
4. **Independence:** No reliance on Microsoft components
5. **True Open Source:** Everything is our code, BFSL licensed

**Legal Advantage:**
- Wine: "We're clean-room, but users can add MS DLLs" (gray)
- LSW: "We're 100% clean-room, zero MS binaries ever" (crystal clear)

**This makes LSW MORE legally defensible than Wine.**

---

## What We Will NEVER Do

### Prohibited Forever:
1. ❌ Ship Microsoft DLLs (even optionally)
2. ❌ Download Microsoft binaries (no LSW-tricks equivalent)
3. ❌ Redistribute Microsoft CAB files
4. ❌ Include Microsoft fonts, icons, or resources
5. ❌ Package Microsoft redistributables
6. ❌ Use WINE DLLs that contain Microsoft code
7. ❌ Accept pull requests with Microsoft binaries

### Our Commitment:
**Every single line of LSW code is written by BarrerSoftware.**

If a Windows app needs a DLL we don't implement yet:
- ✅ We implement it ourselves
- ❌ We DON'T download Microsoft's version

**100% pure, 100% legal, 100% ours.**

---

**Last Updated:** January 1, 2026 - Post-discussion with Daniel on legal purity

