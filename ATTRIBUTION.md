# Attribution and Legal Compliance

## LSW Development is Based on Publicly Available Resources

This project (LSW - Linux Subsystem for Windows) is built using publicly available documentation and open source code released by Microsoft to encourage interoperability.

### Primary Sources

#### 1. Microsoft Open Specifications
**URL**: https://www.microsoft.com/openspecifications/

Microsoft's official Open Specifications program provides detailed technical documentation for protocols and technologies implemented in Microsoft products. These specifications are provided to help developers build interoperable solutions.

**What we use:**
- Windows Protocols documentation
- PE (Portable Executable) format specifications
- Windows API interface documentation
- Registry format specifications
- Filesystem protocol specifications

**Reference Document**: `openspecs-windows_protocols-ms-rdpegfx.pdf` (404 pages)

#### 2. Windows Subsystem for Linux (WSL) - Open Source
**Repository**: https://github.com/microsoft/WSL  
**License**: MIT License  
**Our Fork**: https://github.com/barrersoftware/WSL-research

Microsoft open-sourced WSL2 to encourage community contribution and transparency. We study this codebase to understand how Microsoft bridges Linux and Windows environments.

**What we learn from WSL:**
- Process and VM management architecture
- Filesystem bridge implementation
- Inter-OS communication protocols
- Resource management strategies

**We apply these lessons in reverse** - instead of running Linux on Windows kernel, we run Windows on Linux kernel.

#### 3. WSL2 Linux Kernel - Open Source
**Repository**: https://github.com/microsoft/WSL2-Linux-Kernel  
**License**: GPL v2 (Linux kernel standard)  
**Our Fork**: https://github.com/barrersoftware/WSL2-Kernel-Research

Microsoft's Linux kernel with WSL2-specific patches. We study these modifications to understand kernel-level integration requirements.

## Legal Standing

### Clean Room Implementation
LSW is a **clean room implementation** based on:
1. Published specifications (Microsoft Open Specs)
2. Open source code study (MIT-licensed WSL2)
3. Public API documentation
4. Reverse architecture approach (not reverse engineering)

### No Proprietary Code
- ✅ We do NOT use any closed-source Microsoft code
- ✅ We do NOT reverse-engineer Windows binaries
- ✅ We do NOT violate any patents or copyrights
- ✅ We implement based on public specifications

### Inspired by WSL
If Microsoft can build **WSL** (Windows Subsystem for Linux):
- Runs Linux binaries on Windows kernel
- Open sourced under MIT license
- Encouraged for community use

Then we can build **LSW** (Linux Subsystem for Windows):
- Runs Windows binaries on Linux kernel  
- Open source under MIT license
- Encourages interoperability

**Same concept. Opposite direction. Equally legal.**

## Benefits to Microsoft

LSW actually **expands Microsoft's market**:
- ✅ Makes Windows software run on more platforms
- ✅ Increases value of Windows development
- ✅ Drives Microsoft Store/Office/Azure usage on Unix systems
- ✅ Proves Windows APIs are the universal standard
- ✅ No extra development work required from Microsoft

## Compliance Statement

This project complies with:
- Microsoft Open Specification Promise
- MIT License terms (WSL2)
- GPL v2 (Linux kernel)
- Clean room implementation principles
- Interoperability fair use

## Acknowledgments

We acknowledge and thank Microsoft for:
- Publishing Open Specifications documentation
- Open sourcing WSL2 codebase
- Proving the cross-OS compatibility architecture
- Supporting interoperability and innovation

LSW would not be possible without Microsoft's commitment to openness and interoperability.

## References

1. **Microsoft Open Specifications Program**  
   https://www.microsoft.com/openspecifications/

2. **WSL GitHub Repository (MIT License)**  
   https://github.com/microsoft/WSL

3. **WSL2 Linux Kernel (GPL v2)**  
   https://github.com/microsoft/WSL2-Linux-Kernel

4. **Microsoft Open Specification Promise**  
   https://docs.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/51a0d3ff-9f77-464c-b83f-2de08ed28134

5. **Wine Legal FAQ** (precedent for Windows compatibility)  
   https://wiki.winehq.org/Developer_FAQ#Is_it_legal_to_write_Windows-compatible_software.3F

---

**LSW is a legal, ethical, open-source project built on publicly available resources to promote cross-platform interoperability.**

If you have concerns or questions about LSW's legal standing, please open an issue or contact us at legal@barrersoftware.com

🏴‍☠️ BarrerSoftware - Building bridges, not walls
