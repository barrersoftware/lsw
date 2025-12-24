# LSW - Linux Subsystem for Windows

**Windows binary support for Linux kernels - WSL2 in reverse**

## 🆓 ALWAYS FREE

**LSW is and will always be free.**

- ✅ Free to download
- ✅ Free to use
- ✅ Free to modify
- ✅ Free to distribute
- ❌ NEVER for sale

If anyone is charging you for LSW, report them: legal@barrersoftware.com

**Built on free resources (Microsoft Open Specs, WSL) → Must remain free forever**

## Vision

Enable native Windows application execution on Linux-based operating systems without emulation overhead. Just as WSL2 allows Linux binaries to run on Windows kernel, LSW allows Windows binaries to run on Linux kernel with native performance.

## Project Goals

- **Native Performance**: Direct syscall translation, no emulation layer
- **Full Resource Access**: Windows apps access hardware directly through Linux kernel
- **Universal Compatibility**: Works on any Linux distribution (Ubuntu, Arch, Fedora, BarrerOS, etc.)
- **Open Source**: BarrerSoftware License - free forever, cannot be sold
- **Standards-Based**: Built from Microsoft Open Specifications documentation

## Architecture Overview

### Core Components

1. **Kernel Module** - LSW kernel integration
   - PE (Portable Executable) binary loader
   - Windows syscall interface implementation  
   - Process and thread management translation
   - Memory management mapping

2. **Filesystem Translation Layer**
   - Virtual drive letter mapping (`C:` → `/mnt/c`)
   - Path separator translation (`\` → `/`)
   - Case-insensitive filesystem overlay
   - Windows special folders (AppData, ProgramFiles, etc.)

3. **Registry Emulation**
   - Registry hive storage in `/etc/lsw/registry/`
   - Registry API implementation
   - HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER support

4. **Windows API Translation**
   - Win32 API → Linux equivalent mapping
   - GDI graphics subsystem
   - DirectX to Vulkan/OpenGL translation
   - Windows networking to Linux sockets

### How It Works

```
Windows App (app.exe)
       ↓
PE Binary Loader (LSW Kernel Module)
       ↓  
Windows Syscall Interface
       ↓
Syscall Translation Layer
       ↓
Linux Kernel Native Syscalls
       ↓
Hardware
```

**No emulation. No virtualization. Direct execution.**

## Technical Foundation

### Microsoft Open Specifications

Using official Microsoft protocol documentation:
- **Windows Protocols** - Network and system protocols
- **PE Format Specification** - Executable binary format
- **Windows API Documentation** - System call interfaces
- **Registry Format** - Windows registry structure
- **Filesystem Protocols** - NTFS behaviors and expectations

Reference: `openspecs-windows_protocols-ms-rdpegfx.pdf` (404 pages of protocol specifications)

### Filesystem Mapping

```
Linux Root          Windows View
-----------         ------------
/                   (hidden)
/mnt/c/             C:\
/mnt/d/             D:\
/home/user/         C:\Users\user\
/etc/lsw/registry/  Registry hives
```

### Example Use Case

```bash
# Install LSW kernel module
sudo modprobe lsw

# Enable Windows binary support
sudo lsw-enable

# Run Windows executable natively
./myapp.exe

# App sees:
# - C:\Windows\ filesystem
# - Registry access
# - Windows API calls
# - Native hardware access

# Kernel translates everything to Linux equivalents
```

## Development Phases

### Phase 1: Core Kernel Module (MVP)
- PE binary loader implementation
- Basic syscall translation (file I/O, memory, process)
- Virtual filesystem mapping (C: drive)
- Simple Win32 console app support

### Phase 2: Graphics and GUI
- GDI implementation
- Window management
- DirectX to Vulkan translation layer
- GUI application support

### Phase 3: Advanced Features
- Full registry emulation
- Windows networking stack
- COM/DCOM support
- .NET Framework support
- Driver compatibility layer

### Phase 4: Performance Optimization
- JIT compilation for syscall translation
- Aggressive caching
- Zero-copy memory operations
- Multi-threading optimizations

## Advantages Over Wine

| Feature | Wine | LSW |
|---------|------|-----|
| Execution Model | User-space emulation | Kernel-level native |
| Performance | 60-80% of native | 95-100% of native |
| Resource Access | Limited/translated | Direct hardware access |
| Architecture | Compatibility layer | Kernel integration |
| Overhead | High | Minimal |
| Maintenance | App-by-app fixes | Syscall-level support |

## Use Cases

- **Desktop Linux**: Run Windows-only apps without dual-boot
- **Gaming**: Native Windows game performance on Linux
- **Enterprise**: Legacy Windows app support on Linux infrastructure  
- **Development**: Test Windows apps on Linux workstations
- **BarrerOS**: Unified OS running Linux + Android + Windows apps

## Project Structure

```
lsw-project/
├── kernel/              # Kernel module source
│   ├── pe-loader.c      # PE binary loader
│   ├── syscall.c        # Syscall translation
│   ├── fs-mapping.c     # Filesystem virtualization
│   └── registry.c       # Registry emulation
├── userspace/           # Userspace utilities
│   ├── lsw-enable       # Enable LSW support
│   ├── lsw-config       # Configuration tool
│   └── lsw-monitor      # Debug/monitoring tool
├── docs/                # Documentation
│   ├── ARCHITECTURE.md  # Technical architecture
│   ├── API.md           # API documentation
│   └── SPECS.md         # Microsoft specs reference
├── tests/               # Test suite
└── examples/            # Example Windows apps
```

## Getting Started

### Prerequisites

- Linux kernel 5.15+ with module support
- Build tools (gcc, make, kernel headers)
- Microsoft Open Specifications documentation

### Building LSW

```bash
git clone https://github.com/barrersoftware/lsw.git
cd lsw
make
sudo make install
sudo modprobe lsw
```

### Running Windows Apps

```bash
# Enable LSW for current session
lsw-enable

# Run Windows executable
./myapp.exe

# Or use the launcher
lsw-run myapp.exe
```

## Roadmap

- **Q1 2026**: Phase 1 MVP - Basic console app support
- **Q2 2026**: Phase 2 - GUI and graphics support
- **Q3 2026**: Phase 3 - Advanced Windows features
- **Q4 2026**: Phase 4 - Performance optimization
- **2027**: 1.0 Release - Production ready

## Community

- **License**: BarrerSoftware License v1.0 (open source, free forever)
- **Target**: All Linux distributions
- **First Implementation**: BarrerOS (dogfooding)
- **Goal**: Industry standard for Windows app support on Linux

## 💝 Support BarrerSoftware

LSW is FREE software and will always be free.

If you'd like to support our work:
- 🌟 Star this repo
- 📢 Tell others about it  
- 💰 [Support our mission](https://barrersoftware.com/support)

Or check out our paid products:
- **Velocity Panel** - Premium server management
- **CleanVM Enterprise** - Enterprise virtualization

**No pressure. Just appreciation.**

## Why LSW?

**WSL brought Linux to Windows users.**  
**LSW brings Windows to Linux users.**

One kernel. Two worlds. Native performance.

---

## Technical References

- **Microsoft Open Specifications**: `~/openspecs-windows_protocols-ms-rdpegfx.pdf` (404 pages)
- **WSL2 Open Source**: https://github.com/microsoft/WSL (MIT License)
- **WSL2 Linux Kernel**: https://github.com/microsoft/WSL2-Linux-Kernel  
- **WSL Architecture**: Microsoft's proven integration model (inverse approach)
- **Wine Project**: Lessons learned from user-space compatibility layer
- **PE Format**: Microsoft Portable Executable specification
- **Windows Kernel**: NT kernel syscall interface documentation

**Note**: WSL1's syscall translation layer (`lxcore.sys`) remains closed source, but we don't need it - we're building our own from specs and open source references.

## Authors

- **Captain CP** - Architecture, Design, Initial Implementation
- **Daniel** - Vision, Requirements, Testing
- **BarrerSoftware** - Project sponsor, first deployment target

## Status

**Current**: Planning and Architecture Phase  
**Next**: Kernel module MVP implementation  
**Timeline**: 2026 Development cycle

---

🏴‍☠️ Built by BarrerSoftware  
💙 Open Source, Community Driven  
🚀 The Future of Cross-Platform Computing

**LSW - Because Linux users deserve Windows apps too.**


---

## Trademark Disclaimer

LSW (Linux Subsystem for Windows) is an independent open-source project and is **not affiliated with, endorsed by, or sponsored by Microsoft Corporation or the Windows Subsystem for Linux (WSL) project.**

"Windows," "WSL," and "Windows Subsystem for Linux" are trademarks or registered trademarks of Microsoft Corporation.

LSW is a descriptive name referring to functionality (running Windows applications on Linux systems) and is not intended to cause confusion with Microsoft's WSL product.

## Package Management Integration

LSW integrates with Windows package managers for seamless app installation:

### Winget Support

```bash
# Install Windows apps using Microsoft's official package manager
lsw winget install Microsoft.VisualStudioCode
lsw winget install Google.Chrome
lsw winget search photoshop
lsw winget upgrade --all

# Full winget compatibility on Linux
```

### MSI Installer Support

```bash
# Install from .msi files
lsw install application.msi

# Silent installation
lsw install --silent app.msi
```

### Benefits
- No manual downloads needed
- Uses Microsoft's official repositories
- Automatic updates via winget
- Familiar Windows package management on Linux
