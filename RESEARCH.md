# LSW Research - WSL2 Component Analysis

## Key Discovery: wslhost.exe

**wslhost.exe** is the Windows-side manager that keeps WSL2 running - the "heartbeat" of the system.

### For LSW, we need the inverse:

**lswhost** - Linux daemon that manages Windows PE processes

## WSL2 Architecture (from research forks)

### Windows Side:
- `wslhost.exe` - Host manager process
- `wsl.exe` - User CLI tool
- VM management components
- Filesystem bridge

### Linux Side (inside WSL2):
- Linux kernel (custom patches)
- Init system integration
- 9P filesystem protocol for Windows access

## LSW Architecture (reverse)

### Linux Host Side:
- **lswhost** daemon - Manages Windows processes
- **lsw** CLI tool - User interface
- PE binary loader
- Filesystem bridge (/mnt/c mapping)

### Windows Process Side:
- Windows PE binaries
- Syscall translation layer
- Registry access
- Windows API emulation

## Component Mapping

| WSL2 Component | LSW Equivalent | Function |
|----------------|----------------|----------|
| wslhost.exe | lswhost daemon | Process lifecycle management |
| wsl.exe | lsw CLI | User command interface |
| VM manager | Kernel module | Process isolation/management |
| 9P filesystem | FUSE/overlay | Filesystem bridge |
| Windows host | Linux host | Base operating system |
| Linux kernel | Windows ABI layer | Target execution environment |

## Research Forks

- **WSL Source**: https://github.com/barrersoftware/WSL-research
- **WSL2 Kernel**: https://github.com/barrersoftware/WSL2-Kernel-Research

## Next Steps

1. **Analyze wslhost.exe behavior**
   - Process spawning
   - Lifecycle management
   - Inter-process communication
   - Resource management

2. **Design lswhost daemon**
   - Reverse wslhost functionality
   - PE binary execution
   - Windows process supervision
   - Resource allocation

3. **Study filesystem bridge**
   - How WSL2 maps Windows → Linux
   - Reverse for Linux → Windows (/mnt/c)
   - File handle translation
   - Permission mapping

4. **Syscall translation**
   - Windows syscall interface
   - Linux kernel mapping
   - Performance optimization

## Notes

- WSL2 uses lightweight VM for Linux kernel
- LSW uses kernel module for Windows ABI
- Both achieve near-native performance
- Architecture is proven by Microsoft
- We have source code to study!

---

Research ongoing. This document tracks our analysis of WSL2 to build LSW.

🏴‍☠️ BarrerSoftware - LSW Project
