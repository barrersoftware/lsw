# LSW — Linux Subsystem for Windows

**Run real Windows executables natively on Linux. WSL2 in reverse.**

[![License](https://img.shields.io/badge/License-BFSL_v1.2-blue.svg)](https://barrersoftware.com/foss-license.html)
[![Build](https://img.shields.io/badge/Build-Passing-success.svg)]()
[![APIs](https://img.shields.io/badge/Win32_APIs-1235+-brightgreen.svg)]()
[![Apps](https://img.shields.io/badge/Tested_Apps-10+-brightgreen.svg)]()

---

## What is LSW?

LSW loads and runs Windows PE executables directly on Linux — no Wine, no QEMU, no VM.
It maps Win32 API calls to Linux equivalents at the binary level, translates Windows paths,
emulates the TEB/PEB/registry, and handles the x64 ABI crossing so Windows code runs
as-is on Linux hardware.

```
Windows .exe
    │
    ▼
lsw-pe-loader (PE parser + IAT patcher)
    │
    ▼
Win32 API stubs (1235+ functions across 15 DLLs)
    │
    ▼
Linux syscalls / glibc
    │
    ▼
Native hardware
```

No emulation. No virtualization. Direct execution.

---

## Tested Applications

These real Windows system tools run today:

| Application | Result |
|---|---|
| `hostname.exe` | ✅ Prints hostname |
| `whoami.exe` | ✅ Prints `domain\user` |
| `ipconfig.exe` | ✅ Shows Windows IP Configuration |
| `netstat.exe` | ✅ Shows "Active Connections", exits 0 |
| `systeminfo.exe` | ✅ Full system info output |
| `robocopy.exe` | ✅ Runs, prints banner, processes arguments |
| `ping.exe` | ✅ Sends ICMP pings |
| `reg.exe` | ✅ Registry query/set/delete |
| `7z.exe` (7-Zip) | ✅ Compresses and extracts archives |
| `netstat.exe -a` | ✅ Lists connections |

---

## Quick Start

### Build

```bash
git clone https://github.com/barrersoftware/lsw.git
cd lsw
make
```

### Run a Windows executable

```bash
# Any Windows .exe — no install needed
./build/bin/lsw-pe-loader --launch /path/to/app.exe [args...]

# Examples
./build/bin/lsw-pe-loader --launch /mnt/c/Windows/System32/hostname.exe
./build/bin/lsw-pe-loader --launch /mnt/c/Windows/System32/ipconfig.exe /all
./build/bin/lsw-pe-loader --launch /mnt/c/Windows/System32/robocopy.exe 'C:\src' 'C:\dst' /MIR
./build/bin/lsw-pe-loader --launch /path/to/7z.exe a archive.zip ./files/
```

### With kernel module (optional, for deeper syscall routing)

```bash
sudo insmod build/lsw.ko
./build/bin/lsw-pe-loader --launch app.exe   # automatically uses /dev/lsw
```

---

## Architecture

### Components

| Component | Description |
|---|---|
| `src/pe-loader/` | PE parser, section mapper, IAT patcher, base relocations, PE DLL loader |
| `src/win32-api/` | 1235+ Win32 API stub implementations |
| `src/kernel-module/` | Optional Linux kernel module for deeper syscall routing |
| `include/` | Shared headers (TEB, PEB, PE structures, Win32 types) |

### Win32 API Coverage

| DLL | Functions | Coverage |
|---|---|---|
| `KERNEL32.dll` | CreateFile, ReadFile, WriteFile, VirtualAlloc, CreateThread, WaitForSingleObject, FindFirstFile, GetModuleHandle, LoadLibrary, FreeLibrary, CreateProcess, GetProcAddress, 200+ more | ~350 stubs |
| `ntdll.dll` | NtQueryInformationProcess, RtlAllocateHeap, RtlFreeHeap, Rtl string/memory utils, hash tables, SEH/unwind, NtOpenFile, NtQueryDirectoryFile, 80+ more | ~130 stubs |
| `ADVAPI32.dll` | Registry CRUD, tokens, security descriptors, crypto APIs, services, event log, EFS stubs | ~120 stubs |
| `msvcrt.dll` / `ucrtbase.dll` | malloc/free, printf family, string ops, file I/O, locale, math | ~180 stubs |
| `WS2_32.dll` | WSAStartup, socket, connect, send, recv, getaddrinfo, select, full Winsock | ~60 stubs |
| `ole32.dll` / `oleaut32.dll` | CoInitialize, CoCreateInstance, COM dispatch, BSTR, VARIANT, SafeArray | ~80 stubs |
| `IPHLPAPI.dll` | GetAdaptersInfo, GetIfTable, InternalGetTcpTable, InternalGetBound\*EndpointTable, GetAdaptersAddresses | ~40 stubs |
| `USER32.dll` | MessageBox, GetDesktopWindow, SendMessage, console & window basics | ~50 stubs |
| `SHELL32.dll` | SHGetFolderPath, ShellExecute, path utilities | ~25 stubs |
| `GDI32.dll` | Stub surface for apps that link but don't draw | ~15 stubs |
| `snmpapi.dll`, `shlwapi.dll`, `comctl32.dll`, game APIs | Additional coverage | ~60 stubs |

### Key Technical Details

- **PE Loading**: Full x64 PE support — sections, imports, exports (by name + ordinal), base relocations, bound imports, PE DLL chain loading
- **ABI Crossing**: Windows uses `__ms_abi` (registers RCX/RDX/R8/R9, caller-saves R10/R11), Linux uses System V AMD64; all stubs marked `__attribute__((ms_abi))`
- **TEB/PEB Emulation**: Full Thread Environment Block at `gs:0x00`; critical offsets (0x30 = Self, 0x60 = PEB, 0x68 = LastError, 0x1480 = TlsSlots) verified with compile-time asserts
- **`__chkstk` Fix**: TEB.StackLimit forced to NULL so Windows stack-probe loop always skips (Linux kernel auto-extends stack on access — no probing needed)
- **SEH / C++ Exceptions**: Signal-to-Windows-exception translation (SIGSEGV→EXCEPTION_ACCESS_VIOLATION, etc.), `.pdata` UNWIND_INFO registered, `_CxxThrowException` support
- **Registry**: Backed by `~/.lsw/registry/` (SQLite), HKLM/HKCU/HKCR
- **Filesystem**: `C:\path` → `/mnt/c/path`, `%TEMP%` → `/tmp`, Windows special folders mapped
- **Threading**: `CreateThread` → `pthread_create`, full mutex/semaphore/event/critical-section/SRW-lock/condition-variable/thread-pool emulation
- **Networking**: Full Winsock 2 → POSIX sockets (TCP, UDP, DNS via getaddrinfo)

---

## What Works

- ✅ Console applications (Win32 + CRT)
- ✅ Multi-threaded applications
- ✅ Network applications (TCP/UDP/DNS)
- ✅ Registry access
- ✅ File I/O (CreateFile, ReadFile, WriteFile, FindFirst/NextFile)
- ✅ PE DLL loading (LoadLibrary chains)
- ✅ COM/OLE basics (CoInitialize, dispatch stubs)
- ✅ C++ exceptions across Win32 code
- ✅ MSI installer launch
- ✅ 7-Zip, compression tools
- ✅ Windows system utilities (ipconfig, netstat, systeminfo, etc.)

## What Doesn't Work Yet

- ❌ **GUI applications** — USER32/GDI windowing creates actual windows but no rendering backend yet
- ❌ **DirectX / graphics** — stubs exist, no translation to Vulkan/OpenGL
- ❌ **WMI-heavy tools** — `tasklist.exe` needs framedynos.dll CHString vtable emulation
- ❌ **Full NT file I/O** — `NtOpenFile`/`NtQueryDirectoryFile` are stubs; apps using NT paths for file enumeration see no files
- ❌ **Driver-dependent features** — anything requiring actual Windows kernel drivers

---

## 🆓 Always Free

LSW is and will always be free.

- ✅ Free to download, use, modify, distribute
- ❌ NEVER for sale

**Built from Microsoft Open Specifications (published, free documentation) → must remain free.**

If anyone charges you for LSW, report it: legal@barrersoftware.com

---

## Roadmap

### Near Term
- Full NT path translation (`RtlDosPathNameToRelativeNtPathName_U`) so `robocopy` and similar tools can actually enumerate and copy files
- `tasklist.exe` — minimal CHString class vtable so framedynos.dll works
- More real-world app testing (browsers, .NET CLI tools, games)

### Medium Term
- GUI surface — X11/Wayland backend for USER32/GDI calls
- DirectX → Vulkan translation layer

### Long Term
- `.NET` / CLR runtime hosting
- UWP / AppX support
- MSI full installation (registry, shortcuts, services)

---

## Project Structure

```
lsw/
├── src/
│   ├── pe-loader/          # PE binary loader (main.c, pe_loader.c, pe_parser.c)
│   ├── win32-api/          # Win32 API stubs (15 source files, 1235+ mappings)
│   │   ├── win32_api.c     # KERNEL32, msvcrt, WS2_32, and core stubs
│   │   ├── ntdll_api.c     # ntdll stubs
│   │   ├── advapi32_api.c  # Security, registry, crypto, services
│   │   ├── ole32_api.c     # COM/OLE
│   │   ├── oleaut32_api.c  # Automation, BSTR, VARIANT
│   │   ├── misc_api.c      # IPHLPAPI, DNSAPI, snmpapi, DirectX stubs
│   │   ├── user32_api.c    # USER32 basics
│   │   ├── shell32_api.c   # Shell APIs
│   │   ├── win32_teb.c     # TEB/PEB emulation + GS register setup
│   │   └── ...
│   └── kernel-module/      # Optional Linux kernel module (/dev/lsw)
├── include/                # Shared headers
├── build/                  # Build output (bin/, lib/)
├── tests/                  # Test apps
└── Makefile
```

---

## Legal

LSW is a clean-room implementation using Microsoft's publicly available specifications.

- **APIs are not copyrightable** — Google v. Oracle (2021)
- **Same legal basis as Wine, ReactOS, Samba** (30+ years of precedent)
- **No decompilation, no leaked code, no proprietary sources**

See [LEGAL.md](LEGAL.md) for the full legal foundation.

---

## Advantages Over Wine

| Feature | Wine | LSW |
|---|---|---|
| Execution model | User-space PE loader + translation | Same — user-space PE loader + translation |
| API approach | Per-app fixes, decades of work | Clean modern implementation |
| Kernel module | No | Optional (for deeper syscall routing) |
| Target | Full compatibility (30+ years) | Console/server apps (2026) |
| Architecture | i386 + x86_64 | x86_64 native |

---

## Authors

- **BarrerSoftware** — Architecture, implementation, testing

---

🏴‍☠️ Built by BarrerSoftware  
💙 Open Source, always free  
🚀 Because Linux users deserve Windows apps too

---

## Trademark Disclaimer

LSW is an independent open-source project not affiliated with, endorsed by, or sponsored by
Microsoft Corporation. "Windows," "WSL," and "Windows Subsystem for Linux" are trademarks
of Microsoft Corporation. LSW is a descriptive project name.
