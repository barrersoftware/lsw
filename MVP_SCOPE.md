# LSW MVP Scope - First Working Release

**Goal: Run the simplest possible Windows executable on Linux**

## What is MVP?

Get **ONE** simple Windows program to actually execute. Not full compatibility - just proof it works.

## Target Executable: "Hello World"

We'll create and run the simplest possible Windows console app:

```c
// hello.c - Windows console program
#include <windows.h>

int main() {
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), 
                 "Hello from Windows on Linux!\n", 31, NULL, NULL);
    return 0;
}
```

**Why this target:**
- No GUI (no DirectX/GDI needed)
- Minimal Win32 API usage (2 functions)
- Small binary (~10KB)
- Easy to verify it works

## What We Need to Build

### Phase 1: PE Binary Loader (Week 1) ⚠️ CRITICAL

**Status:** Stub exists, no real implementation

**What needs to happen:**
1. Parse PE header (DOS + NT headers)
2. Read section table
3. Load sections into memory
4. Set up execution environment
5. Jump to entry point

**Files to modify:**
- `src/pe-loader/pe_parser.c` (NEW)
- `src/pe-loader/pe_loader.c` (NEW)
- `include/pe_format.h` (NEW)

**Complexity:** Medium - PE format is documented but complex

**Reference:** Microsoft PE/COFF specification (we have the PDF!)

### Phase 2: Minimal Syscall Translation (Week 2) ⚠️ CRITICAL

**Status:** Doesn't exist

**What we need:**
Just enough to support our hello world program:

```
Windows Syscall          → Linux Equivalent
─────────────────────────────────────────────
GetStdHandle()           → return fd 1 (stdout)
WriteConsole()           → write(1, buffer, length)
ExitProcess()            → exit()
```

**Files to create:**
- `src/syscall/syscall_table.c`
- `src/syscall/console.c`
- `src/syscall/process.c`
- `include/syscall/syscall.h`

**Complexity:** Medium - Need to intercept Windows API calls

### Phase 3: Minimal Win32 API Stubs (Week 2-3)

**Status:** Doesn't exist

**What we need:**
Only the functions our test program uses:

```c
// Minimal kernel32.dll stubs
HANDLE GetStdHandle(DWORD nStdHandle);
BOOL WriteConsoleA(HANDLE hConsoleOutput, const VOID* lpBuffer, 
                   DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, 
                   LPVOID lpReserved);
void ExitProcess(UINT uExitCode);
```

**Files to create:**
- `src/win32/kernel32.c`
- `include/win32/kernel32.h`

**Complexity:** Low - Just 3 functions for MVP

### Phase 4: Memory Management (Week 3)

**Status:** Doesn't exist

**What we need:**
- Allocate memory for PE sections
- Set proper permissions (read/write/execute)
- Map Windows address space to Linux

**Files to create:**
- `src/memory/vm_manager.c`
- `include/memory/vm_manager.h`

**Complexity:** High - Memory mapping is tricky

### Phase 5: Testing & Debug (Week 3)

**What we need:**
- Build test hello.exe on Windows (or with mingw)
- Test LSW loading it
- Debug why it crashes (it will!)
- Fix until it prints "Hello from Windows on Linux!"

## Optional But Helpful

### Registry Emulation (Stub Only)
Most programs query registry. For MVP, just return fake values:

```c
// If program asks: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion
// We return: "Windows 10" (fake)
```

**Files to modify:**
- `src/shared/registry/lsw_registry.c` (expand existing stub)

### Filesystem Translation
Already started! Just need to test it works:
- `C:\` → `/mnt/c/`
- `\` → `/`
- Case-insensitive lookups

**Files to verify:**
- `src/shared/filesystem/lsw_filesystem.c` (exists)

## Build Order (Dependency Graph)

```
1. PE Parser ─────┐
                  ├─→ 4. Memory Manager ──┐
2. PE Loader ─────┘                       ├─→ 5. Full Integration
                                          │
3. Win32 API Stubs ───────────────────────┘
```

**Start with:** PE Parser (can't do anything without loading the binary)

## MVP Success Criteria

✅ **Done when:**
```bash
$ lsw --launch hello.exe
Hello from Windows on Linux!
$ echo $?
0
```

That's it. One program. One successful execution.

## Beyond MVP (Phase 2 - Not in Scope Yet)

Once hello.exe works, we can expand:
- More Win32 APIs (file I/O, networking)
- GUI support (GDI basics)
- Registry emulation (real implementation)
- More complex programs (notepad.exe, calc.exe)

## Realistic Timeline

**Optimistic:** 3 weeks focused work
**Realistic:** 4-6 weeks (expect bugs)
**Pessimistic:** 2-3 months (if we hit hard problems)

## Biggest Risks

1. **PE Loading bugs** - Hard to debug binary formats
2. **Memory mapping issues** - Linux vs Windows address spaces differ
3. **Syscall interception** - Might need kernel module (harder!)
4. **Unknown unknowns** - Windows has weird edge cases

## Can We Test Today?

**Short answer:** No executable support yet.

**What we CAN do today:**
1. Write PE parser (read headers, print info)
2. Create test hello.exe with mingw
3. Verify LSW can at least parse the PE format

Want to start with the PE parser? That's the foundation for everything else.

---

## Current LSW Status (Reality Check)

```
Foundation:        ████████████████████ 100% ✅ (CLI, help, filesystem stubs)
PE Parsing:        ░░░░░░░░░░░░░░░░░░░░   0% ❌
PE Loading:        ░░░░░░░░░░░░░░░░░░░░   0% ❌
Syscall Layer:     ░░░░░░░░░░░░░░░░░░░░   0% ❌
Win32 API Stubs:   ░░░░░░░░░░░░░░░░░░░░   0% ❌
Memory Management: ░░░░░░░░░░░░░░░░░░░░   0% ❌

Overall Progress: ~15% (foundation only)
```

**To MVP:** Need to go from 15% → 100% on core functionality

**Effort required:** ~80-120 hours of focused coding

---

💙🏴‍☠️ **LSW MVP - Let's make Windows run on Linux (for real this time)**

Built by Captain CP & Daniel - Christmas 2024
