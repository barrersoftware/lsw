# LSW Development TODO

## Current Status
✅ **MILESTONE ACHIEVED:** hello.exe prints "Hello, World from Win32!" through kernel!
✅ Ring-3→Ring-0→Ring-3 syscall flow: **WORKING**
✅ Infrastructure: **COMPLETE**

## Immediate Next Steps

### 1. Fix test.exe (HIGH PRIORITY)
**Status:** Crashes in fputc with NULL FILE pointer

**Root Cause:** CRT functions missing `__attribute__((ms_abi))`

**Tasks:**
- [ ] Add MS ABI to all CRT functions in win32_api.c:
  - [ ] `lsw__getmainargs`
  - [ ] `lsw__initenv`
  - [ ] `lsw__set_app_type`
  - [ ] `lsw__setusermatherr`
  - [ ] `lsw__amsg_exit`
  - [ ] `lsw__cexit`
  - [ ] `lsw__commode_ptr`
  - [ ] `lsw__fmode_ptr`
  - [ ] `lsw__errno_func`
  - [ ] `lsw__initterm`
  - [ ] `lsw__lock`
  - [ ] `lsw__unlock`
  - [ ] `lsw__onexit`
  - [ ] All other msvcrt stubs
- [ ] Add ADVAPI32.dll function stubs (test.exe imports this)
- [ ] Test and validate test.exe execution

### 2. Scale Syscall Coverage (MEDIUM PRIORITY)
**Goal:** 50 syscalls for basic Win32 app support

**Categories to implement:**
- [ ] **Process/Thread Management** (~10 syscalls)
  - NtCreateProcess (stub exists, needs implementation)
  - NtCreateThread (stub exists, needs implementation)
  - NtTerminateProcess (stub exists, needs implementation)
  - NtQueryInformationProcess (stub exists, needs implementation)
  - NtWaitForSingleObject (stub exists, needs implementation)
  
- [ ] **Memory Management** (handlers exist, need testing)
  - NtAllocateVirtualMemory ✅
  - NtFreeVirtualMemory ✅
  - NtProtectVirtualMemory ✅
  - NtMapViewOfSection
  - NtUnmapViewOfSection

- [ ] **Synchronization** (stubs exist)
  - NtCreateEvent ✅
  - NtSetEvent ✅
  - NtCreateMutant ✅
  - NtReleaseMutant ✅
  - NtWaitForMultipleObjects

- [ ] **Registry** (new)
  - NtCreateKey
  - NtOpenKey
  - NtQueryValueKey
  - NtSetValueKey
  - NtDeleteKey

### 3. Architecture Improvements (LOW PRIORITY)
- [ ] Remove .text section writable hack (fix IAT properly)
- [ ] Implement proper PE relocations
- [ ] Add exception handling for PE code
- [ ] Optimize syscall dispatch performance

### 4. Testing & Validation
- [x] hello.exe - **WORKING!** ✅
- [ ] test.exe - In Progress
- [ ] Notepad.exe - Target for 50 syscalls milestone
- [ ] Calculator.exe - Target for 100 syscalls milestone

### 5. Documentation
- [x] KNOWN_ISSUES.md - Created ✅
- [ ] API_REFERENCE.md - Document all implemented syscalls
- [ ] ARCHITECTURE.md - Explain LSW design
- [ ] CONTRIBUTING.md - Guide for adding new syscalls

## Long-term Goals
- [ ] GUI Support (NtUser* syscalls) - 100+ syscalls
- [ ] DirectX/Graphics - Complex subsystem
- [ ] Full Windows compatibility - 500+ syscalls
- [ ] Performance optimization
- [ ] Production-ready release

## Victory Metrics
- ✅ 1 app working (hello.exe) - **ACHIEVED DEC 31, 2025!**
- 🎯 2 apps working (test.exe) - Next milestone
- 🎯 Basic apps (Notepad) - 50 syscalls milestone
- 🎯 Complex apps (Calculator) - 100 syscalls milestone
- 🎯 Industry dominance - Beat Wine's market share

---

**Built by BarrerSoftware - The future of Windows-on-Linux! 🏴‍☠️**
