# LSW Syscall Implementation Roadmap
## Target: Basic GUI Apps (Notepad++ Portable)

**Current Status:** 19 syscalls implemented (Phase 1 Complete)  
**Next Target:** 50 syscalls (Phase 2 - Basic GUI Support)  
**Test Application:** Notepad++ Portable

---

## Already Implemented (19 syscalls)

### Memory Management
- ✅ NtAllocateVirtualMemory
- ✅ NtFreeVirtualMemory  
- ✅ NtReadVirtualMemory
- ✅ NtProtectVirtualMemory
- ✅ NtQueryVirtualMemory

### File I/O
- ✅ NtCreateFile
- ✅ NtReadFile
- ✅ NtWriteFile
- ✅ NtClose

### Process/Thread Management
- ✅ NtCreateProcess
- ✅ NtCreateThreadEx
- ✅ NtTerminateProcess
- ✅ NtQuerySystemInformation

### Synchronization
- ✅ NtCreateEvent
- ✅ NtSetEvent
- ✅ NtWaitForSingleObject
- ✅ NtCreateMutant
- ✅ NtReleaseMutant

### DLL Loading
- ✅ NtLoadDriver (DLL loading support)

---

## Next 31 Syscalls (Priority Order)

### Critical for Basic Apps (Priority 1 - Do First)

#### Process/Thread Management (5)
1. **NtQueryInformationProcess** - Get process info (PID, memory usage, etc.)
2. **NtQueryInformationThread** - Get thread info (TID, state, etc.)
3. **NtOpenProcess** - Open handle to existing process
4. **NtResumeThread** - Resume suspended thread
5. **NtSuspendThread** - Suspend thread execution

#### File System (8)
6. **NtOpenFile** - Open existing file (vs create new)
7. **NtDeleteFile** - Delete file
8. **NtQueryInformationFile** - Get file metadata (size, dates, attributes)
9. **NtSetInformationFile** - Set file attributes
10. **NtQueryDirectoryFile** - List directory contents
11. **NtCreateDirectory** - Create directory/folder
12. **NtQueryVolumeInformationFile** - Get volume/drive info
13. **NtFlushBuffersFile** - Flush file buffers to disk

#### Memory/Sections (4)
14. **NtCreateSection** - Create shared memory section
15. **NtMapViewOfSection** - Map section into process memory
16. **NtUnmapViewOfSection** - Unmap section from memory
17. **NtQuerySection** - Query section information

#### Synchronization (5)
18. **NtWaitForMultipleObjects** - Wait on multiple handles
19. **NtCreateSemaphore** - Create semaphore
20. **NtReleaseSemaphore** - Release semaphore
21. **NtCreateTimer** - Create timer object
22. **NtSetTimer** - Set timer

---

### Important for GUI (Priority 2 - Do Second)

#### Handles/Objects (4)
23. **NtDuplicateObject** - Duplicate handle
24. **NtClose** (enhance) - Better handle cleanup
25. **NtQueryObject** - Query object information
26. **NtSetInformationObject** - Set object attributes

#### Time/Performance (3)
27. **NtQueryPerformanceCounter** - High-resolution timer
28. **NtDelayExecution** - Sleep/delay (NtSleep)
29. **NtYieldExecution** - Yield CPU to other threads

---

### Registry Support (Priority 3 - Stub for Now)

#### Registry (6 - Can be stubbed initially)
30. **NtCreateKey** - Create/open registry key (stub)
31. **NtOpenKey** - Open existing registry key (stub)
32. **NtSetValueKey** - Set registry value (stub)
33. **NtQueryValueKey** - Get registry value (stub)
34. **NtEnumerateKey** - List registry keys (stub)
35. **NtDeleteKey** - Delete registry key (stub)

**Note:** Registry can be stubbed to return defaults/empty values initially. Most apps will work fine. Full registry implementation can come later.

---

### Exception Handling (Priority 4 - Minimal for Now)

#### Exceptions (2 - Basic stubs)
36. **NtRaiseException** - Raise exception (stub for now)
37. **NtContinue** - Continue after exception (stub)

**Note:** Basic exception handling can be stubbed. Full SEH (Structured Exception Handling) is complex and can wait.

---

## Implementation Strategy

### Week 1: Priority 1 (Critical - 17 syscalls)
- **Day 1-2:** Process/Thread (5) + File System (8)
- **Day 3:** Memory/Sections (4)
- **Day 4:** Test with simple console apps
- **Day 5:** Synchronization (5)
- **Day 6-7:** Test and debug

### Week 2: Priority 2 + 3 (GUI + Registry - 13 syscalls)
- **Day 1-2:** Handles/Objects (4) + Time (3)
- **Day 3:** Registry stubs (6)
- **Day 4:** Exception stubs (2)
- **Day 5-7:** Test with Notepad++ Portable

### Expected Outcomes
- **After Week 1:** Console apps, simple utilities working
- **After Week 2:** GUI apps like Notepad++, Calculator, basic editors working

---

## Test Progression

1. **Syscall 1-25:** hello.exe, test.exe, cmd.exe
2. **Syscall 26-40:** notepad.exe, calc.exe
3. **Syscall 41-50:** notepad++.exe portable, simple GUI apps

---

## Linux Syscall Mappings (Many are Easy!)

| NT Syscall | Linux Equivalent | Difficulty |
|------------|------------------|------------|
| NtOpenFile | open() | Easy |
| NtDeleteFile | unlink() | Easy |
| NtQueryInformationFile | fstat() | Easy |
| NtSetInformationFile | fchmod(), futimens() | Medium |
| NtQueryDirectoryFile | getdents64() | Medium |
| NtCreateDirectory | mkdir() | Easy |
| NtCreateSection | shmget() or memfd_create() | Medium |
| NtMapViewOfSection | mmap() | Easy |
| NtQueryPerformanceCounter | clock_gettime() | Easy |
| NtDelayExecution | nanosleep() | Easy |
| NtDuplicateObject | dup() | Easy |

**Most map 1:1 to Linux!** That's why Wine took so long - they reverse-engineered. We just read the specs and map to Linux properly.

---

## Success Metrics

- ✅ 50 syscalls implemented
- ✅ Notepad++ Portable launches
- ✅ Can open, edit, save files
- ✅ Menus work
- ✅ No crashes

**Timeline:** 2 weeks of focused work  
**Wine's equivalent:** 5+ years  
**Advantage:** We work at kernel level with documentation

---

## Notes

- Registry can be stubbed - most apps don't require it to function
- Exception handling can be minimal - just don't crash
- Focus on file I/O and process management first
- Test continuously with real apps
- Each syscall implemented CORRECTLY, not guessed

---

**Let's get to 50 and prove LSW can run real Windows apps!** 🏴‍☠️

---

*Generated: 2025-12-30*  
*Project: LSW (Linux Subsystem for Windows)*  
*License: BFSL v1.2*  
*Copyright © 2025 BarrerSoftware*
