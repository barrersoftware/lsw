# LSW API to Syscall Mapping

## Current Status (141 APIs implemented)

### APIs that work WITHOUT kernel module (userspace only):

#### Memory Management (12 APIs) - Use malloc/free
- GetProcessHeap ✅
- HeapAlloc ✅
- HeapFree ✅
- HeapReAlloc ✅
- HeapSize ✅
- LocalAlloc ✅
- LocalFree ✅
- GlobalAlloc ✅
- GlobalFree ✅
- GlobalLock ✅
- GlobalUnlock ✅
- GlobalSize ✅

#### File Enumeration (4 APIs) - Use Linux opendir/readdir
- FindFirstFileW ✅
- FindNextFileW ✅
- FindClose ✅
- FindFirstFileExW ✅

#### Path/Environment (12 APIs) - Pure userspace
- GetWindowsDirectoryA ✅
- GetWindowsDirectoryW ✅
- GetSystemDirectoryA ✅
- GetSystemDirectoryW ✅
- GetTempPathA ✅
- GetTempPathW ✅
- GetEnvironmentVariableA ✅ (uses Linux getenv)
- GetEnvironmentVariableW ✅
- SetEnvironmentVariableA ✅ (uses Linux setenv)
- SetEnvironmentVariableW ✅
- ExpandEnvironmentStringsA ✅
- ExpandEnvironmentStringsW ✅

#### String/Utility (14 APIs) - Pure userspace
- strcmp ✅
- strstr ✅
- MultiByteToWideChar ✅
- WideCharToMultiByte ✅
- lstrlenA ✅
- IsDBCSLeadByteEx ✅
- ... (various CRT functions)

#### Dialog Stubs (2 APIs) - Userspace stubs
- PrintDlgW ✅ (stub returns FALSE)
- ChooseColorW ✅ (stub returns FALSE)

**Total Userspace-only: ~44 APIs**

---

### APIs that NEED kernel module syscalls:

#### File I/O (requires NtCreateFile, NtReadFile, NtWriteFile, NtClose)
- CreateFileA ⚠️ (has userspace fallback)
- CreateFileW ⚠️ (has userspace fallback)
- ReadFile ❌ NEEDS: NtReadFile
- WriteFile ❌ NEEDS: NtWriteFile
- CloseHandle ⚠️ (partial - needs NtClose for file handles)
- DeleteFileA ⚠️
- DeleteFileW ⚠️
- CopyFileW ⚠️
- GetFileSize ❌ NEEDS: LswGetFileSize
- SetFilePointer ❌ NEEDS: LswSetFilePointer

#### Console I/O (requires LswWriteConsole, LswReadConsole, LswGetStdHandle)
- WriteConsoleA ❌ NEEDS: LswWriteConsole
- GetStdHandle ❌ NEEDS: LswGetStdHandle

#### Threading (requires NtCreateThreadEx, NtTerminateThread)
- CreateThread ❌ NEEDS: NtCreateThreadEx
- ExitThread ❌ NEEDS: NtTerminateThread

#### Synchronization (requires NtCreateEvent, NtSetEvent, etc.)
- CreateEventA ❌ NEEDS: NtCreateEvent
- SetEvent ❌ NEEDS: NtSetEvent
- WaitForSingleObject ❌ NEEDS: NtWaitForSingleObject

#### Virtual Memory (requires Nt*VirtualMemory syscalls)
- VirtualAlloc ❌ NEEDS: NtAllocateVirtualMemory
- VirtualFree ❌ NEEDS: NtFreeVirtualMemory
- VirtualProtect ❌ NEEDS: NtProtectVirtualMemory
- VirtualQuery ❌ NEEDS: NtReadVirtualMemory

**Total Kernel-dependent: ~20 APIs**

---

## Missing Kernel Syscalls Needed

### For Directory Operations:
- [ ] NtQueryDirectoryFile - For FindFirstFile/FindNextFile kernel path
  - Currently using userspace opendir/readdir (works!)
  - Can add kernel path later for performance

### For File Attributes:
- [ ] NtQueryInformationFile - Get file info
- [ ] NtSetInformationFile - Set file info
  - GetFileAttributesW uses stat() (works!)
  - SetFileAttributesW uses chmod() (works!)

### For Module Loading:
- [ ] LdrLoadDll - Already defined but needs implementation
- [ ] LdrGetProcedureAddress - Already defined but needs implementation

---

## Action Items

1. **Immediate (works without kernel)**:
   - [x] Memory management APIs
   - [x] File enumeration APIs  
   - [x] Path/Environment APIs
   - [x] String utilities
   - All use userspace - work NOW!

2. **Kernel Module Required**:
   - [ ] Load kernel module on dev server
   - [ ] Test file I/O through kernel
   - [ ] Test console I/O
   - [ ] Test threading
   - [ ] Test synchronization

3. **Future Kernel Syscalls to Add**:
   - NtQueryDirectoryFile (optional - have userspace)
   - NtQueryInformationFile (optional - have stat)
   - NtSetInformationFile (optional - have chmod)
   - Full process/thread management
   - Full synchronization primitives

---

## Summary

**Good news:** 44/141 APIs (31%) work purely in userspace without kernel module!

These include:
- All memory management ✅
- All file enumeration ✅
- All path/environment ✅
- String utilities ✅

**Kernel module needed for:**
- File I/O operations
- Console I/O
- Threading
- Synchronization
- Virtual memory

**Bottom line:** We can test ~31% of our APIs right now without kernel module! The rest needs kernel support.
