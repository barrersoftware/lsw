# LSW Development TODO List

## CRITICAL - Debug Comprehensive Test Crash
**Priority: HIGH**
**Status: In Progress**

### Issue
- Comprehensive test (`test_comprehensive.exe`) crashes with SEGFAULT after file enumeration tests
- Crash occurs when returning from `test_file_enumeration()` to main
- Individual tests work perfectly in isolation:
  - ✅ Memory APIs: 7/7 pass
  - ✅ File Enum APIs: 2/2 pass
  - ✅ Path APIs: work standalone
- Crash happens even if path/env section is commented out

### Investigation Done
- [x] Identified missing APIs (fwprintf, fputwc, fflush) - ADDED
- [x] Fixed UTF-16 to UTF-8 conversion bug
- [x] Verified individual tests work
- [x] Confirmed crash is in test harness, not APIs themselves

### Possible Causes
- [ ] Stack alignment issue in test program
- [ ] CRT initialization/cleanup problem
- [ ] Return value corruption between functions
- [ ] Memory corruption from FindFirstFileW/FindNextFileW
- [ ] Hidden CRT dependency we're missing
- [ ] wprintf stub causing issues

### Next Steps
1. Debug with GDB to get exact crash location
2. Check stack alignment requirements for MS ABI
3. Review FindFirstFileW handle management
4. Test with simpler harness (fewer functions)
5. Add more CRT function stubs if needed

### Files Affected
- `test_comprehensive.c` - test harness
- `src/win32-api/win32_api.c` - API implementations

---

## Medium Priority Tasks

### Implement More KERNEL32 APIs
- [ ] Module loading: LoadLibraryExW, GetModuleFileNameW, GetModuleHandleExW
- [ ] File operations: MoveFileExW, ReplaceFileW, GetFileAttributesExW
- [ ] String functions: lstrcmpW, lstrcpyW, lstrcpynA, lstrlenW
- [ ] Time functions: GetTickCount, GetSystemTimeAsFileTime, FileTimeToSystemTime

### Start USER32 Implementation
- [ ] Window management basics (211 functions needed for Notepad++)
- [ ] Message handling
- [ ] Input processing

### Start GDI32 Implementation  
- [ ] Device context management (63 functions needed)
- [ ] Drawing primitives

---

## Completed Today (Jan 6, 2026)

### APIs Added: +3 (141 → 144)
- [x] fwprintf - wide-char fprintf stub
- [x] fputwc - wide-char fputc stub  
- [x] fflush - flush output with fake FILE* handling

### Bugs Fixed
- [x] UTF-16 to UTF-8 conversion (critical) - Windows uses 2-byte wchar_t, Linux uses 4-byte
- [x] WideCharToMultiByte now properly casts to uint16_t*

### Testing
- [x] Verified Memory APIs: 7/7 tests passing
- [x] Verified File Enum APIs: 2/2 tests passing
- [x] Verified Path APIs work standalone
- [x] Kernel module loaded and functional on new server

---

**Last Updated:** January 7, 2026 @ 12:45 AM PST
**Next Session:** Continue debugging comprehensive test crash
