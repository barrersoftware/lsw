# LSW Filesystem Audit - ~/.lsw Integration

**Date:** January 1, 2026  
**Purpose:** Ensure ALL code uses ~/.lsw/drives/c/ instead of / or /mnt/c/

---

## ✅ ALREADY CORRECT

### Core Path Translation (WORKING!)
- `src/shared/filesystem/lsw_filesystem.c` - lsw_fs_win_to_linux() ✅
- `src/shared/utils/lsw_config.c` - Default: ~/.lsw/drives/c/ ✅
- `src/win32-api/win32_api.c` - CreateFileA uses translation ✅
- `kernel-module/lsw_syscall.c` - NtCreateFile gets path from userspace ✅

---

## ❌ NEEDS FIXING

### 1. User-Facing Messages (main.c) - MISLEADING
**File:** `src/pe-loader/main.c`

**Current (WRONG):**
```
Line 57:  lsw --launch /mnt/c/Games/game.exe
Line 95:  Your C: drive is at /mnt/c
Line 284: Try using the full path: /mnt/c/path/to/file.exe
Line 285: Your C: drive is at /mnt/c on Linux
Line 288: lsw --launch /mnt/c/Windows/notepad.exe
```

**Should Be:**
```
lsw --launch ~/.lsw/drives/c/Games/game.exe
OR just: lsw --launch game.exe (if in PATH)
Your C: drive is at ~/.lsw/drives/c/
```

**Fix:** Update all help text to reflect ~/.lsw architecture

---

### 2. Kernel Module Hardcoded Path (CRITICAL)
**File:** `kernel-module/lsw_syscall.c:615`

**Current (WRONG):**
```c
const char *path = "/tmp/test.dll";  /* TODO: Get from userspace */
```

**Problem:** LdrLoadDll syscall has hardcoded /tmp/test.dll

**Should Be:**
```c
// Get path from userspace like NtCreateFile does
__u64 path_ptr = req->args[0];
char path_kernel[256];
copy_from_user(path_kernel, (const char __user *)path_ptr, sizeof(path_kernel) - 1);
```

**Status:** Daniel identified this - module should translate Win32 to Linux, not hardcode paths

---

### 3. Test Files (Non-Critical, but misleading)
**Files:**
- `src/tests/test_file_io.c:59` - /tmp/lsw_test.txt
- `src/tests/test_file_io.c:155` - cat /tmp/lsw_test.txt
- `src/tests/test_dll_process.c:52` - /tmp/test.dll

**Problem:** Test files use /tmp instead of ~/.lsw/drives/c/

**Should Be:**
```c
// Use Windows paths that get translated
const char* test_path = "C:\\test.txt";  // Translates to ~/.lsw/drives/c/test.txt
```

**Or:** Use ~/.lsw/drives/c/ directly in tests

---

## 🎯 FIXES NEEDED

### Priority 1: LdrLoadDll Hardcoded Path
**File:** kernel-module/lsw_syscall.c, line 615

```c
// BEFORE:
long lsw_syscall_LdrLoadDll(struct lsw_syscall_request *req)
{
    const char *path = "/tmp/test.dll";  /* TODO: Get from userspace */
    // ...
}

// AFTER:
long lsw_syscall_LdrLoadDll(struct lsw_syscall_request *req)
{
    __u64 path_ptr = req->args[0];  // Path from userspace
    char path_kernel[256];
    
    if (copy_from_user(path_kernel, (const char __user *)path_ptr, sizeof(path_kernel) - 1)) {
        lsw_err("Failed to copy DLL path from userspace");
        req->return_value = 0;
        req->error_code = -EFAULT;
        return -EFAULT;
    }
    path_kernel[sizeof(path_kernel) - 1] = '\0';
    
    lsw_info("LdrLoadDll: path='%s'", path_kernel);
    // ... rest of function
}
```

---

### Priority 2: Help Text Updates
**File:** src/pe-loader/main.c

Replace ALL references to `/mnt/c/` with `~/.lsw/drives/c/` or better examples:

```c
// Help text example:
printf("Examples:\n");
printf("  lsw --launch game.exe              # If game.exe is in current directory\n");
printf("  lsw --launch notepad.exe           # Windows apps work like Linux apps\n");
printf("  lsw --launch C:\\Windows\\notepad.exe  # Windows paths work too\n");
printf("\n");
printf("Note: C:\\ paths are mapped to ~/.lsw/drives/c/\n");
printf("      This keeps Windows apps isolated from your Linux system.\n");
```

---

### Priority 3: Test Files
**Files:** src/tests/*.c

Update test files to use Windows paths or correct Linux paths:

```c
// BEFORE:
const char* test_path = "/tmp/lsw_test.txt";

// AFTER (Option 1 - Windows path):
const char* test_path = "C:\\test.txt";  // Translated automatically

// AFTER (Option 2 - Direct Linux path):
const char* test_path = "~/.lsw/drives/c/test.txt";
```

---

## 🔍 VERIFICATION NEEDED

### Check These Don't Assume /:
- [ ] All kernel file operations use translated paths ✅ (already correct)
- [ ] DLL loading uses userspace path (NEEDS FIX)
- [ ] Process creation uses correct paths (check later)
- [ ] Registry paths use ~/.lsw/registry/ (not implemented yet)

---

## 📋 IMPLEMENTATION PLAN

### Session 1 (Now):
1. Fix LdrLoadDll hardcoded path
2. Update help text in main.c
3. Test DLL loading with proper paths

### Session 2 (Later):
1. Update test files to use Windows paths
2. Add ~/.lsw structure verification
3. Document path translation for developers

---

## 🎯 GOAL

**Everything should work with:**
- Windows apps use: `C:\path\to\file.txt`
- LSW translates to: `~/.lsw/drives/c/path/to/file.txt`
- Kernel handles: Linux VFS operations
- Result: Isolated, safe, production-ready

**No hardcoded paths. No /tmp. No /mnt/c/. Just ~/.lsw/**

---

**Built by BarrerSoftware - Clean architecture, no shortcuts! 🏴‍☠️**
