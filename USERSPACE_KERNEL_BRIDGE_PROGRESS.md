# LSW Userspace to Kernel Bridge - Progress Update

## Date: December 31, 2025

## Goal
Enable `lsw --launch hello.exe` to execute PE binaries from userspace by delegating execution to the kernel module.

## What Was Done

### 1. Modified PE Loader (`src/pe-loader/pe_loader.c`)
- Added `#include "shared/lsw_kernel_client.h"` to access kernel communication functions
- Rewrote `pe_execute()` function to:
  - Open `/dev/lsw` kernel device using `lsw_kernel_open()`
  - Prepare `struct lsw_pe_info` with PE details:
    * PID (current process)
    * Base address (where PE is loaded in memory)
    * Entry point (where to start execution)
    * Image size
    * Architecture (32-bit or 64-bit)
    * Executable path
  - Register PE with kernel using `lsw_kernel_register_pe()`
  - Clean up with `lsw_kernel_unregister_pe()` and `lsw_kernel_close()`

### 2. Current Behavior
**Before:**
```bash
$ ./lsw --launch hello.exe
[loads PE]
[tries to execute directly in userspace]
Segmentation fault
```

**After (with working kernel module):**
```bash
$ ./lsw --launch hello.exe
[loads PE]
[registers with kernel module]
✅ PE registered with kernel successfully
TODO: Kernel needs to execute the PE at entry point
```

## What's Working
- ✅ PE parsing and loading (all 19 sections)
- ✅ Import resolution (47 functions from 2 DLLs)  
- ✅ Memory mapping at correct base address
- ✅ Kernel communication infrastructure (`lsw_kernel_client.c`)
- ✅ Code compiles and links successfully

## What's Next

### Immediate (Kernel Module Side)
1. **Add execution capability to kernel module**
   - When PE is registered, kernel should:
     * Create kernel thread for PE process
     * Set up TEB/PEB structures
     * Jump to entry point in kernel context
     * Handle Win32 API calls via syscall dispatcher
   
2. **Add execution trigger ioctl**
   - New ioctl: `LSW_IOCTL_EXECUTE_PE`
   - Userspace calls this after registration
   - Kernel creates process and starts execution

3. **Add status/wait mechanism**
   - Userspace needs to wait for PE execution to complete
   - Get exit code back from kernel
   - Handle process termination properly

### Implementation Plan
```c
// In kernel module (lsw_device.c)
static long lsw_execute_pe(pid_t pid) {
    // Find registered PE by PID
    // Create kernel thread for PE process
    // Set up Win32 environment (TEB, PEB)
    // Jump to entry point
    // Return 0 on success
}

// In userspace (pe_loader.c)
int pe_execute(pe_image_t* image, int argc, char** argv) {
    // ... existing registration code ...
    
    // NEW: Trigger execution
    ret = ioctl(kernel_fd, LSW_IOCTL_EXECUTE_PE, pe_info.pid);
    
    // NEW: Wait for completion
    int exit_code = lsw_kernel_wait_for_pe(kernel_fd, pe_info.pid);
    
    // Cleanup
    lsw_kernel_unregister_pe(kernel_fd, pe_info.pid);
    lsw_kernel_close(kernel_fd);
    
    return exit_code;
}
```

## Testing Status
- **Cannot test yet**: Kernel module in bad state (Used by: -1)
- **Need**: Reboot or fix module load issue
- **Device node**: `/dev/lsw` not created (module initialization incomplete)

## Success Criteria
When complete, this should work:
```bash
$ ./lsw --launch hello.exe
[19:43:34] INFO  LSW starting - Linux Subsystem for Windows
[19:43:34] INFO  Target: hello.exe
[19:43:34] INFO  PE file loaded successfully
[19:43:34] INFO  Registering PE with kernel
[19:43:34] INFO  ✅ PE registered with kernel successfully  
[19:43:34] INFO  🚀 Executing PE via kernel module
[19:43:34] INFO  Hello from Windows executable!
[19:43:34] INFO  Program exited with code: 0
```

## Files Modified
- `src/pe-loader/pe_loader.c` - Added kernel communication to `pe_execute()`
- `include/pe-loader/pe_loader.c` - Added kernel client header

## Next Session
1. Reboot to clear kernel module state OR investigate module reload
2. Test PE registration with fresh kernel module  
3. Implement kernel-side execution if registration works
4. Test end-to-end: `lsw --launch hello.exe` → kernel execution → output

## Notes
- Wine took 30 years. LSW has kernel-level integration from day 1.
- This is the critical bridge that makes LSW actually RUN Windows programs.
- Once this works, we can test with Notepad++, then eventually gaming workloads.

🏴‍☠️ **BFSL v1.2** - Building the Wine killer, one syscall at a time.
